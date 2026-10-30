use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use wasixv2_abi::Errno;
use wasixv2_vnet::{
    Answer, Backend, BackendStream, Domain, Lookup, PollMask, Shutdown, StreamState, WaitQueue,
};
use wasixv2_wait::{WaitEntry, WaitRegistration};

use crate::{CloseReason, Frame, FrameSink, ReceiveError, StreamKind, WispBackend};

/// What the backend sent to the server, decoded.
#[derive(Default)]
struct Wire(Mutex<Vec<Frame>>);

impl FrameSink for Wire {
    fn send(&self, frame: Vec<u8>) {
        self.0.lock().unwrap().push(Frame::decode(&frame).unwrap());
    }
}

impl Wire {
    fn take(&self) -> Vec<Frame> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

/// The events a queue was woken with.
#[derive(Default)]
struct Woken(Mutex<PollMask>);

impl WaitEntry for Woken {
    fn wake(&self, events: PollMask) -> bool {
        *self.0.lock().unwrap() |= events;
        true
    }
}

impl Woken {
    fn take(&self) -> PollMask {
        std::mem::replace(&mut self.0.lock().unwrap(), PollMask::empty())
    }
}

/// A guest socket's queue, and what woke it.
struct Watched {
    wq: WaitQueue,
    woken: Arc<Woken>,
    _registration: WaitRegistration,
}

fn watched() -> Watched {
    let wq = WaitQueue::new();
    let woken = Arc::new(Woken::default());
    let registration = wq.add(woken.clone());
    Watched {
        wq,
        woken,
        _registration: registration,
    }
}

struct Harness {
    backend: WispBackend,
    wire: Arc<Wire>,
}

impl Harness {
    fn new() -> Self {
        let wire = Arc::new(Wire::default());
        Self {
            backend: WispBackend::new(wire.clone()),
            wire,
        }
    }

    fn up(credit: u32) -> Self {
        let h = Self::new();
        h.server(Frame::Continue {
            stream: 0,
            remaining: credit,
        });
        h
    }

    fn server(&self, frame: Frame) {
        self.backend.receive(&frame.encode()).unwrap();
    }

    fn connect(&self, peer: &str) -> (Arc<dyn BackendStream>, Watched, u32) {
        let watched = watched();
        let stream = self
            .backend
            .connect(addr(peer), watched.wq.clone())
            .unwrap();
        let id = match self.wire.take().as_slice() {
            [Frame::Connect { stream, .. }] => *stream,
            other => panic!("expected one CONNECT, got {other:?}"),
        };
        (stream, watched, id)
    }
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn resolve(backend: &WispBackend, name: &str) -> SocketAddr {
    let found = Arc::new(Mutex::new(None));
    let slot = found.clone();
    backend.lookup(
        Lookup::Name(name.into()),
        Box::new(move |r| *slot.lock().unwrap() = Some(r)),
    );
    let answer = found.lock().unwrap().take().unwrap().unwrap().answer;
    match answer {
        Answer::Addrs { addrs, .. } => SocketAddr::new(addrs[0], 443),
        other => panic!("not addresses: {other:?}"),
    }
}

#[test]
fn a_stream_connects_once_the_server_grants_credit() {
    let h = Harness::new();
    let watched = watched();

    let stream = h
        .backend
        .connect(addr("127.0.0.1:8080"), watched.wq.clone())
        .unwrap();

    assert_eq!(
        h.wire.take(),
        [Frame::Connect {
            stream: 1,
            kind: StreamKind::Tcp,
            port: 8080,
            host: "127.0.0.1".into(),
        }]
    );
    assert_eq!(stream.state(), StreamState::Connecting);
    assert_eq!(stream.write(b"x"), Err(Errno::EAGAIN));

    h.server(Frame::Continue {
        stream: 0,
        remaining: 128,
    });

    assert_eq!(stream.state(), StreamState::Established);
    assert!(watched.woken.take().contains(PollMask::OUT));
    assert!(stream.poll(None).contains(PollMask::OUT));
}

#[test]
fn writes_spend_credit_and_continue_restores_it() {
    let h = Harness::up(2);
    let (stream, watched, id) = h.connect("192.0.2.1:80");

    assert_eq!(stream.write(b"one"), Ok(3));
    assert_eq!(stream.write(b"two"), Ok(3));
    assert_eq!(stream.write(b"three"), Err(Errno::EAGAIN));
    assert!(!stream.poll(None).contains(PollMask::OUT));
    assert_eq!(
        h.wire.take(),
        [
            Frame::Data {
                stream: id,
                data: b"one".to_vec()
            },
            Frame::Data {
                stream: id,
                data: b"two".to_vec()
            },
        ]
    );

    watched.woken.take();
    h.server(Frame::Continue {
        stream: id,
        remaining: 1,
    });

    assert!(watched.woken.take().contains(PollMask::OUT));
    assert_eq!(stream.write(b"three"), Ok(5));
}

#[test]
fn a_large_write_is_cut_to_one_packet() {
    let h = Harness::up(8);
    let (stream, _, _) = h.connect("192.0.2.1:80");

    assert_eq!(stream.write(&vec![7; 100_000]), Ok(64 * 1024));
}

#[test]
fn data_is_read_and_a_voluntary_close_is_end_of_stream() {
    let h = Harness::up(8);
    let (stream, watched, id) = h.connect("192.0.2.1:80");
    watched.woken.take();

    h.server(Frame::Data {
        stream: id,
        data: b"hello".to_vec(),
    });
    assert!(watched.woken.take().contains(PollMask::IN));
    assert_eq!(stream.input_len(), 5);

    let mut buf = [0; 3];
    assert_eq!(stream.read(&mut buf, true), Ok(3));
    assert_eq!(stream.read(&mut buf, false), Ok(3));
    assert_eq!(&buf, b"hel");
    assert_eq!(stream.read(&mut buf, false), Ok(2));
    assert_eq!(stream.read(&mut buf, false), Err(Errno::EAGAIN));

    h.server(Frame::Close {
        stream: id,
        reason: CloseReason::VOLUNTARY,
    });

    assert!(watched.woken.take().contains(PollMask::RDHUP));
    assert_eq!(stream.read(&mut buf, false), Ok(0));
    assert_eq!(stream.write(b"more"), Err(Errno::EPIPE));
    drop(stream);
    assert_eq!(h.wire.take(), [], "a closed stream sends no CLOSE");
}

#[test]
fn a_connection_the_server_could_not_open_is_refused() {
    let h = Harness::up(8);
    let (stream, watched, id) = h.connect("192.0.2.1:81");

    h.server(Frame::Close {
        stream: id,
        reason: CloseReason::NETWORK_ERROR,
    });

    assert!(watched.woken.take().contains(PollMask::ERR));
    assert_eq!(stream.state(), StreamState::Closed);
    assert_eq!(stream.take_error(), Some(Errno::ECONNREFUSED));
    assert_eq!(stream.take_error(), None);
}

#[test]
fn close_reasons_become_the_errnos_linux_reports() {
    for (reason, got_data, errno) in [
        (CloseReason::NETWORK_ERROR, false, Errno::ECONNREFUSED),
        (CloseReason::NETWORK_ERROR, true, Errno::ECONNRESET),
        (CloseReason::UNKNOWN, true, Errno::ECONNRESET),
        (CloseReason::UNREACHABLE_HOST, false, Errno::EHOSTUNREACH),
        (CloseReason::NO_RESPONSE, false, Errno::ETIMEDOUT),
        (CloseReason::TRANSFER_TIMEOUT, true, Errno::ETIMEDOUT),
        (CloseReason::CONN_REFUSED, false, Errno::ECONNREFUSED),
        (CloseReason::HOST_BLOCKED, false, Errno::ECONNREFUSED),
    ] {
        let h = Harness::up(8);
        let (stream, _, id) = h.connect("192.0.2.1:80");
        if got_data {
            h.server(Frame::Data {
                stream: id,
                data: b"x".to_vec(),
            });
        }
        h.server(Frame::Close { stream: id, reason });
        assert_eq!(stream.take_error(), Some(errno), "{reason:?}");
    }
}

#[test]
fn dropping_a_stream_closes_it_on_the_server() {
    let h = Harness::up(8);
    let (stream, _, id) = h.connect("192.0.2.1:80");

    drop(stream);

    assert_eq!(
        h.wire.take(),
        [Frame::Close {
            stream: id,
            reason: CloseReason::VOLUNTARY,
        }]
    );
}

#[test]
fn shutting_down_writes_keeps_the_stream_for_the_reply() {
    let h = Harness::up(8);
    let (stream, _, id) = h.connect("192.0.2.1:80");

    stream.shutdown(Shutdown::Write).unwrap();

    assert_eq!(stream.write(b"x"), Err(Errno::EPIPE));
    assert_eq!(h.wire.take(), []);
    h.server(Frame::Data {
        stream: id,
        data: b"reply".to_vec(),
    });
    assert_eq!(stream.read(&mut [0; 8], false), Ok(5));
}

#[test]
fn streams_get_ids_of_their_own() {
    let h = Harness::up(8);
    let (_a, _, a) = h.connect("192.0.2.1:80");
    let (_b, _, b) = h.connect("192.0.2.1:80");

    assert_ne!(a, 0);
    assert_ne!(a, b);
}

#[test]
fn names_resolve_on_the_server() {
    let h = Harness::up(8);
    let peer = resolve(&h.backend, "example.com");

    let _stream = h.backend.connect(peer, WaitQueue::new()).unwrap();

    assert_eq!(
        h.wire.take(),
        [Frame::Connect {
            stream: 1,
            kind: StreamKind::Tcp,
            port: 443,
            host: "example.com".into(),
        }]
    );
    assert_eq!(resolve(&h.backend, "example.com"), peer);
}

#[test]
fn an_address_no_lookup_handed_out_is_unreachable() {
    let h = Harness::up(8);
    let peer = resolve(&h.backend, "example.com");
    let other = SocketAddr::new(
        match peer.ip() {
            std::net::IpAddr::V4(v4) => std::net::Ipv4Addr::from(u32::from(v4) + 1).into(),
            v6 => v6,
        },
        443,
    );

    assert_eq!(
        h.backend.connect(other, WaitQueue::new()).err(),
        Some(Errno::EHOSTUNREACH)
    );
}

#[test]
fn losing_the_websocket_fails_streams_until_a_new_one_is_up() {
    let h = Harness::up(8);
    let (stream, watched, _) = h.connect("192.0.2.1:80");
    watched.woken.take();

    h.backend.disconnected();

    assert!(watched.woken.take().contains(PollMask::ERR));
    assert_eq!(stream.take_error(), Some(Errno::ECONNRESET));
    assert_eq!(
        h.backend
            .connect(addr("192.0.2.1:80"), WaitQueue::new())
            .err(),
        Some(Errno::ENETUNREACH)
    );

    h.server(Frame::Continue {
        stream: 0,
        remaining: 8,
    });
    let (fresh, _, _) = h.connect("192.0.2.1:80");
    assert_eq!(fresh.state(), StreamState::Established);
}

#[test]
fn datagrams_use_one_stream_per_destination() {
    let h = Harness::up(8);
    let watched = watched();
    let dgram = h
        .backend
        .datagram(Domain::Inet, watched.wq.clone())
        .unwrap();
    let dns = addr("192.0.2.53:53");

    assert_eq!(dgram.send_to(b"q1", dns), Ok(2));
    assert_eq!(dgram.send_to(b"q2", dns), Ok(2));
    let sent = h.wire.take();
    let id = match sent.as_slice() {
        [
            Frame::Connect {
                stream,
                kind: StreamKind::Udp,
                port: 53,
                host,
            },
            Frame::Data { .. },
            Frame::Data { .. },
        ] if host == "192.0.2.53" => *stream,
        other => panic!("unexpected frames {other:?}"),
    };

    h.server(Frame::Data {
        stream: id,
        data: b"answer".to_vec(),
    });

    assert!(watched.woken.take().contains(PollMask::IN));
    let mut buf = [0; 16];
    assert_eq!(dgram.recv_from(&mut buf, false), Ok((6, 6, dns)));
    assert_eq!(dgram.recv_from(&mut buf, false), Err(Errno::EAGAIN));

    drop(dgram);
    assert_eq!(
        h.wire.take(),
        [Frame::Close {
            stream: id,
            reason: CloseReason::VOLUNTARY,
        }]
    );
}

#[test]
fn a_connected_datagram_socket_learns_its_peer_refused() {
    let h = Harness::up(8);
    let dgram = h.backend.datagram(Domain::Inet, WaitQueue::new()).unwrap();
    let peer = addr("192.0.2.9:9");
    dgram.connect(Some(peer)).unwrap();
    dgram.send_to(b"x", peer).unwrap();
    let id = match h.wire.take().first() {
        Some(Frame::Connect { stream, .. }) => *stream,
        other => panic!("{other:?}"),
    };

    h.server(Frame::Close {
        stream: id,
        reason: CloseReason::NETWORK_ERROR,
    });

    assert!(dgram.poll(None).contains(PollMask::ERR));
    assert_eq!(dgram.take_error(), Some(Errno::ECONNREFUSED));
}

#[test]
fn malformed_and_server_opened_streams_are_errors() {
    let h = Harness::up(8);

    assert!(matches!(
        h.backend.receive(&[0x02]),
        Err(ReceiveError::Malformed(_))
    ));
    assert_eq!(
        h.backend.receive(
            &Frame::Connect {
                stream: 4,
                kind: StreamKind::Tcp,
                port: 1,
                host: "x".into()
            }
            .encode()
        ),
        Err(ReceiveError::ServerConnect(4))
    );
}

#[test]
fn host_for_names_the_host_behind_an_address() {
    let h = Harness::up(8);
    let peer = resolve(&h.backend, "api.openai.com");
    let unknown = std::net::Ipv4Addr::from(u32::from(match peer.ip() {
        std::net::IpAddr::V4(v4) => v4,
        v6 => panic!("not v4: {v6}"),
    }) + 1);

    assert_eq!(h.backend.host_for(peer.ip()).as_deref(), Some("api.openai.com"));
    assert_eq!(h.backend.host_for(unknown.into()), None);
    assert_eq!(h.backend.host_for(addr("1.2.3.4:80").ip()).as_deref(), Some("1.2.3.4"));
}
