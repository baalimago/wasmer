//! Network backend that carries the guest's outside traffic over WISP, which multiplexes TCP and
//! UDP streams over one WebSocket to a proxy. It is how a machine in a browser reaches the
//! network: the page holds the WebSocket and the proxy opens the real sockets.
//!
//! The backend does no I/O of its own. It hands the frames it sends to the embedder's
//! [`FrameSink`] and is given the frames that arrive with [`WispBackend::receive`], so the same
//! code runs over a browser WebSocket, a native one, or a test's in-memory server.
//!
//! WISP v1 has no handshake beyond the server's first CONTINUE, no connect acknowledgement and
//! no half-close. Streams connect once that first CONTINUE arrives, and a refused connection
//! shows as an error after `connect` succeeded, on the first read or write. `shutdown` of the
//! write side stops the guest writing but keeps the stream open, so the reply still arrives.
//! The guest's names resolve on the WISP server ([`names`]). In a browser, [`web::connect`]
//! (feature `web`) opens the WebSocket and wires it to a backend.

mod datagram;
mod frame;
mod names;
mod stream;
#[cfg(feature = "web")]
pub mod web;

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError, Weak},
};

use thiserror::Error;
use wasixv2_abi::Errno;
use wasixv2_vnet::{
    Backend, BackendDatagram, BackendStream, Domain, InboundSink, Lookup, LookupDone, Publication,
    WaitQueue,
};

pub use frame::{CloseReason, Frame, FrameError, StreamKind};

use datagram::WispDatagram;
use names::Names;
use stream::WispStream;

/// Where the backend's frames go: the WebSocket to the WISP server, as binary messages.
///
/// Frames must reach the server in the order they are sent, so a sink queues them until its
/// WebSocket is open. It must not call back into the backend.
pub trait FrameSink: Send + Sync {
    fn send(&self, frame: Vec<u8>);
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReceiveError {
    #[error(transparent)]
    Malformed(#[from] FrameError),
    #[error("the WISP server opened stream {0}, which only a client may do")]
    ServerConnect(u32),
}

/// A WISP client session that serves as a machine's network backend. Clones share the session:
/// one goes to `MachineBuilder::backend`, another feeds it the frames the WebSocket receives.
#[derive(Clone)]
pub struct WispBackend(Arc<Inner>);

struct Inner {
    sink: Arc<dyn FrameSink>,
    session: Mutex<Session>,
}

enum Link {
    /// Waiting for the server's first CONTINUE.
    Opening,
    /// Every new TCP stream may send this many DATA packets before the server's next CONTINUE.
    Up { credit: u32 },
    /// The WebSocket closed; a new one starts again from [`Link::Opening`] on its first frame.
    Down,
}

struct Session {
    link: Link,
    next_id: u32,
    streams: HashMap<u32, Weak<WispStream>>,
    datagrams: HashMap<u32, (Weak<WispDatagram>, SocketAddr)>,
    names: Names,
}

impl WispBackend {
    pub fn new(sink: Arc<dyn FrameSink>) -> Self {
        Self(Arc::new(Inner {
            sink,
            session: Mutex::new(Session {
                link: Link::Opening,
                next_id: 1,
                streams: HashMap::new(),
                datagrams: HashMap::new(),
                names: Names::default(),
            }),
        }))
    }

    /// Takes one binary message from the WebSocket.
    pub fn receive(&self, message: &[u8]) -> Result<(), ReceiveError> {
        match Frame::decode(message)? {
            Frame::Continue {
                stream: 0,
                remaining,
            } => self.link_up(remaining),
            Frame::Continue { stream, remaining } => {
                if let Some(s) = self.0.stream(stream) {
                    s.credit(remaining);
                }
            }
            Frame::Data { stream, data } => {
                if let Some(s) = self.0.stream(stream) {
                    s.data(data);
                } else if let Some((d, peer)) = self.0.datagram(stream) {
                    d.data(peer, data);
                }
            }
            Frame::Close { stream, reason } => {
                if let Some(s) = self.0.stream(stream) {
                    s.close(reason);
                } else if let Some((d, peer)) = self.0.datagram(stream) {
                    d.close(peer, reason);
                }
                let mut session = self.0.session();
                session.streams.remove(&stream);
                session.datagrams.remove(&stream);
            }
            Frame::Info { .. } => {}
            Frame::Connect { stream, .. } => return Err(ReceiveError::ServerConnect(stream)),
        }
        Ok(())
    }

    /// The WebSocket closed: every stream fails, and new ones fail with `ENETUNREACH` until a
    /// new WebSocket delivers its first frame.
    pub fn disconnected(&self) {
        let (streams, datagrams) = {
            let mut session = self.0.session();
            session.link = Link::Down;
            let streams: Vec<_> = session
                .streams
                .drain()
                .filter_map(|(_, s)| s.upgrade())
                .collect();
            let datagrams: Vec<_> = session
                .datagrams
                .drain()
                .filter_map(|(_, (d, _))| d.upgrade())
                .collect();
            (streams, datagrams)
        };
        streams.iter().for_each(|s| s.link_down());
        datagrams.iter().for_each(|d| d.link_down());
    }

    fn link_up(&self, credit: u32) {
        let waiting: Vec<_> = {
            let mut session = self.0.session();
            session.link = Link::Up { credit };
            session.streams.values().filter_map(Weak::upgrade).collect()
        };
        waiting.iter().for_each(|s| s.first_credit(credit));
    }
}

impl Inner {
    fn session(&self) -> MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn stream(&self, id: u32) -> Option<Arc<WispStream>> {
        self.session().streams.get(&id).and_then(Weak::upgrade)
    }

    fn datagram(&self, id: u32) -> Option<(Arc<WispDatagram>, SocketAddr)> {
        let session = self.session();
        let (d, peer) = session.datagrams.get(&id)?;
        Some((d.upgrade()?, *peer))
    }

    /// Opens a UDP stream to `peer` for `endpoint`, returning its id.
    fn open_udp(&self, peer: SocketAddr, endpoint: Weak<WispDatagram>) -> Result<u32, Errno> {
        let (id, host) = {
            let mut session = self.session();
            let host = session.ready_host(peer)?;
            let id = session.allocate();
            session.datagrams.insert(id, (endpoint, peer));
            (id, host)
        };
        self.sink.send(
            Frame::Connect {
                stream: id,
                kind: StreamKind::Udp,
                port: peer.port(),
                host,
            }
            .encode(),
        );
        Ok(id)
    }

    fn send(&self, frame: Frame) {
        self.sink.send(frame.encode());
    }
}

impl Session {
    /// The host to ask the server for, if the link can carry a new stream to `peer`.
    fn ready_host(&self, peer: SocketAddr) -> Result<String, Errno> {
        if matches!(self.link, Link::Down) {
            return Err(Errno::ENETUNREACH);
        }
        self.names.host_for(peer.ip()).ok_or(Errno::EHOSTUNREACH)
    }

    /// A stream id no live stream holds; 0 is the session's own.
    fn allocate(&mut self) -> u32 {
        self.streams.retain(|_, s| s.strong_count() > 0);
        self.datagrams.retain(|_, (d, _)| d.strong_count() > 0);
        loop {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            if !self.streams.contains_key(&id) && !self.datagrams.contains_key(&id) {
                return id;
            }
        }
    }
}

impl Backend for WispBackend {
    fn connect(&self, peer: SocketAddr, wq: WaitQueue) -> Result<Arc<dyn BackendStream>, Errno> {
        let (stream, host) = {
            let mut session = self.0.session();
            let host = session.ready_host(peer)?;
            let credit = match session.link {
                Link::Up { credit } => Some(credit),
                _ => None,
            };
            let id = session.allocate();
            let stream = WispStream::new(id, peer, wq, credit, self.0.clone());
            session.streams.insert(id, Arc::downgrade(&stream));
            (stream, host)
        };
        self.0.send(Frame::Connect {
            stream: stream.id(),
            kind: StreamKind::Tcp,
            port: peer.port(),
            host,
        });
        Ok(stream)
    }

    fn datagram(&self, _: Domain, wq: WaitQueue) -> Result<Arc<dyn BackendDatagram>, Errno> {
        Ok(WispDatagram::new(wq, self.0.clone()))
    }

    /// WISP only carries connections the client opens.
    fn publish(
        &self,
        _: SocketAddr,
        _: u32,
        _: Arc<dyn InboundSink>,
    ) -> Result<Box<dyn Publication>, std::io::Error> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    fn lookup(&self, lookup: Lookup, done: LookupDone) {
        let found = self.0.session().names.lookup(&lookup);
        done(found);
    }
}

/// What a CLOSE other than a voluntary one means to the guest. A WISP server reports a
/// connection it could not open as a network error, which before any data is a refusal.
fn close_errno(reason: CloseReason, got_data: bool) -> Errno {
    match reason {
        CloseReason::UNREACHABLE_HOST => Errno::EHOSTUNREACH,
        CloseReason::NO_RESPONSE | CloseReason::TRANSFER_TIMEOUT => Errno::ETIMEDOUT,
        CloseReason::CONN_REFUSED
        | CloseReason::HOST_BLOCKED
        | CloseReason::CONN_THROTTLED
        | CloseReason::INVALID_INFO => Errno::ECONNREFUSED,
        _ if got_data => Errno::ECONNRESET,
        _ => Errno::ECONNREFUSED,
    }
}

#[cfg(test)]
mod tests;
