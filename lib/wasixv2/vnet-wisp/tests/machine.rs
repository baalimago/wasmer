//! A guest's connection through the whole stack: its socket syscalls reach the kernel, the
//! kernel's uplink hands the connection to the WISP backend, and a WISP server answers it.

use std::{
    io,
    sync::{Arc, Mutex},
};

use tokio::sync::mpsc;
use wasixv2::{ByteSink, Direction, EmptySource, Event, LocalFuture, Machine, Observer, Stdio};
use wasixv2_vnet_wisp::{CloseReason, Frame, FrameSink, StreamKind, WispBackend};

#[derive(Default)]
struct Capture(Mutex<Vec<u8>>);

impl ByteSink for Capture {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(data);
        Box::pin(async move { Ok(data.len()) })
    }
}

#[derive(Default)]
struct Events(Mutex<Vec<Event>>);

impl Observer for Events {
    fn observe(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }
}

struct Channel(mpsc::UnboundedSender<Vec<u8>>);

impl FrameSink for Channel {
    fn send(&self, frame: Vec<u8>) {
        let _ = self.0.send(frame);
    }
}

/// A WISP server whose every TCP stream answers each DATA packet with `pong` and closes.
/// Returns where each stream was opened to.
async fn pong_server(
    backend: WispBackend,
    mut frames: mpsc::UnboundedReceiver<Vec<u8>>,
) -> Vec<(String, u16)> {
    let reply = |frame: Frame| backend.receive(&frame.encode()).unwrap();
    reply(Frame::Continue {
        stream: 0,
        remaining: 128,
    });
    let mut opened = Vec::new();
    while let Some(frame) = frames.recv().await {
        match Frame::decode(&frame).unwrap() {
            Frame::Connect {
                kind: StreamKind::Tcp,
                host,
                port,
                ..
            } => opened.push((host, port)),
            Frame::Data { stream, .. } => {
                reply(Frame::Data {
                    stream,
                    data: b"pong".to_vec(),
                });
                reply(Frame::Close {
                    stream,
                    reason: CloseReason::VOLUNTARY,
                });
                break;
            }
            _ => {}
        }
    }
    opened
}

// A failing call exits with `step << 8 | errno`.
#[tokio::test]
async fn a_guest_talks_to_the_host_through_the_wisp_server() {
    let wat = r#"
      (module
        (import "wasixv2" "socket" (func $socket (param i32 i32 i32) (result i32)))
        (import "wasixv2" "connect" (func $connect (param i32 i32 i32) (result i32)))
        (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
        (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
        (import "wasixv2" "exit_group" (func $exit_group (param i32)))
        (memory (export "memory") 1)
        ;; sockaddr_in for the gateway, 10.0.2.2:8080, which is the host's loopback
        (data (i32.const 16) "\02\00\1f\90\0a\00\02\02\00\00\00\00\00\00\00\00")
        (data (i32.const 32) "ping")

        (func $check (param $v i32) (param $step i32) (result i32)
          (if (i32.lt_s (local.get $v) (i32.const 0))
            (then
              (call $exit_group
                (i32.or (i32.shl (local.get $step) (i32.const 8))
                        (i32.sub (i32.const 0) (local.get $v))))
              unreachable))
          (local.get $v))

        (func (export "_start") (local $fd i32) (local $n i32)
          ;; AF_INET, SOCK_STREAM
          (local.set $fd (call $check (call $socket (i32.const 2) (i32.const 1) (i32.const 0)) (i32.const 1)))
          (drop (call $check (call $connect (local.get $fd) (i32.const 16) (i32.const 16)) (i32.const 2)))
          (drop (call $check (call $write (local.get $fd) (i32.const 32) (i32.const 4)) (i32.const 3)))
          (local.set $n (call $check (call $read (local.get $fd) (i32.const 64) (i32.const 16)) (i32.const 4)))
          (drop (call $check (call $write (i32.const 1) (i32.const 64) (local.get $n)) (i32.const 5)))
          (call $exit_group (i32.const 0))
          unreachable))
    "#;
    let wasm = wat::parse_str(wat).expect("valid test module");
    let (tx, rx) = mpsc::unbounded_channel();
    let backend = WispBackend::new(Arc::new(Channel(tx)));
    let server = tokio::spawn(pong_server(backend.clone(), rx));
    let events = Arc::new(Events::default());
    let machine = Machine::builder()
        .backend(Arc::new(backend))
        .observer(events.clone())
        .build();
    let stdout = Arc::new(Capture::default());
    let stdio = Stdio {
        stdin: Arc::new(EmptySource),
        stdout: stdout.clone(),
        stderr: Arc::new(Capture::default()),
    };

    let status = machine.run(&wasm, stdio).await.unwrap();

    assert_eq!(status, 0, "step {}, errno {}", status >> 8, status & 0xff);
    assert_eq!(*stdout.0.lock().unwrap(), b"pong");
    assert_eq!(server.await.unwrap(), [("127.0.0.1".to_owned(), 8080)]);
    let events = events.0.lock().unwrap();
    let pid = match events.first() {
        Some(Event::Connect { pid, .. }) => *pid,
        other => panic!("expected the connect first, got {other:?}"),
    };
    assert_eq!(
        *events,
        [
            Event::Connect {
                pid,
                fd: 3,
                addr: "10.0.2.2:8080".parse().unwrap()
            },
            Event::Transfer {
                pid,
                fd: 3,
                direction: Direction::Out,
                bytes: 4
            },
            Event::Transfer {
                pid,
                fd: 3,
                direction: Direction::In,
                bytes: 4
            },
            Event::Transfer {
                pid,
                fd: 1,
                direction: Direction::Out,
                bytes: 4
            },
            Event::Exit { pid, code: 0 },
        ]
    );
}
