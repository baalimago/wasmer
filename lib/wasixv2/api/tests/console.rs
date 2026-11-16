//! A machine with the host's console: programs read what is typed through the kernel's line
//! discipline, and `^C` interrupts the console's foreground process group.

use std::{
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use tokio::sync::mpsc;
use wasixv2::{
    Attach, ByteSink, ByteSource, Console, EmptySource, Engine, LocalFuture, Machine,
    ProcessConfig, Stdio, WindowSize, load,
};

#[derive(Default)]
struct Capture(Mutex<Vec<u8>>);

impl Capture {
    fn contents(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl ByteSink for Capture {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(data);
        Box::pin(async move { Ok(data.len()) })
    }
}

/// The host's terminal: what the test types.
struct Keyboard(Mutex<mpsc::UnboundedReceiver<Vec<u8>>>);

impl ByteSource for Keyboard {
    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut input = self.0.lock().unwrap();
        let Some(data) = std::task::ready!(input.poll_recv(cx)) else {
            return Poll::Ready(Ok(0));
        };
        buf[..data.len()].copy_from_slice(&data);
        Poll::Ready(Ok(data.len()))
    }
}

/// A machine whose console shows on `screen` what the returned sender types.
fn console_machine(screen: &Arc<Capture>) -> (Machine, mpsc::UnboundedSender<Vec<u8>>) {
    let (keys, input) = mpsc::unbounded_channel();
    let console = Console {
        input: Arc::new(Keyboard(Mutex::new(input))),
        output: screen.clone(),
        size: WindowSize {
            rows: 33,
            cols: 100,
            xpixel: 0,
            ypixel: 0,
        },
    };
    let machine = Machine::builder().console(console, [true; 3]).build();
    (machine, keys)
}

/// Stdio that must not be used: the console takes descriptors 0 to 2.
fn unused_stdio() -> (Stdio, Arc<Capture>) {
    let unused = Arc::new(Capture::default());
    let stdio = Stdio {
        stdin: Arc::new(EmptySource),
        stdout: unused.clone(),
        stderr: unused.clone(),
    };
    (stdio, unused)
}

/// Writes `ready\n`, reads a line from descriptor 0 and writes it back to descriptor 1, then
/// exits with the console's row count if it is its controlling terminal with its own group
/// in the foreground, or 99.
const LINE_WAT: &str = r#"
  (module
    (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
    (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
    (import "wasixv2" "ioctl" (func $ioctl (param i32 i32 i32) (result i32)))
    (import "wasixv2" "getpid" (func $getpid (result i32)))
    (import "wasixv2" "exit_group" (func $exit_group (param i32)))
    (memory (export "memory") 1)
    (data (i32.const 16) "ready\n")
    (func (export "_start") (local $n i32)
      (drop (call $write (i32.const 1) (i32.const 16) (i32.const 6)))
      (local.set $n (call $read (i32.const 0) (i32.const 64) (i32.const 32)))
      (drop (call $write (i32.const 1) (i32.const 64) (local.get $n)))
      ;; TIOCGPGRP into 128, TIOCGWINSZ into 136.
      (if (i32.or
            (call $ioctl (i32.const 0) (i32.const 0x540f) (i32.const 128))
            (i32.ne (i32.load (i32.const 128)) (call $getpid)))
        (then (call $exit_group (i32.const 99))))
      (drop (call $ioctl (i32.const 2) (i32.const 0x5413) (i32.const 136)))
      (call $exit_group (i32.load16_u (i32.const 136)))
      unreachable))
"#;

async fn shown(screen: &Capture, what: &[u8]) {
    while !screen.contents().ends_with(what) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// What the host types is echoed and edited by the kernel and read as a line; the program's
/// output gets CR LF; the console is the program's controlling terminal, with its size.
#[tokio::test]
async fn a_program_reads_what_is_typed_on_the_console() {
    let screen = Arc::new(Capture::default());
    let (machine, keys) = console_machine(&screen);
    let wasm = wat::parse_str(LINE_WAT).unwrap();
    let (stdio, unused) = unused_stdio();
    let typing = async {
        shown(&screen, b"ready\r\n").await;
        keys.send(b"hix\x7f\r".to_vec()).unwrap();
    };
    let (status, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(machine.run(&wasm, stdio), typing)
    })
    .await
    .expect("the program read its line");

    assert_eq!(status.unwrap(), 33);
    assert_eq!(screen.contents(), b"ready\r\nhix\x08 \x08\r\nhi\r\n");
    assert!(unused.contents().is_empty());
}

/// Writes `ready\n` and waits for input forever.
const WAIT_WAT: &str = r#"
  (module
    (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
    (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 16) "ready\n")
    (func (export "_start")
      (drop (call $write (i32.const 1) (i32.const 16) (i32.const 6)))
      (loop $forever
        (drop (call $read (i32.const 0) (i32.const 64) (i32.const 32)))
        (br $forever))))
"#;

/// `^C` typed on the console kills a program with SIGINT's default action, and is echoed.
#[tokio::test]
async fn ctrl_c_on_the_console_interrupts_the_program() {
    let screen = Arc::new(Capture::default());
    let (machine, keys) = console_machine(&screen);
    let wasm = wat::parse_str(WAIT_WAT).unwrap();
    let (stdio, _) = unused_stdio();
    let typing = async {
        shown(&screen, b"ready\r\n").await;
        keys.send(b"\x03".to_vec()).unwrap();
        // The discipline signals the foreground group before it writes the echo, as Linux's
        // n_tty does (`isig`, then `echo_char`), so the program can be gone before it shows.
        shown(&screen, b"^C").await;
    };
    let (status, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(machine.run(&wasm, stdio), typing)
    })
    .await
    .expect("the program died");

    assert_eq!(status.unwrap(), 128 + 2);
    assert_eq!(screen.contents(), b"ready\r\n^C");
}

/// A terminal that shows each write only `delay` after it was made, as a slow line does.
struct SlowScreen {
    shown: Capture,
    delay: Duration,
}

impl ByteSink for SlowScreen {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            self.shown.write(data).await
        })
    }
}

/// The echo of the `^C` that ends a program reaches the host before the run returns, however
/// slowly the host takes it, as Linux's close of a console waits for its output to be sent
/// (`hvc_close`, `tty_wait_until_sent`): an embedder that exits right after loses nothing.
#[tokio::test]
async fn the_run_ends_once_the_echo_of_ctrl_c_is_shown() {
    let screen = Arc::new(SlowScreen {
        shown: Capture::default(),
        delay: Duration::from_millis(300),
    });
    let (keys, input) = mpsc::unbounded_channel();
    let console = Console {
        input: Arc::new(Keyboard(Mutex::new(input))),
        output: screen.clone(),
        size: WindowSize::default(),
    };
    let machine = Machine::builder().console(console, [true; 3]).build();
    let wasm = wat::parse_str(WAIT_WAT).unwrap();
    let (stdio, _) = unused_stdio();
    let typing = async {
        shown(&screen.shown, b"ready\r\n").await;
        keys.send(b"\x03".to_vec()).unwrap();
    };
    let (status, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(machine.run(&wasm, stdio), typing)
    })
    .await
    .expect("the program died");

    assert_eq!(status.unwrap(), 128 + 2);
    assert_eq!(screen.shown.contents(), b"ready\r\n^C");
}

/// The signaller's terminal signals go to the console's foreground process group, and a
/// hangup of the console sends its session leader SIGHUP.
#[tokio::test]
async fn the_signaller_reaches_the_console() {
    for (sig, status) in [(Some(3), 128 + 3), (None, 128 + 1)] {
        let screen = Arc::new(Capture::default());
        let (machine, _keys) = console_machine(&screen);
        let signaller = machine.signaller();
        let wasm = wat::parse_str(WAIT_WAT).unwrap();
        let (stdio, _) = unused_stdio();
        let signalling = async {
            shown(&screen, b"ready\r\n").await;
            match sig {
                Some(sig) => assert!(signaller.signal_foreground(sig).unwrap()),
                None => signaller.console_hangup(),
            }
        };
        let (run, ()) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(machine.run(&wasm, stdio), signalling)
        })
        .await
        .expect("the program died");
        assert_eq!(run.unwrap(), status);
    }
}

/// Writes `up\n`, reads descriptor 0 until its end, and exits with 7.
const SERVICE_WAT: &str = r#"
  (module
    (import "wasixv2" "read" (func $read (param i32 i32 i32) (result i32)))
    (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
    (import "wasixv2" "exit_group" (func $exit_group (param i32)))
    (memory (export "memory") 1)
    (data (i32.const 16) "up\n")
    (func (export "_start")
      (drop (call $write (i32.const 1) (i32.const 16) (i32.const 3)))
      (loop $more
        (br_if $more (i32.gt_s (call $read (i32.const 0) (i32.const 64) (i32.const 32)) (i32.const 0))))
      (call $exit_group (i32.const 7))
      unreachable))
"#;

/// A service: its descriptors are the host streams `input` and `out`, not the console.
fn service_stdio() -> (Stdio, mpsc::UnboundedSender<Vec<u8>>, Arc<Capture>) {
    let (input, rx) = mpsc::unbounded_channel();
    let out = Arc::new(Capture::default());
    let stdio = Stdio {
        stdin: Arc::new(Keyboard(Mutex::new(rx))),
        stdout: out.clone(),
        stderr: out.clone(),
    };
    (stdio, input, out)
}

fn config(stdio: Stdio) -> ProcessConfig {
    ProcessConfig {
        args: vec!["program".into()],
        env: Vec::new(),
        stdio,
    }
}

/// A run with its own streams (`Attach::Stdio`), started while the console is free, does not
/// take it: a login started after it gets the console as its controlling terminal, and the
/// service's exit, while the login still reads, hangs nothing up.
#[tokio::test]
async fn a_service_leaves_the_console_to_the_next_login() {
    let screen = Arc::new(Capture::default());
    let (machine, keys) = console_machine(&screen);
    let engine = Engine::default();
    let service = load(&engine, &wat::parse_str(SERVICE_WAT).unwrap()).unwrap();
    let login = load(&engine, &wat::parse_str(LINE_WAT).unwrap()).unwrap();
    let (stdio, service_input, service_out) = service_stdio();
    let (login_stdio, unused) = unused_stdio();
    let (served, logged_in, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        let service_run = machine.run_module_with(&engine, &service, config(stdio), Attach::Stdio);
        let login_run = async {
            shown(&service_out, b"up\n").await;
            machine.run_module_with(&engine, &login, config(login_stdio), Attach::Console).await
        };
        let steps = async {
            shown(&screen, b"ready\r\n").await;
            // The service ends while the login waits for its line.
            drop(service_input);
            tokio::time::sleep(Duration::from_millis(200)).await;
            keys.send(b"hi\r".to_vec()).unwrap();
        };
        tokio::join!(service_run, login_run, steps)
    })
    .await
    .expect("both runs ended");

    assert_eq!(served.unwrap(), 7);
    // 33 rows: the login's group is in the foreground of its controlling terminal.
    assert_eq!(logged_in.unwrap(), 33);
    assert_eq!(screen.contents(), b"ready\r\nhi\r\nhi\r\n");
    assert_eq!(service_out.contents(), b"up\n");
    assert!(unused.contents().is_empty());
}

/// `^C` on the console reaches its login, never a service, which reads its own input.
#[tokio::test]
async fn ctrl_c_on_the_console_spares_a_service() {
    let screen = Arc::new(Capture::default());
    let (machine, keys) = console_machine(&screen);
    let engine = Engine::default();
    let service = load(&engine, &wat::parse_str(SERVICE_WAT).unwrap()).unwrap();
    let login = load(&engine, &wat::parse_str(WAIT_WAT).unwrap()).unwrap();
    let (stdio, service_input, service_out) = service_stdio();
    let (login_stdio, _) = unused_stdio();
    let (served, logged_in, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        let service_run = machine.run_module_with(&engine, &service, config(stdio), Attach::Stdio);
        let login_run = async {
            shown(&service_out, b"up\n").await;
            machine.run_module_with(&engine, &login, config(login_stdio), Attach::Console).await
        };
        let steps = async {
            shown(&screen, b"ready\r\n").await;
            keys.send(b"\x03".to_vec()).unwrap();
            shown(&screen, b"^C").await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Still running: what it reads is its own.
            service_input.send(b"line\n".to_vec()).unwrap();
            drop(service_input);
        };
        tokio::join!(service_run, login_run, steps)
    })
    .await
    .expect("both runs ended");

    assert_eq!(logged_in.unwrap(), 128 + 2);
    assert_eq!(served.unwrap(), 7);
    assert_eq!(screen.contents(), b"ready\r\n^C");
}
