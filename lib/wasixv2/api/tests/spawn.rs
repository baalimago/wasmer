//! `spawn`, `posix_spawn` in one import, called from hand-written guests: the child's file
//! actions and `execve` happen inside the call, which returns in the parent.

use std::{
    io,
    sync::{Arc, Mutex},
};

use wasixv2::{
    ByteSink, EmptySource, Engine, LocalFuture, Machine, OwnedBuffer, ProcessConfig, Stdio,
};

const ENOENT: i32 = 2;
const EINVAL: i32 = 22;

/// `spawner` exits with this plus the child's exit status after a spawn that succeeded.
const SPAWNED: i32 = 100;

const SPAWN_FDOP_CLOSE: u32 = 1;
const SPAWN_FDOP_DUP2: u32 = 2;
const SPAWN_FDOP_CHDIR: u32 = 4;

/// Where `spawner` keeps its file actions, and the path the first `chdir` action names.
const ACTIONS: u32 = 256;
const PATH: u32 = 1024;

#[derive(Default)]
struct Capture(Mutex<Vec<u8>>);

impl ByteSink for Capture {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(data);
        Box::pin(async move { Ok(data.len()) })
    }
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// Prints its arguments, separated by spaces and ended by a newline, and exits with 7.
const ECHO: &str = r#"
(module
  (import "wasixv2" "startup_size" (func $startup_size (result i32)))
  (import "wasixv2" "startup_get" (func $startup_get (param i32 i32) (result i32)))
  (import "wasixv2" "write" (func $write (param i32 i32 i32) (result i32)))
  (import "wasixv2" "exit_group" (func $exit_group (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) " \n")
  (func $strlen (param $p i32) (result i32) (local $n i32)
    (block $done (loop $next
      (br_if $done (i32.eqz (i32.load8_u (i32.add (local.get $p) (local.get $n)))))
      (local.set $n (i32.add (local.get $n) (i32.const 1)))
      (br $next)))
    (local.get $n))
  (func (export "_start") (local $argc i32) (local $i i32) (local $arg i32)
    (drop (call $startup_get (i32.const 1024) (call $startup_size)))
    (local.set $argc (i32.load (i32.const 1024)))
    (block $done (loop $next
      (br_if $done (i32.ge_u (local.get $i) (local.get $argc)))
      (if (local.get $i) (then (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1)))))
      (local.set $arg (i32.load (i32.add (i32.const 1028) (i32.shl (local.get $i) (i32.const 2)))))
      (drop (call $write (i32.const 1) (local.get $arg) (call $strlen (local.get $arg))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $next)))
    (drop (call $write (i32.const 1) (i32.const 1) (i32.const 1)))
    (call $exit_group (i32.const 7))
    unreachable))
"#;

/// [`ECHO`] for WASI preview1, which the v1 compatibility ABI serves; exits with 0.
const V1_ECHO: &str = r#"
(module
  (import "wasi_snapshot_preview1" "args_sizes_get" (func $sizes (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_get" (func $args (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) " \n")
  (func $print (param $p i32) (param $len i32)
    (i32.store (i32.const 16) (local.get $p))
    (i32.store (i32.const 20) (local.get $len))
    (drop (call $fd_write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24))))
  (func $strlen (param $p i32) (result i32) (local $n i32)
    (block $done (loop $next
      (br_if $done (i32.eqz (i32.load8_u (i32.add (local.get $p) (local.get $n)))))
      (local.set $n (i32.add (local.get $n) (i32.const 1)))
      (br $next)))
    (local.get $n))
  (func (export "_start") (local $i i32) (local $arg i32)
    (drop (call $sizes (i32.const 0) (i32.const 4)))
    (drop (call $args (i32.const 1024) (i32.const 2048)))
    (block $done (loop $next
      (br_if $done (i32.ge_u (local.get $i) (i32.load (i32.const 0))))
      (if (local.get $i) (then (call $print (i32.const 8) (i32.const 1))))
      (local.set $arg (i32.load (i32.add (i32.const 1024) (i32.shl (local.get $i) (i32.const 2)))))
      (call $print (local.get $arg) (call $strlen (local.get $arg)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $next)))
    (call $print (i32.const 9) (i32.const 1))
    (call $proc_exit (i32.const 0))))
"#;

/// Spawns `argv[1]` with `&argv[1]` as its arguments and the file `actions`, waits for it and
/// exits with [`SPAWNED`] plus its status. When the spawn fails, exits with its errno if no
/// child is left to wait for, and with 99 otherwise.
fn spawner(actions: &[[u32; 6]], path: &str) -> Vec<u8> {
    let bytes: String = actions
        .iter()
        .flatten()
        .flat_map(|word| word.to_le_bytes())
        .map(|byte| format!("\\{byte:02x}"))
        .collect();
    wat::parse_str(format!(
        r#"
(module
  (import "wasixv2" "startup_size" (func $startup_size (result i32)))
  (import "wasixv2" "startup_get" (func $startup_get (param i32 i32) (result i32)))
  (import "wasixv2" "spawn" (func $spawn (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "waitid" (func $waitid (param i32 i32 i32 i32 i32) (result i32)))
  (import "wasixv2" "exit_group" (func $exit_group (param i32)))
  (memory (export "memory") 1)
  (data (i32.const {ACTIONS}) "{bytes}")
  (data (i32.const {PATH}) "{path}\00")
  (func (export "_start") (local $ret i32)
    (drop (call $startup_get (i32.const 4096) (call $startup_size)))
    (local.set $ret (call $spawn (i32.const 64) (i32.load (i32.const 4104))
      (i32.const {ACTIONS}) (i32.const {count}) (i32.const 0) (i32.const 4104) (i32.const 0)))
    (if (i32.lt_s (local.get $ret) (i32.const 0)) (then
      ;; P_ALL, WEXITED | WNOHANG: -ECHILD when the failed child was reaped.
      (if (i32.eq (call $waitid (i32.const 0) (i32.const 0) (i32.const 128) (i32.const 5) (i32.const 0))
                  (i32.const -10))
        (then (call $exit_group (i32.sub (i32.const 0) (local.get $ret)))))
      (call $exit_group (i32.const 99))
      unreachable))
    ;; P_PID, WEXITED
    (drop (call $waitid (i32.const 1) (i32.load (i32.const 64)) (i32.const 128) (i32.const 4) (i32.const 0)))
    (call $exit_group (i32.add (i32.const {SPAWNED}) (i32.load (i32.const 148))))
    unreachable))
"#,
        count = actions.len(),
    ))
    .unwrap()
}

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

async fn run(spawner: Vec<u8>, args: &[&str]) -> Run {
    let mut machine = Machine::new();
    let commands = [
        ("spawner", spawner),
        ("echo", wat::parse_str(ECHO).unwrap()),
        ("v1echo", wat::parse_str(V1_ECHO).unwrap()),
    ];
    let commands = commands.map(|(name, image)| (name.to_string(), OwnedBuffer::from(image)));
    machine.install_commands(commands).await.unwrap();
    let (stdout, stderr) = (Arc::new(Capture::default()), Arc::new(Capture::default()));
    let config = ProcessConfig {
        args: args.iter().map(|arg| arg.to_string()).collect(),
        env: Vec::new(),
        stdio: Stdio {
            stdin: Arc::new(EmptySource),
            stdout: stdout.clone(),
            stderr: stderr.clone(),
        },
    };
    let status = machine
        .run_file(&Engine::default(), "/bin/spawner", config)
        .await;
    Run {
        status: status.unwrap(),
        stdout: stdout.text(),
        stderr: stderr.text(),
    }
}

/// Runs `test` in a `LocalSet`, which the machine's host work needs.
async fn local<F: Future>(test: F) -> F::Output {
    tokio::task::LocalSet::new().run_until(test).await
}

#[tokio::test]
async fn spawn_returns_in_the_parent_once_the_child_runs_its_image() {
    local(async {
        let run = run(spawner(&[], "/"), &["spawner", "/bin/echo", "a", "b"]).await;
        assert_eq!(run.stdout, "/bin/echo a b\n");
        assert_eq!(run.status, SPAWNED + 7);
    })
    .await;
}

#[tokio::test]
async fn a_spawned_child_may_be_a_wasix_v1_program() {
    local(async {
        let run = run(spawner(&[], "/"), &["spawner", "/bin/v1echo", "a"]).await;
        assert_eq!(run.stdout, "/bin/v1echo a\n");
        assert_eq!(run.status, SPAWNED);
    })
    .await;
}

#[tokio::test]
async fn file_actions_run_in_the_child_in_order() {
    local(async {
        // Stdout onto stderr, and stdin closed.
        let actions = [
            [SPAWN_FDOP_DUP2, 1, 2, 0, 0, 0],
            [SPAWN_FDOP_CLOSE, 0, 0, 0, 0, 0],
        ];
        let run = run(spawner(&actions, "/"), &["spawner", "/bin/echo", "x"]).await;
        assert_eq!(run.stdout, "");
        assert_eq!(run.stderr, "/bin/echo x\n");
        assert_eq!(run.status, SPAWNED + 7);
    })
    .await;
}

#[tokio::test]
async fn a_missing_file_fails_the_spawn_and_leaves_no_child() {
    local(async {
        let run = run(spawner(&[], "/"), &["spawner", "/bin/nothing"]).await;
        assert_eq!(run.status, ENOENT);
        assert_eq!(run.stdout, "");
    })
    .await;
}

#[tokio::test]
async fn a_failed_file_action_fails_the_spawn_with_its_errno() {
    local(async {
        let actions = [[SPAWN_FDOP_CHDIR, 0, 0, 0, 0, PATH]];
        let run = run(spawner(&actions, "/nowhere"), &["spawner", "/bin/echo"]).await;
        assert_eq!(run.status, ENOENT);
        assert_eq!(run.stdout, "");
    })
    .await;
}

#[tokio::test]
async fn an_unknown_file_action_is_einval_before_any_child() {
    local(async {
        let run = run(
            spawner(&[[9, 0, 0, 0, 0, 0]], "/"),
            &["spawner", "/bin/echo"],
        )
        .await;
        assert_eq!(run.status, EINVAL);
    })
    .await;
}
