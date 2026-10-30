//! Syscall layer that traces every call, its arguments and its result, and tells an embedder's
//! [`Observer`] what the processes do: what they run, which files and connections they open, how
//! many bytes they move and how they end.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use wasixv2_abi::{Cstr, CstrArray, FcntlCmd, GuestPtr, OpenFlags};
use wasixv2_syscalls::{
    Caller, Fault, Layer, LocalFuture, SysResult, Syscall, SyscallRet, Syscalls, TaskId,
    UserMemory, dispatch, read_cstr, read_value,
};

/// Emits one `tracing` event per syscall, after it completes, and the [`Event`]s of the calls
/// to its [`Observer`], if it has one.
#[derive(Clone, Default)]
pub struct Trace {
    watch: Option<Watch>,
}

impl Trace {
    /// A layer that also reports to `observer`.
    pub fn observed(observer: Arc<dyn Observer>) -> Self {
        Self {
            watch: Some(Watch {
                observer,
                pids: Arc::default(),
            }),
        }
    }

    /// Reports that `task` started running `path` with `args`, for a process the embedder
    /// started without an `execve` of its own ([`Event::Exec`] with no parent's call).
    pub async fn started<S: Syscalls>(
        &self,
        next: &S,
        task: TaskId,
        path: &[u8],
        args: &[Vec<u8>],
    ) {
        let Some(watch) = &self.watch else { return };
        let caller = Caller::new(task, &NoMemory);
        let Some(pid) = watch.pid(&caller, next).await else {
            return;
        };
        let ppid = next.getppid(&caller).await.unwrap_or(0);
        watch.observer.observe(Event::Exec {
            pid,
            ppid,
            path: text(path),
            argv: args.iter().map(|a| text(a)).collect(),
        });
    }
}

impl std::fmt::Debug for Trace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trace")
            .field("observed", &self.watch.is_some())
            .finish()
    }
}

/// What a process did, as the syscall layer saw it. Pids are the kernel's, as `getpid` gives
/// them; paths are as the process passed them, relative ones included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// `pid`, a child of `ppid`, now runs `path` (an `execve` that succeeded, or a process the
    /// embedder started).
    Exec {
        pid: i32,
        ppid: i32,
        path: String,
        argv: Vec<String>,
    },
    /// `pid` called `exit_group` with `code`.
    Exit { pid: i32, code: i32 },
    /// `pid` reaped its child `child`, which ended as `end` says.
    Reaped { pid: i32, child: i32, end: End },
    /// `pid` opened `path` as `fd`; `write` when it may write to it.
    Open {
        pid: i32,
        fd: i32,
        path: String,
        write: bool,
    },
    /// `pid` connected `fd` to `addr`.
    Connect { pid: i32, fd: i32, addr: SocketAddr },
    /// `pid` moved `bytes` through `fd`.
    Transfer {
        pid: i32,
        fd: i32,
        direction: Direction,
        bytes: u64,
    },
    /// `pid` closed `fd`.
    Close { pid: i32, fd: i32 },
    /// `pid` made `to` refer to what `from` does (`dup`, `dup3`, `fcntl` `F_DUPFD`).
    Dup { pid: i32, from: i32, to: i32 },
    /// `pid` removed `path`.
    Unlink { pid: i32, path: String },
    /// `pid` renamed `from` to `to`.
    Rename { pid: i32, from: String, to: String },
    /// `pid` made the directory `path`.
    Mkdir { pid: i32, path: String },
}

/// How a reaped child ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Exited(i32),
    Killed(i32),
}

/// Which way bytes went through a descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

/// Receives the [`Event`]s of an observed [`Trace`], on the thread the syscall runs on and
/// while it runs: it must not block.
pub trait Observer: Send + Sync {
    fn observe(&self, event: Event);
}

#[derive(Clone)]
struct Watch {
    observer: Arc<dyn Observer>,
    /// Each task's process, as `getpid` gave it.
    pids: Arc<Mutex<HashMap<TaskId, i32>>>,
}

/// What a call's arguments say, read before the kernel runs it: an `execve` replaces the
/// memory they are in.
enum Before {
    Exec { path: String, argv: Vec<String> },
    Path(String),
    Rename(String, String),
    Addr(SocketAddr),
    Wait(GuestPtr<[u8; 128]>),
}

/// The longest path or argument read, as Linux's `PATH_MAX` and `MAX_ARG_STRLEN`.
const MAX_STRING: usize = 4096;
/// The most arguments read for an [`Event::Exec`].
const MAX_ARGS: usize = 256;

impl Watch {
    async fn pid<S: Syscalls>(&self, caller: &Caller<'_>, next: &S) -> Option<i32> {
        let task = caller.task();
        if let Some(pid) = self.pids.lock().unwrap().get(&task) {
            return Some(*pid);
        }
        let pid = next.getpid(caller).await.ok()?;
        self.pids.lock().unwrap().insert(task, pid);
        Some(pid)
    }

    fn forget(&self, task: TaskId) {
        self.pids.lock().unwrap().remove(&task);
    }

    async fn call<S: Syscalls>(
        &self,
        caller: &Caller<'_>,
        call: Syscall,
        next: &S,
    ) -> SysResult<SyscallRet> {
        let memory = caller.memory();
        let before = match call {
            Syscall::Execve { filename, argv, .. } | Syscall::Execveat { filename, argv, .. } => {
                Some(Before::Exec {
                    path: string(memory, filename).await,
                    argv: strings(memory, argv).await,
                })
            }
            Syscall::Openat { filename, .. } => Some(Before::Path(string(memory, filename).await)),
            Syscall::Unlinkat { pathname, .. } | Syscall::Mkdirat { pathname, .. } => {
                Some(Before::Path(string(memory, pathname).await))
            }
            Syscall::Renameat2 {
                oldname, newname, ..
            } => Some(Before::Rename(
                string(memory, oldname).await,
                string(memory, newname).await,
            )),
            Syscall::Connect {
                uservaddr, addrlen, ..
            } => sockaddr(memory, uservaddr.addr(), addrlen)
                .await
                .map(Before::Addr),
            Syscall::Waitid { infop, .. } if !infop.is_null() => {
                Some(Before::Wait(GuestPtr::new(infop.addr())))
            }
            Syscall::ExitGroup { error_code } => {
                if let Some(pid) = self.pid(caller, next).await {
                    self.observer.observe(Event::Exit {
                        pid,
                        code: error_code,
                    });
                }
                self.forget(caller.task());
                None
            }
            Syscall::Exit { .. } => {
                self.forget(caller.task());
                None
            }
            _ => None,
        };
        let watched = before.is_some()
            || transfer(&call).is_some()
            || duplicated(&call).is_some()
            || matches!(call, Syscall::Close { .. });
        // An execve changes the image, not the process: its pid is the one from before.
        let pid = match watched {
            true => self.pid(caller, next).await,
            false => None,
        };
        let ret = dispatch(next, caller, call).await;
        let (Some(pid), Ok(value)) = (pid, &ret) else {
            return ret;
        };
        if let Some(event) = self.after(caller, next, pid, call, before, value).await {
            self.observer.observe(event);
        }
        ret
    }

    async fn after<S: Syscalls>(
        &self,
        caller: &Caller<'_>,
        next: &S,
        pid: i32,
        call: Syscall,
        before: Option<Before>,
        value: &SyscallRet,
    ) -> Option<Event> {
        if let Some(direction) = transfer(&call) {
            let bytes = moved(value)?;
            let fd = descriptor(&call)?;
            return (bytes > 0).then_some(Event::Transfer {
                pid,
                fd,
                direction,
                bytes,
            });
        }
        if let Syscall::Close { fd } = call {
            return Some(Event::Close { pid, fd: fd.0 });
        }
        if let Some(from) = duplicated(&call) {
            let to = match value {
                SyscallRet::Dup(fd) | SyscallRet::Dup3(fd) => fd.0,
                SyscallRet::Fcntl64(fd) => *fd,
                _ => return None,
            };
            return Some(Event::Dup { pid, from, to });
        }
        match (call, before?, value) {
            (Syscall::Execve { .. } | Syscall::Execveat { .. }, Before::Exec { path, argv }, _) => {
                let ppid = next.getppid(caller).await.unwrap_or(0);
                Some(Event::Exec {
                    pid,
                    ppid,
                    path,
                    argv,
                })
            }
            (Syscall::Openat { flags, .. }, Before::Path(path), SyscallRet::Openat(fd)) => {
                Some(Event::Open {
                    pid,
                    fd: fd.0,
                    path,
                    write: writes(flags),
                })
            }
            (Syscall::Unlinkat { .. }, Before::Path(path), _) => Some(Event::Unlink { pid, path }),
            (Syscall::Mkdirat { .. }, Before::Path(path), _) => Some(Event::Mkdir { pid, path }),
            (Syscall::Renameat2 { .. }, Before::Rename(from, to), _) => {
                Some(Event::Rename { pid, from, to })
            }
            (Syscall::Connect { fd, .. }, Before::Addr(addr), _) => Some(Event::Connect {
                pid,
                fd: fd.0,
                addr,
            }),
            (Syscall::Waitid { .. }, Before::Wait(infop), _) => {
                let info = read_value(caller.memory(), infop).await.ok()?;
                let field = |at: usize| i32::from_le_bytes(info[at..at + 4].try_into().unwrap());
                // siginfo: si_code at 8, then si_pid at 12 and si_status at 20.
                let (code, child, status) = (field(8), field(12), field(20));
                let end = match code {
                    CLD_EXITED => End::Exited(status),
                    CLD_KILLED | CLD_DUMPED => End::Killed(status),
                    _ => return None,
                };
                (child > 0).then_some(Event::Reaped { pid, child, end })
            }
            _ => None,
        }
    }
}

const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const CLD_DUMPED: i32 = 3;

fn transfer(call: &Syscall) -> Option<Direction> {
    match call {
        Syscall::Read { .. }
        | Syscall::Readv { .. }
        | Syscall::Pread64 { .. }
        | Syscall::Recvfrom { .. }
        | Syscall::Recvmsg { .. } => Some(Direction::In),
        Syscall::Write { .. }
        | Syscall::Writev { .. }
        | Syscall::Pwrite64 { .. }
        | Syscall::Sendto { .. }
        | Syscall::Sendmsg { .. } => Some(Direction::Out),
        _ => None,
    }
}

// The descriptor a call copies to a new one.
fn duplicated(call: &Syscall) -> Option<i32> {
    match call {
        Syscall::Dup { fildes } => Some(fildes.0),
        Syscall::Dup3 { oldfd, .. } => Some(oldfd.0),
        Syscall::Fcntl64 { fd, cmd, .. }
            if *cmd == FcntlCmd::F_DUPFD || *cmd == FcntlCmd::F_DUPFD_CLOEXEC =>
        {
            Some(fd.0)
        }
        _ => None,
    }
}

fn descriptor(call: &Syscall) -> Option<i32> {
    match call {
        Syscall::Read { fd, .. }
        | Syscall::Readv { fd, .. }
        | Syscall::Pread64 { fd, .. }
        | Syscall::Recvfrom { fd, .. }
        | Syscall::Recvmsg { fd, .. }
        | Syscall::Write { fd, .. }
        | Syscall::Writev { fd, .. }
        | Syscall::Pwrite64 { fd, .. }
        | Syscall::Sendto { fd, .. }
        | Syscall::Sendmsg { fd, .. } => Some(fd.0),
        _ => None,
    }
}

fn moved(value: &SyscallRet) -> Option<u64> {
    match *value {
        SyscallRet::Read(n)
        | SyscallRet::Readv(n)
        | SyscallRet::Pread64(n)
        | SyscallRet::Recvfrom(n)
        | SyscallRet::Write(n)
        | SyscallRet::Writev(n)
        | SyscallRet::Pwrite64(n)
        | SyscallRet::Sendto(n) => Some(n.into()),
        SyscallRet::Recvmsg(n) | SyscallRet::Sendmsg(n) => u64::try_from(n).ok(),
        _ => None,
    }
}

fn writes(flags: OpenFlags) -> bool {
    let access = flags.0 & 0x3;
    access == OpenFlags::O_WRONLY.0
        || access == OpenFlags::O_RDWR.0
        || flags.0 & OpenFlags::O_CREAT.0 != 0
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

async fn string(memory: &dyn UserMemory, ptr: Cstr) -> String {
    match read_cstr(memory, ptr, MAX_STRING).await {
        Ok(bytes) => text(&bytes),
        Err(_) => String::from("?"),
    }
}

async fn strings(memory: &dyn UserMemory, array: CstrArray) -> Vec<String> {
    let mut out = Vec::new();
    if array.is_null() {
        return out;
    }
    while out.len() < MAX_ARGS {
        let at = GuestPtr::<Cstr>::new(array.addr() + 4 * out.len() as u32);
        let Ok(ptr) = read_value(memory, at).await else {
            break;
        };
        if ptr.is_null() {
            break;
        }
        out.push(string(memory, ptr).await);
    }
    out
}

async fn sockaddr(memory: &dyn UserMemory, addr: u32, len: u32) -> Option<SocketAddr> {
    let mut raw = [0u8; 28];
    let len = (len as usize).min(raw.len());
    memory.read(addr, &mut raw[..len]).await.ok()?;
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    match u16::from_le_bytes([raw[0], raw[1]]) {
        AF_INET if len >= 8 => {
            let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        AF_INET6 if len >= 24 => {
            let octets: [u8; 16] = raw[8..24].try_into().ok()?;
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// The memory of a task the embedder started, which has no guest to read from yet.
struct NoMemory;

impl UserMemory for NoMemory {
    fn read<'a>(&'a self, _: u32, _: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async { Err(Fault) })
    }

    fn write<'a>(&'a self, _: u32, _: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        Box::pin(async { Err(Fault) })
    }

    fn size(&self) -> LocalFuture<'_, u64> {
        Box::pin(async { 0 })
    }

    fn grow(&self, _: u32) -> LocalFuture<'_, Option<u64>> {
        Box::pin(async { None })
    }
}

impl<S: Syscalls> Layer<S> for Trace {
    async fn call(&self, caller: &Caller<'_>, call: Syscall, next: &S) -> SysResult<SyscallRet> {
        let ret = match &self.watch {
            Some(watch) => watch.call(caller, call, next).await,
            None => dispatch(next, caller, call).await,
        };
        tracing::trace!(task = caller.task().0, ?call, ?ret, "syscall");
        ret
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use futures::executor::block_on;
    use wasixv2_syscalls::{
        Errno, Fault, Fd, Layered, LocalFuture, SysErr, TaskId, UserMemory, UserSlice, UserSliceMut,
    };

    use super::*;

    struct NoMemory;

    impl UserMemory for NoMemory {
        fn read<'a>(&'a self, _: u32, _: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
            Box::pin(async { Err(Fault) })
        }

        fn write<'a>(&'a self, _: u32, _: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
            Box::pin(async { Err(Fault) })
        }

        fn size(&self) -> LocalFuture<'_, u64> {
            Box::pin(async { 0 })
        }

        fn grow(&self, _: u32) -> LocalFuture<'_, Option<u64>> {
            Box::pin(async { None })
        }
    }

    #[derive(Default)]
    struct Recorder(RefCell<Vec<Syscall>>);

    impl Syscalls for Recorder {
        async fn read(&self, _: &Caller<'_>, fd: Fd, buf: UserSliceMut) -> SysResult<u32> {
            self.0.borrow_mut().push(Syscall::Read { fd, buf });
            Err(SysErr::Errno(Errno::EBADF))
        }

        async fn write(&self, _: &Caller<'_>, fd: Fd, buf: UserSlice) -> SysResult<u32> {
            self.0.borrow_mut().push(Syscall::Write { fd, buf });
            Ok(buf.len)
        }

        async fn exit_group(&self, _: &Caller<'_>, status: i32) -> SysResult<()> {
            self.0
                .borrow_mut()
                .push(Syscall::ExitGroup { error_code: status });
            Ok(())
        }
    }

    #[test]
    fn forwards_calls_and_results_unchanged() {
        let stack = Layered::new(Trace::default(), Recorder::default());
        let caller = Caller::new(TaskId(1), &NoMemory);

        let written = block_on(stack.write(&caller, Fd(1), UserSlice::new(16, 5)));
        let read = block_on(stack.read(&caller, Fd(7), UserSliceMut::new(0, 1)));
        let exited = block_on(stack.exit_group(&caller, 3));

        assert_eq!(written, Ok(5));
        assert_eq!(read, Err(SysErr::Errno(Errno::EBADF)));
        assert_eq!(exited, Ok(()));
        assert_eq!(
            *stack.inner.0.borrow(),
            [
                Syscall::Write {
                    fd: Fd(1),
                    buf: UserSlice::new(16, 5)
                },
                Syscall::Read {
                    fd: Fd(7),
                    buf: UserSliceMut::new(0, 1)
                },
                Syscall::ExitGroup { error_code: 3 },
            ]
        );
    }

    /// Guest memory the observed calls read their arguments from.
    struct Mem(RefCell<Vec<u8>>);

    impl Mem {
        fn new() -> Self {
            Self(RefCell::new(vec![0; 4096]))
        }

        fn put(&self, addr: u32, bytes: &[u8]) -> u32 {
            self.0.borrow_mut()[addr as usize..addr as usize + bytes.len()].copy_from_slice(bytes);
            addr
        }

        fn cstr(&self, addr: u32, text: &str) -> Cstr {
            self.put(addr, format!("{text}\0").as_bytes());
            GuestPtr::new(addr)
        }

        /// `strings` at `addr` and after, and the NULL-terminated array of them at `array`.
        fn argv(&self, array: u32, mut addr: u32, strings: &[&str]) -> CstrArray {
            for (i, s) in strings.iter().enumerate() {
                self.cstr(addr, s);
                self.put(array + 4 * i as u32, &addr.to_le_bytes());
                addr += s.len() as u32 + 1;
            }
            self.put(array + 4 * strings.len() as u32, &0u32.to_le_bytes());
            GuestPtr::new(array)
        }
    }

    impl UserMemory for Mem {
        fn read<'a>(&'a self, addr: u32, buf: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
            let memory = self.0.borrow();
            let result = memory
                .get(addr as usize..addr as usize + buf.len())
                .map(|bytes| buf.copy_from_slice(bytes))
                .ok_or(Fault);
            Box::pin(async move { result })
        }

        fn write<'a>(&'a self, addr: u32, data: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
            self.put(addr, data);
            Box::pin(async { Ok(()) })
        }

        fn size(&self) -> LocalFuture<'_, u64> {
            Box::pin(async { 4096 })
        }

        fn grow(&self, _: u32) -> LocalFuture<'_, Option<u64>> {
            Box::pin(async { None })
        }
    }

    /// A kernel whose task 1 is pid 7, a child of pid 3, and whose calls succeed unless
    /// `fail` is set.
    #[derive(Default)]
    struct Fake {
        fail: bool,
        getpids: RefCell<u32>,
    }

    impl Fake {
        fn answer<T>(&self, value: T) -> SysResult<T> {
            match self.fail {
                true => Err(SysErr::Errno(Errno::ENOENT)),
                false => Ok(value),
            }
        }
    }

    impl Syscalls for Fake {
        async fn getpid(&self, _: &Caller<'_>) -> SysResult<i32> {
            *self.getpids.borrow_mut() += 1;
            Ok(7)
        }

        async fn getppid(&self, _: &Caller<'_>) -> SysResult<i32> {
            Ok(3)
        }

        async fn execve(
            &self,
            _: &Caller<'_>,
            _: Cstr,
            _: CstrArray,
            _: CstrArray,
        ) -> SysResult<i32> {
            self.answer(0)
        }

        async fn openat(
            &self,
            _: &Caller<'_>,
            _: Fd,
            _: Cstr,
            _: OpenFlags,
            _: wasixv2_abi::Mode,
        ) -> SysResult<Fd> {
            self.answer(Fd(5))
        }

        async fn connect(
            &self,
            _: &Caller<'_>,
            _: Fd,
            _: wasixv2_abi::ConstSockaddrPtr,
            _: u32,
        ) -> SysResult<i32> {
            self.answer(0)
        }

        async fn write(&self, _: &Caller<'_>, _: Fd, buf: UserSlice) -> SysResult<u32> {
            self.answer(buf.len)
        }

        async fn read(&self, _: &Caller<'_>, _: Fd, _: UserSliceMut) -> SysResult<u32> {
            self.answer(0)
        }

        async fn close(&self, _: &Caller<'_>, _: Fd) -> SysResult<i32> {
            self.answer(0)
        }

        async fn dup(&self, _: &Caller<'_>, _: Fd) -> SysResult<Fd> {
            self.answer(Fd(8))
        }

        async fn dup3(&self, _: &Caller<'_>, _: Fd, newfd: Fd, _: OpenFlags) -> SysResult<Fd> {
            self.answer(newfd)
        }

        async fn fcntl64(
            &self,
            _: &Caller<'_>,
            _: Fd,
            cmd: wasixv2_abi::FcntlCmd,
            _: wasixv2_abi::Ulong,
        ) -> SysResult<i32> {
            self.answer(if cmd == wasixv2_abi::FcntlCmd::F_DUPFD_CLOEXEC {
                10
            } else {
                0
            })
        }

        async fn waitid(
            &self,
            caller: &Caller<'_>,
            _: wasixv2_abi::Idtype,
            _: i32,
            infop: wasixv2_abi::SiginfoPtr,
            _: wasixv2_abi::WaitOptions,
            _: wasixv2_abi::RusagePtr,
        ) -> SysResult<i32> {
            // Child 9 killed by SIGINT.
            let mut info = [0u8; 128];
            info[8..12].copy_from_slice(&2i32.to_le_bytes());
            info[12..16].copy_from_slice(&9i32.to_le_bytes());
            info[20..24].copy_from_slice(&2i32.to_le_bytes());
            caller
                .memory()
                .write(infop.addr(), &info)
                .await
                .map_err(|_| Errno::EFAULT)?;
            self.answer(0)
        }

        async fn exit_group(&self, _: &Caller<'_>, _: i32) -> SysResult<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct Events(Mutex<Vec<Event>>);

    impl Observer for Events {
        fn observe(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    fn observed(fake: Fake) -> (Layered<Trace, Fake>, Arc<Events>) {
        let events = Arc::new(Events::default());
        (Layered::new(Trace::observed(events.clone()), fake), events)
    }

    #[test]
    fn reports_an_execve_with_its_process_parent_path_and_arguments() {
        let (stack, events) = observed(Fake::default());
        let memory = Mem::new();
        let caller = Caller::new(TaskId(1), &memory);
        let path = memory.cstr(100, "/bin/ffmpeg");
        let argv = memory.argv(200, 300, &["ffmpeg", "-f", "pulse"]);

        block_on(stack.execve(&caller, path, argv, GuestPtr::NULL)).unwrap();

        assert_eq!(
            *events.0.lock().unwrap(),
            [Event::Exec {
                pid: 7,
                ppid: 3,
                path: "/bin/ffmpeg".into(),
                argv: vec!["ffmpeg".into(), "-f".into(), "pulse".into()],
            }]
        );
    }

    #[test]
    fn a_failed_call_reports_nothing() {
        let (stack, events) = observed(Fake {
            fail: true,
            ..Fake::default()
        });
        let memory = Mem::new();
        let caller = Caller::new(TaskId(1), &memory);
        let path = memory.cstr(100, "/usr/bin/ffmpeg");

        let exec = block_on(stack.execve(&caller, path, GuestPtr::NULL, GuestPtr::NULL));
        let open = block_on(stack.openat(&caller, Fd(-100), path, OpenFlags(0), 0));

        assert_eq!(exec, Err(SysErr::Errno(Errno::ENOENT)));
        assert!(open.is_err());
        assert_eq!(*events.0.lock().unwrap(), []);
    }

    #[test]
    fn reports_files_connections_and_the_bytes_through_them() {
        let (stack, events) = observed(Fake::default());
        let memory = Mem::new();
        let caller = Caller::new(TaskId(1), &memory);
        let path = memory.cstr(100, "/tmp/meeting.wav");
        // sockaddr_in: AF_INET, port 443 in network order, 198.18.0.1.
        let addr = memory.put(200, &[2, 0, 1, 187, 198, 18, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);

        let flags = OpenFlags(OpenFlags::O_WRONLY.0 | OpenFlags::O_CREAT.0);
        block_on(stack.openat(&caller, Fd(-100), path, flags, 0o644)).unwrap();
        block_on(stack.write(&caller, Fd(5), UserSlice::new(0, 44))).unwrap();
        block_on(stack.read(&caller, Fd(5), UserSliceMut::new(0, 16))).unwrap();
        block_on(stack.connect(&caller, Fd(6), GuestPtr::new(addr), 16)).unwrap();
        block_on(stack.close(&caller, Fd(5))).unwrap();

        assert_eq!(
            *events.0.lock().unwrap(),
            [
                Event::Open {
                    pid: 7,
                    fd: 5,
                    path: "/tmp/meeting.wav".into(),
                    write: true
                },
                Event::Transfer {
                    pid: 7,
                    fd: 5,
                    direction: Direction::Out,
                    bytes: 44
                },
                Event::Connect {
                    pid: 7,
                    fd: 6,
                    addr: "198.18.0.1:443".parse().unwrap()
                },
                Event::Close { pid: 7, fd: 5 },
            ]
        );
    }

    #[test]
    fn reports_a_descriptor_copied_to_another() {
        let (stack, events) = observed(Fake::default());
        let memory = Mem::new();
        let caller = Caller::new(TaskId(1), &memory);

        block_on(stack.dup(&caller, Fd(3))).unwrap();
        block_on(stack.dup3(&caller, Fd(3), Fd(1), OpenFlags(0))).unwrap();
        block_on(stack.fcntl64(&caller, Fd(4), FcntlCmd::F_DUPFD_CLOEXEC, 10)).unwrap();
        block_on(stack.fcntl64(&caller, Fd(4), FcntlCmd::F_GETFD, 0)).unwrap();

        assert_eq!(
            *events.0.lock().unwrap(),
            [
                Event::Dup {
                    pid: 7,
                    from: 3,
                    to: 8
                },
                Event::Dup {
                    pid: 7,
                    from: 3,
                    to: 1
                },
                Event::Dup {
                    pid: 7,
                    from: 4,
                    to: 10
                },
            ]
        );
    }

    #[test]
    fn reports_how_processes_end() {
        let (stack, events) = observed(Fake::default());
        let memory = Mem::new();
        let caller = Caller::new(TaskId(1), &memory);

        block_on(stack.waitid(
            &caller,
            wasixv2_abi::Idtype(0),
            -1,
            wasixv2_abi::GuestPtrMut::new(512),
            wasixv2_abi::WaitOptions(4),
            wasixv2_abi::GuestPtrMut::NULL,
        ))
        .unwrap();
        block_on(stack.exit_group(&caller, 1)).unwrap();

        assert_eq!(
            *events.0.lock().unwrap(),
            [
                Event::Reaped {
                    pid: 7,
                    child: 9,
                    end: End::Killed(2)
                },
                Event::Exit { pid: 7, code: 1 },
            ]
        );
    }

    #[test]
    fn asks_the_kernel_for_a_tasks_process_once() {
        let (stack, _) = observed(Fake::default());
        let memory = Mem::new();
        let caller = Caller::new(TaskId(1), &memory);

        for _ in 0..3 {
            block_on(stack.write(&caller, Fd(1), UserSlice::new(0, 1))).unwrap();
        }

        assert_eq!(*stack.inner.getpids.borrow(), 1);
    }

    #[test]
    fn an_unobserved_trace_asks_the_kernel_nothing() {
        let stack = Layered::new(Trace::default(), Fake::default());
        let memory = Mem::new();
        let caller = Caller::new(TaskId(1), &memory);

        block_on(stack.write(&caller, Fd(1), UserSlice::new(0, 1))).unwrap();

        assert_eq!(*stack.inner.getpids.borrow(), 0);
    }

    #[test]
    fn started_reports_a_process_the_embedder_ran() {
        let events = Arc::new(Events::default());
        let trace = Trace::observed(events.clone());

        block_on(trace.started(
            &Fake::default(),
            TaskId(1),
            b"/bin/bash",
            &[b"bash".to_vec()],
        ));

        assert_eq!(
            *events.0.lock().unwrap(),
            [Event::Exec {
                pid: 7,
                ppid: 3,
                path: "/bin/bash".into(),
                argv: vec!["bash".into()],
            }]
        );
    }
}
