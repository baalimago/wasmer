//! `spawn`, `posix_spawn` in one import, for native guests that have no wasm exceptions to
//! unwind to a vfork point with (Go). The instance becomes a vfork child of the caller, takes
//! the child's steps and `execve`s as it, all inside the call, and then runs as the parent
//! again, which returns from the import ([`Spawning`]). The WASIX v1 compat layer's
//! `proc_spawn2` does the same for v1 guests.

use std::sync::Mutex;

use wasixv2_abi::{
    AtFd, CloneFlags, ConstSigactionPtr, ConstSigsetPtr, Cstr, CstrArray, FcntlCmd, Fd,
    GuestLayout, GuestPtr, GuestPtrMut, Idtype, OpenFlags, RusagePtr, S32Ptr, SigactionPtr,
    SiginfoPtr, Signal, SigprocmaskHow, SigsetPtr, SpawnAttr, SpawnFileAction, SpawnFileActionCmd,
    SpawnFlags, WaitOptions,
};
use wasixv2_syscalls::{
    Caller, Control, Errno, Fault, LocalFuture, SysResult, Syscalls, TaskId, UserMemory,
    read_value, write_value,
};
use wasmer::{AsyncFunctionEnvMut, Function, FunctionEnv, Imports, RuntimeError, Store};

use crate::{ExecEnv, GuestMemory, IMPORT_MODULE, Outcome, caller_parts, complete, wasixv2};

const SIGCHLD: u32 = 17;

/// vfork: `clone(CLONE_VM | CLONE_VFORK | SIGCHLD)`.
const VFORK: u32 = CloneFlags::CLONE_VM.0 as u32 | CloneFlags::CLONE_VFORK.0 as u32 | SIGCHLD;

/// The status a child whose step failed exits with, as musl's `posix_spawn` child does.
const EXEC_FAILED: i32 = 127;

const KNOWN_FLAGS: u32 = SpawnFlags::POSIX_SPAWN_RESETIDS.0
    | SpawnFlags::POSIX_SPAWN_SETPGROUP.0
    | SpawnFlags::POSIX_SPAWN_SETSIGDEF.0
    | SpawnFlags::POSIX_SPAWN_SETSIGMASK.0
    | SpawnFlags::POSIX_SPAWN_SETSID.0;

/// The `sigsetsize` of the kernel's `sigset_t`.
const SIGSET_SIZE: u32 = 8;

/// The vfork children of an instance's `spawn` calls: their parent resumes by returning from
/// the import, where a vfork parent of `clone` unwinds to its vfork point.
#[derive(Default)]
pub(crate) struct Spawning(Mutex<Vec<TaskId>>);

impl Spawning {
    fn insert(&self, child: TaskId) {
        self.0.lock().unwrap().push(child);
    }

    /// Whether `child` was a `spawn` child, which it is no longer.
    pub(crate) fn take(&self, child: TaskId) -> bool {
        let mut children = self.0.lock().unwrap();
        let found = children.iter().position(|&c| c == child);
        found.map(|i| children.swap_remove(i)).is_some()
    }
}

/// Replaces the generated `spawn`, which the kernel answers with `ENOSYS`.
pub(crate) fn imports<S>(store: &mut Store, env: &FunctionEnv<ExecEnv<S>>, imports: &mut Imports)
where
    S: Syscalls + Control + Send + Sync + 'static,
{
    imports.define(
        IMPORT_MODULE,
        "spawn",
        Function::new_typed_with_env_async(store, env, spawn::<S>),
    );
}

/// What the child does before its `execve`, decoded while still the parent.
struct Request {
    attr: Option<(SpawnAttr, u32)>,
    actions: Vec<SpawnFileAction>,
    path: Cstr,
    argv: CstrArray,
    envp: CstrArray,
}

/// How a child's step ended, other than with its result.
enum Ended {
    /// The child's `execve` succeeded, and the instance runs as the parent again.
    Exec,
    /// A step failed with this errno; the instance still runs as the child.
    Failed(Errno),
    /// The child ended before its `execve` (a signal killed it), and the instance runs as the
    /// parent again.
    Gone,
    /// The import must raise this error.
    Unwind(RuntimeError),
}

#[allow(clippy::too_many_arguments)]
async fn spawn<S>(
    env: AsyncFunctionEnvMut<ExecEnv<S>>,
    pid_out: i32,
    path: i32,
    actions: i32,
    actions_len: i32,
    attr: i32,
    argv: i32,
    envp: i32,
) -> Result<i32, RuntimeError>
where
    S: Syscalls + Control + 'static,
{
    let (syscalls, parent) = caller_parts(&env).await;
    let syscalls = &*syscalls;
    let request = match read_request(&env, actions as u32, actions_len as u32, attr as u32).await {
        Ok(actions_and_attr) => Request {
            path: Cstr::new(path as u32),
            argv: CstrArray::new(argv as u32),
            envp: CstrArray::new(envp as u32),
            ..actions_and_attr
        },
        Err(errno) => return Ok(-errno.0),
    };
    let vfork = step(&env, syscalls, async |caller| {
        syscalls
            .clone(caller, VFORK, 0, S32Ptr::NULL, 0, S32Ptr::NULL)
            .await
    })
    .await;
    match vfork {
        Err(Ended::Exec) => {}
        Err(Ended::Failed(errno)) => return Ok(-errno.0),
        Err(Ended::Unwind(err)) => return Err(err),
        Ok(_) | Err(Ended::Gone) => {
            return Err(RuntimeError::new(
                "vfork returned without switching to the child",
            ));
        }
    }
    let child = env.read().await.data().task();
    let pid = syscalls.pid_in(parent, child);
    mark_spawning(&env, child).await?;
    match run_child(&env, syscalls, &request).await {
        Ended::Exec => {
            let memory = GuestMemory { env: &env };
            let written = write_value(&memory, GuestPtrMut::new(pid_out as u32), &pid).await;
            Ok(written.map_or(-Errno::EFAULT.0, |()| 0))
        }
        Ended::Failed(errno) => {
            let exit = step(&env, syscalls, async |caller| {
                syscalls.exit_group(caller, EXEC_FAILED).await
            })
            .await;
            match exit {
                Err(Ended::Exec | Ended::Gone) => {}
                Err(Ended::Unwind(err)) => return Err(err),
                Ok(()) | Err(Ended::Failed(_)) => {
                    return Err(RuntimeError::new("a spawned child did not end"));
                }
            }
            reap(&env, syscalls, pid).await?;
            Ok(-errno.0)
        }
        Ended::Gone => {
            reap(&env, syscalls, pid).await?;
            Ok(-Errno::ECHILD.0)
        }
        Ended::Unwind(err) => Err(err),
    }
}

/// Marks `child` as a `spawn` child of the instance (see [`Spawning`]).
async fn mark_spawning<S: 'static>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    child: TaskId,
) -> Result<(), RuntimeError> {
    let abi = env.read().await.data().abi().cloned();
    let abi = abi.ok_or_else(|| RuntimeError::new("spawn before bind"))?;
    let instance = (abi.as_any())
        .downcast_ref::<wasixv2::Wasixv2Instance>()
        .ok_or_else(|| RuntimeError::new("spawn from an instance of another ABI"))?;
    instance.spawning.insert(child);
    Ok(())
}

/// The attributes and file actions, checked for what the child cannot do.
async fn read_request<S: 'static>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    actions: u32,
    actions_len: u32,
    attr: u32,
) -> Result<Request, Errno> {
    let memory = GuestMemory { env };
    let attr = match attr {
        0 => None,
        addr => {
            let attr: SpawnAttr = read(&memory, addr).await?;
            if attr.flags.0 & !KNOWN_FLAGS != 0 {
                return Err(Errno::EINVAL);
            }
            Some((attr, addr))
        }
    };
    let mut file_actions = Vec::new();
    for i in 0..actions_len {
        let size = SpawnFileAction::SIZE as u32;
        let addr = i
            .checked_mul(size)
            .and_then(|offset| actions.checked_add(offset))
            .ok_or(Errno::EFAULT)?;
        let action: SpawnFileAction = read(&memory, addr).await?;
        if !(SpawnFileActionCmd::SPAWN_FDOP_CLOSE.0..=SpawnFileActionCmd::SPAWN_FDOP_FCHDIR.0)
            .contains(&action.cmd.0)
        {
            return Err(Errno::EINVAL);
        }
        file_actions.push(action);
    }
    Ok(Request {
        attr,
        actions: file_actions,
        path: Cstr::new(0),
        argv: CstrArray::new(0),
        envp: CstrArray::new(0),
    })
}

async fn read<T: GuestLayout>(memory: &dyn UserMemory, addr: u32) -> Result<T, Errno> {
    read_value(memory, GuestPtr::new(addr))
        .await
        .map_err(|Fault| Errno::EFAULT)
}

/// Makes one syscall as the task the instance runs as, with its return-to-guest path. A call
/// that the path switched away from ends with [`Ended::Exec`]; its caller tells what that
/// switch was.
async fn step<S, T>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    syscalls: &S,
    mut call: impl AsyncFnMut(&Caller<'_>) -> SysResult<T>,
) -> Result<T, Ended>
where
    S: Syscalls + Control + 'static,
{
    loop {
        let task = env.read().await.data().task();
        let memory = GuestMemory { env };
        let ret = call(&Caller::new(task, &memory)).await;
        return match complete(env, syscalls, task, ret).await {
            // The child's steps cannot go on halfway, so a call that saved how to continue
            // runs again from the start too.
            Outcome::Rerun | Outcome::Restart => continue,
            Outcome::Return(Ok(value)) => Ok(value),
            Outcome::Return(Err(errno)) => Err(Ended::Failed(errno)),
            Outcome::Switched(_) => Err(Ended::Exec),
            Outcome::Unwind(err) => Err(Ended::Unwind(err)),
            Outcome::Unwinding => Err(Ended::Unwind(RuntimeError::new(
                "spawn cannot unwind the stack for asyncify",
            ))),
        };
    }
}

/// The child's part: the attributes, the file actions in order, then `execve`.
async fn run_child<S>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    syscalls: &S,
    request: &Request,
) -> Ended
where
    S: Syscalls + Control + 'static,
{
    if let Some((attr, addr)) = &request.attr
        && let Err(ended) = apply_attr(env, syscalls, attr, *addr).await
    {
        return ended;
    }
    for action in &request.actions {
        if let Err(ended) = file_action(env, syscalls, action).await {
            return ended;
        }
    }
    let exec = step(env, syscalls, async |caller| {
        syscalls
            .execve(caller, request.path, request.argv, request.envp)
            .await
    })
    .await;
    match exec {
        // Switching away from the child is how `execve` succeeds.
        Err(ended) => ended,
        Ok(_) => Ended::Unwind(RuntimeError::new(
            "a spawned child's execve returned success",
        )),
    }
}

/// A step before `execve` that switched away from the child lost it.
fn lost(ended: Ended) -> Ended {
    match ended {
        Ended::Exec => Ended::Gone,
        other => other,
    }
}

async fn apply_attr<S>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    syscalls: &S,
    attr: &SpawnAttr,
    addr: u32,
) -> Result<(), Ended>
where
    S: Syscalls + Control + 'static,
{
    let flags = attr.flags.0;
    if flags & SpawnFlags::POSIX_SPAWN_RESETIDS.0 != 0 {
        let gid = step(env, syscalls, async |caller| syscalls.getgid(caller).await)
            .await
            .map_err(lost)?;
        step(env, syscalls, async |caller| {
            syscalls.setgid(caller, gid as u32).await
        })
        .await
        .map_err(lost)?;
        let uid = step(env, syscalls, async |caller| syscalls.getuid(caller).await)
            .await
            .map_err(lost)?;
        step(env, syscalls, async |caller| {
            syscalls.setuid(caller, uid as u32).await
        })
        .await
        .map_err(lost)?;
    }
    if flags & SpawnFlags::POSIX_SPAWN_SETSID.0 != 0 {
        step(env, syscalls, async |caller| syscalls.setsid(caller).await)
            .await
            .map_err(lost)?;
    }
    if flags & SpawnFlags::POSIX_SPAWN_SETPGROUP.0 != 0 {
        step(env, syscalls, async |caller| {
            syscalls.setpgid(caller, 0, attr.pgroup).await
        })
        .await
        .map_err(lost)?;
    }
    if flags & SpawnFlags::POSIX_SPAWN_SETSIGDEF.0 != 0 {
        for sig in 1..=64u32 {
            let word = attr.sigdefault.sig[(sig as usize - 1) / 32];
            if word & (1 << ((sig - 1) % 32)) == 0 || sig == 9 || sig == 19 {
                continue;
            }
            step(env, syscalls, async |caller| {
                // `SIG_DFL` is a zeroed `struct sigaction`, which the guest has nowhere to
                // spare; the call reads it from just past the end of its memory instead.
                let memory = Defaults::new(caller.memory()).await;
                let act = ConstSigactionPtr::new(memory.at);
                let caller = Caller::new(caller.task(), &memory);
                syscalls
                    .rt_sigaction(
                        &caller,
                        Signal(sig as i32),
                        act,
                        SigactionPtr::NULL,
                        SIGSET_SIZE,
                    )
                    .await
            })
            .await
            .map_err(lost)?;
        }
    }
    if flags & SpawnFlags::POSIX_SPAWN_SETSIGMASK.0 != 0 {
        // `sigmask` follows `flags` and `pgroup`.
        let set = ConstSigsetPtr::new(addr + 8);
        step(env, syscalls, async |caller| {
            syscalls
                .rt_sigprocmask(
                    caller,
                    SigprocmaskHow::SIG_SETMASK,
                    set,
                    SigsetPtr::NULL,
                    SIGSET_SIZE,
                )
                .await
        })
        .await
        .map_err(lost)?;
    }
    Ok(())
}

async fn file_action<S>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    syscalls: &S,
    action: &SpawnFileAction,
) -> Result<(), Ended>
where
    S: Syscalls + Control + 'static,
{
    let fd = action.fd;
    match action.cmd {
        SpawnFileActionCmd::SPAWN_FDOP_CLOSE => {
            match step(env, syscalls, async |caller| {
                syscalls.close(caller, fd).await
            })
            .await
            {
                Ok(_) | Err(Ended::Failed(_)) => {}
                Err(ended) => return Err(lost(ended)),
            }
        }
        SpawnFileActionCmd::SPAWN_FDOP_DUP2 if action.src_fd == fd => {
            let flags = step(env, syscalls, async |caller| {
                syscalls.fcntl64(caller, fd, FcntlCmd::F_GETFD, 0).await
            })
            .await
            .map_err(lost)?;
            step(env, syscalls, async |caller| {
                syscalls
                    .fcntl64(caller, fd, FcntlCmd::F_SETFD, (flags & !1) as u32)
                    .await
            })
            .await
            .map_err(lost)?;
        }
        SpawnFileActionCmd::SPAWN_FDOP_DUP2 => {
            step(env, syscalls, async |caller| {
                syscalls.dup3(caller, action.src_fd, fd, OpenFlags(0)).await
            })
            .await
            .map_err(lost)?;
        }
        SpawnFileActionCmd::SPAWN_FDOP_OPEN => {
            let opened = step(env, syscalls, async |caller| {
                syscalls
                    .openat(
                        caller,
                        Fd(AtFd::AT_FDCWD.0),
                        action.path,
                        action.oflag,
                        action.mode,
                    )
                    .await
            })
            .await
            .map_err(lost)?;
            if opened != fd {
                step(env, syscalls, async |caller| {
                    syscalls.dup3(caller, opened, fd, OpenFlags(0)).await
                })
                .await
                .map_err(lost)?;
                step(env, syscalls, async |caller| {
                    syscalls.close(caller, opened).await
                })
                .await
                .map_err(lost)?;
            }
        }
        SpawnFileActionCmd::SPAWN_FDOP_CHDIR => {
            step(env, syscalls, async |caller| {
                syscalls.chdir(caller, action.path).await
            })
            .await
            .map_err(lost)?;
        }
        SpawnFileActionCmd::SPAWN_FDOP_FCHDIR => {
            step(env, syscalls, async |caller| {
                syscalls.fchdir(caller, fd).await
            })
            .await
            .map_err(lost)?;
        }
        _ => return Err(Ended::Failed(Errno::EINVAL)),
    }
    Ok(())
}

/// Waits for the child `pid` that ended before its `execve`, as the parent.
async fn reap<S>(
    env: &AsyncFunctionEnvMut<ExecEnv<S>>,
    syscalls: &S,
    pid: i32,
) -> Result<(), RuntimeError>
where
    S: Syscalls + Control + 'static,
{
    let reaped = step(env, syscalls, async |caller| {
        syscalls
            .waitid(
                caller,
                Idtype::P_PID,
                pid,
                SiginfoPtr::NULL,
                WaitOptions::WEXITED,
                RusagePtr::NULL,
            )
            .await
    })
    .await;
    match reaped {
        Ok(_) | Err(Ended::Failed(_)) => Ok(()),
        Err(Ended::Unwind(err)) => Err(err),
        Err(Ended::Exec | Ended::Gone) => {
            Err(RuntimeError::new("reaping a spawned child switched tasks"))
        }
    }
}

/// The guest's memory, with a zeroed `struct sigaction` at `at`, just past its end.
struct Defaults<'a> {
    memory: &'a dyn UserMemory,
    at: u32,
}

const SIGACTION_SIZE: u32 = 16;

impl<'a> Defaults<'a> {
    async fn new(memory: &'a dyn UserMemory) -> Self {
        let size = memory.size().await;
        let at = u32::try_from(size)
            .ok()
            .filter(|at| at.checked_add(SIGACTION_SIZE).is_some())
            // A full 4 GiB memory has no room past its end; the read then faults.
            .unwrap_or(u32::MAX);
        Self { memory, at }
    }

    fn holds(&self, addr: u32, len: usize) -> bool {
        addr >= self.at
            && u64::from(addr) + len as u64 <= u64::from(self.at) + u64::from(SIGACTION_SIZE)
    }
}

impl UserMemory for Defaults<'_> {
    fn read<'a>(&'a self, addr: u32, buf: &'a mut [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        if self.holds(addr, buf.len()) {
            buf.fill(0);
            return Box::pin(async { Ok(()) });
        }
        self.memory.read(addr, buf)
    }

    fn write<'a>(&'a self, addr: u32, data: &'a [u8]) -> LocalFuture<'a, Result<(), Fault>> {
        self.memory.write(addr, data)
    }

    fn size(&self) -> LocalFuture<'_, u64> {
        self.memory.size()
    }

    fn grow(&self, pages: u32) -> LocalFuture<'_, Option<u64>> {
        self.memory.grow(pages)
    }
}
