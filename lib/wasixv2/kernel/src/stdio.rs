use std::{io, sync::Arc};

use wasixv2_abi::OpenFlags;
use wasixv2_host::{ByteSink, Stdio};
use wasixv2_syscalls::{Errno, LocalFuture, SysResult};
use wasixv2_vfs::{Bound, File};
use wasixv2_wait::{PollMask, PollTable, Pollable};

use crate::{
    file::{Backing, FileObject, Io, OpenFile},
    hoststream::HostStream,
    pseudo::Pseudo,
};

/// The open files behind descriptors 0, 1 and 2. Each host stream looks like a pipe, with an
/// inode of its own that it hangs off, so opening `/proc/self/fd/1` (`/dev/stdout`) reaches
/// the same stream again, as it reaches the same pipe on Linux.
pub(crate) fn open_files(stdio: Stdio, pseudo: &Pseudo, owner: (u32, u32)) -> [OpenFile; 3] {
    fn open<T: FileObject + Send + Sync>(
        object: Arc<T>,
        flags: OpenFlags,
        pseudo: &Pseudo,
        owner: (u32, u32),
    ) -> OpenFile {
        let path = pseudo.pipe(owner);
        let bound: Bound = object.clone();
        path.dentry.inode().bind(&bound);
        OpenFile::new(Backing::Stream(object, path), flags)
    }
    [
        open(
            Arc::new(HostStream::new(stdio.stdin)),
            OpenFlags::O_RDONLY,
            pseudo,
            owner,
        ),
        open(
            Arc::new(HostOutput(stdio.stdout)),
            OpenFlags::O_WRONLY,
            pseudo,
            owner,
        ),
        open(
            Arc::new(HostOutput(stdio.stderr)),
            OpenFlags::O_WRONLY,
            pseudo,
            owner,
        ),
    ]
}

/// The host stream `file`, a pipe inode, belongs to, if it is one: opening it again shares the
/// stream.
pub(crate) fn reopen(file: &File) -> Option<Arc<dyn FileObject>> {
    let bound = file.path.dentry.inode().bound()?;
    let bound = match bound.downcast::<HostStream>() {
        Ok(input) => return Some(input),
        Err(bound) => bound,
    };
    bound
        .downcast::<HostOutput>()
        .ok()
        .map(|output| output as Arc<dyn FileObject>)
}

// Host output streams have no readiness to report, so they always look ready, as a file
// without a poll operation does on Linux, and a write may then still wait for the host.
struct HostOutput(Arc<dyn ByteSink>);

impl Pollable for HostOutput {
    fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
        PollMask::DEFAULT
    }
}

impl FileObject for HostOutput {
    fn read<'a>(&'a self, _: Io<'a>, _: &'a mut [u8]) -> LocalFuture<'a, SysResult<usize>> {
        Box::pin(async { Err(Errno::EBADF.into()) })
    }

    fn write<'a>(&'a self, _: Io<'a>, data: &'a [u8]) -> LocalFuture<'a, SysResult<usize>> {
        Box::pin(async move { Ok(self.0.write(data).await.map_err(io_errno)?) })
    }
}

pub(crate) fn io_errno(err: io::Error) -> Errno {
    match err.kind() {
        io::ErrorKind::BrokenPipe => Errno::EPIPE,
        io::ErrorKind::WouldBlock => Errno::EAGAIN,
        io::ErrorKind::Interrupted => Errno::EINTR,
        _ => Errno::EIO,
    }
}
