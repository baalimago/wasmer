//! `http-open`: one request as data, carried by the host's own HTTP client, and the descriptor
//! its response is read from.

use std::{io, sync::Arc};

use wasixv2_abi::OpenFlags;
use wasixv2_host::{Bad, http};
use wasixv2_syscalls::{Caller, Errno, Fd, SysResult, UserSlice};

use crate::{
    Kernel,
    file::{Backing, OpenFile},
    hoststream::HostStream,
};

/// Most bytes of a request the kernel copies out of the guest, so a bad length cannot exhaust the
/// host's memory.
const MAX_REQUEST: usize = 64 << 20;

impl Kernel {
    /// `ext.http-open`: decodes the guest's request, has the host carry it, and returns a
    /// descriptor that reads the response's head and then its body, then 0.
    pub(crate) async fn sys_http_open(
        &self,
        caller: &Caller<'_>,
        request: UserSlice,
    ) -> SysResult<Fd> {
        if request.len as usize > MAX_REQUEST {
            return Err(Errno::EINVAL.into());
        }
        let bytes = request.copy_in(caller.memory(), MAX_REQUEST).await?;
        let request = http::decode(&bytes).map_err(|bad| match bad {
            Bad::Malformed => Errno::EINVAL,
            Bad::Scheme => Errno::EPROTONOSUPPORT,
        })?;
        let response = self.host.http_open(request).await.map_err(errno)?;
        let head = http::head(response.status, &response.headers);
        let stream = HostStream::with_head(response.body, head);
        let file = OpenFile::new(
            Backing::Stream(Arc::new(stream), self.pseudo.anon("[http]")),
            OpenFlags::O_RDONLY,
        );
        let [fd] = self.install_files(caller, [file], false)?;
        Ok(fd)
    }
}

/// The errno an [`io::Error`] from the host names, `EIO` when it names none; `ENOSYS` for a host
/// without the call.
fn errno(err: io::Error) -> Errno {
    if err.kind() == io::ErrorKind::Unsupported {
        return Errno::ENOSYS;
    }
    err.raw_os_error().map_or(Errno::EIO, Errno)
}