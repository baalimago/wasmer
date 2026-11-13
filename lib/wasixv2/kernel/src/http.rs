//! `http-open`: one request as data, carried by the host's own HTTP client, and the descriptor
//! its response is read from.
//!
//! The descriptor comes back before the host has the response, which arrives on it as a
//! socket's reply does. A guest without threads (Go's wasm port) then has several requests in
//! flight, each goroutine waiting in `poll` on its own descriptor; waiting in the call instead
//! held the whole guest until each response's head came, one request after another.

use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use wasixv2_abi::OpenFlags;
use wasixv2_host::{Bad, ByteSource, HttpResponse, LocalFuture, http};
use wasixv2_syscalls::{Caller, Errno, Fd, SysResult, UserSlice};

use crate::{
    Kernel,
    file::{Backing, OpenFile},
    hoststream::HostStream,
    sync::MutexExt,
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
        let host = self.host.clone();
        let mut response: LocalFuture<'static, io::Result<HttpResponse>> =
            Box::pin(async move { host.http_open(request).await });
        // Polled once here, the request leaves now, and a host that answers at once, such as one
        // without the call (`ENOSYS`), answers this call, so the guest can fall back.
        let stream = match response.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok(response)) => {
                let head = http::head(response.status, &response.headers);
                HostStream::with_head(response.body, head)
            }
            Poll::Ready(Err(err)) => return Err(errno(err).into()),
            Poll::Pending => {
                let pending = Arc::new(Pending::default());
                let to = Arc::downgrade(&pending);
                // A descriptor closed first drops the response, which abandons the request.
                self.host.executor().spawn_local(Box::pin(async move {
                    let response = response.await;
                    if let Some(pending) = to.upgrade() {
                        pending.answer(response);
                    }
                }));
                HostStream::new(pending)
            }
        };
        let file = OpenFile::new(
            Backing::Stream(Arc::new(stream), self.pseudo.anon("[http]")),
            OpenFlags::O_RDONLY,
        );
        let [fd] = self.install_files(caller, [file], false)?;
        Ok(fd)
    }
}

/// A response still on its way, as the descriptor's source: nothing until the host answers,
/// then the head and the body, or the request's error.
#[derive(Default)]
struct Pending {
    state: Mutex<PendingState>,
}

#[derive(Default)]
struct PendingState {
    head: VecDeque<u8>,
    body: Option<Arc<dyn ByteSource>>,
    /// The request's error, until a read reports it.
    failed: Option<io::Error>,
    /// The stream's, woken once the host answers.
    waker: Option<Waker>,
}

impl Pending {
    fn answer(&self, response: io::Result<HttpResponse>) {
        let waker = {
            let mut state = self.state.lock_or_recover();
            match response {
                Ok(response) => {
                    state.head = http::head(response.status, &response.headers).into();
                    state.body = Some(response.body);
                }
                Err(err) => state.failed = Some(err),
            }
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl ByteSource for Pending {
    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let body = {
            let mut state = self.state.lock_or_recover();
            if !state.head.is_empty() {
                let n = buf.len().min(state.head.len());
                for (dst, src) in buf.iter_mut().zip(state.head.drain(..n)) {
                    *dst = src;
                }
                return Poll::Ready(Ok(n));
            }
            if let Some(err) = state.failed.take() {
                return Poll::Ready(Err(err));
            }
            match &state.body {
                Some(body) => body.clone(),
                None => {
                    state.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        };
        body.poll_read(cx, buf)
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

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        task::Wake,
    };

    use super::*;

    /// A body that hands over its bytes on the first read, then ends.
    struct Body(Mutex<Vec<u8>>);

    impl ByteSource for Body {
        fn poll_read(&self, _: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
            let mut data = self.0.lock_or_recover();
            let n = buf.len().min(data.len());
            buf[..n].copy_from_slice(&data[..n]);
            data.drain(..n);
            Poll::Ready(Ok(n))
        }
    }

    #[derive(Default)]
    struct Woken(AtomicBool);

    impl Wake for Woken {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn read(pending: &Pending, waker: &Waker) -> Poll<io::Result<Vec<u8>>> {
        let mut buf = [0; 64];
        pending
            .poll_read(&mut Context::from_waker(waker), &mut buf)
            .map_ok(|n| buf[..n].to_vec())
    }

    #[test]
    fn a_pending_response_reads_nothing_until_the_host_answers_then_its_head_and_body() {
        let pending = Pending::default();
        let woken = Arc::new(Woken::default());
        let waker = Waker::from(woken.clone());
        assert!(read(&pending, &waker).is_pending());
        assert!(!woken.0.load(Ordering::SeqCst));

        let headers = vec![("content-type".to_owned(), "text/plain".to_owned())];
        pending.answer(Ok(HttpResponse {
            status: 200,
            headers: headers.clone(),
            body: Arc::new(Body(Mutex::new(b"ok\n".to_vec()))),
        }));
        assert!(woken.0.load(Ordering::SeqCst), "the answer wakes the stream");

        let mut got = Vec::new();
        loop {
            match read(&pending, &waker) {
                Poll::Ready(Ok(bytes)) if bytes.is_empty() => break,
                Poll::Ready(Ok(bytes)) => got.extend(bytes),
                other => panic!("unexpected read: {other:?}"),
            }
        }
        let mut want = http::head(200, &headers);
        want.extend_from_slice(b"ok\n");
        assert_eq!(got, want);
    }

    #[test]
    fn a_request_that_fails_after_the_call_reports_its_error_on_the_first_read() {
        let pending = Pending::default();
        let waker = Waker::from(Arc::new(Woken::default()));
        assert!(read(&pending, &waker).is_pending());
        pending.answer(Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused")));
        match read(&pending, &waker) {
            Poll::Ready(Err(err)) => assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused),
            other => panic!("unexpected read: {other:?}"),
        }
    }
}
