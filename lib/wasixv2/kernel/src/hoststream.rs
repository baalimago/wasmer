//! A host byte stream as a descriptor: the bytes a host source delivers, buffered like a pipe's
//! read end, which a guest reads and polls. A stream can start with bytes of its own, the head of
//! a response ([`crate::http`]).

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
};

use wasixv2_host::ByteSource;
use wasixv2_syscalls::{Errno, LocalFuture, SysErr, SysResult};
use wasixv2_wait::{PollMask, PollTable, Pollable, WaitQueue, poll_wait, wait_event};

use crate::{
    file::{FileObject, Io, ReadSink, taken},
    sync::MutexExt,
};

/// How much one read from the host source asks for.
const INPUT_CHUNK: usize = 4096;

/// A host input stream, buffered like a pipe's read end: what the source delivered waits here
/// until a guest read takes it, so `poll` can report it, `O_NONBLOCK` reads fail with `EAGAIN`
/// instead of waiting, and a blocked read ends on a signal (`n_tty_read`, `pipe_read`).
pub(crate) struct HostStream {
    source: Arc<dyn ByteSource>,
    state: Mutex<InputState>,
    /// Readers and pollers wait here; the source wakes it through `waker`.
    wait: WaitQueue,
    waker: Waker,
    /// Held by a reader from looking at the data until it consumed it, as a pipe's
    /// (`pipe->mutex`); never while waiting.
    io_lock: futures_util::lock::Mutex<()>,
}

#[derive(Default)]
struct InputState {
    data: VecDeque<u8>,
    /// What the source said after the data, if not more data: end of stream or an error.
    /// Consumed by the read that reports it.
    end: Option<Result<(), Errno>>,
}

/// Turns the source's readiness into a wake of the stream's queue.
pub(crate) struct QueueWaker(pub(crate) WaitQueue);

impl Wake for QueueWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.wake(PollMask::READABLE);
    }
}

impl HostStream {
    pub(crate) fn new(source: Arc<dyn ByteSource>) -> Self {
        Self::with_head(source, Vec::new())
    }

    /// A stream whose first bytes are `head`, which the source's follow.
    pub(crate) fn with_head(source: Arc<dyn ByteSource>, head: Vec<u8>) -> Self {
        let wait = WaitQueue::new();
        Self {
            source,
            state: Mutex::new(InputState {
                data: head.into(),
                end: None,
            }),
            waker: Waker::from(Arc::new(QueueWaker(wait.clone()))),
            wait,
            io_lock: futures_util::lock::Mutex::new(()),
        }
    }

    /// Asks the source for more input once the buffer is used up. A `Pending` source wakes the
    /// queue when that changes.
    fn fill(&self, state: &mut InputState) {
        if !state.data.is_empty() || state.end.is_some() {
            return;
        }
        let mut chunk = [0; INPUT_CHUNK];
        let mut cx = Context::from_waker(&self.waker);
        match self.source.poll_read(&mut cx, &mut chunk) {
            Poll::Ready(Ok(0)) => state.end = Some(Ok(())),
            Poll::Ready(Ok(n)) => state.data.extend(&chunk[..n]),
            Poll::Ready(Err(err)) => state.end = Some(Err(crate::stdio::io_errno(err))),
            Poll::Pending => {}
        }
    }

    /// Copies at most `buf.len()` bytes to `to`, or into `buf` itself without one, and
    /// consumes them only once all arrived, as a pipe's reads do ([`taken`]).
    async fn read_input(
        &self,
        io: Io<'_>,
        buf: &mut [u8],
        mut to: Option<&mut dyn ReadSink>,
    ) -> SysResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let ready = || {
                let mut state = self.state.lock_or_recover();
                self.fill(&mut state);
                if !state.data.is_empty() || state.end.is_some() {
                    return Some(Ok(()));
                }
                io.nonblocking().then_some(Err(Errno::EAGAIN))
            };
            wait_event(&self.wait, ready, io.interrupt)
                .await
                .map_err(|_| SysErr::Restart)??;
            let _io = self.io_lock.lock().await;
            let n = {
                let mut state = self.state.lock_or_recover();
                if state.data.is_empty() {
                    match state.end.take() {
                        Some(end) => return Ok(end.map(|()| 0)?),
                        None => continue,
                    }
                }
                let n = buf.len().min(state.data.len());
                for (dst, src) in buf.iter_mut().zip(state.data.range(..n)) {
                    *dst = *src;
                }
                n
            };
            let copied = match to.as_mut() {
                Some(to) => to.copy_out(&buf[..n]).await,
                None => n,
            };
            let n = taken(n, copied)?;
            self.state.lock_or_recover().data.drain(..n);
            return Ok(n);
        }
    }
}

impl Pollable for HostStream {
    /// Readable while input (or its end) waits to be read, as a pipe's read end.
    fn poll(&self, mut table: Option<&mut PollTable<'_>>) -> PollMask {
        poll_wait(&mut table, &self.wait);
        let mut state = self.state.lock_or_recover();
        self.fill(&mut state);
        match !state.data.is_empty() || state.end.is_some() {
            true => PollMask::READABLE,
            false => PollMask::empty(),
        }
    }
}

impl FileObject for HostStream {
    fn read<'a>(&'a self, io: Io<'a>, buf: &'a mut [u8]) -> LocalFuture<'a, SysResult<usize>> {
        Box::pin(self.read_input(io, buf, None))
    }

    fn read_to<'a>(
        &'a self,
        io: Io<'a>,
        buf: &'a mut [u8],
        to: &'a mut dyn ReadSink,
    ) -> LocalFuture<'a, SysResult<usize>> {
        Box::pin(self.read_input(io, buf, Some(to)))
    }

    fn write<'a>(&'a self, _: Io<'a>, _: &'a [u8]) -> LocalFuture<'a, SysResult<usize>> {
        // Linux reports writes to a descriptor opened read-only as EBADF.
        Box::pin(async { Err(Errno::EBADF.into()) })
    }
}