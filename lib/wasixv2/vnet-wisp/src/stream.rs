//! A TCP connection carried by one WISP stream.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use wasixv2_abi::Errno;
use wasixv2_vnet::{
    BackendStream, PollMask, PollTable, Pollable, Shutdown, StreamState, WaitQueue,
};

use crate::{CloseReason, Frame, Inner, close_errno};

/// The most a DATA packet carries; each one spends one packet of the stream's credit.
const MAX_DATA: usize = 64 * 1024;

pub(crate) struct WispStream {
    id: u32,
    peer: SocketAddr,
    wq: WaitQueue,
    inner: Arc<Inner>,
    conn: Mutex<Conn>,
}

#[derive(Default)]
struct Conn {
    /// DATA packets the server takes before its next CONTINUE; `None` until the link is up.
    credit: Option<u32>,
    rx: VecDeque<u8>,
    got_data: bool,
    /// The server closed the stream voluntarily: the peer's FIN.
    eof: bool,
    err: Option<Errno>,
    failed: bool,
    rd_shut: bool,
    wr_shut: bool,
    /// A CLOSE went either way, so dropping the stream sends none.
    closed: bool,
}

impl WispStream {
    pub(crate) fn new(
        id: u32,
        peer: SocketAddr,
        wq: WaitQueue,
        credit: Option<u32>,
        inner: Arc<Inner>,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            peer,
            wq,
            inner,
            conn: Mutex::new(Conn {
                credit,
                ..Conn::default()
            }),
        })
    }

    pub(crate) fn id(&self) -> u32 {
        self.id
    }

    pub(crate) fn first_credit(&self, credit: u32) {
        let mut conn = self.conn();
        if conn.credit.is_none() && !conn.closed {
            conn.credit = Some(credit);
            drop(conn);
            self.wq.wake(PollMask::OUT | PollMask::WRNORM);
        }
    }

    pub(crate) fn credit(&self, credit: u32) {
        self.conn().credit = Some(credit);
        self.wq.wake(PollMask::OUT | PollMask::WRNORM);
    }

    pub(crate) fn data(&self, data: Vec<u8>) {
        let mut conn = self.conn();
        if conn.closed || conn.rd_shut {
            return;
        }
        conn.got_data = true;
        conn.rx.extend(data);
        drop(conn);
        self.wq.wake(PollMask::IN | PollMask::RDNORM);
    }

    pub(crate) fn close(&self, reason: CloseReason) {
        let mut conn = self.conn();
        conn.closed = true;
        if reason == CloseReason::VOLUNTARY {
            conn.eof = true;
            drop(conn);
            self.wq
                .wake(PollMask::IN | PollMask::RDNORM | PollMask::RDHUP);
        } else {
            let errno = close_errno(reason, conn.got_data);
            self.fail(conn, errno);
        }
    }

    pub(crate) fn link_down(&self) {
        let conn = self.conn();
        if conn.closed {
            return;
        }
        let errno = if conn.credit.is_some() {
            Errno::ECONNRESET
        } else {
            Errno::ENETUNREACH
        };
        self.fail(conn, errno);
    }

    fn fail(&self, mut conn: MutexGuard<'_, Conn>, errno: Errno) {
        conn.closed = true;
        conn.failed = true;
        conn.err = Some(errno);
        drop(conn);
        self.wq
            .wake(PollMask::ERR | PollMask::HUP | PollMask::IN | PollMask::OUT);
    }

    fn conn(&self) -> MutexGuard<'_, Conn> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for WispStream {
    fn drop(&mut self) {
        if !self.conn().closed {
            self.inner.send(Frame::Close {
                stream: self.id,
                reason: CloseReason::VOLUNTARY,
            });
        }
    }
}

impl Pollable for WispStream {
    /// What `tcp_poll` reports for the guest socket this stream carries.
    fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
        let conn = self.conn();
        let mut m = PollMask::empty();
        if conn.err.is_some() {
            m |= PollMask::ERR;
        }
        if conn.failed {
            return m
                | PollMask::HUP
                | PollMask::IN
                | PollMask::RDNORM
                | PollMask::RDHUP
                | PollMask::OUT
                | PollMask::WRNORM;
        }
        let Some(credit) = conn.credit else {
            return m;
        };
        let rcv_shut = conn.eof || conn.rd_shut;
        let snd_shut = conn.eof || conn.wr_shut;
        if rcv_shut && snd_shut {
            m |= PollMask::HUP;
        }
        if rcv_shut {
            m |= PollMask::IN | PollMask::RDNORM | PollMask::RDHUP;
        }
        if !conn.rx.is_empty() {
            m |= PollMask::IN | PollMask::RDNORM;
        }
        if snd_shut || credit > 0 {
            m |= PollMask::OUT | PollMask::WRNORM;
        }
        m
    }
}

impl BackendStream for WispStream {
    fn state(&self) -> StreamState {
        let conn = self.conn();
        match conn.credit {
            _ if conn.failed => StreamState::Closed,
            Some(_) => StreamState::Established,
            None => StreamState::Connecting,
        }
    }

    fn read(&self, buf: &mut [u8], peek: bool) -> Result<usize, Errno> {
        let mut conn = self.conn();
        let n = buf.len().min(conn.rx.len());
        for (dst, src) in buf.iter_mut().zip(conn.rx.iter()) {
            *dst = *src;
        }
        if !peek {
            conn.rx.drain(..n);
        }
        if n > 0 || (buf.is_empty() && !conn.rx.is_empty()) {
            return Ok(n);
        }
        if conn.eof {
            return Ok(0);
        }
        if let Some(e) = conn.err.take() {
            return Err(e);
        }
        if conn.rd_shut || conn.failed {
            return Ok(0);
        }
        Err(Errno::EAGAIN)
    }

    fn write(&self, data: &[u8]) -> Result<usize, Errno> {
        let mut conn = self.conn();
        if conn.failed {
            return Err(conn.err.take().unwrap_or(Errno::EPIPE));
        }
        if conn.wr_shut || conn.eof {
            return Err(Errno::EPIPE);
        }
        if data.is_empty() {
            return Ok(0);
        }
        match conn.credit {
            Some(credit @ 1..) => conn.credit = Some(credit - 1),
            _ => return Err(Errno::EAGAIN),
        }
        let n = data.len().min(MAX_DATA);
        // Under the lock, so the stream's DATA packets leave in the order they were written.
        self.inner.send(Frame::Data {
            stream: self.id,
            data: data[..n].to_vec(),
        });
        Ok(n)
    }

    /// WISP has no urgent data: the byte goes inline, without a mark.
    fn write_urgent(&self, data: &[u8]) -> Result<usize, Errno> {
        self.write(data)
    }

    fn read_urgent(&self, _: bool) -> Result<u8, Errno> {
        Err(Errno::EINVAL)
    }

    fn at_mark(&self) -> bool {
        false
    }

    fn shutdown(&self, how: Shutdown) -> Result<(), Errno> {
        let mut conn = self.conn();
        match how {
            Shutdown::Read => conn.rd_shut = true,
            Shutdown::Write => conn.wr_shut = true,
            Shutdown::Both => {
                conn.rd_shut = true;
                conn.wr_shut = true;
            }
        }
        drop(conn);
        self.wq.wake(PollMask::IN | PollMask::OUT);
        Ok(())
    }

    fn take_error(&self) -> Option<Errno> {
        self.conn().err.take()
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    fn input_len(&self) -> usize {
        self.conn().rx.len()
    }
}
