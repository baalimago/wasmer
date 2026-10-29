//! A guest UDP socket's outside traffic: one WISP UDP stream per destination, since a WISP
//! stream is connected to one address. Only the destinations the socket sent to can answer.

use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError, Weak},
};

use wasixv2_abi::Errno;
use wasixv2_vnet::{BackendDatagram, PollMask, PollTable, Pollable, WaitQueue};

use crate::{CloseReason, Frame, Inner};

/// The largest UDP payload over IPv4.
const MAX_DATAGRAM: usize = 65507;
/// Queued bytes past which arriving datagrams are dropped, each charged with its payload plus
/// the kernel's fixed overhead, as the kernel's own receive queues do.
const QUEUE_LIMIT: usize = 256 * 1024;
const OVERHEAD: usize = 768;

pub(crate) struct WispDatagram {
    me: Weak<WispDatagram>,
    wq: WaitQueue,
    inner: Arc<Inner>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    streams: HashMap<SocketAddr, u32>,
    queue: VecDeque<(Vec<u8>, SocketAddr)>,
    queued: usize,
    connected: Option<SocketAddr>,
    err: Option<Errno>,
}

impl WispDatagram {
    pub(crate) fn new(wq: WaitQueue, inner: Arc<Inner>) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            wq,
            inner,
            state: Mutex::default(),
        })
    }

    pub(crate) fn data(&self, from: SocketAddr, data: Vec<u8>) {
        let mut st = self.state();
        let cost = data.len() + OVERHEAD;
        if st.connected.is_some_and(|peer| peer != from) || st.queued + cost > QUEUE_LIMIT {
            return;
        }
        st.queued += cost;
        st.queue.push_back((data, from));
        drop(st);
        self.wq.wake(PollMask::IN | PollMask::RDNORM);
    }

    /// A destination's stream closed. Sending to it again opens a new one; a connected socket
    /// learns that its peer refused, as from an ICMP port unreachable.
    pub(crate) fn close(&self, peer: SocketAddr, reason: CloseReason) {
        let mut st = self.state();
        st.streams.remove(&peer);
        if reason != CloseReason::VOLUNTARY && st.connected == Some(peer) {
            st.err = Some(Errno::ECONNREFUSED);
            drop(st);
            self.wq.wake(PollMask::ERR);
        }
    }

    pub(crate) fn link_down(&self) {
        self.state().streams.clear();
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for WispDatagram {
    fn drop(&mut self) {
        for (_, stream) in self.state().streams.drain() {
            self.inner.send(Frame::Close {
                stream,
                reason: CloseReason::VOLUNTARY,
            });
        }
    }
}

impl Pollable for WispDatagram {
    fn poll(&self, _: Option<&mut PollTable<'_>>) -> PollMask {
        let st = self.state();
        let mut m = PollMask::OUT | PollMask::WRNORM;
        if !st.queue.is_empty() {
            m |= PollMask::IN | PollMask::RDNORM;
        }
        if st.err.is_some() {
            m |= PollMask::ERR;
        }
        m
    }
}

impl BackendDatagram for WispDatagram {
    fn send_to(&self, data: &[u8], to: SocketAddr) -> Result<usize, Errno> {
        if data.len() > MAX_DATAGRAM {
            return Err(Errno::EMSGSIZE);
        }
        let mut st = self.state();
        let stream = match st.streams.get(&to) {
            Some(stream) => *stream,
            None => {
                let stream = self.inner.open_udp(to, self.me.clone())?;
                st.streams.insert(to, stream);
                stream
            }
        };
        self.inner.send(Frame::Data {
            stream,
            data: data.to_vec(),
        });
        Ok(data.len())
    }

    fn connect(&self, peer: Option<SocketAddr>) -> Result<(), Errno> {
        let mut st = self.state();
        st.connected = peer;
        st.err = None;
        if let Some(peer) = peer {
            let before = st.queue.len();
            st.queue.retain(|(_, from)| *from == peer);
            if st.queue.len() != before {
                st.queued = st.queue.iter().map(|(d, _)| d.len() + OVERHEAD).sum();
            }
        }
        Ok(())
    }

    fn take_error(&self) -> Option<Errno> {
        self.state().err.take()
    }

    fn recv_from(&self, buf: &mut [u8], peek: bool) -> Result<(usize, usize, SocketAddr), Errno> {
        let mut st = self.state();
        let (data, from) = st.queue.front().ok_or(Errno::EAGAIN)?;
        let (full, from) = (data.len(), *from);
        let n = buf.len().min(full);
        buf[..n].copy_from_slice(&data[..n]);
        if !peek {
            st.queue.pop_front();
            st.queued -= full + OVERHEAD;
        }
        Ok((n, full, from))
    }

    fn input_len(&self) -> usize {
        self.state().queue.front().map_or(0, |(d, _)| d.len())
    }
}
