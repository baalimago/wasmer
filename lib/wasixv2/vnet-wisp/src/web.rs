//! The page's WebSocket as the backend's transport.
//!
//! The WebSocket lives on the thread that opened it, as JavaScript objects do, so frames are
//! sent from that thread: the one the machine runs on, until guest threads run on workers.

use std::{cell::RefCell, collections::HashMap};

use js_sys::{ArrayBuffer, Uint8Array};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{BinaryType, Event, MessageEvent, WebSocket};

use crate::{FrameSink, WispBackend};

thread_local! {
    static SOCKETS: RefCell<HashMap<u32, Socket>> = RefCell::new(HashMap::new());
    static NEXT_ID: RefCell<u32> = const { RefCell::new(0) };
}

struct Socket {
    ws: WebSocket,
    /// Frames sent before the WebSocket opened, in order; `None` once it is open.
    pending: Option<Vec<Vec<u8>>>,
    _handlers: [Closure<dyn FnMut(Event)>; 3],
}

struct WebSocketSink(u32);

impl FrameSink for WebSocketSink {
    fn send(&self, frame: Vec<u8>) {
        SOCKETS.with_borrow_mut(|sockets| {
            let Some(socket) = sockets.get_mut(&self.0) else {
                return;
            };
            match &mut socket.pending {
                Some(pending) => pending.push(frame),
                // A WebSocket that failed to send is closing: its close event fails the streams.
                None => drop(socket.ws.send_with_u8_array(&frame)),
            }
        });
    }
}

/// Opens a WebSocket to the WISP server at `url` (`ws:` or `wss:`) and returns the backend
/// it carries. Streams wait for the server's first frame, and fail if the WebSocket closes.
pub fn connect(url: &str) -> Result<WispBackend, JsValue> {
    let ws = WebSocket::new(url)?;
    ws.set_binary_type(BinaryType::Arraybuffer);
    let id = NEXT_ID.with_borrow_mut(|next| {
        *next += 1;
        *next
    });
    let backend = WispBackend::new(std::sync::Arc::new(WebSocketSink(id)));

    let on_open = Closure::<dyn FnMut(Event)>::new(move |_| flush(id));
    let receiver = backend.clone();
    let on_message = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
        let Some(data) = event
            .dyn_ref::<MessageEvent>()
            .and_then(|m| m.data().dyn_into::<ArrayBuffer>().ok())
        else {
            return;
        };
        // A server that breaks the protocol cannot be followed any further.
        if receiver.receive(&Uint8Array::new(&data).to_vec()).is_err() {
            close(id);
        }
    });
    let closed = backend.clone();
    let on_close = Closure::<dyn FnMut(Event)>::new(move |_| closed.disconnected());
    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

    SOCKETS.with_borrow_mut(|sockets| {
        sockets.insert(
            id,
            Socket {
                ws,
                pending: Some(Vec::new()),
                _handlers: [on_open, on_message, on_close],
            },
        )
    });
    Ok(backend)
}

fn flush(id: u32) {
    SOCKETS.with_borrow_mut(|sockets| {
        let Some(socket) = sockets.get_mut(&id) else {
            return;
        };
        for frame in socket.pending.take().unwrap_or_default() {
            drop(socket.ws.send_with_u8_array(&frame));
        }
    });
}

fn close(id: u32) {
    SOCKETS.with_borrow(|sockets| {
        if let Some(socket) = sockets.get(&id) {
            drop(socket.ws.close());
        }
    });
}
