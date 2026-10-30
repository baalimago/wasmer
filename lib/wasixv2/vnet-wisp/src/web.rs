//! The page's WebSocket as the backend's transport.
//!
//! The WebSocket lives on the thread that opened it, as JavaScript objects do, so frames are
//! sent from that thread: the one the machine runs on, until guest threads run on workers.
//! When it closes (the server restarted, the laptop slept), its streams fail and a new one
//! opens after a pause, so the machine's network comes back without reloading the page.

use std::{cell::RefCell, collections::HashMap};

use js_sys::{ArrayBuffer, Function, Uint8Array};
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use web_sys::{BinaryType, Event, MessageEvent, WebSocket};

use crate::{FrameSink, WispBackend};

#[wasm_bindgen]
extern "C" {
    // A global in windows and workers alike.
    #[wasm_bindgen(js_name = setTimeout)]
    fn set_timeout(handler: &Function, millis: f64) -> JsValue;
}

/// The pause before the first reopen, doubled after each WebSocket that closes before the
/// server's first frame, up to the last.
const REOPEN_FIRST_MS: f64 = 500.0;
const REOPEN_LAST_MS: f64 = 30_000.0;

thread_local! {
    static SOCKETS: RefCell<HashMap<u32, Socket>> = RefCell::new(HashMap::new());
    static NEXT_ID: RefCell<u32> = const { RefCell::new(0) };
}

struct Socket {
    ws: WebSocket,
    /// Frames sent before the WebSocket opened, in order; `None` once it is open.
    pending: Option<Vec<Vec<u8>>>,
    /// The pause before reopening this connection if this WebSocket closes.
    reopen_ms: f64,
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
/// it carries. Streams wait for the server's first frame, and fail if the WebSocket closes;
/// a new WebSocket then opens, and streams connect again once it has.
pub fn connect(url: &str) -> Result<WispBackend, JsValue> {
    let id = NEXT_ID.with_borrow_mut(|next| {
        *next += 1;
        *next
    });
    let backend = WispBackend::new(std::sync::Arc::new(WebSocketSink(id)));
    open(id, url.to_owned(), backend.clone(), REOPEN_FIRST_MS)?;
    Ok(backend)
}

fn open(id: u32, url: String, backend: WispBackend, reopen_ms: f64) -> Result<(), JsValue> {
    let ws = WebSocket::new(&url)?;
    ws.set_binary_type(BinaryType::Arraybuffer);

    let on_open = Closure::<dyn FnMut(Event)>::new(move |_| flush(id));
    let receiver = backend.clone();
    let on_message = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
        let Some(data) = event
            .dyn_ref::<MessageEvent>()
            .and_then(|m| m.data().dyn_into::<ArrayBuffer>().ok())
        else {
            return;
        };
        // The server answered, so a later close starts the pauses over.
        SOCKETS.with_borrow_mut(|sockets| {
            if let Some(socket) = sockets.get_mut(&id) {
                socket.reopen_ms = REOPEN_FIRST_MS;
            }
        });
        // A server that breaks the protocol cannot be followed any further.
        if receiver.receive(&Uint8Array::new(&data).to_vec()).is_err() {
            close(id);
        }
    });
    let closed = backend.clone();
    let on_close = Closure::<dyn FnMut(Event)>::new(move |_| {
        closed.disconnected();
        reopen_later(id, url.clone(), closed.clone());
    });
    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

    // Replaces the closed WebSocket, whose handlers have run.
    SOCKETS.with_borrow_mut(|sockets| {
        sockets.insert(
            id,
            Socket {
                ws,
                pending: Some(Vec::new()),
                reopen_ms,
                _handlers: [on_open, on_message, on_close],
            },
        )
    });
    Ok(())
}

fn reopen_later(id: u32, url: String, backend: WispBackend) {
    let pause = SOCKETS.with_borrow(|sockets| sockets.get(&id).map(|s| s.reopen_ms));
    let Some(pause) = pause else {
        return;
    };
    let next = (pause * 2.0).min(REOPEN_LAST_MS);
    let reopen = Closure::once_into_js(move || {
        if open(id, url.clone(), backend.clone(), next).is_err() {
            // The URL was fine the first time; a browser refusing it now is out of sockets.
            reopen_later(id, url, backend);
        }
    });
    set_timeout(reopen.unchecked_ref(), pause);
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
