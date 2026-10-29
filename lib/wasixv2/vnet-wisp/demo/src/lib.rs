//! Boots a WASIX v2 machine in the page, gives it a network through a WISP server, and runs a
//! guest that fetches a file over HTTP through it.

use std::sync::{Arc, Mutex};

use wasixv2::{MachineBuilder, Stdio, WebHost};
use wasm_bindgen::prelude::*;

const GUEST: &str = include_str!("http_get.wat");

/// What the guest printed and how it exited.
#[wasm_bindgen(getter_with_clone)]
pub struct Outcome {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Runs the guest with its network behind the WISP server at `wisp_url`.
#[wasm_bindgen]
pub async fn run(wisp_url: String) -> Result<Outcome, JsError> {
    let wasm = wat::parse_str(GUEST)?;
    let backend = wasixv2_vnet_wisp::web::connect(&wisp_url)
        .map_err(|e| JsError::new(&format!("cannot open {wisp_url}: {e:?}")))?;
    let machine = MachineBuilder::new(Arc::new(WebHost::new()))
        .backend(Arc::new(backend))
        .build();
    let (stdout, stderr) = (Captured::default(), Captured::default());
    let stdio = Stdio::from_fns(stdout.sink(), stderr.sink());
    let status = machine.run(&wasm, stdio).await?;
    Ok(Outcome {
        status,
        stdout: stdout.text(),
        stderr: stderr.text(),
    })
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn sink(&self) -> impl Fn(&[u8]) + Send + Sync + 'static {
        let bytes = self.0.clone();
        move |data| bytes.lock().unwrap().extend_from_slice(data)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}
