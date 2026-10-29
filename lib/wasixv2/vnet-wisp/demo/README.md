# WASIX v2 in the browser, over WISP

A WASIX v2 machine boots in a web page, and a guest running in it fetches a file over HTTP.
The guest's traffic goes through the kernel's network stack, then the WISP backend, then one
WebSocket to a local WISP proxy (wisp-js), which opens the real TCP connection. The guest is
hand-written WebAssembly text (`src/http_get.wat`), so the demo needs no WASIX toolchain.

```
guest (http_get.wat)
  └─ socket / connect / write / read syscalls
     └─ wasixv2 kernel: eth0 10.0.2.15, gateway 10.0.2.2 = the proxy's loopback
        └─ wasixv2-vnet-wisp: WISP frames
           └─ WebSocket ──> server.mjs: WISP proxy + static files on 127.0.0.1:5001
                              └─ GET /hello.txt
```

## Run it

You need the Rust toolchain from `rust-toolchain.toml` with the `wasm32-unknown-unknown` target,
`wasm-bindgen-cli` 0.2.129, Node.js 20 or later, and a browser with JSPI (Chrome or Edge 137+).

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked
npm install
npm run build      # the wasm module and its bindings, into www/pkg
npm start          # then open http://localhost:5001/ and press "Run guest"
```

`npm test` runs the same page in headless Chromium (`npx playwright install chromium` once)
and checks that the guest printed the file and exited with status 0.

## What is where

| Piece | Where |
| --- | --- |
| The machine, booted with the WISP backend | `src/lib.rs` |
| The guest | `src/http_get.wat` |
| The WISP backend and its browser WebSocket | `../src`, `../src/web.rs` (feature `web`) |
| The page | `www/index.html` |
| The WISP proxy and file server | `server.mjs` |
| The headless check | `check.mjs` |

The proxy may connect to its own loopback here (`allow_loopback_ips`), which a public WISP
proxy must not allow.
