// Serves the demo page and a WISP server on one port. The WISP server may reach its own
// loopback, which is where the guest's gateway leads, so the page can fetch from it.
import { readFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "www");
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm" };

export function startServer(port = 5001) {
  logging.set_level(logging.WARN);
  wisp.options.allow_loopback_ips = true;
  const server = http.createServer(async (request, response) => {
    const name = new URL(request.url, "http://localhost").pathname;
    const file = path.join(ROOT, name === "/" ? "index.html" : name);
    if (!file.startsWith(ROOT + path.sep)) {
      response.writeHead(403).end();
      return;
    }
    try {
      const body = await readFile(file);
      const type = TYPES[path.extname(file)] ?? "text/plain";
      response.writeHead(200, { "content-type": type }).end(body);
    } catch {
      response.writeHead(404).end();
    }
  });
  server.on("upgrade", (request, socket, head) => wisp.routeRequest(request, socket, head));
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server));
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await startServer();
  console.log("open http://localhost:5001/ in Chrome or Edge (JSPI: version 137 or later)");
}
