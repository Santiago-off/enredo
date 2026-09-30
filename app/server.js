/* Enredo — servidor local. Sirve la interfaz web y expone el escáner.
   Escucha SOLO en 127.0.0.1 (nada sale de tu equipo). */
const http = require("http");
const fs = require("fs");
const path = require("path");
const { fullScan, detectNetwork } = require("./scanner");

const PORT = process.env.PORT || 4599;
const HOST = "127.0.0.1";
const PUB = path.join(__dirname, "public");
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".json": "application/json", ".ico": "image/x-icon", ".png": "image/png" };

function serveStatic(req, res) {
  let p = decodeURIComponent(req.url.split("?")[0]);
  if (p === "/") p = "/index.html";
  const file = path.join(PUB, path.normalize(p).replace(/^(\.\.[/\\])+/, ""));
  if (!file.startsWith(PUB)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { "content-type": "text/plain" }); return res.end("404"); }
    res.writeHead(200, { "content-type": TYPES[path.extname(file)] || "application/octet-stream" });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = req.url.split("?")[0];

  if (url === "/api/network") {
    try { const n = await detectNetwork(); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(n)); }
    catch (e) { res.writeHead(500, { "content-type": "application/json" }); res.end(JSON.stringify({ error: e.message })); }
    return;
  }

  if (url === "/api/scan") {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
    const send = (ev, data) => res.write(`event: ${ev}\ndata: ${JSON.stringify(data)}\n\n`);
    const includeSelf = !/includeSelf=false/.test(req.url);
    fullScan({ includeSelf }, (p) => send("progress", p))
      .then((r) => { send("result", r); res.end(); })
      .catch((e) => { send("error", { error: e.message }); res.end(); });
    req.on("close", () => res.end());
    return;
  }

  serveStatic(req, res);
});

server.listen(PORT, HOST, () => {
  const url = `http://${HOST}:${PORT}`;
  console.log(`\n  Enredo  ·  analizador de red local`);
  console.log(`  Abre en tu navegador:  ${url}\n`);
  if (!process.env.ENREDO_NOOPEN) {
    const open = process.platform === "win32" ? `start "" ${url}` : process.platform === "darwin" ? `open ${url}` : `xdg-open ${url}`;
    try { require("child_process").exec(open); } catch {}
  }
});
