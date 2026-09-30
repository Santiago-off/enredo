/* Descarga la base OUI de Wireshark y genera oui-full.json (prefijo -> fabricante).
   Uso:  npm run oui:update     (requiere Node 18+ con fetch global) */
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const URL = "https://www.wireshark.org/download/automated/data/manuf.gz";

(async () => {
  console.log("Descargando base de fabricantes de Wireshark…");
  const res = await fetch(URL);
  if (!res.ok) throw new Error("No se pudo descargar: HTTP " + res.status);
  const gz = Buffer.from(await res.arrayBuffer());
  const text = zlib.gunzipSync(gz).toString("utf8");

  const out = {};
  for (const line of text.split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const parts = line.split("\t").filter(Boolean);
    if (parts.length < 2) continue;
    const prefix = parts[0].trim();
    // Solo OUI de 3 bytes (XX:XX:XX); ignora rangos con máscara /28, /36…
    const m = prefix.match(/^([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})$/);
    if (!m) continue;
    const key = (m[1] + m[2] + m[3]).toUpperCase();
    out[key] = (parts[2] || parts[1]).trim(); // nombre largo si existe, si no el corto
  }
  const dest = path.join(__dirname, "..", "oui-full.json");
  fs.writeFileSync(dest, JSON.stringify(out));
  console.log(`Listo: ${Object.keys(out).length} fabricantes guardados en oui-full.json`);
})().catch((e) => { console.error("Error:", e.message); process.exit(1); });
