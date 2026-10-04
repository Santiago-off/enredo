/* Enredo — códec del formato .enredo (navegador)
   Compartido por la app local y el foro. Dos modos:
   - Censurado (C): base64(gzip(JSON sin datos privados)) — lo puede abrir cualquiera.
   - Privado (P):  base64(salt+iv+AES-GCM(gzip(JSON completo))) — cifrado con tu contraseña.
   Renombrar no protege: lo que protege es el cifrado (P) y quitar datos (C). */
(function (global) {
  "use strict";
  const MAGIC = "ENREDO1";
  const te = new TextEncoder(), td = new TextDecoder();

  async function gzip(str) {
    const cs = new CompressionStream("gzip");
    const ab = await new Response(new Blob([te.encode(str)]).stream().pipeThrough(cs)).arrayBuffer();
    return new Uint8Array(ab);
  }
  async function gunzip(bytes) {
    const ds = new DecompressionStream("gzip");
    const ab = await new Response(new Blob([bytes]).stream().pipeThrough(ds)).arrayBuffer();
    return td.decode(ab);
  }
  function toB64(bytes) {
    let s = ""; const CH = 0x8000;
    for (let i = 0; i < bytes.length; i += CH) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    return btoa(s);
  }
  function fromB64(str) {
    const bin = atob(str); const u = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }

  // Quita todo lo identificable, deja lo comparable.
  function censor(data) {
    return {
      v: data.v || 1, app: "Enredo", mode: "censored",
      scannedDate: (data.scannedAt || "").slice(0, 10),
      deviceCount: (data.devices || []).length,
      subnetSize: data.network ? data.network.hostsScanned : undefined,
      devices: (data.devices || []).map((d, i) => ({
        n: i + 1,
        vendor: d.vendor || "Desconocido",
        type: d.type || "Desconocido",
        ports: Array.isArray(d.ports) ? d.ports.slice() : [],
      })),
      stats: data.stats || buildStats(data.devices || []),
    };
  }

  function buildStats(devices) {
    const vendor = {}, ports = {}, type = {};
    for (const d of devices) {
      vendor[d.vendor || "Desconocido"] = (vendor[d.vendor || "Desconocido"] || 0) + 1;
      type[d.type || "Desconocido"] = (type[d.type || "Desconocido"] || 0) + 1;
      for (const p of d.ports || []) ports[p] = (ports[p] || 0) + 1;
    }
    return { vendor, ports, type };
  }

  const PBKDF2_ITERS = 600000;        // OWASP 2023 para PBKDF2-HMAC-SHA256 (antes 150000)
  const PBKDF2_ITERS_LEGACY = 150000; // archivos privados antiguos (cabecera "ENREDO1P.")
  async function deriveKey(pass, salt, iterations) {
    const base = await crypto.subtle.importKey("raw", te.encode(pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: iterations || PBKDF2_ITERS, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }

  async function encodeCensored(data) {
    const gz = await gzip(JSON.stringify(censor(data)));
    return MAGIC + "C." + toB64(gz);
  }

  async function encodePrivate(data, pass) {
    if (!pass) throw new Error("Falta la contraseña");
    const gz = await gzip(JSON.stringify(data));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(pass, salt, PBKDF2_ITERS);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, gz));
    const out = new Uint8Array(16 + 12 + ct.length);
    out.set(salt, 0); out.set(iv, 16); out.set(ct, 28);
    return MAGIC + "P2." + toB64(out);   // P2 = PBKDF2 600k; "P." (sin 2) = formato antiguo 150k
  }

  function peek(str) {
    str = (str || "").trim();
    if (!str.startsWith(MAGIC)) return null;
    return str[MAGIC.length] === "P" ? "private" : str[MAGIC.length] === "C" ? "censored" : null;
  }

  async function decode(str, pass) {
    str = (str || "").trim();
    if (!str.startsWith(MAGIC)) throw new Error("No es un archivo .enredo válido");
    const m = str[MAGIC.length];
    if (m === "C") return JSON.parse(await gunzip(fromB64(str.slice(MAGIC.length + 2))));
    if (m === "P") {
      if (!pass) { const e = new Error("Este archivo está cifrado"); e.code = "NEED_PASS"; throw e; }
      // Versionado del cifrado: "ENREDO1P2." = PBKDF2 600k (nuevo); "ENREDO1P." = 150k (antiguo).
      const v2 = str[MAGIC.length + 1] === "2";
      const iterations = v2 ? PBKDF2_ITERS : PBKDF2_ITERS_LEGACY;
      const bytes = fromB64(str.slice(MAGIC.length + (v2 ? 3 : 2)));
      const salt = bytes.slice(0, 16), iv = bytes.slice(16, 28), ct = bytes.slice(28);
      let pt;
      try { pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, await deriveKey(pass, salt, iterations), ct); }
      catch { const e = new Error("Contraseña incorrecta"); e.code = "BAD_PASS"; throw e; }
      return JSON.parse(await gunzip(new Uint8Array(pt)));
    }
    throw new Error("Formato .enredo desconocido");
  }

  const api = { MAGIC, censor, buildStats, encodeCensored, encodePrivate, decode, peek };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.Enredo = api;
})(typeof self !== "undefined" ? self : this);
