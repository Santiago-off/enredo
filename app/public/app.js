/* Enredo — lógica de la app local */
(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  let current = null; // último escaneo/importación mostrado

  /* ---- utilidades ---- */
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  function toast(msg, kind = "ok") {
    const t = document.createElement("div"); t.className = "toast toast--" + kind; t.textContent = msg;
    $("#toasts").appendChild(t); setTimeout(() => t.remove(), 3000);
  }
  function download(name, text) {
    const b = new Blob([text], { type: "application/octet-stream" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = name;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  function fname(data) {
    const d = new Date(data.scannedAt || Date.now());
    const host = (data.network && data.network.interface) ? "mi-red" : "red";
    const pad = (n) => String(n).padStart(2, "0");
    return `${host}_${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}.enredo`;
  }
  function modalAsk(title, text, password = true) {
    return new Promise((resolve) => {
      $("#modalTitle").textContent = title; $("#modalText").textContent = text || "";
      const inp = $("#modalIn"); inp.type = password ? "password" : "text"; inp.value = "";
      $("#modal").hidden = false; setTimeout(() => inp.focus(), 30);
      const done = (v) => { $("#modal").hidden = true; cleanup(); resolve(v); };
      const ok = () => done(inp.value); const cancel = () => done(null);
      const key = (e) => { if (e.key === "Enter") ok(); if (e.key === "Escape") cancel(); };
      function cleanup() { $("#modalOk").onclick = null; $("#modalCancel").onclick = null; document.removeEventListener("keydown", key); }
      $("#modalOk").onclick = ok; $("#modalCancel").onclick = cancel; document.addEventListener("keydown", key);
    });
  }

  /* ---- red detectada ---- */
  async function loadNetwork() {
    try {
      const n = await fetch("/api/network").then((r) => r.json());
      if (!n || n.error) throw new Error(n && n.error);
      $("#netSummary").innerHTML = `Subred <b class="ip">${esc(n.base)}.0/24</b> · puerta de enlace <b class="ip">${esc(n.gateway || "?")}</b> · interfaz ${esc(n.interface)}`;
      $("#scanBtn").disabled = false;
    } catch { $("#netSummary").textContent = "No se detectó red activa. ¿Estás conectado?"; }
  }

  /* ---- escaneo ---- */
  function scan() {
    $("#scanBtn").disabled = true; $("#results").hidden = true;
    $("#progress").hidden = false; $("#progressFill").style.width = "0%"; $("#progressTxt").textContent = "Descubriendo equipos…";
    const es = new EventSource("/api/scan?includeSelf=" + ($("#inclSelf").checked ? "true" : "false"));
    es.addEventListener("progress", (e) => {
      const p = JSON.parse(e.data); const pct = p.total ? Math.round(p.done / p.total * 100) : 0;
      $("#progressFill").style.width = pct + "%";
      $("#progressTxt").textContent = p.phase === "descubriendo" ? `Buscando equipos… ${p.done}/${p.total}` : p.phase === "analizando" ? `Analizando equipos… ${p.done}/${p.total}` : "Casi…";
    });
    es.addEventListener("result", (e) => { es.close(); current = JSON.parse(e.data); $("#progress").hidden = true; $("#scanBtn").disabled = false; renderResults(current, false); toast(`${current.devices.length} equipos encontrados`); });
    es.addEventListener("error", (e) => { es.close(); $("#progress").hidden = true; $("#scanBtn").disabled = false; let m = "Error en el escaneo"; try { m = JSON.parse(e.data).error; } catch {} toast(m, "err"); });
  }

  /* ---- render resultados ---- */
  function renderResults(data, imported) {
    $("#results").hidden = false;
    const devs = data.devices || [];
    const stats = data.stats || (window.Enredo.buildStats(devs));
    const topVendor = Object.entries(stats.vendor || {}).sort((a, b) => b[1] - a[1])[0];
    const openPorts = Object.keys(stats.ports || {}).length;
    $("#statsRow").innerHTML =
      `<div class="stat"><b>${devs.length}</b><small>equipos</small></div>` +
      `<div class="stat"><b>${Object.keys(stats.vendor || {}).length}</b><small>fabricantes</small></div>` +
      `<div class="stat"><b>${openPorts}</b><small>puertos vistos</small></div>` +
      (topVendor ? `<div class="stat"><b style="font-size:15px">${esc(topVendor[0])}</b><small>más común</small></div>` : "");

    const censored = data.mode === "censored" || imported && !devs.some((d) => d.ip);
    $("#devBody").innerHTML = devs.map((d) => {
      if (!d.ip) { // censurado: no hay IP/MAC/host
        return `<tr><td class="ip">#${d.n}</td><td class="host">—</td><td>${esc(d.vendor)}</td><td>${esc(d.type)}</td><td class="mac">oculto</td><td>${renderPorts(d.ports)}</td></tr>`;
      }
      const tags = (d.isSelf ? '<span class="pill pill--self">este equipo</span>' : "") + (d.isGateway ? '<span class="pill pill--gw">router</span>' : "");
      return `<tr><td class="ip">${esc(d.ip)}</td><td class="host">${esc(d.hostname || "—")} ${tags}</td><td>${esc(d.vendor)}</td><td>${esc(d.type)}</td><td class="mac">${esc(d.mac || "—")}</td><td>${renderPorts(d.ports, d.portNames)}</td></tr>`;
    }).join("");

    const badge = $("#modeBadge"); badge.hidden = false;
    badge.innerHTML = censored
      ? "📄 Archivo <b>compartido/censurado</b>: sin IPs, MACs ni nombres. Ideal para el foro."
      : imported ? "📂 Archivo <b>privado importado</b>." : "✅ Escaneo de tu red. Exporta <b>censurado</b> para compartir o <b>cifrado</b> para guardar.";
  }
  function renderPorts(ports, names) {
    if (!ports || !ports.length) return '<span class="mac">ninguno</span>';
    return ports.map((p, i) => `<span class="port">${p}${names && names[i] ? " " + esc(names[i]) : ""}</span>`).join("");
  }

  /* ---- exportar ---- */
  async function exportCensored() {
    if (!current) return;
    try { const txt = await window.Enredo.encodeCensored(current); download(fname(current), txt); toast("Exportado (censurado, listo para compartir)"); }
    catch (e) { toast("No se pudo exportar: " + e.message, "err"); }
  }
  async function exportPrivate() {
    if (!current) return;
    const pass = await modalAsk("Exportar cifrado", "Elige una contraseña. La necesitarás para volver a abrir el archivo. Si la pierdes, no hay recuperación.");
    if (!pass) return;
    if (pass.length < 4) return toast("Contraseña demasiado corta", "err");
    try { const txt = await window.Enredo.encodePrivate(current, pass); download(fname(current), txt); toast("Exportado y cifrado 🔒"); }
    catch (e) { toast("No se pudo cifrar: " + e.message, "err"); }
  }

  /* ---- importar ---- */
  async function importFile(file, intoCompare) {
    const text = await file.text();
    const mode = window.Enredo.peek(text);
    if (!mode) return toast("No es un archivo .enredo válido", "err");
    let pass = null;
    if (mode === "private") { pass = await modalAsk("Archivo cifrado", `“${file.name}” está cifrado. Introduce su contraseña.`); if (pass === null) return; }
    try {
      const data = await window.Enredo.decode(text, pass);
      if (intoCompare) addCompareCard(file.name, data);
      else { current = data; switchView("scan"); renderResults(data, true); toast("Importado: " + file.name); }
    } catch (e) { toast(e.code === "BAD_PASS" ? "Contraseña incorrecta" : ("No se pudo abrir: " + e.message), "err"); }
  }

  /* ---- comparar ---- */
  function addCompareCard(name, data) {
    const stats = data.stats || window.Enredo.buildStats(data.devices || []);
    const dc = (data.devices || []).length || data.deviceCount || 0;
    const top = (obj, n = 4) => Object.entries(obj || {}).sort((a, b) => b[1] - a[1]).slice(0, n);
    const card = document.createElement("div"); card.className = "cmpcard";
    card.innerHTML = `<h3>${esc(name)}</h3><p class="meta">${esc((data.scannedDate || data.scannedAt || "").slice(0, 10))} · ${data.mode === "censored" ? "censurado" : "privado"}</p>
      <div class="cmprow"><span>Equipos</span><b>${dc}</b></div>
      <div class="cmprow"><span>Fabricantes</span><b>${Object.keys(stats.vendor || {}).length}</b></div>
      <div class="cmprow"><span>Puertos distintos</span><b>${Object.keys(stats.ports || {}).length}</b></div>
      <div class="cmpdist"><b style="font-size:12px;color:var(--ink-mute)">TOP FABRICANTES</b>${top(stats.vendor).map(([k, v]) => `<div><span>${esc(k)}</span><span>${v}</span></div>`).join("") || "<div>—</div>"}</div>
      <div class="cmpdist"><b style="font-size:12px;color:var(--ink-mute)">TOP PUERTOS</b>${top(stats.ports).map(([k, v]) => `<div><span>puerto ${esc(k)}</span><span>${v}</span></div>`).join("") || "<div>—</div>"}</div>`;
    $("#cmpGrid").appendChild(card);
  }

  /* ---- vistas ---- */
  function switchView(v) {
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("is-active", t.dataset.view === v));
    $("#view-scan").hidden = v !== "scan"; $("#view-compare").hidden = v !== "compare";
  }

  /* ---- eventos ---- */
  $("#scanBtn").addEventListener("click", scan);
  $("#expCensor").addEventListener("click", exportCensored);
  $("#expPrivate").addEventListener("click", exportPrivate);
  $("#importBtn").addEventListener("click", () => $("#fileInput").click());
  $("#fileInput").addEventListener("change", (e) => { if (e.target.files[0]) importFile(e.target.files[0], false); e.target.value = ""; });
  $("#addCompare").addEventListener("click", () => $("#fileInputCmp").click());
  $("#fileInputCmp").addEventListener("change", (e) => { for (const f of e.target.files) importFile(f, true); e.target.value = ""; });
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => switchView(t.dataset.view)));
  $("#modal").addEventListener("click", (e) => { if (e.target === $("#modal")) { $("#modalCancel").click(); } });

  loadNetwork();
})();
