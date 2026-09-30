/* Enredo — foro (cliente) */
(() => {
  "use strict";
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const api = (p, o) => fetch("/api/" + p, o).then(async (r) => { const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.error || "Error " + r.status); return d; });
  function toast(m, k = "ok") { const t = document.createElement("div"); t.className = "toast toast--" + k; t.textContent = m; $("#toasts").appendChild(t); setTimeout(() => t.remove(), 3200); }
  function ago(ts) {
    const s = Math.floor((Date.now() - ts) / 1000);
    if (s < 60) return "hace un momento"; if (s < 3600) return "hace " + Math.floor(s / 60) + " min";
    if (s < 86400) return "hace " + Math.floor(s / 3600) + " h"; return new Date(ts).toLocaleDateString("es-ES", { day: "2-digit", month: "short" });
  }

  let pendingFile = null, tsToken = "", tsWidget = null, lastTs = 0, feedTimer = null, threadId = null, threadTimer = null, lastComment = 0;

  /* ---- Turnstile (opcional) ---- */
  async function initTurnstile() {
    try {
      const cfg = await api("config");
      if (!cfg.turnstileSitekey) return;
      $("#tsWrap").hidden = false;
      const render = () => { tsWidget = window.turnstile.render("#tsWrap", { sitekey: cfg.turnstileSitekey, callback: (t) => { tsToken = t; }, "expired-callback": () => { tsToken = ""; } }); };
      let tries = 0; const wait = () => { if (window.turnstile && window.turnstile.render) render(); else if (tries++ < 40) setTimeout(wait, 150); }; wait();
    } catch {}
  }
  function resetTurnstile() { tsToken = ""; try { if (tsWidget !== null && window.turnstile) window.turnstile.reset(tsWidget); } catch {} }

  /* ---- Subir ---- */
  async function handleFile(file) {
    $("#upMsg").textContent = "";
    const text = await file.text();
    const mode = window.Enredo.peek(text);
    if (mode !== "censored") {
      pendingFile = null; $("#publishBtn").disabled = true; $("#fileName").hidden = true;
      $("#upMsg").className = "err";
      $("#upMsg").textContent = mode === "private"
        ? "Ese archivo es privado/cifrado. Exporta tu red en modo «compartir» desde Enredo."
        : "No es un archivo .enredo válido.";
      return;
    }
    try { await window.Enredo.decode(text); } catch { $("#upMsg").className = "err"; $("#upMsg").textContent = "El archivo está dañado."; return; }
    pendingFile = text; $("#fileName").hidden = false; $("#fileName").textContent = "✓ " + file.name;
    $("#upMsg").className = "ok"; $("#upMsg").textContent = "Listo para publicar (sin datos privados).";
    $("#publishBtn").disabled = false;
  }
  async function publish() {
    if (!pendingFile) return;
    $("#publishBtn").disabled = true;
    try {
      await api("posts", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ title: $("#title").value, file: pendingFile, token: tsToken }) });
      toast("¡Red publicada!"); pendingFile = null; $("#title").value = ""; $("#fileName").hidden = true; $("#upMsg").textContent = ""; resetTurnstile();
      loadFeed(true);
    } catch (e) { toast(e.message, "err"); $("#publishBtn").disabled = false; }
  }

  /* ---- Feed (tiempo real por sondeo) ---- */
  function postCard(p) {
    const s = p.summary || {};
    const vendors = (s.vendors || []).slice(0, 3).map((x) => `<span class="chip"><b>${x.v}</b> ${esc(x.k)}</span>`).join("");
    const ports = (s.ports || []).slice(0, 3).map((x) => `<span class="chip">puerto <b>${esc(x.k)}</b></span>`).join("");
    return `<div class="post" data-id="${p.id}">
      <div class="post__top"><span class="post__title">${esc(p.title)}</span><span class="post__time">${ago(p.created)}</span></div>
      <div class="post__stats"><span class="chip"><b>${p.deviceCount}</b> equipos</span>${vendors}${ports}</div>
      <div class="post__foot"><span>💬 ${p.comments} comentarios</span><span>Ver y comparar →</span></div>
    </div>`;
  }
  async function loadFeed(reset) {
    try {
      if (reset) { lastTs = 0; $("#feed").innerHTML = ""; }
      const { posts } = await api("posts?after=" + lastTs);
      if (posts.length) {
        for (const p of posts) if (p.created > lastTs) lastTs = p.created;
        const html = posts.map(postCard).join("");
        $("#feed").insertAdjacentHTML("afterbegin", html);
      }
      $("#empty").hidden = $("#feed").children.length > 0;
    } catch {}
  }

  /* ---- Hilo ---- */
  async function openThread(id) {
    threadId = id; clearInterval(feedTimer);
    $("#feed").hidden = true; $("#empty").hidden = true; $("#uploader").hidden = true;
    const t = $("#thread"); t.hidden = false; t.innerHTML = "<p class='empty'>Cargando…</p>";
    try {
      const p = await api("post?id=" + encodeURIComponent(id));
      const data = await window.Enredo.decode(p.data);
      const devs = (data.devices || []).map((d) => `<div class="dev"><b>${esc(d.vendor)}</b><small>${esc(d.type)}</small>${(d.ports || []).length ? `<small>puertos: ${d.ports.join(", ")}</small>` : ""}</div>`).join("");
      t.innerHTML = `<span class="back" id="back">← Volver al foro</span>
        <h2>${esc(p.title)}</h2>
        <p style="color:var(--ink-mute);font-size:13px">${p.deviceCount} equipos · ${ago(p.created)} · <span class="back" id="report" style="color:var(--bad)">reportar</span></p>
        <div class="devs">${devs || "<p>Sin equipos.</p>"}</div>
        <div class="comments"><h3 style="font-size:15px;margin:0 0 10px">Comentarios</h3><div id="clist"></div>
        <div class="cbox"><textarea id="cbody" placeholder="Comenta o compara con tu red…" maxlength="1000"></textarea><button class="btn btn--primary" id="csend" type="button">Enviar</button></div></div>`;
      lastComment = 0; renderComments(p.comments); lastComment = (p.comments[p.comments.length - 1] || {}).created || 0;
      $("#back").onclick = closeThread;
      $("#report").onclick = () => report(id);
      $("#csend").onclick = () => sendComment(id);
      threadTimer = setInterval(() => pollComments(id), 3000);
    } catch (e) { t.innerHTML = `<span class="back" id="back">← Volver</span><p class='empty'>${esc(e.message)}</p>`; $("#back").onclick = closeThread; }
  }
  function renderComments(list) {
    const html = list.map((c) => `<div class="comment"><div class="meta">anónimo · ${ago(c.created)}</div>${esc(c.body)}</div>`).join("");
    $("#clist").insertAdjacentHTML("beforeend", html);
  }
  async function pollComments(id) {
    try { const { comments } = await api("comments?id=" + encodeURIComponent(id) + "&after=" + lastComment); if (comments.length) { renderComments(comments); lastComment = comments[comments.length - 1].created; } } catch {}
  }
  async function sendComment(id) {
    const body = $("#cbody").value.trim(); if (!body) return;
    $("#csend").disabled = true;
    try { await api("comment", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ postId: id, body, token: tsToken }) }); $("#cbody").value = ""; resetTurnstile(); pollComments(id); }
    catch (e) { toast(e.message, "err"); } finally { $("#csend").disabled = false; }
  }
  async function report(id) {
    if (!confirm("¿Reportar esta publicación como inapropiada?")) return;
    try { await api("report", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ postId: id }) }); toast("Gracias, reportado."); } catch (e) { toast(e.message, "err"); }
  }
  function closeThread() {
    clearInterval(threadTimer); threadId = null;
    $("#thread").hidden = true; $("#feed").hidden = false; $("#uploader").hidden = false;
    loadFeed(true); feedTimer = setInterval(() => loadFeed(false), 4000);
  }

  /* ---- eventos ---- */
  $("#drop").addEventListener("click", () => $("#fileInput").click());
  $("#fileInput").addEventListener("change", (e) => { if (e.target.files[0]) handleFile(e.target.files[0]); });
  ["dragover", "dragenter"].forEach((ev) => $("#drop").addEventListener(ev, (e) => { e.preventDefault(); $("#drop").classList.add("hover"); }));
  ["dragleave", "drop"].forEach((ev) => $("#drop").addEventListener(ev, (e) => { e.preventDefault(); $("#drop").classList.remove("hover"); }));
  $("#drop").addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) handleFile(f); });
  $("#publishBtn").addEventListener("click", publish);
  $("#feed").addEventListener("click", (e) => { const c = e.target.closest(".post"); if (c) openThread(c.dataset.id); });

  /* ---- init ---- */
  initTurnstile();
  loadFeed(true);
  feedTimer = setInterval(() => loadFeed(false), 4000);
})();
