/* Enredo — grafo de red en canvas (sin dependencias).
   Dibuja la topología como una "red neuronal": router al centro, equipos de la LAN
   alrededor, este PC destacado y los destinos de Internet (conexiones salientes/entrantes).
   Física: repulsión + muelles + gravedad al centro. Animación: paquetes que viajan por
   las conexiones activas. Interacción: arrastrar nodos, hover, clic (detalle), rueda = zoom. */
(function (global) {
  "use strict";

  const COLORS = {
    router: "#22D3EE", self: "#8B5CF6", pc: "#60A5FA", phone: "#34D399",
    printer: "#FBBF24", camera: "#F472B6", iot: "#A78BFA", server: "#86EFAC",
    web: "#93C5FD", wan: "#F59E0B", unknown: "#7688A3",
  };
  const LABELS = {
    router: "Router", self: "Este PC", pc: "PC", phone: "Móvil/Tablet", printer: "Impresora",
    camera: "Cámara", iot: "IoT/Domótica", server: "Servidor", web: "Web", wan: "Internet", unknown: "Otro",
  };

  function categoryOf(type) {
    const t = (type || "").toLowerCase();
    if (/router|puerta/.test(t)) return "router";
    if (/impresora/.test(t)) return "printer";
    if (/cámara|camara/.test(t)) return "camera";
    if (/iphone|ipad|móvil|movil|android/.test(t)) return "phone";
    if (/iot|mqtt|esp|domót|domot|hue|sonos|amazon|raspberry/.test(t)) return "iot";
    if (/servidor|linux/.test(t)) return "server";
    if (/pc|windows/.test(t)) return "pc";
    if (/web/.test(t)) return "web";
    return "unknown";
  }

  function buildModel(data) {
    const nodes = [], edges = [], byId = {};
    const add = (n) => { if (byId[n.id]) return byId[n.id]; n.deg = 0; nodes.push(n); byId[n.id] = n; return n; };
    const devices = (data && data.devices) || [];
    const net = (data && data.network) || {};
    const gatewayIp = net.gateway;
    const selfDev = devices.find((d) => d.isSelf);
    const selfIp = (selfDev && selfDev.ip) || net.ip;

    // Router (un dispositivo-gateway real, o sintético a partir de network.gateway)
    const gwDev = devices.find((d) => d.ip && d.ip === gatewayIp) || devices.find((d) => d.isGateway);
    let routerId = null;
    if (gwDev) routerId = "dev:" + gwDev.ip;
    else if (gatewayIp) { routerId = "net:gw"; add({ id: routerId, type: "router", label: gatewayIp, sub: "puerta de enlace", ip: gatewayIp, meta: { ip: gatewayIp, type: "Router / Puerta de enlace" } }); }

    for (const d of devices) {
      const id = "dev:" + d.ip;
      const type = d.isSelf ? "self" : (d.isGateway || d.ip === gatewayIp) ? "router" : categoryOf(d.type);
      add({ id, type, label: (d.hostname || d.ip || "").replace(/\s*\(este equipo\)/, ""), sub: d.ip, ip: d.ip, meta: d });
    }
    const selfId = selfIp ? "dev:" + selfIp : null;

    // Topología LAN: router ↔ cada equipo
    if (routerId) for (const d of devices) { const id = "dev:" + d.ip; if (id !== routerId) edges.push({ a: routerId, b: id, dir: "lan", count: 1 }); }

    // Conexiones activas de este PC (datos privados; solo en vivo/cifrado)
    const conns = (data && data.connections) || null;
    if (conns && selfId && byId[selfId]) {
      for (const r of conns.byRemote || []) {
        if (r.isLan) {
          const did = "dev:" + r.ip;
          if (byId[did] && did !== selfId) edges.push({ a: selfId, b: did, dir: r.dir || "out", count: r.count || 1, active: true });
        } else {
          const wid = "wan:" + r.ip;
          add({ id: wid, type: "wan", label: r.rdns || r.ip, sub: r.ip, ip: r.ip, meta: r });
          edges.push({ a: selfId, b: wid, dir: r.dir || "out", count: r.count || 1, active: true });
        }
      }
    }

    for (const e of edges) { if (byId[e.a]) byId[e.a].deg++; if (byId[e.b]) byId[e.b].deg++; }
    return { nodes, edges, byId, routerId, selfId };
  }

  function mount(container, data, opts = {}) {
    container.innerHTML = "";
    const canvas = document.createElement("canvas");
    canvas.style.cssText = "display:block;width:100%;height:100%;cursor:grab;touch-action:none";
    container.appendChild(canvas);
    const tip = document.createElement("div");
    tip.style.cssText = "position:absolute;pointer-events:none;z-index:5;background:rgba(10,14,20,.94);border:1px solid #3A4657;border-radius:9px;padding:8px 10px;font:500 12px/1.5 ui-monospace,Consolas,monospace;color:#E6EDF3;max-width:260px;display:none;box-shadow:0 10px 30px -10px #000";
    container.appendChild(tip);
    const ctx = canvas.getContext("2d");

    let model = buildModel(data);
    let W = 0, H = 0, dpr = Math.min(global.devicePixelRatio || 1, 2);
    let scale = 1, ox = 0, oy = 0;          // zoom/pan
    let raf = null, t0 = performance.now();
    let drag = null, hover = null, panning = null;

    function layout() {
      const cx = W / (2 * dpr), cy = H / (2 * dpr);
      model.nodes.forEach((n, i) => {
        const ang = (i / model.nodes.length) * Math.PI * 2;
        const rad = n.type === "router" ? 0 : n.type === "wan" ? 230 : 120;
        n.x = cx + Math.cos(ang) * rad + (Math.random() - 0.5) * 40;
        n.y = cy + Math.sin(ang) * rad + (Math.random() - 0.5) * 40;
        n.vx = 0; n.vy = 0;
      });
    }
    function resize() {
      const r = container.getBoundingClientRect();
      W = Math.max(320, r.width) * dpr; H = Math.max(260, r.height) * dpr;
      canvas.width = W; canvas.height = H;
      if (!model.nodes[0] || model.nodes[0].x === undefined) layout();
    }

    function radiusOf(n) {
      if (n.type === "router") return 15;
      if (n.type === "self") return 13;
      if (n.type === "wan") return 6 + Math.min(6, Math.log2((n.meta && n.meta.count) || 1) * 2);
      return 7 + Math.min(6, n.deg);
    }

    function step() {
      const cx = W / (2 * dpr), cy = H / (2 * dpr);
      const N = model.nodes;
      for (let i = 0; i < N.length; i++) {
        const a = N[i];
        for (let j = i + 1; j < N.length; j++) {
          const b = N[j];
          let dx = a.x - b.x, dy = a.y - b.y; let d2 = dx * dx + dy * dy || 0.01;
          if (d2 > 90000) continue;
          const f = 1400 / d2; const d = Math.sqrt(d2);
          const fx = (dx / d) * f, fy = (dy / d) * f;
          a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
        }
      }
      for (const e of model.edges) {
        const a = model.byId[e.a], b = model.byId[e.b]; if (!a || !b) continue;
        const rest = e.dir === "lan" ? 96 : 150;
        let dx = b.x - a.x, dy = b.y - a.y; const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const f = (d - rest) * 0.012;
        const fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
      }
      for (const n of N) {
        // gravedad al centro; el router fuerte (ancla), Internet empujado al anillo exterior
        const gx = (cx - n.x), gy = (cy - n.y);
        let g = 0.0016;
        if (n.type === "router") g = 0.04;
        n.vx += gx * g; n.vy += gy * g;
        if (n.type === "wan") { const dd = Math.sqrt(gx * gx + gy * gy) || 1; const pull = (dd < 210) ? -0.02 : 0; n.vx += (gx / dd) * pull * dd; n.vy += (gy / dd) * pull * dd; }
        if (n === drag) continue;
        n.vx *= 0.86; n.vy *= 0.86;
        n.x += n.vx; n.y += n.vy;
      }
    }

    function toScreen(x, y) { return [x * scale + ox, y * scale + oy]; }
    function toWorld(px, py) { return [(px - ox) / scale, (py - oy) / scale]; }

    function draw(now) {
      const time = (now - t0) / 1000;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      ctx.save();
      ctx.translate(ox, oy); ctx.scale(scale, scale);

      // aristas
      for (const e of model.edges) {
        const a = model.byId[e.a], b = model.byId[e.b]; if (!a || !b) continue;
        const hot = hover && (hover === a || hover === b);
        const active = !!e.active;
        const grad = ctx.createLinearGradient(a.x, a.y, b.x, b.y);
        grad.addColorStop(0, COLORS[a.type] || COLORS.unknown);
        grad.addColorStop(1, COLORS[b.type] || COLORS.unknown);
        ctx.strokeStyle = grad;
        ctx.globalAlpha = hot ? 0.95 : active ? 0.5 : 0.18;
        ctx.lineWidth = (active ? 1.1 + Math.min(3, Math.log2((e.count || 1) + 1) * 0.6) : 0.8) / 1;
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        ctx.globalAlpha = 1;

        if (active) { // paquetes viajando
          const packets = e.dir === "both" ? 2 : 1;
          for (let k = 0; k < packets; k++) {
            let p = (time * 0.5 + (e._ph || (e._ph = Math.random())) + k * 0.5) % 1;
            const rev = (e.dir === "in") || (e.dir === "both" && k === 1);
            if (rev) p = 1 - p;
            const px = a.x + (b.x - a.x) * p, py = a.y + (b.y - a.y) * p;
            ctx.fillStyle = e.dir === "in" ? COLORS.phone : "#E6EDF3";
            ctx.globalAlpha = hot ? 1 : 0.8;
            ctx.beginPath(); ctx.arc(px, py, hot ? 2.6 : 2, 0, 7); ctx.fill();
            ctx.globalAlpha = 1;
          }
        }
      }

      // nodos
      for (const n of model.nodes) {
        const r = radiusOf(n), col = COLORS[n.type] || COLORS.unknown;
        const hot = hover === n || drag === n;
        if (n.type === "self" || n.type === "router") { // halo pulsante
          const pulse = 1 + Math.sin(time * 2 + (n.type === "self" ? 0 : 1)) * 0.18;
          ctx.globalAlpha = 0.16; ctx.fillStyle = col;
          ctx.beginPath(); ctx.arc(n.x, n.y, r * 2.1 * pulse, 0, 7); ctx.fill(); ctx.globalAlpha = 1;
        }
        ctx.shadowColor = col; ctx.shadowBlur = hot ? 20 : 10;
        ctx.fillStyle = col;
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 7); ctx.fill();
        ctx.shadowBlur = 0;
        if (n.type === "self") { ctx.strokeStyle = "#fff"; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(n.x, n.y, r + 3, 0, 7); ctx.stroke(); }

        // etiqueta
        if (hot || scale > 0.75 || n.type === "router" || n.type === "self") {
          const label = n.label || n.ip || "";
          ctx.font = (n.type === "router" || n.type === "self" ? "700 " : "500 ") + "11px ui-monospace,Consolas,monospace";
          ctx.textAlign = "center"; ctx.textBaseline = "top";
          const txt = label.length > 22 ? label.slice(0, 21) + "…" : label;
          ctx.fillStyle = "rgba(10,14,20,.7)";
          const w = ctx.measureText(txt).width + 8;
          ctx.fillRect(n.x - w / 2, n.y + r + 3, w, 15);
          ctx.fillStyle = hot ? "#fff" : "#A9B6C6";
          ctx.fillText(txt, n.x, n.y + r + 5);
        }
      }
      ctx.restore();
    }

    function frame(now) { step(); draw(now); raf = requestAnimationFrame(frame); }

    function nodeAt(px, py) {
      const [wx, wy] = toWorld(px, py);
      let best = null, bd = 1e9;
      for (const n of model.nodes) { const dx = n.x - wx, dy = n.y - wy; const d = dx * dx + dy * dy; const r = radiusOf(n) + 6; if (d < r * r && d < bd) { bd = d; best = n; } }
      return best;
    }
    function showTip(n, cx, cy) {
      const m = n.meta || {};
      const rows = [];
      rows.push(`<b style="color:${COLORS[n.type] || COLORS.unknown}">${escape(n.label || n.ip)}</b> · ${LABELS[n.type] || "nodo"}`);
      if (n.ip && n.ip !== n.label) rows.push(n.ip);
      if (m.mac) rows.push("MAC " + m.mac);
      if (m.vendor) rows.push(m.vendor);
      if (m.type && n.type !== "wan") rows.push(m.type);
      if (typeof m.rttMs === "number") rows.push("Latencia " + m.rttMs + " ms" + (m.osGuess ? " · " + m.osGuess : ""));
      if (m.ports && m.ports.length && n.type !== "wan") rows.push("Puertos: " + m.ports.join(", "));
      if (n.type === "wan") {
        if (m.dir) rows.push(m.dir === "in" ? "Conexión entrante" : m.dir === "both" ? "Entrante + saliente" : "Conexión saliente");
        if (m.count) rows.push(m.count + " conexión(es)");
        if (m.procs && m.procs.length) rows.push("App: " + m.procs.join(", "));
      }
      tip.innerHTML = rows.join("<br>");
      tip.style.display = "block";
      const r = container.getBoundingClientRect();
      let x = cx - r.left + 14, y = cy - r.top + 14;
      if (x + 270 > r.width) x = cx - r.left - 270;
      tip.style.left = x + "px"; tip.style.top = y + "px";
    }
    const escape = (s) => String(s == null ? "" : s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

    function onMove(ev) {
      const r = canvas.getBoundingClientRect();
      const px = ev.clientX - r.left, py = ev.clientY - r.top;
      if (drag) { const [wx, wy] = toWorld(px, py); drag.x = wx; drag.y = wy; drag.vx = drag.vy = 0; return; }
      if (panning) { ox = panning.ox + (ev.clientX - panning.x); oy = panning.oy + (ev.clientY - panning.y); return; }
      const n = nodeAt(px, py);
      hover = n; canvas.style.cursor = n ? "pointer" : "grab";
      if (n) showTip(n, ev.clientX, ev.clientY); else tip.style.display = "none";
    }
    function onDown(ev) {
      const r = canvas.getBoundingClientRect();
      const n = nodeAt(ev.clientX - r.left, ev.clientY - r.top);
      if (n) { drag = n; canvas.style.cursor = "grabbing"; }
      else { panning = { x: ev.clientX, y: ev.clientY, ox, oy }; canvas.style.cursor = "grabbing"; }
    }
    function onUp(ev) {
      if (drag && opts.onSelect) { const moved = false; opts.onSelect(drag.meta || null, drag); }
      drag = null; panning = null; canvas.style.cursor = hover ? "pointer" : "grab";
    }
    function onWheel(ev) {
      ev.preventDefault();
      const r = canvas.getBoundingClientRect(); const mx = ev.clientX - r.left, my = ev.clientY - r.top;
      const [wx, wy] = toWorld(mx, my);
      scale = Math.max(0.3, Math.min(3, scale * (ev.deltaY < 0 ? 1.12 : 0.9)));
      ox = mx - wx * scale; oy = my - wy * scale;
    }

    canvas.addEventListener("mousemove", onMove);
    canvas.addEventListener("mousedown", onDown);
    global.addEventListener("mouseup", onUp);
    canvas.addEventListener("mouseleave", () => { if (!drag && !panning) { hover = null; tip.style.display = "none"; } });
    canvas.addEventListener("wheel", onWheel, { passive: false });
    const ro = new ResizeObserver(resize); ro.observe(container);

    resize(); layout(); raf = requestAnimationFrame(frame);

    return {
      setData(d) { model = buildModel(d); layout(); },
      reset() { scale = 1; ox = oy = 0; layout(); },
      destroy() { cancelAnimationFrame(raf); ro.disconnect(); global.removeEventListener("mouseup", onUp); container.innerHTML = ""; },
      stats() { return { nodes: model.nodes.length, wan: model.nodes.filter((n) => n.type === "wan").length, active: model.edges.filter((e) => e.active).length }; },
      colors: COLORS, labels: LABELS,
    };
  }

  global.EnredoGraph = { mount, categoryOf, COLORS, LABELS };
})(typeof self !== "undefined" ? self : this);
