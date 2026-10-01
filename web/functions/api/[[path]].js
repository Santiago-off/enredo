// Enredo — API del foro (Cloudflare Pages Functions + D1)
// Solo acepta archivos .enredo CENSURADOS (ENREDO1C). Rechaza privados/cifrados y
// cualquier archivo con datos privados. Anti-spam por IP hasheada (anónima) + Turnstile.
// Moderación protegida por Cloudflare Access (OTP) — JWT verificado aquí; MOD_KEY como respaldo.

const MAX_FILE = 300 * 1024;     // 300 KB
const MAX_TITLE = 120;
const MAX_COMMENT = 1000;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });

const uid = () => (crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2));

async function ipHash(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const salt = env.IP_SALT || "enredo-salt";
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ip + "|" + salt));
  return [...new Uint8Array(buf)].slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyTurnstile(token, ip, env) {
  if (!env.TURNSTILE_SECRET) return true; // no configurado => modo abierto (dev)
  if (!token) return false;
  const body = new FormData();
  body.append("secret", env.TURNSTILE_SECRET);
  body.append("response", token);
  if (ip) body.append("remoteip", ip);
  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
    return (await r.json()).success === true;
  } catch { return false; }
}

/* ---- Cloudflare Access: verificación del JWT (OTP) ---- */
let JWKS_CACHE = { keys: null, exp: 0 };
function b64urlToU8(s) {
  s = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s); const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
const b64urlToJson = (s) => JSON.parse(new TextDecoder().decode(b64urlToU8(s)));

async function getJwks(teamDomain) {
  const now = Date.now();
  if (JWKS_CACHE.keys && JWKS_CACHE.exp > now) return JWKS_CACHE.keys;
  const r = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
  const j = await r.json().catch(() => ({}));
  JWKS_CACHE = { keys: j.keys || [], exp: now + 3600_000 };
  return JWKS_CACHE.keys;
}

// Devuelve el email autenticado si el JWT de Access es válido; si no, null.
async function accessIdentity(request, env) {
  const teamDomain = env.ACCESS_TEAM_DOMAIN, aud = env.ACCESS_AUD;
  if (!teamDomain || !aud) return null;
  let token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) {
    const m = (request.headers.get("Cookie") || "").match(/CF_Authorization=([^;]+)/);
    if (m) token = m[1];
  }
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let header, payload;
  try { header = b64urlToJson(parts[0]); payload = b64urlToJson(parts[1]); } catch { return null; }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) return null;
  if (payload.iss && payload.iss !== `https://${teamDomain}`) return null;
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(aud)) return null;
  try {
    const keys = await getJwks(teamDomain);
    const jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64urlToU8(parts[2]), new TextEncoder().encode(parts[0] + "." + parts[1]));
    if (!ok) return null;
  } catch { return null; }
  return String(payload.email || "autenticado");
}

// Autorizado para moderar si: JWT de Access válido (y, si se fija ACCESS_EMAIL, coincide) O MOD_KEY correcta.
async function modAuth(request, env) {
  const email = await accessIdentity(request, env);
  if (email) {
    const allow = (env.ACCESS_EMAIL || "").toLowerCase();
    if (!allow || email.toLowerCase() === allow) return { via: "access", who: email };
  }
  if (env.MOD_KEY && request.headers.get("X-Mod-Key") === env.MOD_KEY) return { via: "key", who: "clave" };
  return null;
}

async function gunzipB64(b64) {
  const bin = atob(b64); const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const ab = await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"))).arrayBuffer();
  return new TextDecoder().decode(ab);
}

// Decodifica y EXIGE que sea censurado y sin datos privados.
async function parseCensored(text) {
  text = (text || "").trim();
  if (!text.startsWith("ENREDO1C")) throw new Error("Solo se permiten archivos .enredo en modo compartir (censurado). Los privados o cifrados no se aceptan.");
  let data;
  try { data = JSON.parse(await gunzipB64(text.slice(9))); }
  catch { throw new Error("El archivo .enredo está dañado o no es válido."); }
  if (data.self || data.network || data.connections) throw new Error("El archivo contiene datos privados. Exporta en modo 'compartir' desde Enredo.");
  if (!Array.isArray(data.devices)) throw new Error("Formato .enredo no reconocido.");
  if (data.devices.length > 4096) throw new Error("Demasiados equipos.");
  for (const d of data.devices) {
    if (d.ip || d.mac || d.hostname || d.portNames || d.rttMs || d.ttl) throw new Error("El archivo contiene datos privados (IP/MAC/nombre). Usa el modo 'compartir'.");
  }
  return data;
}

function summarize(data) {
  const vendor = {}, ports = {}, type = {};
  for (const d of data.devices) {
    const v = d.vendor || "Desconocido"; vendor[v] = (vendor[v] || 0) + 1;
    const t = d.type || "Desconocido"; type[t] = (type[t] || 0) + 1;
    for (const p of d.ports || []) ports[p] = (ports[p] || 0) + 1;
  }
  const top = (o, n) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({ k, v }));
  return { deviceCount: data.devices.length, vendors: top(vendor, 5), ports: top(ports, 5), types: top(type, 6) };
}

async function rateOk(env, iph, action, max, windowSec) {
  const since = Date.now() - windowSec * 1000;
  const row = await env.DB.prepare("SELECT COUNT(*) AS c FROM rate WHERE iph=? AND action=? AND ts>?").bind(iph, action, since).first();
  if (row && row.c >= max) return false;
  await env.DB.prepare("INSERT INTO rate (iph, action, ts) VALUES (?,?,?)").bind(iph, action, Date.now()).run();
  return true;
}

async function isBanned(env, iph) {
  const b = await env.DB.prepare("SELECT iph FROM bans WHERE iph=?").bind(iph).first();
  return !!b;
}

export async function onRequest(context) {
  const { request, env, params } = context;
  const route = Array.isArray(params.path) ? params.path.join("/") : params.path || "";
  const method = request.method;
  const url = new URL(request.url);
  if (!env.DB) return json({ error: "Base de datos no conectada." }, 500);

  try {
    if (route === "config" && method === "GET") {
      return json({ turnstileSitekey: env.TURNSTILE_SITEKEY || "" });
    }

    // Lista de posts (para el feed y el polling en tiempo real)
    if (route === "posts" && method === "GET") {
      const after = Number(url.searchParams.get("after") || 0);
      const rs = await env.DB.prepare(
        "SELECT id, created, title, device_count, summary, comments FROM posts WHERE hidden=0 AND created>? ORDER BY created DESC LIMIT 60"
      ).bind(after).all();
      const posts = (rs.results || []).map((p) => ({ id: p.id, created: p.created, title: p.title, deviceCount: p.device_count, comments: p.comments, summary: JSON.parse(p.summary || "{}") }));
      return json({ posts, now: Date.now() });
    }

    // Detalle de un post (+ comentarios)
    if (route === "post" && method === "GET") {
      const id = url.searchParams.get("id");
      const p = await env.DB.prepare("SELECT * FROM posts WHERE id=? AND hidden=0").bind(id).first();
      if (!p) return json({ error: "No encontrado" }, 404);
      const cs = await env.DB.prepare("SELECT id, created, body FROM comments WHERE post_id=? ORDER BY created ASC LIMIT 500").bind(id).all();
      return json({ id: p.id, created: p.created, title: p.title, data: p.data, deviceCount: p.device_count, summary: JSON.parse(p.summary || "{}"), comments: cs.results || [] });
    }

    // Comentarios nuevos (polling)
    if (route === "comments" && method === "GET") {
      const id = url.searchParams.get("id");
      const after = Number(url.searchParams.get("after") || 0);
      const cs = await env.DB.prepare("SELECT id, created, body FROM comments WHERE post_id=? AND created>? ORDER BY created ASC LIMIT 500").bind(id, after).all();
      return json({ comments: cs.results || [], now: Date.now() });
    }

    // Crear post (subir .enredo censurado)
    if (route === "posts" && method === "POST") {
      const b = await request.json().catch(() => ({}));
      const ip = request.headers.get("CF-Connecting-IP") || "";
      if (!(await verifyTurnstile(b.token, ip, env))) return json({ error: "Verificación anti-bot fallida. Recarga e inténtalo de nuevo." }, 403);
      const iph = await ipHash(request, env);
      if (await isBanned(env, iph)) return json({ error: "No tienes permiso para publicar." }, 403);
      if (!(await rateOk(env, iph, "post", 3, 600))) return json({ error: "Has publicado demasiado en poco tiempo. Espera un rato." }, 429);
      const file = String(b.file || "");
      if (file.length > MAX_FILE) return json({ error: "El archivo es demasiado grande." }, 413);
      let data;
      try { data = await parseCensored(file); } catch (e) { return json({ error: e.message }, 400); }
      const title = String(b.title || "").slice(0, MAX_TITLE).trim() || "Red sin título";
      const id = uid();
      await env.DB.prepare("INSERT INTO posts (id, created, title, data, device_count, summary, comments, reports, hidden, iph) VALUES (?,?,?,?,?,?,0,0,0,?)")
        .bind(id, Date.now(), title, file, data.devices.length, JSON.stringify(summarize(data)), iph).run();
      return json({ ok: true, id });
    }

    // Comentar
    if (route === "comment" && method === "POST") {
      const b = await request.json().catch(() => ({}));
      const ip = request.headers.get("CF-Connecting-IP") || "";
      if (!(await verifyTurnstile(b.token, ip, env))) return json({ error: "Verificación anti-bot fallida." }, 403);
      const iph = await ipHash(request, env);
      if (await isBanned(env, iph)) return json({ error: "No tienes permiso para comentar." }, 403);
      if (!(await rateOk(env, iph, "comment", 15, 600))) return json({ error: "Demasiados comentarios en poco tiempo." }, 429);
      const body = String(b.body || "").slice(0, MAX_COMMENT).trim();
      if (!body) return json({ error: "Escribe algo." }, 400);
      const post = await env.DB.prepare("SELECT id FROM posts WHERE id=? AND hidden=0").bind(b.postId).first();
      if (!post) return json({ error: "Publicación no encontrada." }, 404);
      await env.DB.prepare("INSERT INTO comments (id, post_id, created, body, iph) VALUES (?,?,?,?,?)").bind(uid(), b.postId, Date.now(), body, iph).run();
      await env.DB.prepare("UPDATE posts SET comments = comments + 1 WHERE id=?").bind(b.postId).run();
      return json({ ok: true });
    }

    // Reportar (1 por persona y post; auto-oculta con 4 reportes distintos)
    if (route === "report" && method === "POST") {
      const b = await request.json().catch(() => ({}));
      if (!b.postId) return json({ error: "Falta el id." }, 400);
      const iph = await ipHash(request, env);
      if (!(await rateOk(env, iph, "report", 15, 600))) return json({ error: "Demasiados reportes en poco tiempo." }, 429);
      const r = await env.DB.prepare("INSERT OR IGNORE INTO reports (post_id, iph, created) VALUES (?,?,?)").bind(b.postId, iph, Date.now()).run();
      if (r.meta && r.meta.changes) {
        await env.DB.prepare("UPDATE posts SET reports = reports + 1 WHERE id=?").bind(b.postId).run();
        await env.DB.prepare("UPDATE posts SET hidden = 1 WHERE id=? AND reports >= 4").bind(b.postId).run();
      }
      return json({ ok: true });
    }

    // ---- Moderación (Cloudflare Access/OTP, o MOD_KEY de respaldo) ----
    if (route === "mod" && method === "POST") {
      const auth = await modAuth(request, env);
      if (!auth) return json({ error: "No autorizado" }, 403);
      const b = await request.json().catch(() => ({}));
      const a = b.action;

      if (a === "list") {
        const n = async (sql, ...bind) => (await env.DB.prepare(sql).bind(...bind).first()).n;
        const dayAgo = Date.now() - 86400000;
        const counts = {
          posts: await n("SELECT COUNT(*) n FROM posts"),
          hidden: await n("SELECT COUNT(*) n FROM posts WHERE hidden=1"),
          reported: await n("SELECT COUNT(*) n FROM posts WHERE reports>0"),
          comments: await n("SELECT COUNT(*) n FROM comments"),
          bans: await n("SELECT COUNT(*) n FROM bans"),
          posts24h: await n("SELECT COUNT(*) n FROM posts WHERE created>?", dayAgo),
          comments24h: await n("SELECT COUNT(*) n FROM comments WHERE created>?", dayAgo),
        };
        const cols = "id, created, title, device_count, comments, reports, hidden, iph";
        const reported = (await env.DB.prepare(`SELECT ${cols} FROM posts WHERE reports>0 ORDER BY reports DESC, created DESC LIMIT 100`).all()).results || [];
        const posts = (await env.DB.prepare(`SELECT ${cols} FROM posts ORDER BY created DESC LIMIT 80`).all()).results || [];
        const comments = (await env.DB.prepare("SELECT c.id, c.post_id, c.created, c.body, c.iph, p.title AS post_title FROM comments c LEFT JOIN posts p ON p.id=c.post_id ORDER BY c.created DESC LIMIT 120").all()).results || [];
        const bans = (await env.DB.prepare("SELECT iph, created, reason FROM bans ORDER BY created DESC LIMIT 100").all()).results || [];
        return json({ viewer: auth.who, via: auth.via, counts, reported, posts, comments, bans });
      }

      if (a === "delPost") {
        await env.DB.prepare("DELETE FROM comments WHERE post_id=?").bind(b.id).run();
        await env.DB.prepare("DELETE FROM reports WHERE post_id=?").bind(b.id).run();
        await env.DB.prepare("DELETE FROM posts WHERE id=?").bind(b.id).run();
        return json({ ok: true });
      }
      if (a === "hide") { await env.DB.prepare("UPDATE posts SET hidden=? WHERE id=?").bind(b.hidden ? 1 : 0, b.id).run(); return json({ ok: true }); }

      // Aprobar: descarta reportes y vuelve a mostrar (para falsos positivos / auto-ocultados)
      if (a === "approve") {
        await env.DB.prepare("DELETE FROM reports WHERE post_id=?").bind(b.id).run();
        await env.DB.prepare("UPDATE posts SET hidden=0, reports=0 WHERE id=?").bind(b.id).run();
        return json({ ok: true });
      }
      // Ocultar en lote todo lo que supere N reportes
      if (a === "hideReported") {
        const min = Math.max(1, Number(b.min || 4));
        const r = await env.DB.prepare("UPDATE posts SET hidden=1 WHERE reports>=? AND hidden=0").bind(min).run();
        return json({ ok: true, changed: (r.meta && r.meta.changes) || 0 });
      }

      if (a === "delComment") {
        const c = await env.DB.prepare("SELECT post_id FROM comments WHERE id=?").bind(b.id).first();
        await env.DB.prepare("DELETE FROM comments WHERE id=?").bind(b.id).run();
        if (c) await env.DB.prepare("UPDATE posts SET comments = MAX(0, comments-1) WHERE id=?").bind(c.post_id).run();
        return json({ ok: true });
      }
      if (a === "ban" || a === "purgeIp") {
        let iph = b.iph;
        if (!iph && b.postId) { const p = await env.DB.prepare("SELECT iph FROM posts WHERE id=?").bind(b.postId).first(); iph = p && p.iph; }
        if (!iph && b.commentId) { const c = await env.DB.prepare("SELECT iph FROM comments WHERE id=?").bind(b.commentId).first(); iph = c && c.iph; }
        if (!iph) return json({ error: "No se encontró el autor." }, 400);
        if (a === "purgeIp") {
          await env.DB.prepare("DELETE FROM comments WHERE iph=?").bind(iph).run();
          await env.DB.prepare("DELETE FROM posts WHERE iph=?").bind(iph).run();
        }
        await env.DB.prepare("INSERT OR IGNORE INTO bans (iph, created, reason) VALUES (?,?,?)").bind(iph, Date.now(), String(b.reason || (a === "purgeIp" ? "purga" : ""))).run();
        return json({ ok: true, iph });
      }
      if (a === "unban") { await env.DB.prepare("DELETE FROM bans WHERE iph=?").bind(b.iph).run(); return json({ ok: true }); }
      return json({ error: "Acción desconocida" }, 400);
    }

    return json({ error: "Ruta no encontrada" }, 404);
  } catch (e) {
    return json({ error: "Error interno", detail: String(e && e.message || e) }, 500);
  }
}
