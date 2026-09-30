/* Enredo — escáner de red local (Node, sin dependencias, sin privilegios de admin).
   Técnicas: ping-sweep ICMP (comando del SO) + caché ARP + reverse DNS + TCP connect.
   NO usa captura de paquetes (evita Npcap/admin). Escanea SOLO tu propia subred. */
const os = require("os");
const net = require("net");
const dns = require("dns").promises;
const { exec } = require("child_process");
const { vendorFromMac } = require("./oui");

const isWin = process.platform === "win32";
const COMMON_PORTS = [21, 22, 23, 53, 80, 135, 139, 443, 445, 554, 631, 1883, 3306, 3389, 5000, 5432, 8080, 8443, 9100, 62078];
const PORT_NAMES = { 21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 135: "RPC", 139: "NetBIOS", 443: "HTTPS", 445: "SMB", 554: "RTSP", 631: "IPP", 1883: "MQTT", 3306: "MySQL", 3389: "RDP", 5000: "UPnP/HTTP", 5432: "PostgreSQL", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "Impresora", 62078: "iOS-sync" };

function sh(cmd, timeout = 8000) {
  return new Promise((resolve) => {
    exec(cmd, { timeout, maxBuffer: 8 * 1024 * 1024, windowsHide: true }, (err, stdout) => resolve(stdout || ""));
  });
}
async function pool(items, worker, concurrency = 40) {
  const out = []; let i = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await worker(items[idx], idx); }
  });
  await Promise.all(runners);
  return out;
}

function primaryIface() {
  const ifs = os.networkInterfaces();
  for (const name of Object.keys(ifs)) {
    for (const a of ifs[name]) {
      if (a.family === "IPv4" && !a.internal && !a.address.startsWith("169.254")) {
        return { name, address: a.address, netmask: a.netmask, mac: a.mac };
      }
    }
  }
  return null;
}

async function detectNetwork() {
  const iface = primaryIface();
  if (!iface) return null;
  const base = iface.address.split(".").slice(0, 3).join(".");
  let gateway = "", dnsServers = [];
  const cfg = await sh(isWin ? "ipconfig /all" : "ip route && cat /etc/resolv.conf");
  const gw = cfg.match(/(?:Default Gateway|Puerta de enlace predeterminada)[^\n]*?:?\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})/i)
    || cfg.match(/default via ([0-9.]+)/i);
  if (gw) gateway = gw[1];
  const dm = cfg.match(/(?:DNS Servers|Servidores DNS)[^\n]*?:?\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})/i)
    || cfg.match(/nameserver ([0-9.]+)/i);
  if (dm) dnsServers.push(dm[1]);
  return { interface: iface.name, ip: iface.address, mac: iface.mac, netmask: iface.netmask, base, gateway, dnsServers };
}

async function pingOne(ip) {
  const out = await sh(isWin ? `ping -n 1 -w 500 ${ip}` : `ping -c 1 -W 1 ${ip}`, 3000);
  return /TTL=/i.test(out) ? ip : null;
}

async function arpTable() {
  const out = await sh("arp -a");
  const map = {};
  const re = /([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})/g;
  let m; while ((m = re.exec(out)) !== null) map[m[1]] = m[2].replace(/-/g, ":").toLowerCase();
  return map;
}

// Descarta broadcast (.255/.0), multicast y MACs no reales.
function isBcastMcast(ip, mac) {
  const last = Number(ip.split(".")[3]);
  if (last === 0 || last === 255) return true;
  const m = (mac || "").toLowerCase();
  if (!m) return false;
  if (m === "ff:ff:ff:ff:ff:ff" || m === "00:00:00:00:00:00") return true;
  if (m.startsWith("01:00:5e") || m.startsWith("33:33") || m.startsWith("01:80:c2")) return true;
  return false;
}

function checkPort(ip, port, timeout = 700) {
  return new Promise((resolve) => {
    const s = new net.Socket(); let done = false;
    const end = (open) => { if (done) return; done = true; s.destroy(); resolve(open ? port : null); };
    s.setTimeout(timeout);
    s.once("connect", () => end(true));
    s.once("timeout", () => end(false));
    s.once("error", () => end(false));
    s.connect(port, ip);
  });
}
async function scanPorts(ip) {
  const res = await pool(COMMON_PORTS, (p) => checkPort(ip, p), 20);
  return res.filter((p) => p !== null).sort((a, b) => a - b);
}

async function reverseDns(ip) {
  try { const names = await Promise.race([dns.reverse(ip), new Promise((_, r) => setTimeout(r, 1200))]); return names && names[0] ? names[0] : ""; }
  catch { return ""; }
}

function guessType(vendor, ports, isGateway) {
  if (isGateway) return "Router / Puerta de enlace";
  const has = (p) => ports.includes(p);
  if (has(9100) || has(631)) return "Impresora";
  if (has(554)) return "Cámara IP";
  if (has(62078)) return "iPhone / iPad";
  if (/Sonos/i.test(vendor)) return "Altavoz (Sonos)";
  if (/Hue|Philips/i.test(vendor)) return "Domótica";
  if (/Espressif/i.test(vendor)) return "IoT (ESP)";
  if (/Raspberry/i.test(vendor)) return "Raspberry Pi";
  if (/Amazon/i.test(vendor)) return "Amazon (Echo/Fire)";
  if (has(1883)) return "IoT (MQTT)";
  if (has(3389) || (has(445) && has(139))) return "PC / Windows";
  if (has(22)) return "Servidor / Linux";
  if (has(80) || has(443) || has(8080)) return "Dispositivo web";
  return "Desconocido";
}

async function fullScan(opts = {}, onProgress = () => {}) {
  const started = Date.now();
  const network = await detectNetwork();
  if (!network) throw new Error("No se detectó una interfaz de red activa.");
  onProgress({ phase: "descubriendo", done: 0, total: 254 });

  // 1) Ping sweep
  const hosts = Array.from({ length: 254 }, (_, i) => `${network.base}.${i + 1}`);
  let done = 0;
  let alive = (await pool(hosts, async (ip) => {
    const r = await pingOne(ip); onProgress({ phase: "descubriendo", done: ++done, total: 254 }); return r;
  }, 50)).filter(Boolean);

  // 2) ARP para MACs (el ping ya pobló la caché)
  const arp = await arpTable();
  for (const ip of Object.keys(arp)) {
    if (!ip.startsWith(network.base + ".") || isBcastMcast(ip, arp[ip])) { delete arp[ip]; continue; }
    if (!alive.includes(ip)) alive.push(ip);
  }
  alive = alive.filter((ip) => !isBcastMcast(ip, arp[ip] || ""));
  alive.sort((a, b) => Number(a.split(".")[3]) - Number(b.split(".")[3]));

  // 3) Enriquecer cada equipo
  let d2 = 0;
  const devices = await pool(alive, async (ip) => {
    const mac = arp[ip] || (ip === network.ip ? (network.mac || "") : "");
    const vendor = vendorFromMac(mac);
    const [hostname, ports] = await Promise.all([reverseDns(ip), scanPorts(ip)]);
    onProgress({ phase: "analizando", done: ++d2, total: alive.length });
    const isGw = ip === network.gateway;
    return {
      ip, mac, vendor,
      hostname: ip === network.ip ? (os.hostname() + " (este equipo)") : hostname,
      ports, portNames: ports.map((p) => PORT_NAMES[p] || String(p)),
      type: guessType(vendor, ports, isGw),
      isSelf: ip === network.ip, isGateway: isGw,
    };
  }, 12);

  const result = {
    v: 1, app: "Enredo", scannedAt: new Date(started).toISOString(),
    network: { ...network, hostsScanned: 254 },
    devices,
  };

  if (opts.includeSelf !== false) result.self = await getSelf(network);
  result.stats = buildStats(devices);
  onProgress({ phase: "hecho", done: alive.length, total: alive.length });
  return result;
}

async function getSelf(network) {
  const self = { hostname: os.hostname(), platform: `${os.type()} ${os.release()}` };
  try {
    const ctrl = AbortSignal.timeout ? AbortSignal.timeout(4000) : undefined;
    const r = await fetch("https://api.ipify.org?format=json", ctrl ? { signal: ctrl } : {});
    self.publicIp = (await r.json()).ip;
  } catch { self.publicIp = "(no disponible)"; }
  if (isWin) {
    const w = await sh("netsh wlan show interfaces");
    const ssid = w.match(/^\s*SSID\s*:\s*(.+)$/m);
    const sig = w.match(/(\d{1,3})\s*%/);
    const auth = w.match(/(?:Authentication|Autenticaci)[^\n]*:\s*(.+)$/m);
    if (ssid) self.wifiSsid = ssid[1].trim();
    if (sig) self.wifiSignal = sig[1] + "%";
    if (auth) self.wifiSecurity = auth[1].trim();
  }
  return self;
}

function buildStats(devices) {
  const vendor = {}, ports = {}, type = {};
  for (const d of devices) {
    const v = d.vendor.replace(/\s*\(.*?\)$/, "");
    vendor[v] = (vendor[v] || 0) + 1;
    type[d.type] = (type[d.type] || 0) + 1;
    for (const p of d.ports) ports[p] = (ports[p] || 0) + 1;
  }
  return { vendor, ports, type };
}

module.exports = { fullScan, detectNetwork };
