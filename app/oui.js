/* Enredo — búsqueda de fabricante por MAC (OUI).
   Set de arranque con fabricantes comunes. Para cobertura completa (IEEE/Wireshark),
   ejecuta `npm run oui:update` (descarga y genera oui-full.json, que se fusiona aquí). */
const fs = require("fs");
const path = require("path");

// Prefijos OUI comunes (3 primeros bytes, sin separadores, mayúsculas).
const STARTER = {
  B827EB: "Raspberry Pi Foundation", DCA632: "Raspberry Pi Trading", E45F01: "Raspberry Pi Trading",
  "28CDC1": "Raspberry Pi Trading", D83ADD: "Raspberry Pi Trading",
  "240AC4": "Espressif (ESP32/IoT)", "30AEA4": "Espressif (ESP32/IoT)", "3C71BF": "Espressif (ESP32/IoT)",
  "84CCA8": "Espressif (ESP32/IoT)", A020A6: "Espressif (ESP32/IoT)", "5CCF7F": "Espressif (ESP8266/IoT)",
  "18FE34": "Espressif (ESP8266/IoT)", ECFABC: "Espressif (IoT)", "8CAAB5": "Espressif (IoT)",
  F018A8: "Apple", A483E7: "Apple", ACBC32: "Apple", "3C0630": "Apple", DC56E7: "Apple", "88665A": "Apple",
  D0817A: "Apple", "6C4008": "Apple",
  FCFBFB: "Samsung", "5001BB": "Samsung", "8CF5A3": "Samsung", "1C5A3E": "Samsung",
  "50C7BF": "TP-Link", C46E1F: "TP-Link", "003192": "TP-Link", AC84C6: "TP-Link",
  "687F74": "Xiaomi", "64B473": "Xiaomi", "78118A": "Xiaomi", "28E31F": "Xiaomi",
  "44650D": "Amazon (Echo/Fire)", FCA667: "Amazon", "68370E": "Amazon", "0C47C9": "Amazon",
  "1827EB": "Google/Nest", "3C5AB4": "Google", "48D6D5": "Google",
  "5CAAFD": "Sonos", "949F3E": "Sonos", B8E937: "Sonos",
  "001A2B": "Intel", A0A8CD: "Intel", "7CB27D": "Intel", "9C2A70": "Intel Wi-Fi",
  D4CA6D: "Routerboard/MikroTik", CC2DE0: "MikroTik", "4C5E0C": "Routerboard/MikroTik",
  E8DE27: "TP-Link", "204EF6": "AVM (FRITZ!Box)", "3810D5": "AVM (FRITZ!Box)",
  "001788": "Philips Hue", ECB5FA: "Philips Hue",
  B0BE76: "TP-Link", "086A0A": "ASUSTek", "2C56DC": "ASUSTek", "1C872C": "ASUSTek",
};

let full = null;
function loadFull() {
  if (full !== null) return;
  full = {};
  const p = path.join(__dirname, "oui-full.json");
  try { if (fs.existsSync(p)) full = JSON.parse(fs.readFileSync(p, "utf8")); } catch {}
}

function vendorFromMac(mac) {
  if (!mac) return "Desconocido";
  const hex = mac.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
  if (hex.length < 6) return "Desconocido";
  const pfx = hex.slice(0, 6);
  loadFull();
  return full[pfx] || STARTER[pfx] || ("Desconocido (" + pfx.match(/../g).join(":") + ")");
}

module.exports = { vendorFromMac, STARTER };
