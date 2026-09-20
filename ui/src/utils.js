// 通用工具 —— 全工程共享，避免各页面重复定义
// 一体化安全态势感知平台 · 前端工程

// 选择器：兼容 $("#id") / $("id") / $(".cls") 三种写法
export const $ = (sel, root = document) => {
  if (!sel) return null;
  const s = (sel[0] === "#" || sel[0] === ".") ? sel : "#" + sel;
  return root.querySelector(s);
};

export function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

export function fmtTs(t) {
  if (!t) return "-";
  const d = new Date(t);
  if (isNaN(d)) return "-";
  return d.toLocaleString("zh-CN", { hour12: false });
}

export function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(2) + " MB";
}

export const PROTO = { 1: "icmp", 6: "tcp", 17: "udp" };
export const protoName = p => PROTO[p] || ("proto" + p);

// 私有/保留网段判定（用于区分"外网 IP → 可查流量"）
export function isPrivateIP(ip) {
  if (!ip) return true;
  return /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|203\.0\.113\.|198\.51\.100\.|192\.0\.2\.)/.test(ip);
}

export function localToMs(v) { return v ? new Date(v).getTime() : null; }

export function msToLocalInput(ms) {
  const d = new Date(Number(ms));
  if (isNaN(d)) return "";
  const p = n => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function parseGeo(g) {
  if (!g) return null;
  if (Array.isArray(g) && g.length === 2) {
    const [a, b] = g;
    return (Math.abs(a) > 90) ? { lon: a, lat: b } : { lon: b, lat: a };
  }
  if (typeof g === "object") {
    if (g.location) return parseGeo(g.location);
    if (typeof g.lat === "number" && typeof g.lon === "number") return { lat: g.lat, lon: g.lon };
    if (typeof g.latitude === "number" && typeof g.longitude === "number") return { lat: g.latitude, lon: g.longitude };
  }
  if (typeof g === "string" && g.indexOf(",") > 0) {
    const [a, b] = g.split(",").map(Number);
    if (isFinite(a) && isFinite(b)) return (Math.abs(a) > 90) ? { lat: b, lon: a } : { lat: a, lon: b };
  }
  return null;
}

// 轻量 toast
export function toast(msg, kind = "ok") {
  let host = document.querySelector(".toast");
  if (!host) {
    host = document.createElement("div");
    host.className = "toast";
    document.body.appendChild(host);
  }
  const el = document.createElement("div");
  el.className = kind === "err" ? "err" : (kind === "ok" ? "ok" : "");
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => el.remove(), 3600);
}

// 经纬度 → 等距圆柱投影（攻击地图用，与 world-land.svg 一致：viewBox 1000x500）
export function proj(lon, lat) {
  return [(lon + 180) / 360 * 1000, (90 - lat) / 180 * 500];
}
