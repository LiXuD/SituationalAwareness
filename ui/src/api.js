// 统一 API 层 —— 浏览器只与同源 /api 打交道（nginx 反代到平台后端）
// 一体化安全态势感知平台 · 前端工程

// 同源：空 BASE。所有路径以 /api 开头。
async function send(method, path, { body, raw = false } = {}) {
  const opt = { method, headers: {} };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, opt);
  } catch (e) {
    throw new Error("网络不可达：" + e.message);
  }
  if (raw) {
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res;
  }
  const txt = await res.text();
  let data;
  try { data = JSON.parse(txt); } catch (e) { data = { raw: txt }; }
  if (!res.ok) {
    const err = (data && (data.error || data.detail)) || ("HTTP " + res.status);
    const e = new Error(typeof err === "string" ? err : JSON.stringify(err));
    e.status = res.status;
    e.data = data;
    throw e;
  }
  return data;
}

export const apiGet = (p, o) => send("GET", p, o);
export const apiPost = (p, body, o) => send("POST", p, { ...o, body });
export const apiPut = (p, body, o) => send("PUT", p, { ...o, body });
export const apiDelete = (p, o) => send("DELETE", p, o);

// 二进制下载（PCAP / Excel 模板）：同源自动带会话 Cookie
export function download(path) { window.location = path; }
