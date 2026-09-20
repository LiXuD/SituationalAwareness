// 会话管理 —— 登录态在 window.__ssp_user__ 上缓存，供权限判断使用
import { apiGet, apiPost } from "./api.js";

let _user = null;

export async function me() {
  try {
    const d = await apiGet("/api/auth/me");
    _user = d.user || null;
  } catch (e) {
    _user = null;
  }
  window.__ssp_user__ = _user;
  return _user;
}

export async function login(username, password) {
  const d = await apiPost("/api/auth/login", { username, password });
  _user = d.user || null;
  window.__ssp_user__ = _user;
  return _user;
}

export async function logout() {
  try { await apiPost("/api/auth/logout"); } catch (e) { /* 忽略 */ }
  _user = null;
  window.__ssp_user__ = null;
}

export function currentUser() { return _user; }
