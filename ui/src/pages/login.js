// 登录页（SPA 壳内渲染，无独立 HTML）
import { login } from "../session.js";

export function renderLogin(root, onOk) {
  root.innerHTML = `
  <div class="login-wrap">
    <form class="login-card" id="login-form">
      <div class="lc-brand">🛡 一体化安全态势感知平台</div>
      <div class="lc-sub">统一安全管理控制台 · 请登录</div>
      <label>用户名</label>
      <input id="u" autocomplete="username" placeholder="如 analyst"/>
      <label>密码</label>
      <input id="p" type="password" autocomplete="current-password" placeholder="••••••"/>
      <button type="submit" id="btn-login">登录</button>
      <div id="lc-err" class="err"></div>
      <div class="lc-hint">账号由管理员统一创建（scripts/gen-portal-user.py）· 角色：analyst / ops / asset_admin / admin</div>
    </form>
  </div>`;

  const form = root.querySelector("#login-form");
  form.addEventListener("submit", async e => {
    e.preventDefault();
    const u = root.querySelector("#u").value.trim();
    const pw = root.querySelector("#p").value;
    root.querySelector("#lc-err").textContent = "";
    root.querySelector("#btn-login").disabled = true;
    try {
      await login(u, pw);
      onOk();
    } catch (err) {
      root.querySelector("#lc-err").textContent = err.message || "登录失败";
      root.querySelector("#btn-login").disabled = false;
    }
  });
  root.querySelector("#u").focus();
}
