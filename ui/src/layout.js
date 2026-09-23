// 应用外壳 —— 侧边导航 + 顶栏（用户/角色/退出），内容区由路由挂载
import { logout } from "./session.js";
import { ROLE_LABEL } from "./perms.js";
import { esc } from "./utils.js";

const NAV = [
  ["/dashboard", "📊", "态势大屏"],
  ["/search", "🔍", "统一检索"],
  ["/traffic", "⇄", "流量回溯"],
  ["/assets", "🖥", "资产库"],
  ["/discovery", "🛰", "资产测绘"],
  ["/soar", "🚫", "拉黑审批"],
  ["/users", "👤", "账号管理", "admin"],
];

const TITLES = {
  "/dashboard": "态势大屏",
  "/search": "统一检索",
  "/traffic": "流量回溯",
  "/assets": "统一资产库",
  "/discovery": "资产测绘",
  "/soar": "拉黑审批",
  "/users": "账号管理",
};

export function mountApp(root, user) {
  root.innerHTML = `
  <div class="app">
    <aside class="sidebar">
      <div class="brand">🛡 一体化安全<br><span>态势感知平台</span></div>
      <nav id="nav">${NAV.filter(([, , , role]) => !role || role === user.role).map(([p, ic, t]) =>
        `<a data-route="${p}"><span class="ic">${ic}</span>${esc(t)}</a>`).join("")}</nav>
      <div class="sb-foot">v1.0 · POC</div>
    </aside>
    <div class="main">
      <header class="topbar">
        <div class="pg-title" id="pg-title"></div>
        <div class="spacer"></div>
        <div class="who">
          <span id="pg-user"></span>
          <button id="btn-logout" class="ghost sm">退出</button>
        </div>
      </header>
      <main id="content"></main>
    </div>
  </div>`;

  const navEl = root.querySelector("#nav");
  navEl.addEventListener("click", e => {
    const a = e.target.closest("a[data-route]");
    if (a) location.hash = a.dataset.route;
  });

  root.querySelector("#btn-logout").addEventListener("click", async () => {
    await logout();
    location.reload();
  });

  root.querySelector("#pg-user").innerHTML =
    `${esc(user.username)} <span class="role">${esc(ROLE_LABEL[user.role] || user.role)}</span>`;

  document.addEventListener("ssp:route", e => {
    const p = e.detail;
    navEl.querySelectorAll("a").forEach(a => a.classList.toggle("active", a.dataset.route === p));
    root.querySelector("#pg-title").textContent = TITLES[p] || "";
  });

  return root.querySelector("#content");
}
