// 哈希路由 —— 单页应用在各视图间切换，不刷新、不跳第三方
import * as dashboard from "./pages/dashboard.js";
import * as search from "./pages/search.js";
import * as traffic from "./pages/traffic.js";
import * as assets from "./pages/assets.js";
import * as soar from "./pages/soar.js";
import * as users from "./pages/users.js";

const routes = {
  "/dashboard": dashboard,
  "/search": search,
  "/traffic": traffic,
  "/assets": assets,
  "/soar": soar,
  "/users": users,
};

let active = null;

function parse() {
  const h = location.hash.replace(/^#/, "");
  const [p, q] = h.split("?");
  return { path: p || "/dashboard", query: new URLSearchParams(q || "") };
}

function render(root) {
  const { path, query } = parse();
  const page = routes[path] || routes["/dashboard"];
  if (active && active.unmount) {
    try { active.unmount(); } catch (e) { /* ignore */ }
  }
  root.innerHTML = "";
  if (page.mount) page.mount(root, { query });
  active = page;
  document.dispatchEvent(new CustomEvent("ssp:route", { detail: path }));
}

export function navigate(path) { location.hash = path; }

export function start(root) {
  window.addEventListener("hashchange", () => render(root));
  render(root);
}
