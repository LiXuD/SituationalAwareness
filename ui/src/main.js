// 应用引导 —— 校验登录态：未登录显示登录页；已登录挂载外壳 + 启动路由
import { me } from "./session.js";
import { mountApp } from "./layout.js";
import { start as startRouter } from "./router.js";
import { renderLogin } from "./pages/login.js";

const root = document.getElementById("app");

(async () => {
  const user = await me();
  if (!user) {
    renderLogin(root, boot);
    return;
  }
  boot();
})();

function boot() {
  const content = mountApp(root, window.__ssp_user__);
  startRouter(content);
  if (!location.hash) location.hash = "/dashboard";
}
