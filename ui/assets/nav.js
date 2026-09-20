/* 统一导航（同站多页共用）—— 一体化安全态势感知平台
 *
 * 目标：消除"各管各的"。所有平台页面共用同一套导航，站内切换；
 * 页面**不再**出现任何指向 Arkime(8005) / OpenSearch Dashboards(5601) 的外跳链接
 * —— 这两者的能力已由平台原生提供（流量回溯页 / 统一检索页 / 态势大屏）。
 *
 * 用法：在页面 </body> 前引入 <script src="assets/nav.js"></script>
 * 行为：① 在 body 顶部注入统一导航条；② 移除各页遗留的 .links 外跳区。
 */
(function () {
  var PAGES = [
    { href: "dashboard.html", label: "态势大屏", icon: "▦" },
    { href: "index.html",     label: "统一检索", icon: "⌕" },
    { href: "traffic.html",   label: "流量回溯", icon: "⇄" },
    { href: "assets.html",    label: "资产库",   icon: "▤" },
    { href: "soar.html",      label: "拉黑审批", icon: "⛔" }
  ];

  var here = (location.pathname.split("/").pop() || "dashboard.html").toLowerCase();

  // ① 清掉各页遗留的外跳链接区（Arkime / Dashboards）
  var stale = document.querySelectorAll(".links");
  for (var i = 0; i < stale.length; i++) { stale[i].parentNode.removeChild(stale[i]); }

  // ② 样式（页面为深色主题，这里保持一致）
  var css = document.createElement("style");
  css.textContent = [
    ".ssp-nav{display:flex;align-items:center;gap:18px;padding:9px 18px;",
    "background:linear-gradient(180deg,#131c2e,#0b0f18);border-bottom:1px solid #273147;",
    "font:13px/1.4 -apple-system,Segoe UI,Roboto,'PingFang SC',sans-serif;flex-wrap:wrap}",
    ".ssp-brand{font-weight:700;color:#e6ebf5;letter-spacing:.5px;white-space:nowrap}",
    ".ssp-brand b{color:#38bdf8}",
    ".ssp-menu{display:flex;gap:6px;flex-wrap:wrap}",
    ".ssp-menu a{display:inline-flex;align-items:center;gap:5px;padding:5px 11px;border-radius:7px;",
    "color:#8b97ad;text-decoration:none;border:1px solid transparent}",
    ".ssp-menu a:hover{color:#e6ebf5;background:#1b2333}",
    ".ssp-menu a.on{color:#0b0f18;background:#38bdf8;font-weight:600}",
    ".ssp-hint{margin-left:auto;color:#5b6779;font-size:11px;white-space:nowrap}"
  ].join("");
  document.head.appendChild(css);

  // ③ 注入导航条
  var nav = document.createElement("header");
  nav.className = "ssp-nav";
  var items = PAGES.map(function (p) {
    var on = (p.href === here) ? " on" : "";
    return '<a class="' + on.trim() + '" href="' + p.href + '">' + p.icon + " " + p.label + "</a>";
  }).join("");
  nav.innerHTML = '<div class="ssp-brand">🛡 <b>一体化安全态势感知平台</b></div>' +
                  '<nav class="ssp-menu">' + items + "</nav>" +
                  '<div class="ssp-hint">单平台 · 统一管理查看</div>';

  if (document.body.firstChild) { document.body.insertBefore(nav, document.body.firstChild); }
  else { document.body.appendChild(nav); }
})();
