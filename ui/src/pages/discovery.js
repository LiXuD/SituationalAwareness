// 资产测绘（I-12）—— 被动识别候选池：立即测绘 / 采纳入库 / 忽略
import { apiGet, apiPost, apiPut } from "../api.js";
import { $, esc, toast } from "../utils.js";
import { canWrite } from "../perms.js";

const sel = new Set();

export function mount(root) {
  const writable = canWrite("discovery");
  const isAdmin = (window.__ssp_user__ || {}).role === "admin";
  let page = 1;

  root.innerHTML = `
  <div class="page page-discovery">
    <div class="wrap">
      <div class="card">
        <h3 style="margin:0 0 4px">资产测绘（被动识别）</h3>
        <div class="muted" style="font-size:11px">
          从 Zeek 连接日志（ECS）自动识别被保护资产 → 候选池 → 采纳后合并入资产库；
          <b>不会覆盖手工资产的人工字段</b>（名称 / 重要度 / 责任人…）。
        </div>
        <div class="stats" id="stats" style="margin-top:10px"><span class="pill muted">加载中…</span></div>
        <div style="margin-top:10px">
          <button id="run">立即测绘</button>
          <span class="muted" style="font-size:11px;margin-left:8px" id="runhint"></span>
        </div>
        <hr style="border-color:var(--line);margin:14px 0"/>
        <div class="muted" style="font-size:11px;cursor:pointer" id="cfgtoggle">▸ 测绘配置（${
          isAdmin ? "可修改" : "只读"}）</div>
        <div id="cfgbox" style="display:none">
          <label>授权网段 cidr_allow（逗号分隔）</label><input id="c_cidr"/>
          <label>排除网段 exclude_cidrs</label><input id="c_excl"/>
          <label>排除 IP exclude_ips</label><input id="c_exips"/>
          <label>观测次数阈值 min_obs</label><input id="c_min"/>
          <label>回溯窗口（分钟）window_minutes</label><input id="c_win"/>
          <label>自动采纳 auto_adopt（true/false）</label><input id="c_auto"/>
          ${isAdmin ? `<button id="cfgsave">保存配置</button>` : `<div class="muted" style="font-size:11px">仅技术负责人可修改。</div>`}
          <div id="cfgmsg"></div>
        </div>
        <div id="errbox"></div>
      </div>
      <div>
        <div class="stats">
          <select id="f_status" class="sm">
            <option value="pending">待审核</option><option value="adopted">已采纳</option>
            <option value="ignored">已忽略</option><option value="all">全部</option>
          </select>
          <input id="f_q" placeholder="按 IP / 服务 / 协议搜索" style="max-width:220px"/>
          <button id="qbtn" class="ghost sm">查询</button>
          <span class="spacer" style="flex:1"></span>
          <button id="adopt" class="sm">采纳入库</button>
          <button id="ignore" class="ghost sm">忽略</button>
        </div>
        <div class="card" style="padding:0">
          <table>
            <thead><tr>
              <th style="width:28px"><input type="checkbox" id="ckall"/></th>
              <th>IP</th><th>端口</th><th>协议</th><th>服务</th><th>观测</th>
              <th>首次</th><th>最近</th><th>来源</th><th>状态</th>
            </tr></thead>
            <tbody id="rows"><tr><td colspan="10" class="empty">—</td></tr></tbody>
          </table>
        </div>
        <div class="stats" style="margin-top:12px">
          <button id="prev" class="ghost sm">上一页</button>
          <span class="pill muted" id="pageinfo">-</span>
          <button id="next" class="ghost sm">下一页</button>
        </div>
        <div id="msg"></div>
      </div>
    </div>
  </div>`;

  const setMsg = (t, ok = true) => { $("#msg").innerHTML = `<span class="${ok ? "ok" : "err"}">${esc(t)}</span>`; };
  const fmt = t => t ? new Date(t).toLocaleString("zh-CN", { hour12: false }) : "-";

  if (!writable) {
    ["run", "adopt", "ignore", "ckall"].forEach(id => { const e = $("#" + id); if (e) e.disabled = true; });
    $("#runhint").textContent = "（当前角色只读）";
  }

  const loadStats = async () => {
    try {
      const s = await apiGet("/api/discovery/stats");
      $("#stats").innerHTML =
        `<span class="pill">候选总数 <b>${s.total}</b></span>` +
        `<span class="pill">待审核 <b>${s.pending}</b></span>` +
        `<span class="pill">已采纳 <b>${s.adopted}</b></span>` +
        `<span class="pill">已忽略 <b>${s.ignored}</b></span>` +
        `<span class="pill">覆盖主机 <b>${s.adopted_hosts}</b></span>`;
    } catch (e) { $("#stats").innerHTML = `<span class="pill err">统计失败：${esc(e.message)}</span>`; }
  };

  const load = async () => {
    sel.clear();
    const status = $("#f_status").value, q = $("#f_q").value.trim();
    try {
      const d = await apiGet(`/api/discovery/candidates?status=${encodeURIComponent(status)}` +
        `&q=${encodeURIComponent(q)}&page=${page}&size=50`);
      const items = d.items || [];
      const stBadge = s => s === "pending" ? "important" : s === "adopted" ? "core" : "";
      const stLabel = { pending: "待审核", adopted: "已采纳", ignored: "已忽略" };
      $("#rows").innerHTML = items.length ? items.map(it => `
        <tr>
          <td><input type="checkbox" data-id="${it.id}" ${writable && it.status === "pending" ? "" : "disabled"}/></td>
          <td>${esc(it.ip)} ${it.in_assets ? '<span class="tag core" title="资产库已有同 IP，采纳将合并">已在资产库</span>' : ""}</td>
          <td>${it.port ?? "-"}</td><td>${esc(it.proto || "-")}</td><td>${esc(it.service || "-")}</td>
          <td>${it.obs_count}</td>
          <td class="muted">${fmt(it.first_seen)}</td><td class="muted">${fmt(it.last_seen)}</td>
          <td><span class="tag">${esc(it.source)}</span></td>
          <td><span class="tag ${stBadge(it.status)}">${stLabel[it.status] || it.status}</span></td>
        </tr>`).join("") : '<tr><td colspan="10" class="empty">暂无候选，点「立即测绘」从流量中识别</td></tr>';
      const pages = Math.max(1, Math.ceil((d.total || 0) / (d.size || 50)));
      $("#pageinfo").textContent = `第 ${page} / ${pages} 页 · 共 ${d.total} 条`;
      $("#rows").querySelectorAll('input[type=checkbox][data-id]').forEach(cb => {
        cb.onchange = () => { cb.checked ? sel.add(cb.dataset.id) : sel.delete(cb.dataset.id); };
      });
      $("#ckall").checked = false;
    } catch (e) { setMsg("加载失败：" + e.message, false); }
  };

  const act = async (kind) => {
    const ids = [...sel];
    if (!ids.length) { setMsg("请先勾选候选（仅「待审核」可选）", false); return; }
    try {
      const d = await apiPost(`/api/discovery/${kind}`, { ids });
      if (kind === "adopt") setMsg(`已采纳 ${d.adopted} 条：新增资产 ${d.created} / 合并 ${d.merged}`, true);
      else setMsg(`已忽略 ${d.ignored} 条`, true);
      await loadStats(); await load();
    } catch (e) { setMsg(`${kind === "adopt" ? "采纳" : "忽略"}失败：` + e.message, false); }
  };

  $("#run").onclick = async () => {
    setMsg("测绘中…", true);
    try {
      const d = await apiPost("/api/discovery/run", {});
      setMsg(`测绘完成：扫描主机 ${d.scanned_hosts}，新增候选 ${d.created}，刷新 ${d.updated}` +
        (d.auto_adopt ? `，自动采纳 ${d.auto_adopt_result && d.auto_adopt_result.adopted}` : ""), true);
      page = 1; await loadStats(); await load();
    } catch (e) { setMsg("测绘失败：" + e.message, false); }
  };
  $("#adopt").onclick = () => act("adopt");
  $("#ignore").onclick = () => act("ignore");
  $("#qbtn").onclick = () => { page = 1; load(); };
  $("#f_status").onchange = () => { page = 1; load(); };
  $("#prev").onclick = () => { if (page > 1) { page--; load(); } };
  $("#next").onclick = () => { page++; load(); };
  $("#ckall").onchange = e => {
    $("#rows").querySelectorAll('input[type=checkbox][data-id]:not(:disabled)').forEach(cb => {
      cb.checked = e.target.checked;
      cb.checked ? sel.add(cb.dataset.id) : sel.delete(cb.dataset.id);
    });
  };

  const loadCfg = async () => {
    try {
      const c = await apiGet("/api/discovery/config");
      $("#c_cidr").value = c["discovery.cidr_allow"] || "";
      $("#c_excl").value = c["discovery.exclude_cidrs"] || "";
      $("#c_exips").value = c["discovery.exclude_ips"] || "";
      $("#c_min").value = c["discovery.min_obs"] || "";
      $("#c_win").value = c["discovery.window_minutes"] || "";
      $("#c_auto").value = c["discovery.auto_adopt"] || "";
      $("#cfgtoggle").textContent = "▾ 测绘配置（" + (isAdmin ? "可修改" : "只读") + "）";
    } catch (e) { $("#cfgmsg").innerHTML = `<span class="err">${esc(e.message)}</span>`; }
  };
  $("#cfgtoggle").onclick = () => {
    const b = $("#cfgbox");
    if (b.style.display === "none") { b.style.display = "block"; loadCfg(); }
    else { b.style.display = "none"; $("#cfgtoggle").textContent = "▸ 测绘配置"; }
  };
  if ($("#cfgsave")) {
    $("#cfgsave").onclick = async () => {
      const body = {
        "discovery.cidr_allow": $("#c_cidr").value.trim(),
        "discovery.exclude_cidrs": $("#c_excl").value.trim(),
        "discovery.exclude_ips": $("#c_exips").value.trim(),
        "discovery.min_obs": $("#c_min").value.trim(),
        "discovery.window_minutes": $("#c_win").value.trim(),
        "discovery.auto_adopt": $("#c_auto").value.trim(),
      };
      try { await apiPut("/api/discovery/config", body); $("#cfgmsg").innerHTML = '<span class="ok">配置已保存</span>'; toast("测绘配置已保存"); }
      catch (e) { $("#cfgmsg").innerHTML = `<span class="err">${esc(e.message)}</span>`; }
    };
  }

  loadStats();
  load();
}

export function unmount() { sel.clear(); }
