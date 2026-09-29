// 分支汇聚（I-13）—— 分支机构登记 + 汇聚健康（在线/离线/未登记）
import { apiGet, apiPost, apiPut, apiDelete } from "../api.js";
import { $, esc } from "../utils.js";
import { canWrite } from "../perms.js";

const STATE_LABEL = {
  ok: "在线", stale: "滞后", no_data: "离线",
  disabled: "停用", unregistered: "未登记", unknown: "未知",
};
const LINK_LABEL = { leased: "专线", vpn: "VPN", internet: "互联网" };

export function mount(root) {
  const writable = canWrite("branches");

  root.innerHTML = `
  <div class="page page-branches">
    <div class="wrap">
      <div class="kpis" id="kpis"><div class="kpi"><div class="lab">加载中</div><div class="val">—</div></div></div>
      <div class="stats">
        <button id="probe">立即探测</button>
        <span class="pill muted" id="lastev">—</span>
        <span class="spacer" style="flex:1"></span>
        <button id="reset" class="ghost sm">清空表单</button>
      </div>
      <div class="card">
        <h3 style="margin:0 0 4px">分支机构登记</h3>
        <div class="muted small">分支身份由采集层注入（Filebeat <code>fields.branch</code> → Logstash → <code>ssp.branch</code>）；
          此处登记用于<b>汇聚健康判定</b>：某分支在期望间隔内无事件上报即标记离线，<b>不影响其他分支</b>。</div>
        <div class="row" style="margin-top:10px">
          <div style="flex:1;min-width:150px"><label>分支标识 branch_id *</label><input id="f_id" placeholder="如 sh-01"/></div>
          <div style="flex:1;min-width:150px"><label>分支名称</label><input id="f_name" placeholder="如 上海分行"/></div>
          <div style="flex:1;min-width:130px"><label>站点 / 机房</label><input id="f_site"/></div>
          <div style="flex:1;min-width:130px"><label>专线类型</label>
            <select id="f_link"><option value="leased">专线</option><option value="vpn">VPN</option><option value="internet">互联网</option></select></div>
        </div>
        <div class="row">
          <div style="flex:2;min-width:220px"><label>该分支网段（逗号分隔，可空）</label><input id="f_cidr" placeholder="10.9.0.0/16"/></div>
          <div style="flex:1;min-width:130px"><label>期望上报间隔（秒）</label><input id="f_exp" value="3600"/></div>
          <div style="flex:1;min-width:110px"><label>启用</label>
            <select id="f_en"><option value="1">启用</option><option value="0">停用</option></select></div>
        </div>
        <label>备注</label><input id="f_note"/>
        <button id="save" style="margin-top:12px">保存分支</button>
        <span id="msg" style="margin-left:10px"></span>
      </div>
      <div class="card" style="padding:0">
        <div class="tblwrap" style="border:0">
          <table>
            <thead><tr><th>状态</th><th>分支</th><th>名称</th><th>站点</th><th>专线</th>
              <th>最近上报</th><th>事件量</th><th>操作</th></tr></thead>
            <tbody id="rows"><tr><td colspan="8" class="empty">加载中…</td></tr></tbody>
          </table>
        </div>
      </div>
      <div class="muted small">判定口径：与「全局最新事件」相比滞后 ≤ 期望上报间隔 → 在线；超出 → 滞后；完全无事件 → 离线。
        未登记的分支会出现「未登记」提示（不影响入库）。</div>
    </div>
  </div>`;

  const setMsg = (t, ok = true) => { $("#msg").innerHTML = `<span class="${ok ? "ok" : "err"}">${esc(t)}</span>`; };
  const fmt = s => s ? new Date(s * 1000).toLocaleString("zh-CN", { hour12: false }) : "-";

  if (!writable) {
    ["f_id", "f_name", "f_site", "f_link", "f_cidr", "f_exp", "f_en", "f_note", "save", "probe", "reset"]
      .forEach(id => { const e = $("#" + id); if (e) e.disabled = true; });
  }

  const load = async () => {
    try {
      const d = await apiGet("/api/branches");
      const items = d.items || [];
      const cnt = {};
      items.forEach(i => { cnt[i.state] = (cnt[i.state] || 0) + 1; });
      $("#kpis").innerHTML =
        `<div class="kpi"><div class="lab">分支总数</div><div class="val">${items.length}</div></div>` +
        `<div class="kpi"><div class="lab">在线</div><div class="val" style="color:var(--ok)">${cnt.ok || 0}</div></div>` +
        `<div class="kpi"><div class="lab">离线 / 滞后</div><div class="val" style="color:var(--err)">${(cnt.no_data || 0) + (cnt.stale || 0)}</div></div>` +
        `<div class="kpi"><div class="lab">未登记</div><div class="val" style="color:var(--acc)">${cnt.unregistered || 0}</div></div>`;
      $("#lastev").textContent = d.latest_event_epoch
        ? "全局最新事件：" + fmt(d.latest_event_epoch) : "暂无事件数据";
      if (d.probe_error) setMsg("探测告警：" + d.probe_error, false);
      $("#rows").innerHTML = items.length ? items.map(it => `
        <tr>
          <td><span class="bd"><span class="dot ${esc(it.state)}"></span>${esc(STATE_LABEL[it.state] || it.state)}</span></td>
          <td class="mono">${esc(it.branch_id)}</td>
          <td>${esc(it.name || "-")}</td>
          <td>${esc(it.site || "-")}</td>
          <td><span class="tag">${esc(LINK_LABEL[it.link_type] || it.link_type || "-")}</span>${it.enabled ? "" : ' <span class="tag">停用</span>'}</td>
          <td class="muted">${fmt(it.last_seen)}</td>
          <td class="mono">${it.events}</td>
          <td class="row-actions">${it.registered && writable
            ? `<button class="ghost" onclick="event.stopPropagation();edit('${esc(it.branch_id)}')">编辑</button>
               <button class="danger" onclick="event.stopPropagation();del('${esc(it.branch_id)}')">删除</button>`
            : `<span class="muted">${it.registered ? "只读" : "待登记"}</span>`}</td>
        </tr>`).join("") : '<tr><td colspan="8" class="empty">暂无分支登记</td></tr>';
    } catch (e) { setMsg("加载失败：" + e.message, false); }
  };

  const body = () => ({
    branch_id: $("#f_id").value.trim(), name: $("#f_name").value.trim(), site: $("#f_site").value.trim(),
    link_type: $("#f_link").value, cidr: $("#f_cidr").value.trim(),
    expect_interval_seconds: $("#f_exp").value.trim(), enabled: $("#f_en").value, note: $("#f_note").value.trim(),
  });

  const reset = () => {
    ["f_id", "f_name", "f_site", "f_cidr", "f_note"].forEach(i => $("#" + i).value = "");
    $("#f_link").value = "leased"; $("#f_exp").value = "3600"; $("#f_en").value = "1";
  };

  $("#save").onclick = async () => {
    const b = body();
    if (!b.branch_id) { setMsg("请填写分支标识", false); return; }
    try {
      await apiPut("/api/branches/" + encodeURIComponent(b.branch_id), b);
      setMsg("已更新分支 " + b.branch_id, true);
    } catch (e) {
      try { await apiPost("/api/branches", b); setMsg("已登记分支 " + b.branch_id, true); }
      catch (e2) { setMsg("保存失败：" + e2.message, false); return; }
    }
    reset(); load();
  };
  $("#reset").onclick = () => { reset(); setMsg(""); };
  $("#probe").onclick = async () => {
    setMsg("探测中…", true);
    try {
      const d = await apiPost("/api/branches/probe", {});
      const sc = d.state_counts || {};
      setMsg(`探测完成：在线 ${sc.ok || 0}、离线 ${sc.no_data || 0}、滞后 ${sc.stale || 0}` +
        ((d.unregistered || []).length ? `、未登记 ${d.unregistered.join(",")}` : ""), true);
      load();
    } catch (e) { setMsg("探测失败：" + e.message, false); }
  };

  const edit = async id => {
    try {
      const d = await apiGet("/api/branches");
      const it = (d.items || []).find(x => x.branch_id === id);
      if (!it) return;
      $("#f_id").value = it.branch_id; $("#f_name").value = it.name || ""; $("#f_site").value = it.site || "";
      $("#f_link").value = it.link_type || "leased"; $("#f_cidr").value = it.cidr || "";
      $("#f_exp").value = it.expect_interval_seconds || 3600; $("#f_en").value = String(it.enabled);
      $("#f_note").value = it.note || "";
      setMsg("编辑模式：改完点「保存分支」", true);
    } catch (e) { setMsg("加载失败：" + e.message, false); }
  };
  const del = async id => {
    if (!confirm("确认删除分支登记 " + id + "？（不影响已入湖数据）")) return;
    try { await apiDelete("/api/branches/" + encodeURIComponent(id)); setMsg("已删除登记 " + id, true); load(); }
    catch (e) { setMsg("删除失败：" + e.message, false); }
  };
  window.edit = edit; window.del = del;

  load();
}

export function unmount() {
  if (window.edit) delete window.edit;
  if (window.del) delete window.del;
}
