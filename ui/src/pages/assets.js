// 统一资产库 —— 平台内视图（ES 模块）
import { apiGet, apiPost, apiPut, apiDelete, download } from "../api.js";
import { $, esc, toast } from "../utils.js";
import { canWrite } from "../perms.js";

export function mount(root) {
  const writable = canWrite("asset");
  root.innerHTML = `
  <div class="page page-assets">
    <div class="wrap">
      <div class="card">
        <h3 style="margin:0 0 4px">新增 / 编辑资产</h3>
        <div class="muted" style="font-size:11px">手工录入（含 重要度 / 风险评分，供大屏热力着色）</div>
        <input id="f_id" placeholder="资产编号（留空自动生成，编辑时必填）" style="margin-top:10px"/>
        <label>资产名称 *</label><input id="f_name"/>
        <label>IP 地址 *</label><input id="f_ip" placeholder="如 10.20.30.40"/>
        <label>资产类型</label>
          <select id="f_type"><option>服务器</option><option>网络设备</option><option>安全设备</option><option>终端设备</option><option>应用系统</option><option>数据库</option><option>其他</option></select>
        <label>重要度 *</label>
          <select id="f_imp"><option>核心</option><option>重要</option><option>一般</option></select>
        <label>风险评分 (0-100) *</label><input id="f_risk" placeholder="0-100"/>
        <label>责任人</label><input id="f_owner"/>
        <label>所属部门</label><input id="f_dept"/>
        <label>位置/机房</label><input id="f_loc"/>
        <label>操作系统</label><input id="f_os"/>
        <label>标签（逗号分隔）</label><input id="f_tags"/>
        <label>备注</label><input id="f_desc"/>
        <button id="save">保存资产</button>
        <button id="reset" class="ghost">清空</button>
        <hr style="border-color:var(--line);margin:14px 0"/>
        <h3 style="margin:0 0 4px">Excel 批量导入</h3>
        <input id="file" type="file" accept=".xlsx"/>
        <button id="imp" class="ghost">导入 Excel</button>
        <button id="tpl" class="ghost">下载模板</button>
        <div id="errbox"></div>
      </div>
      <div>
        <div class="stats" id="stats"><span class="pill muted">加载中…</span></div>
        <div class="card" style="padding:0">
          <table>
            <thead><tr><th>编号</th><th>名称</th><th>IP</th><th>类型</th><th>重要度</th><th>风险</th><th>责任人</th><th>部门</th><th>操作</th></tr></thead>
            <tbody id="rows"><tr><td colspan="9" class="empty">—</td></tr></tbody>
          </table>
        </div>
        <div class="stats" style="margin-top:12px">
          <span class="pill muted">检索目标：别名 <b>ssp-assets</b>（资产独立域，非日志事件）</span>
        </div>
        <div id="msg"></div>
      </div>
    </div>
  </div>`;

  // 无写权限（非 资产管理员/技术负责人）：禁用录入与导入
  if (!writable) {
    ["f_id", "f_name", "f_ip", "f_type", "f_imp", "f_risk", "f_owner", "f_dept",
      "f_loc", "f_os", "f_tags", "f_desc", "file", "save", "imp", "reset"]
      .forEach(id => { const e = $("#" + id); if (e) e.disabled = true; });
  }

  const impBadge = v => v === "核心" ? "core" : v === "重要" ? "important" : v === "一般" ? "normal" : "";
  const riskCls = v => ((v = +v) >= 80 ? "hi" : v >= 50 ? "mid" : "lo");
  const setMsg = (t, ok) => { $("#msg").innerHTML = `<span class="${ok ? "ok" : "err"}">${t}</span>`; };
  const showErrs = errs => {
    const box = $("#errbox");
    if (!errs || !errs.length) { box.style.display = "none"; return; }
    box.style.display = "block";
    box.innerHTML = `<div class="muted">导入被回滚，以下为错误行（任一非法即整批拒绝，未写入任何文档）：</div>` +
      errs.map(e => `<div class="row">第 ${e.row} 行 · ${e.field}：${e.reason}</div>`).join("");
  };

  const load = async () => {
    try {
      const data = await apiGet("/api/asset/api/assets?size=200");
      const items = data.items || [];
      const byImp = { 核心: 0, 重要: 0, 一般: 0 };
      items.forEach(it => { if (byImp[it.importance] != null) byImp[it.importance]++; });
      $("#stats").innerHTML =
        `<span class="pill">资产总数 <b>${data.total}</b></span>` +
        `<span class="pill">核心 <b>${byImp["核心"]}</b></span>` +
        `<span class="pill">重要 <b>${byImp["重要"]}</b></span>` +
        `<span class="pill">一般 <b>${byImp["一般"]}</b></span>`;
      $("#rows").innerHTML = items.length ? items.map(it => `
        <tr onclick='edit("${it.asset_id}")'>
          <td>${it.asset_id || "-"}</td><td>${it.name || "-"}</td><td>${it.ip || "-"}</td>
          <td><span class="tag">${it.asset_type || "-"}</span></td>
          <td><span class="tag ${impBadge(it.importance)}">${it.importance || "-"}</span></td>
          <td class="risk ${riskCls(it.risk_score)}">${it.risk_score ?? "-"}</td>
          <td>${it.owner || "-"}</td><td>${it.department || "-"}</td>
          <td class="row-actions">
            ${writable ? `<button class="ghost" onclick="event.stopPropagation();edit('${it.asset_id}')">编辑</button>
            <button class="danger" onclick="event.stopPropagation();del('${it.asset_id}')">删除</button>` : `<span class="muted">只读</span>`}
          </td>
        </tr>`).join("") : '<tr><td colspan="9" class="empty">暂无资产，请先新增或导入</td></tr>';
    } catch (e) {
      $("#stats").innerHTML = `<span class="pill err">加载失败：${esc(e.message)}</span>`;
    }
  };

  const save = async () => {
    const id = $("#f_id").value.trim();
    const body = {
      asset_id: id, name: $("#f_name").value.trim(), ip: $("#f_ip").value.trim(),
      asset_type: $("#f_type").value, importance: $("#f_imp").value, risk_score: $("#f_risk").value,
      owner: $("#f_owner").value.trim(), department: $("#f_dept").value.trim(),
      location: $("#f_loc").value.trim(), os: $("#f_os").value.trim(),
      tags: $("#f_tags").value.trim(), description: $("#f_desc").value.trim(),
    };
    if (!body.name || !body.ip || !body.risk_score) { setMsg("请填写 名称 / IP / 风险评分", false); return; }
    const isEdit = !!id;
    try {
      const data = isEdit
        ? await apiPut("/api/asset/api/assets/" + encodeURIComponent(id), body)
        : await apiPost("/api/asset/api/assets", body);
      setMsg("已" + (isEdit ? "更新" : "新增") + "资产 " + data.asset_id, true);
      showErrs([]); resetForm(); load();
    } catch (e) { showErrs(e.data && e.data.errors); setMsg("保存失败：" + e.message, false); }
  };

  const del = async id => {
    if (!confirm("确认删除资产 " + id + "？")) return;
    try {
      const data = await apiDelete("/api/asset/api/assets/" + encodeURIComponent(id));
      setMsg(data.ok ? "已删除 " + id : "删除失败：" + (data.error || ""), data.ok);
      load();
    } catch (e) { setMsg("请求失败：" + e.message, false); }
  };

  const edit = async id => {
    try {
      const data = await apiGet("/api/asset/api/assets");
      const it = (data.items || []).find(x => x.asset_id === id);
      if (!it) return;
      $("#f_id").value = it.asset_id || ""; $("#f_name").value = it.name || ""; $("#f_ip").value = it.ip || "";
      $("#f_type").value = it.asset_type || "其他"; $("#f_imp").value = it.importance || "一般";
      $("#f_risk").value = it.risk_score ?? ""; $("#f_owner").value = it.owner || ""; $("#f_dept").value = it.department || "";
      $("#f_loc").value = it.location || ""; $("#f_os").value = it.os || ""; $("#f_tags").value = (it.tags || []).join(",");
      $("#f_desc").value = it.description || "";
      setMsg("编辑模式：修改后点「保存资产」（将 PUT /api/assets/" + id + "）", true);
    } catch (e) { setMsg("加载失败：" + e.message, false); }
  };

  const importXlsx = async () => {
    const f = $("#file").files[0];
    if (!f) { setMsg("请先选择 xlsx 文件", false); return; }
    const fd = new FormData(); fd.append("file", f);
    setMsg("导入中…", true); showErrs([]);
    try {
      const res = await fetch("/api/asset/api/assets/import", { method: "POST", body: fd });
      const data = await res.json();
      if (!res.ok || !data.ok) { showErrs(data.errors); setMsg("导入被回滚：" + (data.error || ""), false); }
      else { setMsg("导入成功，新增 " + data.imported + " 条", true); showErrs([]); load(); }
    } catch (e) { setMsg("请求失败：" + e.message, false); }
  };

  const resetForm = () => {
    ["f_id", "f_name", "f_ip", "f_risk", "f_owner", "f_dept", "f_loc", "f_os", "f_tags", "f_desc"].forEach(i => $("#" + i).value = "");
    $("#f_type").value = "服务器"; $("#f_imp").value = "核心";
  };

  $("#save").onclick = save;
  $("#reset").onclick = () => { resetForm(); setMsg("", true); };
  $("#imp").onclick = importXlsx;
  $("#tpl").onclick = () => download("/api/asset/api/assets/template.xlsx");

  // 暴露给行内 onclick
  window.edit = edit; window.del = del;

  load();
}

export function unmount() {
  if (window.edit) delete window.edit;
  if (window.del) delete window.del;
}
