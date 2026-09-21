// 账号管理 —— 平台内视图（仅技术负责人；落平台业务库）
import { apiGet, apiPost, apiPut, apiDelete } from "../api.js";
import { $, esc, fmtTs } from "../utils.js";
import { ROLE_LABEL } from "../perms.js";

export function mount(root) {
  const me = window.__ssp_user__ || {};
  if (me.role !== "admin") {
    root.innerHTML = `
    <div class="page page-users">
      <div class="card">
        <h3 style="margin:0 0 6px">无权限</h3>
        <div class="muted">账号管理仅对「技术负责人」开放。</div>
      </div>
    </div>`;
    return;
  }

  root.innerHTML = `
  <div class="page page-users">
    <div class="wrap">
      <div class="card">
        <h3 style="margin:0 0 4px">新增 / 编辑账号</h3>
        <div class="muted" style="font-size:11px">账号落平台业务库；密码 PBKDF2 加盐存储</div>
        <label>用户名 *</label><input id="u_name" placeholder="3-32 位字母/数字/_.-"/>
        <label>显示名</label><input id="u_display"/>
        <label>角色 *</label>
          <select id="u_role">
            <option value="admin">技术负责人</option>
            <option value="ops">运维值班</option>
            <option value="analyst">安全分析师</option>
            <option value="asset_admin">资产管理员</option>
          </select>
        <label>状态</label>
          <select id="u_status"><option value="active">启用</option><option value="disabled">停用</option></select>
        <label>密码（新增必填；编辑留空不改）</label><input id="u_pwd" type="password" placeholder="至少 6 位"/>
        <button id="u_save">保存账号</button>
        <button id="u_reset" class="ghost">清空</button>
        <div id="u_msg"></div>
      </div>
      <div>
        <div class="stats" id="u_stats"><span class="pill muted">加载中…</span></div>
        <div class="card" style="padding:0">
          <table>
            <thead><tr><th>用户名</th><th>显示名</th><th>角色</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead>
            <tbody id="u_rows"><tr><td colspan="6" class="empty">—</td></tr></tbody>
          </table>
        </div>
        <div id="u_msg2"></div>
      </div>
    </div>
  </div>`;

  const setMsg = (t, ok) => { $("#u_msg").innerHTML = `<span class="${ok ? "ok" : "err"}">${esc(t)}</span>`; };

  const load = async () => {
    try {
      const data = await apiGet("/api/users");
      const us = data.users || [];
      const active = us.filter(u => u.status === "active").length;
      $("#u_stats").innerHTML =
        `<span class="pill">账号总数 <b>${data.total}</b></span>` +
        `<span class="pill">启用 <b>${active}</b></span>` +
        `<span class="pill">停用 <b>${us.length - active}</b></span>`;
      $("#u_rows").innerHTML = us.length ? us.map(u => `
        <tr onclick='editUser("${esc(u.username)}")'>
          <td>${esc(u.username)}</td><td>${esc(u.display)}</td>
          <td><span class="tag">${esc(u.role_label || ROLE_LABEL[u.role] || u.role)}</span></td>
          <td><span class="tag ${u.status === "active" ? "" : "danger"}">${u.status === "active" ? "启用" : "停用"}</span></td>
          <td>${fmtTs(u.created_at)}</td>
          <td class="row-actions">
            <button class="ghost" onclick="event.stopPropagation();editUser('${esc(u.username)}')">编辑</button>
            <button class="danger" onclick="event.stopPropagation();delUser('${esc(u.username)}')">删除</button>
          </td>
        </tr>`).join("") : '<tr><td colspan="6" class="empty">暂无账号</td></tr>';
    } catch (e) {
      $("#u_stats").innerHTML = `<span class="pill err">加载失败：${esc(e.message)}</span>`;
    }
  };

  const save = async () => {
    const name = $("#u_name").value.trim();
    const pwd = $("#u_pwd").value;
    const isEdit = $("#u_name").dataset.edit === "1";
    const body = {
      display: $("#u_display").value.trim(),
      role: $("#u_role").value,
      status: $("#u_status").value,
    };
    if (pwd) body.password = pwd;
    try {
      if (isEdit) {
        await apiPut("/api/users/" + encodeURIComponent(name), body);
        setMsg("已更新账号 " + name, true);
      } else {
        if (!name || pwd.length < 6) { setMsg("请填写用户名 / 密码（≥6 位）", false); return; }
        body.username = name;
        await apiPost("/api/users", body);
        setMsg("已新增账号 " + name, true);
      }
      resetForm(); load();
    } catch (e) { setMsg("保存失败：" + e.message, false); }
  };

  const editUser = async username => {
    try {
      const u = await apiGet("/api/users/" + encodeURIComponent(username));
      const n = $("#u_name");
      n.value = u.username; n.dataset.edit = "1"; n.disabled = true;
      $("#u_display").value = u.display || "";
      $("#u_role").value = u.role || "analyst";
      $("#u_status").value = u.status || "active";
      $("#u_pwd").value = "";
      setMsg("编辑模式：修改后点「保存账号」（密码留空则不修改）", true);
    } catch (e) { setMsg("加载失败：" + e.message, false); }
  };

  const delUser = async username => {
    if (!confirm("确认删除账号 " + username + "？")) return;
    try {
      const d = await apiDelete("/api/users/" + encodeURIComponent(username));
      setMsg(d.ok ? "已删除 " + username : "删除失败：" + (d.error || ""), !!d.ok);
      load();
    } catch (e) { setMsg("请求失败：" + e.message, false); }
  };

  const resetForm = () => {
    const n = $("#u_name");
    n.value = ""; n.dataset.edit = "0"; n.disabled = false;
    $("#u_display").value = ""; $("#u_role").value = "analyst";
    $("#u_status").value = "active"; $("#u_pwd").value = "";
  };

  $("#u_save").onclick = save;
  $("#u_reset").onclick = () => { resetForm(); setMsg("", true); };
  window.editUser = editUser;
  window.delUser = delUser;

  load();
}

export function unmount() {
  if (window.editUser) delete window.editUser;
  if (window.delUser) delete window.delUser;
}
