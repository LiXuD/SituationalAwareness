// 拉黑审批 —— 平台内视图（ES 模块）
import { esc, fmtTs } from "../utils.js";
import { canWrite } from "../perms.js";

const LABEL = { pending_approval: "待审批", executed: "已提交封禁", rejected: "已驳回", failed: "落黑失败", reverted: "已解除" };
const OPERATOR = "lixd";

export function mount(root) {
  const writable = canWrite("soar");
  root.innerHTML = `
  <div class="page page-soar">
    <div class="wrap">
      <div class="card">
        <div class="row">
          <button id="gen">运行剧本 · 生成拉黑草稿</button>
          <button id="refresh" class="ghost">刷新</button>
          <span class="muted" style="font-size:12px">剧本自动生成草稿；<b>提交封禁必须由人工确认</b>，系统不会自动提交。</span>
        </div>
        <div class="stats" id="stats" style="margin-top:12px"><span class="pill muted">加载中…</span></div>
      </div>
      <div class="card">
        <div class="row" style="justify-content:space-between">
          <b>当前封禁规则（iptables 自定义链）</b>
          <span class="muted" style="font-size:12px" id="chainInfo"></span>
        </div>
        <div style="margin-top:10px" id="blocks"><span class="muted">—</span></div>
      </div>
      <div class="card" style="padding:0">
        <table>
          <thead><tr><th>创建时间</th><th>级别</th><th>规则</th><th>目标 IP</th><th>命中情报</th><th>状态</th><th>操作</th></tr></thead>
          <tbody id="rows"><tr><td colspan="7" class="empty">—</td></tr></tbody>
        </table>
      </div>
    </div>
    <div id="detail">
      <button class="close ghost" onclick="document.getElementById('detail').style.display='none'">关闭</button>
      <h3 id="dt" style="margin-top:0">草稿详情</h3>
      <pre id="dj"></pre>
    </div>
  </div>`;

  if (!writable) { document.getElementById("gen").disabled = true; }

  const showDetail = json => {
    document.getElementById("dj").textContent = JSON.stringify(JSON.parse(json), null, 2);
    document.getElementById("detail").style.display = "block";
  };
  window.showDetail = showDetail;

  const load = async () => {
    const rows = document.getElementById("rows");
    try {
      const { data } = await apiWrap("/soar/drafts?limit=100");
      const drafts = data.drafts || [];
      const c = { pending_approval: 0, executed: 0, rejected: 0, failed: 0, reverted: 0 };
      drafts.forEach(d => { c[d.status] = (c[d.status] || 0) + 1; });
      document.getElementById("stats").innerHTML =
        `<span class="pill">草稿总数 <b>${drafts.length}</b></span>` +
        `<span class="pill">待审批 <b>${c.pending_approval}</b></span>` +
        `<span class="pill">已提交封禁 <b>${c.executed}</b></span>` +
        `<span class="pill">已驳回 <b>${c.rejected}</b></span>` +
        `<span class="pill">落黑失败 <b>${c.failed}</b></span>`;
      rows.innerHTML = drafts.length ? drafts.map(d => {
        const ioc = d.threat && d.threat.matched
          ? `<span class="ioc">${esc(d.threat.value || "命中")}</span>` : `<span class="muted">未匹配</span>`;
        const canAct = writable && (d.status === "pending_approval" || d.status === "failed");
        return `<tr>
          <td>${fmtTs(d.created_at)}</td>
          <td><span class="tag ${d.grade}">${esc(d.grade)}</span></td>
          <td>${esc(d.rule_id)} ${esc(d.rule_name || "")}</td>
          <td><code>${esc(d.target_ip)}</code></td>
          <td>${ioc}</td>
          <td><span class="st ${d.status}">${LABEL[d.status] || d.status}</span></td>
          <td>
            <button class="ghost" onclick='showDetail(${JSON.stringify(JSON.stringify(d))})'>详情</button>
            ${canAct ? `<button class="ok" onclick="act('${d.draft_id}','approve')">通过</button>
            <button class="no" onclick="act('${d.draft_id}','reject')">驳回</button>` : ""}
          </td></tr>`;
      }).join("") : '<tr><td colspan="7" class="empty">暂无草稿，点上方「运行剧本」生成</td></tr>';
    } catch (e) {
      rows.innerHTML = `<tr><td colspan="7" class="empty err">加载失败：${esc(e.message)}</td></tr>`;
    }
  };

  const loadBlocks = async () => {
    try {
      const { data } = await apiWrap("/soar/blocks");
      document.getElementById("chainInfo").textContent = `chain=${data.chain || "-"} exists=${data.exists}`;
      const rules = data.rules || [];
      document.getElementById("blocks").innerHTML = rules.length
        ? rules.map(r => `<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:6px 0">
            <span><code>${esc(r.spec)}</code></span>
            ${writable ? `<button class="ghost" onclick="unblock('${esc(r.ip)}')">解除封禁</button>` : ""}</div>`).join("")
        : '<span class="muted">当前无封禁规则</span>';
    } catch (e) {
      document.getElementById("blocks").innerHTML = `<span class="err">读取失败：${esc(e.message)}</span>`;
    }
  };

  // 后端返回的 {status, data} 包装
  async function apiWrap(path) {
    const res = await fetch("/api/soar" + path, { method: "GET" });
    const txt = await res.text();
    let data; try { data = JSON.parse(txt); } catch (e) { data = { raw: txt }; }
    return { ok: res.ok, status: res.status, data };
  }

  window.act = async (id, kind) => {
    const verb = kind === "approve" ? "通过并执行落黑（iptables）" : "驳回";
    if (!confirm(`确认${verb}？草稿 ${id}`)) return;
    const { data, ok } = await apiWrapCall(`/soar/drafts/${id}/${kind}`, "POST", { operator: OPERATOR });
    if (!ok && data.error) alert(data.error + (data.block && data.block.error ? "\n" + data.block.error : ""));
    load(); loadBlocks();
  };
  window.unblock = async ip => {
    if (!confirm(`确认解除对 ${ip} 的封禁？`)) return;
    await apiWrapCall("/soar/blocks/remove", "POST", { ip, operator: OPERATOR });
    load(); loadBlocks();
  };
  async function apiWrapCall(path, method, body) {
    const res = await fetch("/api/soar" + path, {
      method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    const txt = await res.text();
    let data; try { data = JSON.parse(txt); } catch (e) { data = { raw: txt }; }
    return { ok: res.ok, status: res.status, data };
  }

  document.getElementById("refresh").onclick = () => { load(); loadBlocks(); };
  document.getElementById("gen").onclick = async () => {
    const { data } = await apiWrapCall("/soar/drafts/generate", "POST", {});
    alert(`剧本已运行：新增草稿 ${data.created_count || 0}，跳过 ${(data.skipped || []).length}。\n（草稿不会自动提交，请在列表中人工审批）`);
    load();
  };

  load(); loadBlocks();
}

export function unmount() {
  if (window.showDetail) delete window.showDetail;
  if (window.act) delete window.act;
  if (window.unblock) delete window.unblock;
}
