// 流量回溯 —— 平台内视图（ES 模块）；支持从其它视图带 ?ip=&start=&end= 进入
import { apiGet } from "../api.js";
import { $, esc, fmtTs, fmtBytes, protoName, localToMs, msToLocalInput } from "../utils.js";
import { download } from "../api.js";

let LAST = [];

export function mount(root, ctx) {
  const q = ctx && ctx.query;
  root.innerHTML = `
  <div class="page page-traffic">
    <div class="pagehead">
      <h1>⇄ 流量回溯 <span>· 一体化安全态势感知平台</span></h1>
      <span class="sub">会话与 PCAP 回溯（平台原生，数据源 Arkime，经平台统一后端代理）</span>
      <span class="spacer"></span>
      <span class="sub" id="arkime-state">数据源检测中…</span>
    </div>
    <div class="wrap">
      <div class="bar">
        <div class="fld"><label>IP（源或目的）</label><input id="ip" placeholder="如 203.0.113.45" size="16"/></div>
        <div class="fld"><label>起始时间</label><input id="start" type="datetime-local"/></div>
        <div class="fld"><label>结束时间</label><input id="end" type="datetime-local"/></div>
        <div class="fld"><label>协议</label>
          <select id="proto"><option value="">全部</option><option value="tcp">TCP</option>
            <option value="udp">UDP</option><option value="icmp">ICMP</option></select></div>
        <div class="fld"><label>端口</label><input id="port" placeholder="如 80" size="6"/></div>
        <div class="fld"><label>条数</label><input id="limit" type="number" value="100" min="1" max="1000" size="5"/></div>
        <button id="btn-q">查询</button>
        <button id="btn-pcap" class="ghost">导出 PCAP</button>
        <button id="btn-reset" class="ghost">重置</button>
      </div>
      <div class="meta">
        <span>命中会话：<b id="m-total">—</b></span>
        <span>本次返回：<b id="m-returned">—</b></span>
        <span>筛选表达式：<b id="m-expr">—</b></span>
        <span>时间范围：<b id="m-date">—</b></span>
      </div>
      <div class="tblwrap">
        <table>
          <thead><tr><th>#</th><th>起始时间</th><th>源</th><th>目的</th><th>协议</th><th>字节</th><th>包</th><th>摘要</th></tr></thead>
          <tbody id="rows"><tr><td colspan="8" class="empty">加载中…</td></tr></tbody>
        </table>
      </div>
      <div class="panel" id="detail">
        <h2>会话详情 <span class="spacer"></span><span class="pill" id="d-sid"></span></h2>
        <div class="kv" id="d-kv"></div>
        <div class="hint" id="d-hint"></div>
      </div>
      <div class="panel">
        <h2>已入库 PCAP 文件</h2>
        <div id="files" class="hint">加载中…</div>
      </div>
      <div class="hint">说明：本页通过平台统一后端访问 Arkime，浏览器不再跳转 Arkime 自己的控制台。若列表为空，请先回放流量：<code>./scripts/arkime-import.sh</code>。</div>
    </div>
  </div>`;

  // 从其它视图带入的初始条件
  if (q) {
    if (q.get("ip")) $("#ip").value = q.get("ip");
    if (q.get("proto")) $("#proto").value = q.get("proto");
    if (q.get("port")) $("#port").value = q.get("port");
    if (q.get("start")) $("#start").value = msToLocalInput(q.get("start"));
    if (q.get("end")) $("#end").value = msToLocalInput(q.get("end"));
  }

  function qs() {
    const p = new URLSearchParams();
    if ($("#ip").value.trim()) p.set("ip", $("#ip").value.trim());
    if ($("#proto").value) p.set("proto", $("#proto").value);
    if ($("#port").value.trim()) p.set("port", $("#port").value.trim());
    p.set("limit", $("#limit").value || "100");
    const s = localToMs($("#start").value), e = localToMs($("#end").value);
    if (s != null && e != null) { p.set("start", s); p.set("end", e); }
    return p;
  }

  function summarize(s) {
    const bits = [];
    if (s.http && s.http.uri) bits.push("HTTP " + s.http.uri.join(",").slice(0, 60));
    if (s.dns && s.dns.host) bits.push("DNS " + s.dns.host);
    if (s.tls && s.tls.host) bits.push("TLS " + s.tls.host);
    if (!bits.length && s.network) bits.push(protoName(s.ipProtocol) + " " + s.network.packets + " 包");
    return bits.join(" · ") || "—";
  }

  function renderRows(list) {
    LAST = list || [];
    if (!LAST.length) {
      $("#rows").innerHTML = '<tr><td colspan="8" class="empty">无匹配会话（可先执行 ./scripts/arkime-import.sh 回放流量）</td></tr>';
      return;
    }
    $("#rows").innerHTML = LAST.map((s, i) => {
      const p = protoName(s.ipProtocol);
      return `<tr data-i="${i}">
        <td class="mono">${i + 1}</td>
        <td class="mono">${fmtTs(s.firstPacket)}</td>
        <td class="mono">${esc(s.source && s.source.ip)}${s.source && s.source.geo && s.source.geo.country_iso_code ? " <span class='pill'>" + esc(s.source.geo.country_iso_code) + "</span>" : ""}</td>
        <td class="mono">${esc(s.destination && s.destination.ip)}${s.destination && s.destination.geo && s.destination.geo.country_iso_code ? " <span class='pill'>" + esc(s.destination.geo.country_iso_code) + "</span>" : ""}</td>
        <td><span class="pill ${p}">${p.toUpperCase()}</span></td>
        <td class="mono">${fmtBytes(s.totDataBytes)}</td>
        <td class="mono">${(s.network && s.network.packets) || "-"}</td>
        <td>${esc(summarize(s))}</td>
      </tr>`;
    }).join("");
    document.querySelectorAll("#rows tr[data-i]").forEach(tr => {
      tr.onclick = () => showDetail(LAST[Number(tr.dataset.i)]);
    });
  }

  function showDetail(s) {
    if (!s) return;
    $("#detail").style.display = "block";
    $("#d-sid").textContent = s.id || "-";
    const rows = [
      ["会话 ID", s.id], ["起始", fmtTs(s.firstPacket)], ["结束", fmtTs(s.lastPacket)],
      ["源", (s.source && s.source.ip) + ":" + (s.source && s.source.port)],
      ["目的", (s.destination && s.destination.ip) + ":" + (s.destination && s.destination.port)],
      ["协议", protoName(s.ipProtocol)],
      ["总字节", fmtBytes(s.totDataBytes) + "（源 " + (s.source && s.source.bytes || 0) + " / 目的 " + (s.destination && s.destination.bytes || 0) + "）"],
      ["包数", (s.network && s.network.packets) + "（源 " + (s.source && s.source.packets || 0) + " / 目的 " + (s.destination && s.destination.packets || 0) + "）"],
      ["节点", s.node],
    ];
    if (s.http && s.http.uri) rows.push(["HTTP URI", s.http.uri.join(" , ")]);
    if (s.dns && s.dns.host) rows.push(["DNS", s.dns.host]);
    $("#d-kv").innerHTML = rows.map(([k, v]) => `<div class="k">${esc(k)}</div><div class="mono">${esc(v)}</div>`).join("");
    const p = qs();
    if (s.source && s.source.ip && !p.get("ip")) p.set("ip", s.source.ip);
    $("#d-hint").innerHTML = `导出该会话相关 PCAP：` +
      `<a style="color:var(--acc)" href="/api/traffic/pcap?${p.toString()}" download="ssp-session.pcap">下载</a>` +
      `（按当前筛选条件；如需精确单会话可在 IP 框填入对端 IP）`;
  }

  async function load() {
    $("#btn-q").disabled = true;
    try {
      const d = await apiGet("/api/traffic/sessions?" + qs().toString());
      $("#m-total").textContent = d.recordsTotal != null ? d.recordsTotal : "—";
      $("#m-returned").textContent = (d.data || []).length;
      $("#m-expr").textContent = (d._query && d._query.expression) || "—";
      $("#m-date").textContent = (d._query && d._query.date) || "—";
      renderRows(d.data);
    } catch (e) {
      $("#rows").innerHTML = `<tr><td colspan="8" class="empty err">查询失败：${esc(e.message)}</td></tr>`;
    } finally { $("#btn-q").disabled = false; }
  }

  async function loadHealth() {
    try {
      const d = await apiGet("/api/traffic/health");
      const ok = d && !d.error;
      $("#arkime-state").innerHTML = `数据源 Arkime：` +
        (ok ? `<span style="color:var(--ok)">● 正常</span>（集群 ${esc(d.status)}，节点 ${esc(d.number_of_nodes)}）`
          : `<span style="color:var(--p0)">● 异常</span>`);
    } catch (e) {
      $("#arkime-state").innerHTML = `<span style="color:var(--p0)">● 平台后端不可达</span>（${esc(e.message)}）`;
    }
  }

  async function loadFiles() {
    try {
      const d = await apiGet("/api/traffic/files");
      const rows = d.data || [];
      $("#files").innerHTML = rows.length
        ? rows.map(f => `<div>• <b>${esc(f.name)}</b> — ${f.packets} 包 / ${fmtBytes(f.packetsSize || f.filesize)} / 节点 ${esc(f.node)}</div>`).join("")
        : "（暂无入库 PCAP 文件）";
    } catch (e) { $("#files").textContent = "读取失败：" + e.message; }
  }

  $("#btn-q").onclick = load;
  $("#btn-reset").onclick = () => {
    ["ip", "start", "end", "port"].forEach(id => $("#" + id).value = "");
    $("#proto").value = ""; $("#limit").value = "100"; load();
  };
  $("#btn-pcap").onclick = () => download("/api/traffic/pcap?" + qs().toString());
  ["ip", "proto", "port", "limit", "start", "end"].forEach(id =>
    $("#" + id).addEventListener("keydown", e => { if (e.key === "Enter") load(); }));

  loadHealth(); load(); loadFiles();
}

export function unmount() { LAST = []; }
