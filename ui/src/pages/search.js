// 统一检索 —— 平台内视图（ES 模块）
import { apiPost } from "../api.js";
import { esc, fmtTs, isPrivateIP } from "../utils.js";

const RANGES = { "15m": "now-15m", "1h": "now-1h", "24h": "now-24h", "7d": "now-7d", "all": null };

export function mount(root) {
  root.innerHTML = `
  <div class="page page-search">
    <div class="wrap">
      <div class="card">
        <label>时间范围</label>
        <select id="range">
          <option value="15m">最近 15 分钟</option>
          <option value="1h" selected>最近 1 小时</option>
          <option value="24h">最近 24 小时</option>
          <option value="7d">最近 7 天</option>
          <option value="all">全部</option>
        </select>
        <label>关键字（规则/URL/域名/文件/原始日志）</label>
        <input id="kw" placeholder="如 evil-c2 / payload.bin"/>
        <label>来源 (event.module)</label>
        <select id="module">
          <option value="">全部</option>
          <option value="suricata">Suricata</option>
          <option value="zeek">Zeek</option>
          <option value="wazuh">Wazuh</option>
        </select>
        <label>事件类型 (event.kind)</label>
        <select id="kind">
          <option value="">全部</option>
          <option value="alert">alert 告警</option>
          <option value="event">event 事件</option>
        </select>
        <label>源 IP</label>
        <input id="sip" placeholder="如 203.0.113.45"/>
        <label>目的 IP</label>
        <input id="dip" placeholder="如 8.8.8.8"/>
        <button id="go">检索</button>
      </div>
      <div>
        <div class="stats" id="stats"><span class="pill muted">输入条件后点「检索」</span></div>
        <div class="card" style="padding:0">
          <table>
            <thead><tr><th>时间</th><th>来源</th><th>类型</th><th>源</th><th>目的</th><th>规则 / 摘要</th></tr></thead>
            <tbody id="rows"><tr><td colspan="6" class="empty">—</td></tr></tbody>
          </table>
        </div>
        <div class="stats" style="margin-top:12px">
          <span class="pill muted">检索目标：别名 <b>ssp-events</b>（跨 Suricata / Zeek / Wazuh 归一事件）</span>
        </div>
      </div>
    </div>
    <div id="detail">
      <button class="close" onclick="document.getElementById('detail').style.display='none'">关闭</button>
      <h3 id="dt" style="margin-top:0">事件详情</h3>
      <pre id="dj"></pre>
    </div>
  </div>`;

  const search = async () => {
    const rows = document.getElementById("rows");
    const stats = document.getElementById("stats");
    rows.innerHTML = '<tr><td colspan="6" class="empty">检索中…</td></tr>';
    try {
      const body = buildQuery();
      const data = await apiPost("/api/os/ssp-events/_search", body);
      const total = data.hits.total.value ?? data.hits.total;
      const agg = data.aggregations || {};
      stats.innerHTML =
        `<span class="pill">命中 <b>${total}</b></span>` +
        Object.entries(agg).map(([k, v]) =>
          `${v.buckets.map(b => `<span class="pill">${k.replace("by_", "")} ${b.key}: <b>${b.doc_count}</b></span>`).join("")}`).join("");

      const win = ts => {
        if (!ts) return "";
        const t = new Date(ts).getTime();
        if (isNaN(t)) return "";
        return `&start=${t - 300000}&end=${t + 300000}`;
      };
      const flow = (ip, ts) => isPrivateIP(ip)
        ? ""
        : ` <a href="#/traffic?ip=${encodeURIComponent(ip)}${win(ts)}" onclick="event.stopPropagation()" title="在平台内查看该 IP 的流量会话（不跳第三方控制台）" style="color:#38bdf8;text-decoration:none">⇄</a>`;

      rows.innerHTML = data.hits.hits.length ? data.hits.hits.map(h => {
        const s = h._source, mod = s.event?.module || "", kind = s.event?.kind || "";
        const summary = s.rule?.name || s.rule?.description || s.url?.full || s.dns?.question.name ||
          s.file?.name || s["log.original"] || s.event?.category || "";
        return `<tr onclick='showDetail(${JSON.stringify(JSON.stringify(s))})'>
          <td>${fmtTs(s["@timestamp"])}</td>
          <td><span class="tag ${mod}">${mod}</span></td>
          <td><span class="tag ${kind === "alert" ? "alert" : ""}">${kind}</span></td>
          <td>${s.source?.ip || "-"}${s.source?.port ? ":" + s.source.port : ""}${flow(s.source?.ip, s["@timestamp"])}</td>
          <td>${s.destination?.ip || "-"}${s.destination?.port ? ":" + s.destination.port : ""}${flow(s.destination?.ip, s["@timestamp"])}</td>
          <td title="${summary}">${summary}</td>
        </tr>`;
      }).join("") : '<tr><td colspan="6" class="empty">无结果</td></tr>';
    } catch (e) {
      rows.innerHTML = `<tr><td colspan="6" class="empty err">检索失败：${esc(e.message)}</td></tr>`;
    }
  };

  function buildQuery() {
    const must = [], filter = [];
    const r = RANGES[document.getElementById("range").value];
    if (r) filter.push({ range: { "@timestamp": { gte: r } } });
    const kw = document.getElementById("kw").value.trim();
    if (kw) must.push({ query_string: { query: kw, fields: ["rule.name^3", "rule.description", "url.full", "url.domain", "dns.question.name", "file.name", "file.hash.sha256", "log.original", "event.module"] } });
    const m = document.getElementById("module").value; if (m) filter.push({ term: { "event.module": m } });
    const k = document.getElementById("kind").value; if (k) filter.push({ term: { "event.kind": k } });
    const sip = document.getElementById("sip").value.trim(); if (sip) filter.push({ term: { "source.ip": sip } });
    const dip = document.getElementById("dip").value.trim(); if (dip) filter.push({ term: { "destination.ip": dip } });
    return {
      size: 50, sort: [{ "@timestamp": "desc" }],
      query: { bool: { must: must.length ? must : [{ match_all: {} }], filter } },
      aggs: { by_module: { terms: { field: "event.module" } }, by_kind: { terms: { field: "event.kind" } } },
      _source: ["@timestamp", "event.module", "event.kind", "event.category", "source.ip", "source.port", "destination.ip", "destination.port", "rule.name", "rule.description", "url.full", "dns.question.name", "file.name", "host.name", "source.geo"],
    };
  }

  window.showDetail = (json) => {
    document.getElementById("dj").textContent = JSON.stringify(JSON.parse(json), null, 2);
    document.getElementById("detail").style.display = "block";
  };

  document.getElementById("go").onclick = search;
  document.getElementById("kw").addEventListener("keydown", e => { if (e.key === "Enter") search(); });
  search();
}

export function unmount() {
  if (window.showDetail) delete window.showDetail;
}
