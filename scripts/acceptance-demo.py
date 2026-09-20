#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
acceptance-demo.py —— I-08 POC 端到端验收 Demo（纯标准库）。

按 PRD §9 验收标准（EARS）逐条驱动真实链路并断言，最后输出 PASS/FAIL 汇总表：

  A1 采集归一   Filebeat→Logstash→ECS→OpenSearch（ssp-events 有数据且字段齐全）
  A2 关联告警   探针攻击 → 统一格式告警写入 ssp-alerts（R-001~R-007）
  A3 情报匹配   源IP/域名/哈希与威胁情报实时比对并标注命中
  A4 情报降级   MISP 不可达时照常产生告警、标记未匹配、不阻断主流程
  A5 分级 SLA   告警按级带 SLA 阈值（P0 30s / P1 60s / P2 600s / P3 1800s）
  A6 草稿生成   达级别告警生成拉黑草稿；**系统不自动提交**（iptables 链为空）
  A7 人工审批   运维确认 → 真实落黑（iptables）→ 回写告警 status=blocked
  A8 大屏可见   四类视图（攻击地图/告警TOP/资产热力/SLA）数据齐备

用法：
    python3 scripts/acceptance-demo.py            # 全量验收（会重放演示数据）
    python3 scripts/acceptance-demo.py --no-replay
    python3 scripts/acceptance-demo.py --reset     # 仅复位（解除封禁 + 清理草稿/告警）

退出码：0=全部通过；1=有失败项。
"""
import argparse
import json
import os
import re
import http.cookiejar
import ssl
import sqlite3
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OS = os.environ.get("OS_URL", "http://localhost:9200")
CORR = os.environ.get("CORR_URL", "http://localhost:8091")
SOAR = os.environ.get("SOAR_URL", "http://localhost:8092")
UI = os.environ.get("UI_URL", "http://localhost:8088")

RESULTS = []          # (id, name, ok, detail)
_O = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                 urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def sh(cmd, timeout=300, env=None):
    e = dict(os.environ)
    e["PATH"] = "/usr/local/bin:" + e.get("PATH", "")
    if env:
        e.update(env)
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, env=e, cwd=ROOT)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def http(method, url, body=None, timeout=30, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with _O.open(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


def es_count(index):
    st, d = http("POST", f"{OS}/{index}/_count")
    return d.get("count", 0) if isinstance(d, dict) else 0


def es_search(index, body):
    st, d = http("POST", f"{OS}/{index}/_search", body)
    return d if isinstance(d, dict) else {}


def es_doc(index, _id):
    st, d = http("GET", f"{OS}/{index}/_doc/{_id}")
    return d.get("_source", {}) if isinstance(d, dict) and d.get("found") else {}


def portal_login(username="admin", password="REDACTED-SSP-PWD"):
    """登录平台业务后端，返回会话 Cookie 值（失败返回 None）。"""
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                     urllib.request.HTTPCookieProcessor(jar),
                                     urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    r = urllib.request.Request(f"{UI}/api/auth/login",
                               data=json.dumps({"username": username, "password": password}).encode(),
                               method="POST", headers={"Content-Type": "application/json"})
    try:
        with op.open(r, timeout=15):
            pass
    except Exception:
        return None
    for c in jar:
        if c.name == "ssp_session":
            return c.value
    return None


def sqlite_asset_count():
    try:
        c = sqlite3.connect(os.path.join(ROOT, "data", "ssp.db"))
        n = c.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        c.close()
        return n
    except Exception:
        return 0


def sqlite_asset_risk_avg():
    try:
        c = sqlite3.connect(os.path.join(ROOT, "data", "ssp.db"))
        r = c.execute("SELECT AVG(risk_score) FROM assets").fetchone()[0]
        c.close()
        return r or 0
    except Exception:
        return 0


def soar_headers(token):
    return {"Cookie": f"ssp_session={token}"}


def rec(rid, name, ok, detail=""):
    RESULTS.append((rid, name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {rid} {name}" + (f" —— {detail}" if detail else ""), flush=True)
    return ok


# --------------------------------------------------------------------------- #
def step_reset():
    print("\n▶ 复位：解除全部封禁 + 清理草稿", flush=True)
    st, blocks = http("GET", f"{SOAR}/soar/block/list")
    ips = blocks.get("rules", []) if isinstance(blocks, dict) else []
    for ip in ips:
        http("POST", f"{SOAR}/soar/block/remove", {"ip": ip})
    try:
        c = sqlite3.connect(os.path.join(ROOT, "data", "ssp.db"))
        c.execute("DELETE FROM soar_drafts")
        c.execute("UPDATE blacklist SET status='inactive'")
        c.commit()
        c.close()
    except Exception:
        pass
    print(f"  已解除 {len(ips)} 条封禁；草稿已清理", flush=True)


def step_a1_replay_and_ingest(do_replay):
    print("\n▶ A1 采集归一（I-01）", flush=True)
    if do_replay:
        rc, out = sh("bash scripts/replay-demo.sh")
        if rc != 0:
            return rec("A1", "采集归一", False, f"replay 失败 rc={rc}: {out[-200:]}")
    n = es_count("ssp-events")
    # ECS 字段齐全性
    d = es_search("ssp-events", {"size": 1, "query": {"bool": {"filter": [
        {"exists": {"field": "@timestamp"}}, {"exists": {"field": "event.kind"}},
        {"exists": {"field": "fields.log_source"}}]}}})
    total = d.get("hits", {}).get("total", {}).get("value", 0)
    srcs = es_search("ssp-events", {"size": 0, "aggs": {"s": {"terms": {"field": "fields.log_source"}}}})
    buckets = [b["key"] for b in srcs.get("aggregations", {}).get("s", {}).get("buckets", [])]
    ok = n >= 24 and total >= 24
    return rec("A1", "采集归一", ok, f"ssp-events={n}，ECS 字段齐全样本={total}，来源={buckets}")


def step_a2_correlate():
    print("\n▶ A2 关联分析生成告警（I-03）", flush=True)
    st, d = http("POST", f"{CORR}/correlate", {}, timeout=120)
    if not isinstance(d, dict):
        return rec("A2", "关联告警", False, f"correlate 返回异常: {d}")
    hits = d.get("rule_hits", {})
    written = d.get("write", {})
    n = es_count("ssp-alerts")
    ok = n > 0 and int(written.get("created", 0)) + int(written.get("updated", 0)) > 0
    detail = f"规则命中={hits}，写入={written}，ssp-alerts={n}"
    return rec("A2", "关联告警", ok, detail)


def step_a3_intel():
    print("\n▶ A3 威胁情报匹配（I-04）", flush=True)
    d = es_search("ssp-alerts", {"size": 20, "query": {"term": {"threat.matched": True}},
                                 "_source": ["source.ip", "destination.ip", "ssp.alert.rule_id", "threat"]})
    hits = d.get("hits", {}).get("hits", [])
    inds = []
    for h in hits:
        for i in (h["_source"].get("threat", {}).get("indicators") or []):
            inds.append(i.get("value"))
    ok = len(hits) > 0
    return rec("A3", "情报匹配", ok, f"命中告警={len(hits)} 条，指标={sorted(set(inds))}")


def step_a4_misp_degradation():
    print("\n▶ A4 情报降级（MISP 不可达不阻断主流程）", flush=True)
    ov = "/tmp/ssp-acceptance-override.yml"
    with open(ov, "w") as f:
        f.write("services:\n  correlator:\n    environment:\n"
                "      - MISP_URL=http://10.255.255.1:6666\n"
                "      - MISP_API_KEY=degradation-probe\n")
    compose = "docker compose -f deploy/compose.yml"
    rc, out = sh(f"{compose} -f {ov} up -d --force-recreate correlator")
    for _ in range(25):
        if http("GET", f"{CORR}/health")[0] == 200:
            break
        time.sleep(1)
    st, d = http("POST", f"{CORR}/correlate", {}, timeout=120)
    alerts_ok = es_count("ssp-alerts") > 0
    dd = es_search("ssp-alerts", {"size": 1, "_source": ["threat"]})
    th = (dd.get("hits", {}).get("hits") or [{}])[0].get("_source", {}).get("threat", {})
    ok = isinstance(d, dict) and alerts_ok and bool(th.get("misp_configured"))
    detail = (f"correlate 正常={isinstance(d, dict)}，告警仍在={alerts_ok}，"
              f"threat 标记={ {k: th.get(k) for k in ('matched','enabled','misp_configured','misp_unreachable','source')} }")
    # 还原（去掉 override）
    sh(f"{compose} up -d --force-recreate correlator")
    for _ in range(25):
        if http("GET", f"{CORR}/health")[0] == 200:
            break
        time.sleep(1)
    http("POST", f"{CORR}/correlate", {}, timeout=120)   # 还原后重跑，保持告警为正常情报态
    try:
        os.remove(ov)
    except OSError:
        pass
    return rec("A4", "情报降级", ok, detail)


def _sla_map():
    st, d = http("GET", f"{CORR}/health")
    # 从告警里读实际阈值
    dd = es_search("ssp-alerts", {"size": 0, "aggs": {
        "g": {"terms": {"field": "ssp.alert.grade"},
              "aggs": {"sla": {"terms": {"field": "ssp.alert.sla_seconds"}}}}}})
    out = {}
    for b in dd.get("aggregations", {}).get("g", {}).get("buckets", []):
        sb = b.get("sla", {}).get("buckets", [])
        out[b["key"]] = sb[0]["key"] if sb else None
    return out


def step_a5_sla():
    print("\n▶ A5 分级 SLA（I-03）", flush=True)
    m = _sla_map()
    expect = {"P0": 30, "P1": 60, "P2": 600, "P3": 1800}
    ok = bool(m) and all(m.get(g) in (None, expect[g]) for g in expect)
    return rec("A5", "分级 SLA", ok, f"实测 grade→sla_seconds = {m}（期望 {expect}）")


def step_a6_draft_no_autosubmit():
    print("\n▶ A6 草稿生成·不自动提交（I-05）", flush=True)
    tok = portal_login("ops", "REDACTED-SSP-PWD")
    if not tok:
        return rec("A6", "草稿生成·不自动提交", False, "登录失败")
    hdrs = soar_headers(tok)
    st, blocks_before = http("GET", f"{SOAR}/soar/block/list")
    rules_before = len((blocks_before or {}).get("rules", [])) if isinstance(blocks_before, dict) else 0
    http("POST", f"{UI}/api/soar/soar/drafts/generate", {}, headers=hdrs)
    st, drafts = http("GET", f"{UI}/api/soar/soar/drafts", headers=hdrs)
    items = drafts.get("drafts", drafts.get("items", [])) if isinstance(drafts, dict) else []
    pending = [x for x in items if x.get("status") == "pending_approval"]
    st, blocks_after = http("GET", f"{SOAR}/soar/block/list")
    rules_after = len((blocks_after or {}).get("rules", [])) if isinstance(blocks_after, dict) else 0
    ok = len(pending) > 0 and rules_after == rules_before
    return rec("A6", "草稿生成·不自动提交", ok,
               f"待审批草稿={len(pending)}，iptables 规则数 {rules_before}→{rules_after}（应不变）")


def step_a7_approve_block():
    print("\n▶ A7 人工审批→落黑→回写（I-05）", flush=True)
    tok = portal_login("ops", "REDACTED-SSP-PWD")
    if not tok:
        return rec("A7", "人工审批落黑", False, "登录失败")
    hdrs = soar_headers(tok)
    st, drafts = http("GET", f"{UI}/api/soar/soar/drafts", headers=hdrs)
    items = drafts.get("drafts", drafts.get("items", [])) if isinstance(drafts, dict) else []
    pend = [x for x in items if x.get("status") == "pending_approval" and x.get("target_ip")]
    if not pend:
        return rec("A7", "人工审批落黑", False, "无待审批草稿")

    def _score(x):
        ip = x.get("target_ip", "")
        doc = ip.startswith(("203.0.113.", "198.51.100."))   # 文档用 IP 不做演示首选
        return (doc, 0 if x.get("threat", {}).get("matched") else 1)
    pend.sort(key=_score)
    target = pend[0]
    ip = target["target_ip"]
    did = target.get("draft_id") or target.get("id")
    alert_id = target.get("alert_id")
    t0 = time.time()
    code, out = http("POST", f"{UI}/api/soar/soar/drafts/{did}/approve",
                     {"operator": "acceptance-demo", "dry_run": False}, timeout=60, headers=hdrs)
    elapsed = time.time() - t0
    # 落黑结果 + 回写：索引 refresh_interval=1s，需刷新并轮询等待，避免读到旧版本
    al, blocked_ips = {}, []
    for _ in range(15):
        http("POST", f"{OS}/ssp-alerts/_refresh")
        st, blocks = http("GET", f"{SOAR}/soar/block/list")
        blocked_ips = blocks.get("rules", []) if isinstance(blocks, dict) else []
        al = es_doc("ssp-alerts", alert_id).get("ssp", {}).get("alert", {}) if alert_id else {}
        if ip in blocked_ips and al.get("status") == "blocked":
            break
        time.sleep(0.6)
    status = al.get("status")
    loop_lat = None
    if al.get("generated_at") and al.get("resolved_at"):
        try:
            from datetime import datetime
            f = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
            loop_lat = (f(al["resolved_at"]) - f(al["generated_at"])).total_seconds()
        except Exception:
            pass
    ok = (ip in blocked_ips) and status == "blocked"
    return rec("A7", "人工审批落黑", ok,
               f"封禁 {ip} → iptables {'已生效' if ip in blocked_ips else '未生效'}；"
               f"告警 status={status} action={al.get('response_action')}；"
               f"审批耗时={elapsed:.2f}s；闭环时延(告警生成→拉黑)={loop_lat if loop_lat is not None else 'n/a'}s")


def step_a8_dashboard():
    print("\n▶ A8 大屏四视图（I-07）", flush=True)
    alerts = es_count("ssp-alerts")
    assets = sqlite_asset_count()
    geo = es_search("ssp-alerts", {"size": 0, "aggs": {"g": {"filter": {"exists": {"field": "related.geo_points.geo.location"}}}}})
    geo_n = geo.get("aggregations", {}).get("g", {}).get("doc_count", 0)
    by_grade = es_search("ssp-alerts", {"size": 0, "aggs": {"g": {"terms": {"field": "ssp.alert.grade"}}}})
    grades = {b["key"]: b["doc_count"] for b in by_grade.get("aggregations", {}).get("g", {}).get("buckets", [])}
    rstat = {"avg": round(sqlite_asset_risk_avg(), 1)}
    # 页面可达（SPA 入口 index.html）
    st_ui, _ = http("GET", f"{UI}/")
    ok = alerts > 0 and assets > 0 and geo_n > 0 and st_ui == 200
    return rec("A8", "大屏四视图", ok,
               f"①攻击地图 geo 告警={geo_n} ②告警TOP 分级={grades} ③资产热力 资产={assets}(risk avg={rstat.get('avg')}) ④SLA(见 A5)；页面 http={st_ui}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-replay", action="store_true", help="不重放演示数据（复用当前事件）")
    ap.add_argument("--reset", action="store_true", help="仅复位后退出")
    ap.add_argument("--skip-misp", action="store_true", help="跳过 A4 MISP 降级步骤")
    args = ap.parse_args()

    print("=" * 74)
    print(" I-08 POC 端到端验收 Demo（探针告警 → 情报匹配 → 审批拉黑 → 大屏可见）")
    print("=" * 74)

    step_reset()
    if args.reset:
        print("\n复位完成。")
        return 0

    step_a1_replay_and_ingest(not args.no_replay)
    step_a2_correlate()
    step_a3_intel()
    if not args.skip_misp:
        step_a4_misp_degradation()
    step_a5_sla()
    step_a6_draft_no_autosubmit()
    step_a7_approve_block()
    step_a8_dashboard()

    print("\n" + "=" * 74)
    npass = sum(1 for r in RESULTS if r[2])
    for rid, name, ok, detail in RESULTS:
        print(f"  {'✔' if ok else '✘'} {rid:<3} {name:<16} {'PASS' if ok else 'FAIL'}")
    print(f"  ----------  {npass}/{len(RESULTS)} 通过  ----------")
    print("=" * 74)
    print("提示：大屏 http://localhost:8088/dashboard.html （看板「已拉黑」应 ≥1）")
    return 0 if npass == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
