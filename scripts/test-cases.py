#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test-cases.py —— I-09 测试用例（反例/边界）执行器，纯标准库。

正例（P）由 I-08 的 `scripts/acceptance-demo.py`（A1~A8）覆盖，本脚本默认先跑一遍作为回归；
本脚本聚焦 PRD §10 的**边界与异常**：

  N1 探针断连        某源无数据 → 该源标记异常，**不影响其他源**（PRD §10）
  N2 审批超时        草稿长时间不审批 → **保留且不自动提交**（PRD §10）
  N3 落黑失败        执行落黑报错 → 记录失败原因，告警**保持待处置(open)**（PRD §10）
  N4 Excel 导入失败  含非法行 → **整批回滚 + 逐行报错**，存量资产不受影响（PRD §9/§10）

用法：
    python3 scripts/test-cases.py                 # 正例回归 + 全部反例
    python3 scripts/test-cases.py --skip-positive # 只跑反例
    python3 scripts/test-cases.py --only N3
退出码：0=全部通过；1=有失败项。
"""
import argparse
from http.cookiejar import CookieJar
import json
import os
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OS = os.environ.get("OS_URL", "http://localhost:9200")
CORR = os.environ.get("CORR_URL", "http://localhost:8091")
SOAR = os.environ.get("SOAR_URL", "http://localhost:8092")
ASSET = os.environ.get("ASSET_URL", "http://localhost:8090")
UI = os.environ.get("UI_URL", "http://localhost:8088")
COMPOSE = "docker compose -f deploy/compose.yml"
VENV_PY = "/Users/lixd/.workbuddy/binaries/python/envs/default/bin/python"
PY = VENV_PY if os.path.exists(VENV_PY) else sys.executable

RESULTS = []
_O = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                 urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def sh(cmd, timeout=300):
    e = dict(os.environ)
    e["PATH"] = "/usr/local/bin:" + e.get("PATH", "")
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, env=e, cwd=ROOT)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def http(method, url, body=None, timeout=30, ctype="application/json", headers=None):
    data = body if isinstance(body, (bytes, bytearray)) else (
        json.dumps(body).encode() if body is not None else None)
    h = {"Content-Type": ctype}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with _O.open(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw
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


def portal_login(username="admin", password="REDACTED-SSP-PWD"):
    """登录平台业务后端，返回会话 Cookie 值（失败返回 None）。"""
    jar = CookieJar()
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


def asset_total(tok):
    """经 portal API 读资产总数（后端无关：SQLite / PostgreSQL 均可）。"""
    st, d = http("GET", f"{UI}/api/asset/api/assets?size=1",
                 headers={"Cookie": f"ssp_session={tok}"})
    return d.get("total", -1) if isinstance(d, dict) else -1


def rec(tid, name, ok, detail=""):
    RESULTS.append((tid, name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {tid} {name}" + (f" —— {detail}" if detail else ""), flush=True)
    return ok


def health():
    st, d = http("GET", f"{CORR}/sources/health")
    return d if isinstance(d, dict) else {}


def clear_drafts():
    dbp = os.path.join(ROOT, "data", "ssp.db")
    try:
        c = sqlite3.connect(dbp)
        c.execute("DELETE FROM soar_drafts")
        c.execute("UPDATE blacklist SET status='inactive'")
        c.commit()
        c.close()
    except Exception:
        pass


def ipt_ips():
    st, d = http("GET", f"{SOAR}/soar/block/list")
    if isinstance(d, dict):
        return [r.get("ip") for r in d.get("rules", []) if isinstance(r, dict)]
    return []


def wait_port(url, n=25):
    for _ in range(n):
        if http("GET", url)[0] == 200:
            return True
        time.sleep(1)
    return False


# --------------------------------------------------------------------------- #
def suite_positive():
    print("\n▶ 正例回归（复核 I-08 acceptance-demo 的 A1~A8）", flush=True)
    rc, out = sh(f"{sys.executable} scripts/acceptance-demo.py", timeout=900)
    tail = [ln for ln in out.splitlines() if "通过" in ln or "FAIL" in ln]
    return rec("P0", "正例回归(A1~A8)", rc == 0, " | ".join(tail[-2:]) or f"rc={rc}")


def case_n1_probe_down():
    print("\n▶ N1 探针断连（标记该源异常，不影响其他源）", flush=True)
    h0 = health()
    states0 = {s["source"]: s["state"] for s in h0.get("sources", [])}
    if not (states0 and all(v == "ok" for v in states0.values())):
        return rec("N1", "探针断连", False, f"前置不满足（应全 ok）：{states0}")
    ev0 = {s["source"]: s["events"] for s in h0.get("sources", [])}
    # 制造"wazuh 源断连"：删掉 wazuh 索引（其他源不动）
    http("DELETE", f"{OS}/ssp-wazuh-*", timeout=30)
    time.sleep(1)
    h1 = health()
    st1 = {s["source"]: s["state"] for s in h1.get("sources", [])}
    ev1 = {s["source"]: s["events"] for s in h1.get("sources", [])}
    ok = (st1.get("wazuh") == "down"
          and st1.get("suricata") == "ok" and st1.get("zeek") == "ok"
          and h1.get("overall") == "degraded"
          and ev1.get("suricata") == ev0.get("suricata") and ev1.get("zeek") == ev0.get("zeek"))
    detail = f"断连前={states0} → 断连后={st1}；其他源事件数 suricata {ev0.get('suricata')}→{ev1.get('suricata')}、zeek {ev0.get('zeek')}→{ev1.get('zeek')}（应不变）"
    # 恢复
    sh("bash scripts/replay-demo.sh", timeout=600)
    h2 = health()
    st2 = {s["source"]: s["state"] for s in h2.get("sources", [])}
    ok = ok and all(v == "ok" for v in st2.values())
    return rec("N1", "探针断连", ok, detail + f"；恢复后={st2}")


def case_n2_approval_timeout():
    print("\n▶ N2 审批超时（草稿保留、不自动提交）", flush=True)
    tok = portal_login("ops", "REDACTED-SSP-PWD")
    if not tok:
        return rec("N2", "审批超时", False, "登录失败")
    hdrs = {"Cookie": f"ssp_session={tok}"}
    clear_drafts()
    http("POST", f"{UI}/api/soar/soar/drafts/generate", {}, headers=hdrs)
    st, d = http("GET", f"{UI}/api/soar/soar/drafts", headers=hdrs)
    items = (d or {}).get("drafts", []) if isinstance(d, dict) else []
    pend = [x for x in items if x.get("status") == "pending_approval"]
    if not pend:
        return rec("N2", "审批超时", False, "无待审批草稿（前置失败）")
    before = ipt_ips()
    wait = int(os.environ.get("N2_WAIT_SECONDS", "20"))
    print(f"  不审批，等待 {wait}s（模拟运维未及时处理）...", flush=True)
    time.sleep(wait)
    st, d2 = http("GET", f"{UI}/api/soar/soar/drafts", headers=hdrs)
    items2 = (d2 or {}).get("drafts", []) if isinstance(d2, dict) else []
    still = [x for x in items2 if x.get("status") == "pending_approval"]
    after = ipt_ips()
    ok = len(still) >= len(pend) and set(after) == set(before)
    return rec("N2", "审批超时", ok,
               f"等待后仍待审批 {len(still)} 条（原 {len(pend)}）；iptables 规则 {before}→{after}（应不变）")


def case_n3_block_failure():
    print("\n▶ N3 落黑失败（记录原因，告警保持待处置）", flush=True)
    ov = "/tmp/ssp-test-override.yml"
    with open(ov, "w") as f:
        f.write("services:\n  soar:\n    environment:\n"
                "      - SSP_HOST_PID=999999\n")     # 非法宿主 PID → nsenter 必失败
    sh(f"{COMPOSE} -f {ov} up -d --force-recreate soar")
    wait_port(f"{SOAR}/health")
    tok = portal_login("ops", "REDACTED-SSP-PWD")
    if not tok:
        sh(f"{COMPOSE} up -d --force-recreate soar")
        return rec("N3", "落黑失败", False, "登录失败")
    hdrs = {"Cookie": f"ssp_session={tok}"}
    clear_drafts()
    http("POST", f"{UI}/api/soar/soar/drafts/generate", {}, headers=hdrs)
    st, d = http("GET", f"{UI}/api/soar/soar/drafts", headers=hdrs)
    items = (d or {}).get("drafts", []) if isinstance(d, dict) else []
    pend = [x for x in items if x.get("status") == "pending_approval" and x.get("target_ip")]
    if not pend:
        sh(f"{COMPOSE} up -d --force-recreate soar")   # 还原
        return rec("N3", "落黑失败", False, "无待审批草稿（前置失败）")
    t = pend[0]
    ip, did, aid = t["target_ip"], t.get("draft_id") or t.get("id"), t.get("alert_id")
    http("POST", f"{UI}/api/soar/soar/drafts/{did}/approve",
         {"operator": "test-n3", "dry_run": False}, timeout=60, headers=hdrs)
    time.sleep(1)
    st, d3 = http("GET", f"{UI}/api/soar/soar/drafts", headers=hdrs)
    items3 = (d3 or {}).get("drafts", []) if isinstance(d3, dict) else []
    cur = next((x for x in items3 if (x.get("draft_id") or x.get("id")) == did), {})
    acts = [h.get("action") for h in cur.get("history", [])]
    blocks = ipt_ips()
    # 告警应保持 open 且记录失败原因
    al = {}
    for _ in range(10):
        http("POST", f"{OS}/ssp-alerts/_refresh")
        st, ad = http("GET", f"{OS}/ssp-alerts/_doc/{aid}")
        if isinstance(ad, dict) and ad.get("found"):
            al = ad["_source"].get("ssp", {}).get("alert", {})
            break
        time.sleep(0.5)
    ok = (cur.get("status") == "failed" and ip not in blocks
          and al.get("status") == "open"
          and str(al.get("response_action", "")).startswith("block_failed"))
    detail = (f"草稿 status={cur.get('status')}；history={acts}；"
              f"iptables 未新增({ip} in {blocks}={ip in blocks})；告警 status={al.get('status')} action={al.get('response_action')}")
    sh(f"{COMPOSE} up -d --force-recreate soar")       # 还原
    wait_port(f"{SOAR}/health")
    clear_drafts()
    return rec("N3", "落黑失败", ok, detail)


def _make_bad_xlsx(path):
    """用 openpyxl 生成一个"含非法行"的资产 Excel（合法表头 + 1 合法行 + 1 非法行）。"""
    gen = r'''
import sys
from openpyxl import Workbook
wb = Workbook(); ws = wb.active
ws.append(["资产名称","IP地址","重要度","风险评分","资产类型"])
ws.append(["测试资产-合法","10.99.0.1","一般",10,"服务器"])
ws.append(["测试资产-非法","not-an-ip","超级重要",999,"服务器"])
wb.save(sys.argv[1])
'''
    p = subprocess.run([PY, "-c", gen, path], capture_output=True, text=True)
    return p.returncode == 0, p.stderr


def case_n4_excel_import_rollback():
    print("\n▶ N4 Excel 导入失败（整批回滚 + 逐行报错）", flush=True)
    tok = portal_login("asset", "REDACTED-SSP-PWD")
    if not tok:
        return rec("N4", "Excel 导入回滚", False, "登录失败，无法获取会话")
    base = asset_total(tok)
    xp = "/tmp/ssp-bad-assets.xlsx"
    ok_gen, err = _make_bad_xlsx(xp)
    if not ok_gen:
        return rec("N4", "Excel 导入回滚", False, f"生成测试 xlsx 失败: {err[-160:]}")
    with open(xp, "rb") as f:
        content = f.read()
    b = uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"bad.xlsx\"\r\n"
            f"Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\n\r\n").encode() \
        + content + f"\r\n--{b}--\r\n".encode()
    st, resp = http("POST", f"{UI}/api/asset/api/assets/import", body, timeout=60,
                    ctype=f"multipart/form-data; boundary={b}",
                    headers={"Cookie": f"ssp_session={tok}"})
    after = asset_total(tok)
    errs = resp.get("errors", []) if isinstance(resp, dict) else []
    ok = (st == 422 and after == base and len(errs) >= 2)
    detail = (f"HTTP={st}（应 422）；资产数 {base}→{after}（应不变）；"
              f"逐行报错 {len(errs)} 条：{[ (e.get('row'), e.get('field'), e.get('reason')) for e in errs ]}")
    return rec("N4", "Excel 导入回滚", ok, detail)


CASES = {"N1": case_n1_probe_down, "N2": case_n2_approval_timeout,
         "N3": case_n3_block_failure, "N4": case_n4_excel_import_rollback}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-positive", action="store_true")
    ap.add_argument("--only", default=None, help="只跑某个用例，如 N3")
    args = ap.parse_args()

    print("=" * 74)
    print(" I-09 测试用例（反例 / 边界）—— PRD §9 验收标准 + §10 边界与异常")
    print("=" * 74)

    if not args.skip_positive:
        suite_positive()

    for tid, fn in CASES.items():
        if args.only and tid != args.only:
            continue
        try:
            fn()
        except Exception as e:
            rec(tid, "异常", False, f"{type(e).__name__}: {e}")

    print("\n" + "=" * 74)
    npass = sum(1 for r in RESULTS if r[2])
    for tid, name, ok, _ in RESULTS:
        print(f"  {'✔' if ok else '✘'} {tid:<4} {name:<18} {'PASS' if ok else 'FAIL'}")
    print(f"  ----------  {npass}/{len(RESULTS)} 通过  ----------")
    print("=" * 74)
    return 0 if npass == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
