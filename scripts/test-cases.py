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

I-12 资产测绘（本脚本追加，正例 A9~A11 + 反例 N5~N7）：
  A9  被动测绘本轮化  Zeek 连接记录 → 候选池（幂等；越权/公网 IP 不生成候选）
  A10 采纳           同 IP 已有人工资产 → **合并且不改人工字段**；无同 IP → 新建 discovered 资产
  A11 忽略           候选置 ignored，后续测绘**不回退**其状态
  N5  OS 不可达      测绘失败但**不影响存量资产**与平台其它功能
  N6  越权 IP 采纳   授权网段外候选 → 422 拒绝
  N7  越权角色       analyst 触发/采纳 → 403（读候选仍 200）

I-13 多分支汇聚（本脚本追加，正例 A13~A15 + 反例 N10~N11）：
  A13 分支打标入库    事件带 ssp.branch，可按分支检索/聚合
  A14 分支登记与探测  登记/在线判定/停用判定（disabled）
  A15 分支独立        某分支断链 → 该分支 no_data，**其他分支事件量不变**
  N10 未登记分支      事件里有但未登记 → 提示 unregistered，不阻断入库
  N11 探测遇 OS 不可达 探测失败但**不误改分支状态**，平台列表仍可读

用法：
    python3 scripts/test-cases.py                 # 正例回归 + 全部反例
    python3 scripts/test-cases.py --skip-positive # 只跑反例
    python3 scripts/test-cases.py --only N3
退出码：0=全部通过；1=有失败项。
"""
import argparse
from http.cookiejar import CookieJar
import hashlib
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
PORTAL = os.environ.get("PORTAL_URL", "http://localhost:8093")   # 统一业务后端（直连，绕过 nginx）
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


def asset_by_ip(tok, ip):
    st, d = http("GET", f"{UI}/api/asset/api/assets?q={ip}&size=50",
                 headers={"Cookie": f"ssp_session={tok}"})
    return [x for x in ((d or {}).get("items") or []) if x.get("ip") == ip]


# --------------------------- I-12 资产测绘辅助 --------------------------- #
# Docker Desktop(macOS) 绑定挂载下，**宿主直写 SQLite → 容器内定时可见**有约 1s 传播延迟；
# 直写后需短暂等待，否则 portal（容器内）读到旧快照会误判（实测 1.2s 足够）。
DB_SYNC_WAIT = 1.2


def _ssp_db():
    return os.path.join(ROOT, "data", "ssp.db")


def _sqlite_conn():
    return sqlite3.connect(_ssp_db())


def reset_discovery():
    """测试隔离：清空候选池 + 清除测绘产生的 discovered 资产 + 复位测绘配置。"""
    try:
        c = _sqlite_conn()
        c.execute("DELETE FROM asset_candidates")
        c.execute("DELETE FROM assets WHERE source IN ('discovered','scan')")
        c.execute("DELETE FROM config WHERE key LIKE 'discovery.%'")
        c.commit()
        c.close()
        time.sleep(DB_SYNC_WAIT)
    except Exception:
        pass


def clear_discovery_config():
    """测试收尾：移除测绘配置覆写，使默认值（min_obs=3 等）重新生效。"""
    try:
        c = _sqlite_conn()
        c.execute("DELETE FROM config WHERE key LIKE 'discovery.%'")
        c.commit()
        c.close()
    except Exception:
        pass


def insert_candidate(ip, port, proto, service, obs=1, status="pending"):
    """直接向候选池插入一条候选（用于构造“资产库无同 IP”/“越权 IP”等确定性场景）。"""
    cid = hashlib.sha1(f"{ip}|{port}|{proto}|{service}".encode()).hexdigest()
    now = int(time.time())
    c = _sqlite_conn()
    c.execute("DELETE FROM asset_candidates WHERE id=?", (cid,))
    c.execute(
        "INSERT INTO asset_candidates (id, ip, port, proto, service, obs_count, first_seen, last_seen, "
        "source, evidence, status, asset_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (cid, ip, port, proto, service, obs, now, now, "passive", "synthetic", status, "", now, now))
    c.commit()
    c.close()
    time.sleep(DB_SYNC_WAIT)
    return cid


def delete_candidate(cid):
    try:
        c = _sqlite_conn()
        c.execute("DELETE FROM asset_candidates WHERE id=?", (cid,))
        c.commit()
        c.close()
    except Exception:
        pass


def disc_config(tok, body):
    return http("PUT", f"{UI}/api/discovery/config", body,
                headers={"Cookie": f"ssp_session={tok}"})


def disc_run(tok):
    return http("POST", f"{UI}/api/discovery/run", {},
                headers={"Cookie": f"ssp_session={tok}"})


def disc_candidates(tok, status="pending", size=200):
    st, d = http("GET", f"{UI}/api/discovery/candidates?status={status}&size={size}",
                 headers={"Cookie": f"ssp_session={tok}"})
    return (d or {}).get("items", []) if isinstance(d, dict) else []


def find_cand(tok, ip, status="pending"):
    return next((it for it in disc_candidates(tok, status) if it.get("ip") == ip), None)


def prime_discovery(admin_tok, run_tok=None):
    """准备可复现的测绘前置：min_obs=1（演示数据每目标仅 1 条）、窗口 14 天（数据在 09-19）。

    配置项仅 admin 可改（见 portal 路由），触发/采纳可由 asset_admin 执行。
    """
    reset_discovery()
    disc_config(admin_tok, {"discovery.min_obs": "1", "discovery.window_minutes": "20160"})
    return disc_run(run_tok or admin_tok)


# --------------------------- I-13 多分支汇聚辅助 --------------------------- #
def branch_agg():
    """OpenSearch 侧按 ssp.branch 聚合事件数。"""
    st, d = http("POST", f"{OS}/ssp-events/_search",
                 {"size": 0, "aggs": {"b": {"terms": {"field": "ssp.branch", "size": 50}}}})
    if not isinstance(d, dict):
        return {}
    return {b["key"]: b["doc_count"]
            for b in d.get("aggregations", {}).get("b", {}).get("buckets", [])}


def branch_list(tok):
    st, d = http("GET", f"{UI}/api/branches", headers={"Cookie": f"ssp_session={tok}"})
    return st, d


def branch_probe(tok):
    return http("POST", f"{UI}/api/branches/probe", {},
                headers={"Cookie": f"ssp_session={tok}"})


BRANCH_DEFAULTS = {
    "hq": {"name": "总部", "site": "总部机房",
           "cidr": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", "link_type": "leased",
           "expect_interval_seconds": 3600, "enabled": 1},
    "sh-01": {"name": "上海分行", "site": "上海", "cidr": "10.9.0.0/16",
              "link_type": "leased", "expect_interval_seconds": 3600, "enabled": 1},
    "bj-01": {"name": "北京分行", "site": "北京", "cidr": "10.7.0.0/16",
              "link_type": "leased", "expect_interval_seconds": 3600, "enabled": 1},
}


def restore_branches(tok):
    """收尾：确保三个默认分支都已登记且启用。

    注意：/api/branches 列表里含有「未登记」的合成条目（registered=false），
    它们**不是**真实登记项，不能据此判定"已存在"，否则会漏建。
    """
    h = {"Cookie": f"ssp_session={tok}"}
    st, d = branch_list(tok)
    have = {it["branch_id"] for it in ((d or {}).get("items") or []) if it.get("registered")}
    for bid, cfg in BRANCH_DEFAULTS.items():
        body = dict(cfg, branch_id=bid)
        if bid in have:
            http("PUT", f"{UI}/api/branches/{bid}", body, headers=h)
        else:
            http("POST", f"{UI}/api/branches", body, headers=h)
    branch_probe(tok)          # 刷新状态（新建项的 state 初值为 unknown）


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
        time.sleep(DB_SYNC_WAIT)      # 宿主直写 → 容器可见有约 1s 延迟，须等待
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


# =========================================================================== #
# I-12 资产测绘（被动识别 → 候选池 → 采纳/忽略）
# =========================================================================== #
def case_a9_discovery_run():
    print("\n▶ A9 资产测绘本轮化（Zeek 连接记录 → 候选池，幂等）", flush=True)
    tok = portal_login("admin", "REDACTED-SSP-PWD")
    if not tok:
        return rec("A9", "资产测绘本轮化", False, "登录失败")
    reset_discovery()                        # 清空候选池（隔离），随后本案例自建
    st0, _c0 = disc_config(tok, {"discovery.min_obs": "1", "discovery.window_minutes": "20160"})
    if st0 != 200:
        return rec("A9", "资产测绘本轮化", False, f"配置失败 HTTP={st0}")
    st, d = disc_run(tok)                    # 首次测绘：应新增 2 条候选
    items = disc_candidates(tok, "pending")
    ips = {it["ip"] for it in items}
    internal = {"10.0.0.20", "10.20.30.40"}
    leaked = sorted(ips - internal)          # 公网/越权 IP 不应成为候选
    st2, d2 = disc_run(tok)                  # 幂等：重复测绘不重复建候选
    ok = (st == 200 and d.get("created") == 2 and d.get("scanned_hosts") == 2
          and internal <= ips and not leaked
          and d2.get("created") == 0 and d2.get("updated") == 2)
    detail = (f"run HTTP={st} created={d.get('created')} hosts={d.get('scanned_hosts')}；"
              f"候选={sorted(ips)}；越权候选={leaked}（应空）；"
              f"二次 run created={d2.get('created')}/updated={d2.get('updated')}（应 0/2 幂等）")
    return rec("A9", "资产测绘本轮化", ok, detail)


def case_a10_discovery_adopt():
    print("\n▶ A10 采纳：同 IP 已有手工资产→合并（不改人工字段）；无同 IP→新建", flush=True)
    admin = portal_login("admin", "REDACTED-SSP-PWD")
    tok = portal_login("asset", "REDACTED-SSP-PWD")      # 采纳由资产管理员执行（校验角色矩阵）
    if not admin or not tok:
        return rec("A10", "资产测绘采纳", False, "登录失败")
    cand = find_cand(tok, "10.0.0.20")
    if not cand:
        prime_discovery(admin, tok)
        cand = find_cand(tok, "10.0.0.20")
    if not cand:
        return rec("A10", "资产测绘采纳", False, "未找到 10.0.0.20 候选（前置失败）")
    h = {"Cookie": f"ssp_session={tok}"}
    # —— 合并路径：AST-101 是既有手工资产（ip=10.0.0.20）——
    st, d = http("POST", f"{UI}/api/discovery/adopt", {"ids": [cand["id"]]}, headers=h)
    rows = asset_by_ip(tok, "10.0.0.20")
    ast = next((x for x in rows if x.get("asset_id") == "AST-101"), None)
    merge_ok = (st == 200 and d.get("merged") == 1 and len(rows) == 1 and ast
                and ast.get("name") == "生产Web服务器-web-prod-01"
                and ast.get("importance") == "重要" and ast.get("owner") == "运维组"
                and "passive" in (ast.get("discovered_by") or "")
                and any(e.get("port") == 22 for e in (ast.get("endpoints") or [])))
    # —— 新建路径：合成一个资产库无同 IP 的候选 ——
    cid = insert_candidate("10.20.30.55", 8443, "tcp", "https", 5)
    st2, d2 = http("POST", f"{UI}/api/discovery/adopt", {"ids": [cid]}, headers=h)
    new = next(iter(asset_by_ip(tok, "10.20.30.55")), None)
    create_ok = (d2.get("created") == 1 and new and new.get("source") == "discovered"
                 and any(e.get("port") == 8443 for e in (new.get("endpoints") or [])))
    ok = merge_ok and create_ok
    detail = (f"合并：HTTP={st} merged={d.get('merged')} 同IP资产数={len(rows)}；"
              f"人工字段保留 name={ast and ast.get('name')} importance={ast and ast.get('importance')} "
              f"owner={ast and ast.get('owner')}；discovered_by={ast and ast.get('discovered_by')}；"
              f"新建：created={d2.get('created')} source={new and new.get('source')} "
              f"ports={[e.get('port') for e in ((new or {}).get('endpoints') or [])]}")
    return rec("A10", "资产测绘采纳", ok, detail)


def case_a11_discovery_ignore():
    print("\n▶ A11 忽略候选（后续测绘不回退其状态）", flush=True)
    admin = portal_login("admin", "REDACTED-SSP-PWD")
    tok = portal_login("asset", "REDACTED-SSP-PWD")
    if not admin or not tok:
        return rec("A11", "资产测绘忽略", False, "登录失败")
    cand = find_cand(tok, "10.20.30.40")
    if not cand:
        prime_discovery(admin, tok)
        cand = find_cand(tok, "10.20.30.40")
    if not cand:
        return rec("A11", "资产测绘忽略", False, "未找到 10.20.30.40 候选（前置失败）")
    h = {"Cookie": f"ssp_session={tok}"}
    st, d = http("POST", f"{UI}/api/discovery/ignore", {"ids": [cand["id"]]}, headers=h)
    disc_run(tok)                            # 该 (ip,port) 仍在流量中 → 不得复位为 pending
    row = next((it for it in disc_candidates(tok, "all") if it.get("id") == cand["id"]), None)
    st3, _d3 = http("POST", f"{UI}/api/discovery/adopt", {"ids": [cand["id"]]}, headers=h)
    ok = (st == 200 and d.get("ignored") == 1 and row
          and row.get("status") == "ignored" and st3 == 409)
    detail = (f"ignore HTTP={st} 已忽略={d.get('ignored')}；再测绘后状态={row and row.get('status')}（应 ignored）；"
              f"再采纳 HTTP={st3}（应 409 非待审）")
    return rec("A11", "资产测绘忽略", ok, detail)


def case_n5_discovery_os_down():
    print("\n▶ N5 测绘：OpenSearch 不可达（失败不影响存量资产）", flush=True)
    ov = "/tmp/ssp-test-osdown.yml"
    with open(ov, "w") as f:
        f.write("services:\n  portal:\n    environment:\n      OPENSEARCH_URL: http://127.0.0.1:9\n")
    sh(f"{COMPOSE} -f {ov} up -d --force-recreate portal")
    ready = wait_port(f"{PORTAL}/health")           # 直连 portal（/health 不经 nginx）
    tok = None
    for _ in range(15):                              # nginx 动态解析最长 10s 缓存，登录稍重试
        tok = portal_login("asset", "REDACTED-SSP-PWD")
        if tok:
            break
        time.sleep(1)
    if not ready or not tok:
        sh(f"{COMPOSE} up -d --force-recreate portal")
        wait_port(f"{PORTAL}/health")
        return rec("N5", "测绘:OS不可达", False, f"portal 未能就绪（ready={ready} login={bool(tok)}）")
    base = asset_total(tok)
    st, d = disc_run(tok)
    after = asset_total(tok)
    ok = (st == 502 and after == base)
    detail = (f"HTTP={st}（应 502）；资产数 {base}→{after}（应不变）；"
              f"error={d.get('error') if isinstance(d, dict) else d}")
    sh(f"{COMPOSE} up -d --force-recreate portal")      # 还原
    wait_port(f"{PORTAL}/health")
    return rec("N5", "测绘:OS不可达", ok, detail)


def case_n6_discovery_out_of_range():
    print("\n▶ N6 测绘：授权网段外候选 → 采纳被拒（422）", flush=True)
    tok = portal_login("asset", "REDACTED-SSP-PWD")
    if not tok:
        return rec("N6", "测绘:越权IP拒绝", False, "登录失败")
    h = {"Cookie": f"ssp_session={tok}"}
    cid = insert_candidate("8.8.8.8", 53, "udp", "dns", 9, status="pending")
    st, d = http("POST", f"{UI}/api/discovery/adopt", {"ids": [cid]}, headers=h)
    row = next((it for it in disc_candidates(tok, "all") if it.get("id") == cid), None)
    delete_candidate(cid)
    errs = (d or {}).get("errors", []) if isinstance(d, dict) else []
    ok = (st == 422 and bool(errs) and row and row.get("status") == "pending")
    detail = f"HTTP={st}（应 422）；errors={errs}；候选仍为 {row and row.get('status')}（应 pending，未写入）"
    return rec("N6", "测绘:越权IP拒绝", ok, detail)


def case_n7_discovery_forbidden():
    print("\n▶ N7 测绘：analyst 无写权限（403），读候选仍 200", flush=True)
    tok = portal_login("analyst", "REDACTED-SSP-PWD")
    if not tok:
        return rec("N7", "测绘:越权角色403", False, "登录失败")
    h = {"Cookie": f"ssp_session={tok}"}
    st1, _ = http("POST", f"{UI}/api/discovery/run", {}, headers=h)
    st2, _ = http("POST", f"{UI}/api/discovery/adopt", {"ids": ["x"]}, headers=h)
    st3, _ = http("GET", f"{UI}/api/discovery/candidates?status=pending", headers=h)
    ok = (st1 == 403 and st2 == 403 and st3 == 200)
    return rec("N7", "测绘:越权角色403", ok, f"run={st1} adopt={st2}（应 403）；读候选={st3}（应 200）")


# =========================================================================== #
# I-13 多分支汇聚（分支身份 / 分支登记 / 分支独立）
# =========================================================================== #
def case_a13_branch_tagging():
    print("\n▶ A13 分支打标入库（ssp.branch 可按分支检索与聚合）", flush=True)
    buckets = branch_agg()
    need = {"hq", "sh-01", "bj-01"}
    got = need <= set(buckets)
    filt = {}
    for br in ("sh-01", "bj-01"):
        st, d = http("POST", f"{OS}/ssp-events/_search",
                     {"size": 1, "query": {"term": {"ssp.branch": br}},
                      "_source": ["ssp.branch", "ssp.branch_site"]})
        hits = (d or {}).get("hits", {}) if isinstance(d, dict) else {}
        total = hits.get("total", {}).get("value", -1)
        src = ((hits.get("hits") or [{}])[0] or {}).get("_source", {})
        filt[br] = (total, (src.get("ssp") or {}).get("branch_site"))
    ok = (got and all(filt[b][0] == buckets.get(b) for b in filt)
          and all(filt[b][1] for b in filt))
    detail = (f"分支聚合={buckets}；term 过滤=" +
              "; ".join(f"{b}: 命中 {filt[b][0]}（聚合 {buckets.get(b)}）站点={filt[b][1]}" for b in filt))
    return rec("A13", "分支打标入库", ok, detail)


def case_a14_branch_registry():
    print("\n▶ A14 分支登记与汇聚探测（在线判定 / 停用判定）", flush=True)
    tok = portal_login("admin", "REDACTED-SSP-PWD")
    if not tok:
        return rec("A14", "分支登记与探测", False, "登录失败")
    h = {"Cookie": f"ssp_session={tok}"}
    st, d = branch_list(tok)
    items = {it["branch_id"]: it for it in ((d or {}).get("items") or [])}
    reg_ok = all(items.get(b, {}).get("state") == "ok"
                 for b in ("hq", "sh-01", "bj-01"))
    st2, p = branch_probe(tok)
    probe_ok = st2 == 200 and (p.get("state_counts", {}) or {}).get("ok", 0) >= 3
    # 停用 → disabled；恢复 → ok
    st3, _ = http("PUT", f"{UI}/api/branches/bj-01", dict(BRANCH_DEFAULTS["bj-01"], enabled=0), headers=h)
    st4, p2 = branch_probe(tok)
    bj = next((x for x in ((p2 or {}).get("branches") or []) if x["branch_id"] == "bj-01"), {})
    dis_ok = st3 == 200 and bj.get("state") == "disabled"
    st5, _ = http("PUT", f"{UI}/api/branches/bj-01", dict(BRANCH_DEFAULTS["bj-01"], enabled=1), headers=h)
    st6, p3 = branch_probe(tok)
    bj2 = next((x for x in ((p3 or {}).get("branches") or []) if x["branch_id"] == "bj-01"), {})
    back_ok = st5 == 200 and bj2.get("state") == "ok"
    ok = reg_ok and probe_ok and dis_ok and back_ok
    detail = (f"登记状态={ {k: v.get('state') for k, v in items.items()} }；"
              f"探测={p.get('state_counts')}；停用后 bj-01={bj.get('state')}（应 disabled）；"
              f"恢复后={bj2.get('state')}（应 ok）")
    return rec("A14", "分支登记与探测", ok, detail)


def case_a15_branch_isolation():
    print("\n▶ A15 分支独立（某分支断链不影响其他分支）", flush=True)
    tok = portal_login("admin", "REDACTED-SSP-PWD")
    if not tok:
        return rec("A15", "分支独立", False, "登录失败")
    h = {"Cookie": f"ssp_session={tok}"}
    b0 = branch_agg()
    if "bj-01" not in b0:
        return rec("A15", "分支独立", False, f"前置不满足：无 bj-01 事件 {b0}")
    # 模拟 bj-01 断链：清掉该分支已入湖事件（无存量 → 判定立即转 no_data）
    http("POST", f"{OS}/ssp-events/_delete_by_query?refresh=true",
         {"query": {"term": {"ssp.branch": "bj-01"}}}, timeout=60)
    st, p = branch_probe(tok)
    states = {x["branch_id"]: x["state"] for x in ((p or {}).get("branches") or [])}
    b1 = branch_agg()
    ok = (st == 200 and states.get("bj-01") == "no_data"
          and states.get("sh-01") == "ok" and states.get("hq") == "ok"
          and "bj-01" not in b1
          and b1.get("sh-01") == b0.get("sh-01") and b1.get("hq") == b0.get("hq"))
    detail = (f"断链前={b0}；断链后={b1}（bj-01 应消失，sh-01/hq 应不变）；状态={states}")
    # 恢复：重建该分支边缘代理，重新采集
    sh(f"{COMPOSE} up -d --force-recreate filebeat-branch-bj")
    for _ in range(20):
        time.sleep(2)
        if "bj-01" in branch_agg():
            break
    branch_probe(tok)
    return rec("A15", "分支独立", ok, detail)


def case_n10_unregistered_branch():
    print("\n▶ N10 未登记分支（提示 unregistered，不阻断入库）", flush=True)
    tok = portal_login("admin", "REDACTED-SSP-PWD")
    if not tok:
        return rec("N10", "未登记分支提示", False, "登录失败")
    h = {"Cookie": f"ssp_session={tok}"}
    # 摘掉 hq 的登记 —— 事件里仍有 hq，应被判为 unregistered
    http("DELETE", f"{UI}/api/branches/hq", headers=h)
    st, d = branch_list(tok)
    hq = next((x for x in ((d or {}).get("items") or []) if x["branch_id"] == "hq"), None)
    st2, p = branch_probe(tok)
    unreg = (p or {}).get("unregistered") or []
    listed = bool(hq) and hq.get("state") == "unregistered" and hq.get("registered") is False
    ok = (st == 200 and listed and "hq" in unreg and st2 == 200)
    detail = (f"列表含 hq={bool(hq)} state={hq and hq.get('state')} registered={hq and hq.get('registered')}；"
              f"探测 unregistered={unreg}（应含 hq）")
    restore_branches(tok)          # 恢复 hq 登记
    return rec("N10", "未登记分支提示", ok, detail)


def case_n11_branch_probe_os_down():
    print("\n▶ N11 分支探测：OpenSearch 不可达（探测失败但不误改状态）", flush=True)
    tok0 = portal_login("admin", "REDACTED-SSP-PWD")
    if not tok0:
        return rec("N11", "分支探测:OS不可达", False, "登录失败")
    st0, d0 = branch_list(tok0)
    before = {it["branch_id"]: it["state"] for it in ((d0 or {}).get("items") or [])}

    ov = "/tmp/ssp-test-osdown-branch.yml"
    with open(ov, "w") as f:
        f.write("services:\n  portal:\n    environment:\n      OPENSEARCH_URL: http://127.0.0.1:9\n")
    sh(f"{COMPOSE} -f {ov} up -d --force-recreate portal")
    ready = wait_port(f"{PORTAL}/health")
    tok = None
    for _ in range(15):
        tok = portal_login("admin", "REDACTED-SSP-PWD")
        if tok:
            break
        time.sleep(1)
    if not ready or not tok:
        sh(f"{COMPOSE} up -d --force-recreate portal")
        wait_port(f"{PORTAL}/health")
        return rec("N11", "分支探测:OS不可达", False, f"portal 未能就绪（ready={ready}）")

    st, p = branch_probe(tok)
    st2, d = branch_list(tok)
    after = {it["branch_id"]: it["state"] for it in ((d or {}).get("items") or [])}
    ok = (st == 502 and st2 == 200 and (d or {}).get("probe_error")
          and after == before)
    detail = (f"probe HTTP={st}（应 502）；列表 HTTP={st2}（应 200，仍可读）；"
              f"探测错误={bool((d or {}).get('probe_error'))}；状态 {before}→{after}（应不变）")
    sh(f"{COMPOSE} up -d --force-recreate portal")      # 还原
    wait_port(f"{PORTAL}/health")
    return rec("N11", "分支探测:OS不可达", ok, detail)


CASES = {
    "A9": case_a9_discovery_run,
    "A10": case_a10_discovery_adopt,
    "A11": case_a11_discovery_ignore,
    "A13": case_a13_branch_tagging,
    "A14": case_a14_branch_registry,
    "A15": case_a15_branch_isolation,
    "N1": case_n1_probe_down,
    "N2": case_n2_approval_timeout,
    "N3": case_n3_block_failure,
    "N4": case_n4_excel_import_rollback,
    "N5": case_n5_discovery_os_down,
    "N6": case_n6_discovery_out_of_range,
    "N7": case_n7_discovery_forbidden,
    "N10": case_n10_unregistered_branch,
    "N11": case_n11_branch_probe_os_down,
}


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

    clear_discovery_config()          # 收尾：移除测绘配置覆写，恢复默认（min_obs=3 等）
    try:                              # 收尾：确保默认分支登记齐全且启用（N10 会临时摘除 hq）
        _adm = portal_login("admin", "REDACTED-SSP-PWD")
        if _adm:
            restore_branches(_adm)
    except Exception:
        pass

    print("\n" + "=" * 74)
    npass = sum(1 for r in RESULTS if r[2])
    for tid, name, ok, _ in RESULTS:
        print(f"  {'✔' if ok else '✘'} {tid:<4} {name:<18} {'PASS' if ok else 'FAIL'}")
    print(f"  ----------  {npass}/{len(RESULTS)} 通过  ----------")
    print("=" * 74)
    return 0 if npass == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
