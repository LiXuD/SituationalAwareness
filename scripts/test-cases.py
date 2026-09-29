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

I-14 流式关联与外部日志源适配（本脚本追加，正例 A16~A18 + 反例 N12~N13）：
  A16 流式关联端到端   事件入 Kafka → **≤5s** 告警落库，且带 ssp.branch（流式时延实测）
  A17 幂等与批式共存   批式/流式先后命中同一实体 → 告警总数**不重复增长**（并集 engines）
  A18 外部源适配       syslog/CEF/JSON 三入口 → 打标入库（fields.log_source/ssp.branch）
                        → 可检索、**可被流式关联消费**（防火墙+WAF 同 IP → R-001）
  N12 消费者中断       停消费者期间事件留在 Kafka；恢复后**位点续读、不丢事件**，
                       批式与大屏不受影响
  N13 外部源关闭       适配器默认关闭 → **不监听端口、不产生任何事件**（无副作用）

用法：
    python3 scripts/test-cases.py                 # 正例回归 + 全部反例
    python3 scripts/test-cases.py --skip-positive # 只跑反例
    python3 scripts/test-cases.py --only N3
退出码：0=全部通过；1=有失败项。
"""
import argparse
from http.cookiejar import CookieJar
import datetime
import hashlib
import json
import os
import random
import re
import socket
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
STREAM = os.environ.get("STREAM_URL", "http://localhost:8094")      # I-14 流式关联引擎
ADAPTER = os.environ.get("ADAPTER_URL", "http://localhost:5516")    # I-14 外部源适配器
SOAR = os.environ.get("SOAR_URL", "http://localhost:8092")
ASSET = os.environ.get("ASSET_URL", "http://localhost:8090")
UI = os.environ.get("UI_URL", "http://localhost:8088")
PORTAL = os.environ.get("PORTAL_URL", "http://localhost:8093")   # 统一业务后端（直连，绕过 nginx）
COMPOSE = "docker compose -f deploy/compose.yml"
VENV_PY = "/Users/lixd/.workbuddy/binaries/python/envs/default/bin/python"
PY = VENV_PY if os.path.exists(VENV_PY) else sys.executable
SYSLOG_UDP_PORT = int(os.environ.get("ADAPTER_SYSLOG_UDP_PORT", "5514"))

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
    """测试夹具用的业务库连接。

    注：`journal_mode=MEMORY` 是**连接级**设置（MEMORY/OFF 不写入库头、不影响其它连接，
    也不改变 portal 容器侧的回滚日志策略）。这里显式使用它有两个好处：
      ① 夹具的写操作不产生 `ssp.db-journal` 落盘文件，避免在受限环境（如平台沙箱
         禁止文件删除）里 commit 阶段报 `disk I/O error` 而误判为用例失败；
      ② 写入仍是单事务原子提交，只是回滚日志放在内存里。
    默认（未设置该 PRAGMA）的连接行为完全不变，业务容器不受影响。
    """
    c = sqlite3.connect(_ssp_db(), timeout=15)
    try:
        c.execute("PRAGMA journal_mode=MEMORY")
    except Exception:
        pass
    return c


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
    """清理草稿与黑名单状态（N2/N3 的前置）。

    ⚠️ 必须用 `_sqlite_conn()`（连接级 MEMORY 回滚日志）：默认 journal 模式下 DELETE
    会生成 `data/ssp.db-journal` 并在 commit 时删除它，若所在环境禁止删除文件
    （如平台沙箱），commit 会报 `disk I/O error` —— 本函数原先 `except: pass` 会**静默失败**，
    残留草稿使 `generate_drafts()` 因去重而不再生成新草稿，表现为 N2/N3 "无待审批草稿"。
    """
    try:
        c = _sqlite_conn()
        c.execute("DELETE FROM soar_drafts")
        c.execute("UPDATE blacklist SET status='inactive'")
        c.commit()
        c.close()
        time.sleep(DB_SYNC_WAIT)      # 宿主直写 → 容器可见有约 1s 延迟，须等待
    except Exception as e:
        print(f"  [warn] 清理草稿失败：{type(e).__name__}: {e}", flush=True)


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


# =========================================================================== #
# I-14 流式关联与外部日志源适配（L1 流式关联 / L2 外部源适配）
# =========================================================================== #
def sh_in(cmd, text, timeout=60):
    """带 stdin 的命令执行（Kafka 控制台生产者等需要管道输入）。"""
    e = dict(os.environ)
    e["PATH"] = "/usr/local/bin:" + e.get("PATH", "")
    p = subprocess.run(cmd, shell=True, input=text, capture_output=True, text=True,
                       timeout=timeout, env=e, cwd=ROOT)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def stream_stats():
    st, d = http("GET", f"{STREAM}/stats")
    return d if isinstance(d, dict) else {}


def kafka_produce(topic, docs):
    """把 JSON 文档投递到指定 Kafka 主题（等价于 Filebeat/Logstash 的生产端）。"""
    text = "\n".join(json.dumps(x, ensure_ascii=False) for x in docs)
    return sh_in(f"docker exec -i ssp-kafka /opt/kafka/bin/kafka-console-producer.sh "
                 f"--bootstrap-server localhost:9092 --topic {topic}", text)


def kafka_end_offsets(topic):
    """直接向 Kafka 取主题末位点（不依赖消费者，用于"消费者停机期间"观测）。"""
    rc, out = sh(f"docker exec ssp-kafka /opt/kafka/bin/kafka-get-offsets.sh "
                 f"--bootstrap-server localhost:9092 --topic {topic}", timeout=60)
    res = {}
    for ln in out.splitlines():
        parts = ln.strip().split(":")
        if len(parts) == 3 and parts[0] == topic and parts[2].lstrip("-").isdigit():
            res[f"{parts[0]}:{parts[1]}"] = int(parts[2])
    return res


def alerts_total():
    http("POST", f"{OS}/ssp-alerts/_refresh")
    st, d = http("POST", f"{OS}/ssp-alerts/_count")
    return d.get("count", -1) if isinstance(d, dict) else -1


def find_alerts(filters, size=5):
    http("POST", f"{OS}/ssp-alerts/_refresh")
    st, d = http("POST", f"{OS}/ssp-alerts/_search", {"size": size, "query": {"bool": {"filter": filters}}})
    if not isinstance(d, dict):
        return []
    return [h.get("_source", {}) for h in ((d.get("hits") or {}).get("hits") or [])]


def del_alerts(query):
    """删除告警（先 refresh，确保刚写入的告警对 delete_by_query 的检索阶段可见）。"""
    http("POST", f"{OS}/ssp-alerts/_refresh", timeout=30)
    return http("POST", f"{OS}/ssp-alerts/_delete_by_query?refresh=true", {"query": query})


def ext_index_count():
    """外部源索引事件总数（索引不存在按 0 计）。"""
    st, d = http("POST", f"{OS}/ssp-firewall-*,ssp-waf-*,ssp-ids-*,ssp-proxy-*/_count")
    return (d or {}).get("count", 0) if isinstance(d, dict) else 0


def ecs_suricata_alert(ip, dst, sid, branch="bj-01"):
    """构造一条**归一后**的 ECS 事件（等价于 Logstash 输出到 ssp-ecs 的文档）。"""
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        "@timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "event": {"kind": "alert", "category": "intrusion_detection", "module": "suricata",
                  "dataset": "suricata.eve", "severity": "high"},
        "rule": {"id": str(sid), "name": "ET POLICY SMB2 NT Create AndX Request For an Executable File"},
        "fields": {"log_source": "suricata", "branch": branch, "branch_site": "北京"},
        "ssp": {"branch": branch, "branch_site": "北京"},
        "source": {"ip": ip, "port": 44551},
        "destination": {"ip": dst, "port": 445},
        "network": {"transport": "TCP"},
        "message": f"I-14 流式用例探针 src={ip}",
    }


def inject_suricata_raw(ip, sid, dst, branch="bj-01", topic="ssp-raw"):
    """向 Kafka 投递一条 Filebeat 风格的**原始**suricata 事件（走完整链路：
    ssp-raw → Logstash 归一 → OpenSearch + ssp-ecs → 流式引擎）。返回投递时刻。"""
    now = datetime.datetime.now(datetime.timezone.utc)
    eve = {"timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000", "flow_id": 880001 + (sid % 1000),
           "event_type": "alert", "src_ip": ip, "src_port": 44551, "dest_ip": dst,
           "dest_port": 445, "proto": "TCP",
           "alert": {"action": "allowed", "gid": 1, "signature_id": int(sid), "rev": 3,
                     "signature": "ET POLICY SMB2 NT Create AndX Request For an Executable File",
                     "category": "Potentially Bad Traffic", "severity": 2}}
    env = {"@timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
           "message": json.dumps(eve),
           "fields": {"log_source": "suricata", "branch": branch, "branch_site": "北京"},
           "host": {"name": "ssp-verify"}, "agent": {"type": "filebeat", "version": "7.17.23"}}
    t0 = time.time()
    kafka_produce(topic, [env])
    return t0


def cleanup_ingested_probe(ips):
    """清理用例注入的探针事件（避免影响 N1 数据源健康判定与 A1 计数口径）。

    ⚠️ 必须先 `_refresh` 再 `_delete_by_query`：事件索引 `refresh_interval=5s`，
    刚写入的文档在 refresh 前**对 delete_by_query 的检索阶段不可见**，会静默删 0 条
    （曾导致残留"新鲜"事件把探针源判成 stale，连累 N1）。返回删除条数。
    """
    if not ips:
        return 0
    url = f"{OS}/ssp-suricata-*,ssp-zeek-*,ssp-wazuh-*"
    body = {"query": {"terms": {"source.ip": list(ips)}}}
    total = 0
    for _ in range(3):
        http("POST", f"{url}/_refresh", timeout=30)
        st, d = http("POST", f"{url}/_delete_by_query?refresh=true", body, timeout=60)
        total += (d or {}).get("deleted", 0) if isinstance(d, dict) else 0
        st, c = http("POST", f"{OS}/ssp-events/_count", body)
        if isinstance(c, dict) and c.get("count", 1) == 0:
            break
        time.sleep(1)
    return total


def tcp_port_free(port, n=8):
    """TCP 端口是否无监听（用于 N13 确认适配器关闭后不监听端口）。"""
    for _ in range(n):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            time.sleep(0.5)
        except Exception:
            return True
    return False


def udp_send(port, lines):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for ln in lines:
            s.sendto(ln.encode("utf-8"), ("127.0.0.1", port))
        s.close()
        return True
    except Exception:
        return False


def adapter_up():
    st, d = http("GET", f"{ADAPTER}/health", timeout=5)
    return st == 200 and isinstance(d, dict)


def ensure_adapter_up(timeout=60):
    """启动外部源适配器（compose profile `external`，默认不启动）并等待就绪。"""
    if adapter_up():
        return True
    sh(f"{COMPOSE} --profile external up -d ingest-adapter", timeout=180)
    t0 = time.time()
    while time.time() - t0 < timeout:
        if adapter_up():
            return True
        time.sleep(2)
    return False


def adapter_down():
    sh(f"{COMPOSE} --profile external rm -sf ingest-adapter", timeout=120)
    for _ in range(15):
        if not adapter_up():
            return True
        time.sleep(1)
    return False


def cleanup_external():
    """清空外部源演示数据（索引 + 索引名）——保证默认态"零外部事件"。"""
    for idx in ("ssp-firewall-*", "ssp-waf-*", "ssp-ids-*", "ssp-proxy-*"):
        http("DELETE", f"{OS}/{idx}", timeout=30)


def case_a16_stream_realtime():
    print("\n▶ A16 流式关联端到端（事件入 Kafka → ≤5s 告警，带 ssp.branch）", flush=True)
    s0 = stream_stats()
    if s0.get("engine") != "stream":
        return rec("A16", "流式关联端到端", False, f"流式引擎不可用：{s0 or '无响应'}")
    if s0.get("status") != "ok":
        return rec("A16", "流式关联端到端", False, f"流式引擎状态异常：{s0.get('status')}")
    ip, sid, dst, br = "203.0.113.211", random.randint(2011000, 2011999), "10.7.1.30", "bj-01"
    # 测试隔离：清掉历史同 IP 告警，避免命中上一轮残留
    del_alerts({"bool": {"filter": [{"term": {"ssp.alert.rule_id": "R-006"}},
                                    {"term": {"source.ip": ip}}]}})
    t0 = inject_suricata_raw(ip, sid, dst, br)
    found, el = None, None
    while time.time() - t0 < 20:
        hits = find_alerts([{"term": {"ssp.alert.rule_id": "R-006"}},
                            {"term": {"source.ip": ip}}], 1)
        if hits:
            found, el = hits[0], time.time() - t0
            break
        time.sleep(0.2)
    a = (found or {}).get("ssp", {}).get("alert", {}) or {}
    lat = a.get("stream_latency_ms")
    ok = (bool(found) and el is not None and el <= 5.0
          and (found.get("ssp") or {}).get("branch") == br
          and "stream" in (a.get("engines") or [])
          and lat is not None and lat <= 5000)
    detail = (f"端到端实测 {('%.2fs' % el) if el else '超时(>20s)'}（阈值 ≤5s）；"
              f"告警 branch={(found or {}).get('ssp', {}).get('branch')}（应 {br}）；"
              f"engines={a.get('engines')}；流式段时延 stream_latency_ms={lat}ms（阈值 ≤5000）；"
              f"引擎累计消费={stream_stats().get('consumed_total')}")
    cleaned = cleanup_ingested_probe([ip])
    leftover = http("POST", f"{OS}/ssp-events/_count",
                    {"query": {"terms": {"source.ip": [ip]}}})
    left_n = leftover[1].get("count", -1) if isinstance(leftover[1], dict) else -1
    ok = ok and cleaned >= 1 and left_n == 0
    detail += (f"；已清理注入的探针事件 {cleaned} 条（残留 {left_n} 条，须为 0，"
               f"否则会影响 N1 数据源口径）")
    return rec("A16", "流式关联端到端", ok, detail)


def case_a17_stream_batch_coexist():
    print("\n▶ A17 幂等与共存（批式/流式先后命中同一实体不重复计数）", flush=True)
    cands = find_alerts([{"term": {"ssp.alert.rule_id": "R-006"}},
                         {"term": {"ssp.alert.engines": "batch"}}], 10)
    tgt = None
    for c in cands:
        m = re.search(r"\[(\d+)\]", c.get("message", "") or "")
        if m and (c.get("source") or {}).get("ip") and (c.get("destination") or {}).get("ip"):
            tgt, rid = c, m.group(1)
            break
    if not tgt:
        return rec("A17", "幂等与批式共存", False, "未找到可用的批式 R-006 告警（前置失败）")
    aid = tgt["ssp"]["alert"]["id"]
    ip, dst = tgt["source"]["ip"], tgt["destination"]["ip"]
    # 重置该告警：删掉后由批式引擎重新产生（确保 first_engine=batch）
    http("DELETE", f"{OS}/ssp-alerts/_doc/{aid}?refresh=true", timeout=30)
    st, _ = http("POST", f"{CORR}/correlate", {}, timeout=180)
    t1 = alerts_total()
    st2, _ = http("POST", f"{CORR}/correlate", {}, timeout=180)
    t2 = alerts_total()
    # 流式注入同一实体（同 rule.id / src / dst）→ 应命中同一 _id，只更新不新增
    kafka_produce("ssp-ecs", [ecs_suricata_alert(ip, dst, rid)])
    cur, eng = {}, []
    for _ in range(60):
        hits = find_alerts([{"term": {"ssp.alert.id": aid}}], 1)
        if hits:
            cur = hits[0]
            eng = (cur.get("ssp", {}).get("alert", {}) or {}).get("engines") or []
            if "stream" in eng:
                break
        time.sleep(0.25)
    t3 = alerts_total()
    ok = (st == 200 and st2 == 200 and t1 == t2 == t3
          and "stream" in eng and "batch" in eng)
    detail = (f"批式两次 total {t1}→{t2}（同实体幂等）；流式命中同一 _id 后 total={t3}（应不变）；"
              f"该告警 engines={eng}（应同时含 batch 与 stream）；"
              f"first_engine={(cur.get('ssp', {}).get('alert', {}) or {}).get('first_engine')}")
    return rec("A17", "幂等与批式共存", ok, detail)


def case_a18_external_source():
    print("\n▶ A18 外部源适配（syslog/CEF/JSON → 打标入库 → 可检索可关联）", flush=True)
    ip, ip2 = "203.0.113.212", "203.0.113.213"
    was_up = adapter_up()
    if not ensure_adapter_up():
        return rec("A18", "外部源适配", False, "适配器未能在 60s 内就绪（make external-up 失败）")
    cleanup_external()                                   # 从零开始，便于断言增量
    del_alerts({"term": {"related.entities.external_ips": ip}})
    n0 = es_count("ssp-events")
    # ① syslog(UDP)：防火墙 deny（ASA 风格，含同一外部 IP）
    udp_send(SYSLOG_UDP_PORT, [
        f'<134>Oct 11 22:14:15 fw-edge-01 %ASA-4-106023: Deny tcp src outside:{ip}/41000 '
        f'dst inside:10.0.0.20/445 by access-group "outside_in"',
        f'<134>1 2026-09-29T09:00:00.000Z fw-edge-01 ASA 1234 IDS - Deny udp src {ip2} dst 10.0.0.21',
    ])
    # ② CEF(TCP)：WAF 告警（含同一外部 IP，用于跨源关联）
    try:
        s = socket.create_connection(("127.0.0.1", 5515), timeout=5)
        s.sendall((f'CEF:0|Vendor|WAF-Prod|1.0|942100|SQL Injection Attempt|8|src={ip} '
                   f'dst=10.0.0.30 spt=52000 dpt=443 proto=TCP act=blocked msg=SQLi\n').encode())
        s.close()
    except Exception as e:
        adapter_down()
        return rec("A18", "外部源适配", False, f"CEF/TCP 投递失败：{e}")
    # ③ JSON(HTTP)：以 waf 身份投递（第二来源）
    stj, _ = http("POST", f"{ADAPTER}/ingest/json?source=waf&branch=bj-01", {
        "src_ip": ip, "dst_ip": "10.0.0.40", "dst_port": 3389, "protocol": "TCP",
        "action": "deny", "name": "RDP brute force", "severity": "high",
        "msg": "Access denied", "vendor": "XX-FW"}, timeout=20)
    # 等待入库
    t0, tot = time.time(), 0
    while time.time() - t0 < 40:
        st, d = http("POST", f"{OS}/ssp-firewall-*,ssp-waf-*/_search", {
            "size": 0, "aggs": {"s": {"terms": {"field": "fields.log_source"}},
                                "b": {"terms": {"field": "ssp.branch"}},
                                "ad": {"terms": {"field": "fields.adapter"}}}})
        tot = (d.get("hits", {}).get("total", {}).get("value", 0)
               if isinstance(d, dict) else 0)
        if tot >= 4:
            break
        time.sleep(1)
    srcs = {b["key"]: b["doc_count"] for b in
            (d.get("aggregations", {}).get("s", {}).get("buckets", []) if isinstance(d, dict) else [])}
    branches = {b["key"] for b in
                (d.get("aggregations", {}).get("b", {}).get("buckets", []) if isinstance(d, dict) else [])}
    entries = sorted({b["key"] for b in
                      (d.get("aggregations", {}).get("ad", {}).get("buckets", []) if isinstance(d, dict) else [])})
    # ECS 归一（方言解析）与"可检索"
    st, dq = http("POST", f"{OS}/ssp-events/_search", {
        "size": 3, "query": {"term": {"fields.external": "true"}},
        "sort": [{"@timestamp": "desc"}]})
    ext_hits = (dq.get("hits", {}).get("hits", []) if isinstance(dq, dict) else [])
    with_ip = [h["_source"] for h in ext_hits if (h["_source"].get("source") or {}).get("ip")]
    # 可被关联消费：同一外部 IP 出现在 firewall 与 waf 两个来源 → R-001
    r001 = {}
    for _ in range(60):
        hits = find_alerts([{"term": {"ssp.alert.rule_id": "R-001"}},
                            {"term": {"related.entities.external_ips": ip}}], 1)
        if hits:
            r001 = hits[0]
            break
        time.sleep(0.5)
    ok = (tot >= 4 and {"firewall", "waf"} <= set(srcs) and {"hq", "bj-01"} <= branches
          and {"syslog", "cef", "json"} <= set(entries) and bool(with_ip)
          and bool(r001) and "stream" in ((r001.get("ssp", {}).get("alert", {}) or {}).get("engines") or [])
          and {"firewall", "waf"} <= set((r001.get("related") or {}).get("log_sources") or []))
    detail = (f"入库 {tot} 条（来源={srcs}，分支={sorted(branches)}，入口={entries}）；"
              f"带源 IP 的归一事件={len(with_ip)}（syslog/CEF 方言解析）；"
              f"可检索(ssp-events 内 fields.external=true)={len(ext_hits)}；"
              f"关联消费 R-001={'命中' if r001 else '未命中'}"
              f"{'（' + str((r001.get('related') or {}).get('log_sources')) + '）' if r001 else ''}")
    cleanup_external()          # 收尾：外部源数据清零
    adapter_down()              # 收尾：适配器回到"默认关闭"
    detail += f"；已清理并关闭适配器（此前运行中={was_up}）"
    return rec("A18", "外部源适配", ok, detail)


def case_n12_stream_interrupt():
    print("\n▶ N12 消费者中断（停消费不丢事件，位点续读；不影响批式与大屏）", flush=True)
    s0 = stream_stats()
    if s0.get("engine") != "stream":
        return rec("N12", "消费者中断", False, f"流式引擎不可用：{s0 or '无响应'}")
    before = s0.get("consumed_total", 0)
    committed0 = sum((s0.get("positions") or {}).values())
    total_before = alerts_total()
    corr_ok = http("GET", f"{CORR}/health")[0] == 200
    ui_ok = http("GET", f"{UI}/")[0] == 200
    # 停消费者
    sh(f"{COMPOSE} stop stream", timeout=120)
    time.sleep(1)
    running = "ssp-stream" in sh("docker ps --format '{{.Names}}'")[1]
    # 停机期间注入事件：应留在 Kafka（不丢）
    ip = "203.0.113.214"
    del_alerts({"bool": {"filter": [{"term": {"ssp.alert.rule_id": "R-006"}},
                                    {"term": {"source.ip": ip}}]}})
    end0 = kafka_end_offsets("ssp-ecs")
    kafka_produce("ssp-ecs", [ecs_suricata_alert(ip, "10.7.1.31", random.randint(2021000, 2021999))])
    time.sleep(2)
    end1 = kafka_end_offsets("ssp-ecs")
    retained = (sum(end1.values()) > sum(end0.values()) or not end0) and sum(end1.values()) > committed0
    # 恢复消费者
    sh(f"{COMPOSE} start stream", timeout=120)
    wait_port(f"{STREAM}/health", 40)
    caught, s1 = False, {}
    for _ in range(80):
        s1 = stream_stats()
        pos, end = s1.get("positions") or {}, s1.get("end_offsets") or {}
        if pos and end and all(pos.get(k, 0) >= (end.get(k) or 0) for k in pos):
            caught = True
            break
        time.sleep(0.5)
    hits = []
    for _ in range(40):
        hits = find_alerts([{"term": {"ssp.alert.rule_id": "R-006"}},
                            {"term": {"source.ip": ip}}], 1)
        if hits:
            break
        time.sleep(0.5)
    eng = ((hits[0].get("ssp", {}).get("alert", {}) or {}).get("engines") or []) if hits else []
    total_after = alerts_total()
    pos_sum = sum((s1.get("positions") or {}).values())
    # 注意：consumed_total 是进程内计数器，容器重启会归零；判"不丢事件"要看**位点推进**
    ok = (not running and retained and caught and bool(hits) and "stream" in eng
          and "resume" in (s1.get("bootstrap_mode") or "")
          and pos_sum > committed0 and s1.get("consumed_total", 0) >= 1
          and corr_ok and ui_ok and total_after >= total_before)
    detail = (f"停机验证：容器运行={running}（应 False）；停机期间 Kafka 末位点 {sum(end0.values())}→"
              f"{sum(end1.values())}（事件已留在 Kafka，committed={committed0}）；"
              f"恢复后启动模式={s1.get('bootstrap_mode')}（应 resume）；追平={caught}；"
              f"位点 {committed0}→{pos_sum}（续读，未重置）；重启后消费={s1.get('consumed_total')} 条；"
              f"停机期间事件对应告警={'已产生' if hits else '缺失'} engines={eng}；"
              f"批式 /health={corr_ok}、大屏={ui_ok}、告警总数 {total_before}→{total_after}（不减）")
    return rec("N12", "消费者中断", ok, detail)


def case_n13_external_source_off():
    print("\n▶ N13 外部源关闭（默认关闭 → 不监听端口、无额外入库、无副作用）", flush=True)
    running = "ssp-ingest-adapter" in sh("docker ps --format '{{.Names}}'")[1]
    if running:
        adapter_down()
    cef_free = tcp_port_free(5515)          # CEF/TCP 入口应无监听
    n0_ext, n0_ev = ext_index_count(), es_count("ssp-events")
    udp_send(SYSLOG_UDP_PORT, [
        '<134>Oct 11 22:14:15 fw-edge-01 %ASA-4-106023: Deny tcp src outside:203.0.113.215/41000 '
        'dst inside:10.0.0.20/445 by group "outside_in"'])
    st_http, _ = http("GET", f"{ADAPTER}/health", timeout=5)     # 无监听 → 连不通
    time.sleep(3)
    n1_ext, n1_ev = ext_index_count(), es_count("ssp-events")
    ok = (not running and cef_free and n1_ext == n0_ext and n1_ev == n0_ev
          and st_http != 200)
    detail = (f"适配器容器运行={running}（应 False）；5515/tcp 无监听={cef_free}（应 True）；"
              f"投递 syslog 后外部源事件 {n0_ext}→{n1_ext}（应不变）、"
              f"ssp-events {n0_ev}→{n1_ev}（应不变）；适配器 /health HTTP={st_http}（应连不通）")
    return rec("N13", "外部源关闭", ok, detail)


CASES = {
    "A9": case_a9_discovery_run,
    "A10": case_a10_discovery_adopt,
    "A11": case_a11_discovery_ignore,
    "A13": case_a13_branch_tagging,
    "A14": case_a14_branch_registry,
    "A15": case_a15_branch_isolation,
    "A16": case_a16_stream_realtime,
    "A17": case_a17_stream_batch_coexist,
    "A18": case_a18_external_source,
    "N1": case_n1_probe_down,
    "N2": case_n2_approval_timeout,
    "N3": case_n3_block_failure,
    "N4": case_n4_excel_import_rollback,
    "N5": case_n5_discovery_os_down,
    "N6": case_n6_discovery_out_of_range,
    "N7": case_n7_discovery_forbidden,
    "N10": case_n10_unregistered_branch,
    "N11": case_n11_branch_probe_os_down,
    "N12": case_n12_stream_interrupt,
    "N13": case_n13_external_source_off,
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
