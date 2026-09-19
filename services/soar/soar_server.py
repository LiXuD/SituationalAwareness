#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
I-05 Shuffle SOAR 剧本 + 人工审批拉黑（纯标准库实现，零第三方依赖）

设计要点（对应 PRD F-10 / §6.2-6.4 / §10 / EARS）：
- **剧本**：扫描 `ssp-alerts` 中达到「自动处置级别」的告警（默认 P0）→ 生成**拉黑草稿**。
  「达到自动处置级别 → 生成草稿」是自动的；**提交封禁必须经人工确认**（human-in-the-loop），
  系统**绝不自动提交**（EARS State-driven 验收）。
- **人工审批**：运维通过 API / 审批界面 confirm → 才真正执行落黑。
- **落黑点**：本机 iptables（`blocker.py`：宿主 netns 自定义链 `SSP_BLACKLIST`）。
- **回写**：执行结果回写 `ssp-alerts` 的 `ssp.alert.status/response_action/ticket_id`，
  供态势大屏展示；失败时告警**保持待处置**并记录原因（PRD §10）。
- **审批超时**：草稿保留、不自动提交（PRD §10）。
- 与 POC 其它服务的协同纯靠 OpenSearch（无强耦合）；生产替换为真实 Shuffle 时，
  本服务等价于「Shuffle 剧本 + 审批节点」的轻量实现。

接口：
  POST /soar/drafts/generate            扫描告警生成草稿（幂等）
  GET  /soar/drafts?status=&limit=      草稿列表
  GET  /soar/drafts/{id}                草稿详情
  POST /soar/drafts/{id}/approve        审批通过 → 执行落黑
  POST /soar/drafts/{id}/reject         驳回
  GET  /soar/blocks                     当前封禁规则
  POST /soar/blocks/remove              解除封禁（回滚）
  GET  /soar/rules                      剧本配置
  GET  /health
"""
import os
import sys
import json
import time
import hashlib
import datetime
import threading
import ipaddress
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import blocker

# ----------------------------- 配置 -----------------------------
OS_URL = os.environ.get("OS_URL", "http://opensearch:9200").rstrip("/")
ALERTS_INDEX = os.environ.get("ALERTS_INDEX", "ssp-alerts")
DRAFTS_INDEX = os.environ.get("DRAFTS_INDEX", "ssp-soar-drafts")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8092"))
# 触发「生成拉黑草稿」的告警级别（默认仅 P0）
BLOCK_GRADES = [g.strip() for g in os.environ.get("SOAR_BLOCK_GRADES", "P0").split(",") if g.strip()]
# 周期剧本（秒）；0 = 仅手动触发
SOAR_INTERVAL = int(os.environ.get("SOAR_INTERVAL_SECONDS", "60"))
CORS_ALLOW_ORIGIN = os.environ.get("CORS_ALLOW_ORIGIN", "*")
# 默认审批人（POC 单用户）
DEFAULT_OPERATOR = os.environ.get("SOAR_DEFAULT_OPERATOR", "ops")

_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
)]
BENIGN = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "114.114.114.114"}


def is_blockable(ip):
    """可封禁 = 外网地址且不在良性白名单。"""
    if not ip or ip in BENIGN:
        return False
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if a.is_multicast or a.is_loopback or a.is_link_local or a.is_unspecified:
        return False
    return not any(a in n for n in _PRIVATE_NETS)


# ----------------------------- 工具 -----------------------------
def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt=None):
    dt = dt or now_utc()
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def get_in(d, path, default=None):
    cur = d
    for k in path.split("."):
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


def os_request(method, path, body=None, timeout=15):
    url = OS_URL + path
    data = None
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw}
    except Exception as e:
        return 503, {"error": str(e)}


# ----------------------------- 草稿存储 -----------------------------
def draft_id_for(alert_id, ip):
    return hashlib.sha1(f"{alert_id}|{ip}".encode("utf-8")).hexdigest()[:20]


def get_draft(draft_id):
    st, res = os_request("GET", f"/{DRAFTS_INDEX}/_doc/{draft_id}")
    if st == 200 and res.get("found"):
        d = res["_source"]
        d["_id"] = res["_id"]
        return d
    return None


def save_draft(doc):
    # 注意：OpenSearch 禁止文档体内出现元数据字段 _id（get_draft 会注入 _id），必须先剔除
    body = {k: v for k, v in doc.items() if not str(k).startswith("_")}
    return os_request("PUT", f"/{DRAFTS_INDEX}/_doc/{doc['draft_id']}?refresh=true",
                      json.dumps(body, ensure_ascii=False))


def find_active_draft_by_ip(ip):
    """同一 IP 只保留一个「未闭环」草稿（待审批/已执行），避免重复拉黑请求。"""
    body = {"size": 1, "query": {"bool": {"filter": [
        {"term": {"target_ip": ip}},
        {"terms": {"status": ["pending_approval", "executed"]}},
    ]}}}
    st, res = os_request("POST", f"/{DRAFTS_INDEX}/_search", json.dumps(body))
    if st == 200 and get_in(res, "hits.total.value", 0) > 0:
        return get_in(res, "hits.hits")[0]["_source"]
    return None


def list_drafts(status=None, limit=100):
    must = []
    if status:
        must.append({"term": {"status": status}})
    body = {"size": limit, "sort": [{"created_at": "desc"}],
            "query": {"bool": {"filter": must}} if must else {"match_all": {}}}
    st, res = os_request("POST", f"/{DRAFTS_INDEX}/_search", json.dumps(body))
    if st != 200:
        return st, res
    return 200, {"total": get_in(res, "hits.total.value", 0),
                 "drafts": [h.get("_source") for h in get_in(res, "hits.hits", [])]}


def update_alert(alert_id, fields):
    """回写告警的 ssp.alert.* 字段（部分更新）。"""
    body = {"doc": {"ssp": {"alert": fields}}}
    return os_request("POST", f"/{ALERTS_INDEX}/_update/{alert_id}", json.dumps(body))


def find_alerts_for_block(limit=200):
    """找出达到自动处置级别、待处置、且可封禁外网源 IP 的告警。"""
    body = {"size": limit, "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": [
                {"term": {"ssp.alert.status": "open"}},
                {"terms": {"ssp.alert.grade": BLOCK_GRADES}},
            ]}}}
    st, res = os_request("POST", f"/{ALERTS_INDEX}/_search", json.dumps(body))
    if st != 200:
        return [], res
    out = []
    for h in get_in(res, "hits.hits", []):
        s = h.get("_source", {}) or {}
        out.append({"id": h.get("_id"), "src": s})
    return out, None


# ----------------------------- 剧本：生成草稿 -----------------------------
def generate_drafts():
    alerts, err = find_alerts_for_block()
    if err:
        return {"ok": False, "error": err}
    created, skipped, blocked_ips = [], [], []
    for a in alerts:
        s = a["src"]
        alert_id = get_in(s, "ssp.alert.id") or a["id"]
        ip = get_in(s, "source.ip")
        if not is_blockable(ip):
            skipped.append({"alert_id": alert_id, "reason": f"无可封禁外网源IP（{ip}）"})
            continue
        did = draft_id_for(alert_id, ip)
        if get_draft(did):
            skipped.append({"alert_id": alert_id, "reason": "草稿已存在"})
            continue
        if find_active_draft_by_ip(ip):
            skipped.append({"alert_id": alert_id, "reason": f"{ip} 已有未闭环草稿，去重"})
            continue
        threat = s.get("threat") or {}
        ind = threat.get("indicator") or {}
        doc = {
            "draft_id": did,
            "alert_id": alert_id,
            "rule_id": get_in(s, "ssp.alert.rule_id"),
            "rule_name": get_in(s, "ssp.alert.rule_name"),
            "grade": get_in(s, "ssp.alert.grade"),
            "target_ip": ip,
            "direction": blocker.DIRECTION,
            "status": "pending_approval",
            "reason": s.get("message", ""),
            "impact": "封禁该外部 IP 的全部入向流量；可能影响合法业务，请确认非误报后再提交。",
            "threat": {
                "matched": bool(threat.get("matched")),
                "source": threat.get("source"),
                "value": ind.get("value"),
                "tags": ind.get("tags") or [],
            },
            "created_at": iso(),
            "history": [{"at": iso(), "actor": "soar", "action": "draft_created",
                         "detail": f"由告警 {alert_id}（{get_in(s,'ssp.alert.grade')}）自动生成拉黑草稿，待人工审批"}],
        }
        st, res = save_draft(doc)
        if st in (200, 201):
            created.append(did)
            blocked_ips.append(ip)
        else:
            skipped.append({"alert_id": alert_id, "reason": f"写入失败 {st}"})
    return {"ok": True, "created": created, "created_count": len(created),
            "skipped": skipped, "block_grades": BLOCK_GRADES,
            "note": "草稿已生成，等待人工审批；系统不会自动提交"}


# ----------------------------- 审批 / 执行 -----------------------------
def approve_draft(draft_id, operator=None, dry_run=False):
    d = get_draft(draft_id)
    if not d:
        return 404, {"ok": False, "error": "草稿不存在"}
    if d["status"] not in ("pending_approval", "failed"):
        return 409, {"ok": False, "error": f"草稿当前状态为 {d['status']}，不可审批"}

    # 临时覆盖 blocker 模式（dry_run 演练）
    old_mode = blocker.MODE
    if dry_run:
        blocker.MODE = "dry-run"
    try:
        res = blocker.apply_block(d["target_ip"])
    finally:
        blocker.MODE = old_mode

    operator = operator or DEFAULT_OPERATOR
    d["decided_at"] = iso()
    d["decided_by"] = operator
    h = d.setdefault("history", [])
    if res.get("ok"):
        d["status"] = "executed"
        d["executed_at"] = iso()
        d["block_backend"] = res.get("backend")
        d["block_rule"] = "; ".join(res.get("rules") or []) or "(已存在)"
        d["block_error"] = None
        h.append({"at": iso(), "actor": operator, "action": "approved",
                  "detail": f"审批通过，落黑 {d['target_ip']} 成功（{res.get('backend')}）"
                            + ("（dry-run 演练）" if dry_run else "")})
        # 回写告警：已封禁
        update_alert(d["alert_id"], {
            "status": "blocked",
            "response_action": f"block:{res.get('backend')}",
            "ticket_id": draft_id,
            "resolved_at": iso(),
        })
        code, out = 200, {"ok": True, "draft": d, "block": res}
    else:
        d["status"] = "failed"
        d["block_error"] = res.get("error")
        h.append({"at": iso(), "actor": operator, "action": "approve_failed",
                  "detail": f"落黑失败：{res.get('error')}；告警保持待处置"})
        # 回写告警：保持待处置，记录失败（PRD §10）
        update_alert(d["alert_id"], {
            "status": "open",
            "response_action": f"block_failed:{res.get('error')}",
            "ticket_id": draft_id,
        })
        code, out = 500, {"ok": False, "draft": d, "block": res,
                          "error": "落黑执行失败，告警保持待处置"}
    save_draft(d)
    return code, out


def reject_draft(draft_id, operator=None):
    d = get_draft(draft_id)
    if not d:
        return 404, {"ok": False, "error": "草稿不存在"}
    if d["status"] not in ("pending_approval", "failed"):
        return 409, {"ok": False, "error": f"草稿当前状态为 {d['status']}，不可驳回"}
    operator = operator or DEFAULT_OPERATOR
    d["status"] = "rejected"
    d["decided_at"] = iso()
    d["decided_by"] = operator
    d.setdefault("history", []).append(
        {"at": iso(), "actor": operator, "action": "rejected", "detail": "人工驳回，不执行封禁"})
    save_draft(d)
    update_alert(d["alert_id"], {"status": "rejected", "response_action": "reject",
                                 "ticket_id": draft_id})
    return 200, {"ok": True, "draft": d}


def unblock(ip, operator=None):
    if not is_blockable(ip):
        return 400, {"ok": False, "error": f"非法或不可封禁的 IP: {ip}"}
    operator = operator or DEFAULT_OPERATOR
    res = blocker.remove_block(ip)
    # 回滚相关草稿与告警状态
    reverted = []
    st, lst = list_drafts(limit=500)
    if st == 200:
        for d in lst["drafts"]:
            if d.get("target_ip") == ip and d.get("status") == "executed":
                d["status"] = "reverted"
                d.setdefault("history", []).append(
                    {"at": iso(), "actor": operator, "action": "unblocked",
                     "detail": f"解除封禁 {ip}，草稿作废"})
                save_draft(d)
                update_alert(d["alert_id"], {"status": "open", "response_action": "unblock"})
                reverted.append(d["draft_id"])
    return 200, {"ok": res.get("ok"), "block": res, "reverted_drafts": reverted, "operator": operator}


# ----------------------------- HTTP -----------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", CORS_ALLOW_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    def do_OPTIONS(self):
        self._send(204, {})

    def _safe(self, fn):
        try:
            fn()
        except Exception as e:
            try:
                self._send(500, {"error": f"{type(e).__name__}: {e}"})
            except Exception:
                pass

    def do_GET(self):
        self._safe(self._get)

    def do_POST(self):
        self._safe(self._post)

    def _get(self):
        path = self.path.split("?")[0]
        q = {}
        if "?" in self.path:
            for kv in self.path.split("?", 1)[1].split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    q[k] = v
        if path in ("/health", "/"):
            self._send(200, {"status": "ok", "drafts_index": DRAFTS_INDEX,
                             "alerts_index": ALERTS_INDEX, "block_grades": BLOCK_GRADES,
                             "interval_seconds": SOAR_INTERVAL, "blocker": blocker.status()})
            return
        if path == "/soar/rules":
            self._send(200, {"block_grades": BLOCK_GRADES, "auto_execute": False,
                             "blocker_mode": blocker.MODE, "chain": blocker.CHAIN,
                             "hook_chain": blocker.HOOK_CHAIN, "direction": blocker.DIRECTION,
                             "note": "达到级别的告警自动生成草稿；提交封禁必须人工审批"})
            return
        if path == "/soar/drafts":
            st, res = list_drafts(q.get("status"), int(q.get("limit", "100")))
            self._send(st, res)
            return
        if path.startswith("/soar/drafts/"):
            d = get_draft(path.split("/")[-1])
            self._send(200 if d else 404, d or {"error": "not found"})
            return
        if path == "/soar/blocks":
            self._send(200, blocker.list_blocks())
            return
        self._send(404, {"error": "not found"})

    def _post(self):
        path = self.path.split("?")[0]
        b = self._body()
        if path == "/soar/drafts/generate":
            self._send(200, generate_drafts())
            return
        if path.endswith("/approve") and path.startswith("/soar/drafts/"):
            code, out = approve_draft(path.split("/")[-2],
                                      b.get("operator"), bool(b.get("dry_run")))
            self._send(code, out)
            return
        if path.endswith("/reject") and path.startswith("/soar/drafts/"):
            code, out = reject_draft(path.split("/")[-2], b.get("operator"))
            self._send(code, out)
            return
        if path == "/soar/blocks/remove":
            code, out = unblock(b.get("ip"), b.get("operator"))
            self._send(code, out)
            return
        self._send(404, {"error": "not found"})


def start_loop():
    def _loop():
        while True:
            time.sleep(SOAR_INTERVAL)
            try:
                r = generate_drafts()
                if r.get("created_count"):
                    print(f"[soar] 周期剧本：新增草稿 {r['created_count']}（待审批）", flush=True)
            except Exception as e:
                print(f"[soar] 周期剧本异常: {e}", flush=True)
    threading.Thread(target=_loop, daemon=True).start()


def main():
    if "--generate" in sys.argv:
        print(json.dumps(generate_drafts(), ensure_ascii=False, indent=2))
        return 0
    if SOAR_INTERVAL > 0:
        start_loop()
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"[soar] SOAR 服务启动 http://{LISTEN_HOST}:{LISTEN_PORT} "
          f"触发级别={BLOCK_GRADES} 周期={SOAR_INTERVAL}s blocker={blocker.MODE}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
