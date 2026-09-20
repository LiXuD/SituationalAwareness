#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar.py —— SOAR 拉黑审批业务逻辑（落平台业务库，见 db.py 的 soar_drafts/blacklist 表）。

统一边界：
  * 草稿状态机 + 黑名单 → 平台业务库（SQLite），不再借用 OpenSearch 当业务库。
  * 落黑执行（iptables）→ 仍由 soar 容器（privileged）执行，portal 通过 HTTP 调其
    纯执行接口（/soar/block/apply|remove|list），这是合理的技术分工（系统级操作）。
  * 告警（ssp-alerts）仍在 OpenSearch（检索型数据），审批结果回写其中供大屏展示。
"""
import datetime
import hashlib
import ipaddress
import json
import os
import time
import urllib.error
import urllib.request

import db

OS_URL = os.environ.get("OPENSEARCH_URL", "http://opensearch:9200").rstrip("/")
SOAR_URL = os.environ.get("SOAR_URL", "http://soar:8092").rstrip("/")
ALERTS_INDEX = os.environ.get("ALERTS_INDEX", "ssp-alerts")
BLOCK_GRADES = [g.strip() for g in os.environ.get("SOAR_BLOCK_GRADES", "P0").split(",") if g.strip()]
DEFAULT_OPERATOR = os.environ.get("SOAR_DEFAULT_OPERATOR", "ops")

_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
)]
BENIGN = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "114.114.114.114"}


def _now():
    return int(time.time())


def _iso(epoch=None):
    dt = datetime.datetime.fromtimestamp(epoch or _now(), datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def is_blockable(ip):
    if not ip or ip in BENIGN:
        return False
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if a.is_multicast or a.is_loopback or a.is_link_local or a.is_unspecified:
        return False
    return not any(a in n for n in _PRIVATE_NETS)


def draft_id_for(alert_id, ip):
    return hashlib.sha1(f"{alert_id}|{ip}".encode("utf-8")).hexdigest()[:20]


def _http(url, method="GET", body=None, timeout=20):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
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


def _os(method, path, body=None):
    return _http(OS_URL + path, method, body)


def _soar_exec(method, path, body=None):
    """调 soar 容器的纯执行接口。"""
    return _http(SOAR_URL + path, method, body)


def _get_in(d, path, default=None):
    cur = d
    for k in path.split("."):
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


# ----------------------------- 草稿（SQLite） -----------------------------
def _row_to_doc(row):
    """SQLite 行 -> 对外草稿 doc（核心字段 + payload 完整信息）。"""
    try:
        payload = json.loads(row.get("payload") or "{}")
    except Exception:
        payload = {}
    payload.update({
        "draft_id": row["id"], "alert_id": row["alert_id"], "target_ip": row["entity"],
        "grade": row["grade"], "status": row["status"], "reason": row["reason"],
    })
    if row.get("approver"):
        payload["decided_by"] = row["approver"]
    return payload


def get_draft(draft_id):
    row = db.query_one("SELECT * FROM soar_drafts WHERE id=?", (draft_id,))
    return _row_to_doc(row) if row else None


def _save_draft(draft_id, alert_id, entity, grade, status, payload, reason="", approver="", decided_at=None, fail_reason=""):
    now = _now()
    db.execute(
        "INSERT INTO soar_drafts (id, alert_id, entity, entity_type, action, grade, status, reason, "
        "created_at, updated_at, approver, decided_at, fail_reason, payload) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET status=excluded.status, reason=excluded.reason, "
        "updated_at=excluded.updated_at, approver=excluded.approver, decided_at=excluded.decided_at, "
        "fail_reason=excluded.fail_reason, payload=excluded.payload",
        (draft_id, alert_id, entity, "ip", "block", grade, status, reason,
         now, now, approver, decided_at, fail_reason, json.dumps(payload, ensure_ascii=False)))


def list_drafts(status=None, limit=100):
    where, params = "", []
    if status:
        where = "WHERE status=?"
        params = [status]
    rows = db.query(f"SELECT * FROM soar_drafts {where} ORDER BY updated_at DESC LIMIT {limit}", params)
    return 200, {"total": len(rows), "drafts": [_row_to_doc(r) for r in rows]}


def _find_active_draft_by_ip(ip):
    row = db.query_one(
        "SELECT id FROM soar_drafts WHERE entity=? AND status IN ('pending_approval','executed') LIMIT 1",
        (ip,))
    return row is not None


# ----------------------------- 剧本：生成草稿 -----------------------------
def _find_alerts_for_block(limit=200):
    body = {"size": limit, "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": [
                {"term": {"ssp.alert.status": "open"}},
                {"terms": {"ssp.alert.grade": BLOCK_GRADES}},
            ]}}}
    st, res = _os("POST", f"/{ALERTS_INDEX}/_search", body)
    if st != 200:
        return [], res
    return [{"id": h.get("_id"), "src": h.get("_source", {}) or {}}
            for h in _get_in(res, "hits.hits", [])], None


def generate_drafts():
    alerts, err = _find_alerts_for_block()
    if err:
        return {"ok": False, "error": err}
    created, skipped = [], []
    for a in alerts:
        s = a["src"]
        alert_id = _get_in(s, "ssp.alert.id") or a["id"]
        ip = _get_in(s, "source.ip")
        if not is_blockable(ip):
            skipped.append({"alert_id": alert_id, "reason": f"无可封禁外网源IP（{ip}）"})
            continue
        did = draft_id_for(alert_id, ip)
        if get_draft(did):
            skipped.append({"alert_id": alert_id, "reason": "草稿已存在"})
            continue
        if _find_active_draft_by_ip(ip):
            skipped.append({"alert_id": alert_id, "reason": f"{ip} 已有未闭环草稿，去重"})
            continue
        threat = s.get("threat") or {}
        ind = threat.get("indicator") or {}
        now_iso = _iso()
        payload = {
            "draft_id": did, "alert_id": alert_id, "target_ip": ip,
            "rule_id": _get_in(s, "ssp.alert.rule_id"),
            "rule_name": _get_in(s, "ssp.alert.rule_name"),
            "grade": _get_in(s, "ssp.alert.grade"),
            "direction": "inbound", "status": "pending_approval",
            "reason": s.get("message", ""),
            "impact": "封禁该外部 IP 的全部入向流量；可能影响合法业务，请确认非误报后再提交。",
            "threat": {"matched": bool(threat.get("matched")), "source": threat.get("source"),
                       "value": ind.get("value"), "tags": ind.get("tags") or []},
            "created_at": now_iso,
            "history": [{"at": now_iso, "actor": "soar", "action": "draft_created",
                         "detail": f"由告警 {alert_id}（{_get_in(s,'ssp.alert.grade')}）自动生成拉黑草稿，待人工审批"}],
        }
        _save_draft(did, alert_id, ip, _get_in(s, "ssp.alert.grade"), "pending_approval", payload)
        created.append(did)
    return {"ok": True, "created": created, "created_count": len(created),
            "skipped": skipped, "block_grades": BLOCK_GRADES,
            "note": "草稿已生成，等待人工审批；系统不会自动提交"}


# ----------------------------- 审批 / 执行 -----------------------------
def _update_alert(alert_id, fields):
    _os("POST", f"/{ALERTS_INDEX}/_update/{alert_id}", {"doc": {"ssp": {"alert": fields}}})


def approve_draft(draft_id, operator=None, dry_run=False):
    row = db.query_one("SELECT * FROM soar_drafts WHERE id=?", (draft_id,))
    if not row:
        return 404, {"ok": False, "error": "草稿不存在"}
    payload = _row_to_doc(row)
    if row["status"] not in ("pending_approval", "failed"):
        return 409, {"ok": False, "error": f"草稿当前状态为 {row['status']}，不可审批"}

    operator = operator or DEFAULT_OPERATOR
    ip = row["entity"]
    # 调 soar 容器执行落黑（dry_run 演练则不动 iptables）
    st, res = _soar_exec("POST", "/soar/block/apply", {"ip": ip, "dry_run": dry_run})

    decided_at = _now()
    now_iso = _iso()
    hist = payload.setdefault("history", [])
    if st == 200 and res.get("ok"):
        payload.update({"status": "executed", "decided_at": now_iso, "decided_by": operator,
                        "executed_at": now_iso, "block_backend": res.get("backend"),
                        "block_rule": "; ".join(res.get("rules") or []), "block_error": None})
        hist.append({"at": now_iso, "actor": operator, "action": "approved",
                     "detail": f"审批通过，落黑 {ip} 成功（{res.get('backend')}）"
                               + ("（dry-run 演练）" if dry_run else "")})
        db.execute("INSERT INTO blacklist (entity, entity_type, action, reason, source, created_at, status) "
                   "VALUES (?,?,?,?,?,?,?) ON CONFLICT(entity) DO UPDATE SET status='active', created_at=excluded.created_at",
                   (ip, "ip", "block", row["reason"], "soar", decided_at, "active"))
        _save_draft(draft_id, row["alert_id"], ip, row["grade"], "executed", payload,
                    approver=operator, decided_at=decided_at)
        _update_alert(row["alert_id"], {"status": "blocked",
                                        "response_action": f"block:{res.get('backend')}",
                                        "ticket_id": draft_id, "resolved_at": now_iso})
        return 200, {"ok": True, "draft": payload, "block": res}
    err = res.get("error") or f"落黑执行器返回 {st}"
    payload.update({"status": "failed", "block_error": err, "decided_at": now_iso, "decided_by": operator})
    hist.append({"at": now_iso, "actor": operator, "action": "approve_failed",
                 "detail": f"落黑失败：{err}；告警保持待处置"})
    _save_draft(draft_id, row["alert_id"], ip, row["grade"], "failed", payload,
                approver=operator, decided_at=decided_at, fail_reason=err)
    _update_alert(row["alert_id"], {"status": "open", "response_action": f"block_failed:{err}",
                                    "ticket_id": draft_id})
    return 500, {"ok": False, "draft": payload, "block": res, "error": "落黑执行失败，告警保持待处置"}


def reject_draft(draft_id, operator=None):
    row = db.query_one("SELECT * FROM soar_drafts WHERE id=?", (draft_id,))
    if not row:
        return 404, {"ok": False, "error": "草稿不存在"}
    if row["status"] not in ("pending_approval", "failed"):
        return 409, {"ok": False, "error": f"草稿当前状态为 {row['status']}，不可驳回"}
    operator = operator or DEFAULT_OPERATOR
    payload = _row_to_doc(row)
    now_iso = _iso()
    payload.update({"status": "rejected", "decided_at": now_iso, "decided_by": operator})
    payload.setdefault("history", []).append(
        {"at": now_iso, "actor": operator, "action": "rejected", "detail": "人工驳回，不执行封禁"})
    _save_draft(draft_id, row["alert_id"], row["entity"], row["grade"], "rejected", payload,
                approver=operator, decided_at=_now())
    _update_alert(row["alert_id"], {"status": "rejected", "response_action": "reject",
                                    "ticket_id": draft_id})
    return 200, {"ok": True, "draft": payload}


def unblock(ip, operator=None):
    if not is_blockable(ip):
        return 400, {"ok": False, "error": f"非法或不可封禁的 IP: {ip}"}
    operator = operator or DEFAULT_OPERATOR
    st, res = _soar_exec("POST", "/soar/block/remove", {"ip": ip})
    db.execute("UPDATE blacklist SET status='inactive' WHERE entity=?", (ip,))
    reverted = []
    for r in db.query("SELECT * FROM soar_drafts WHERE entity=? AND status='executed'", (ip,)):
        payload = _row_to_doc(r)
        payload.update({"status": "reverted"})
        payload.setdefault("history", []).append(
            {"at": _iso(), "actor": operator, "action": "unblocked",
             "detail": f"解除封禁 {ip}，草稿作废"})
        _save_draft(r["id"], r["alert_id"], ip, r["grade"], "reverted", payload,
                    approver=operator, decided_at=_now())
        _update_alert(r["alert_id"], {"status": "open", "response_action": "unblock"})
        reverted.append(r["id"])
    return 200, {"ok": res.get("ok"), "block": res, "reverted_drafts": reverted, "operator": operator}


def list_blocks():
    rows = db.query("SELECT * FROM blacklist WHERE status='active' ORDER BY created_at DESC")
    return [{"entity": r["entity"], "entity_type": r["entity_type"], "action": r["action"],
             "reason": r["reason"], "source": r["source"], "created_at": _iso(r["created_at"]),
             "status": r["status"]} for r in rows]
