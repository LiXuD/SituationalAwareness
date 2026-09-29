#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
branches.py —— 多分支汇聚：分支登记 + 汇聚健康（I-13）。

职责
----
1. 分支登记（业务库 branches 表）：branch_id / 名称 / 站点 / 网段 / 专线类型 / 期望上报间隔。
2. 汇聚健康：对 OpenSearch 做**一次**聚合，按事件里的 ssp.branch 统计各分支的
   最近上报时间与事件量，判定 ok / stale / no_data / disabled / unregistered。

判定口径（与 correlator 的 source_health 同思路：用**相对陈旧度**而非绝对当前时间，
故历史数据重放场景同样适用）：
    * ok           —— 已登记、启用，且相对"全局最新事件"滞后 ≤ expect_interval_seconds
    * stale        —— 已登记、启用，但滞后 > expect_interval_seconds
    * no_data      —— 已登记、启用，但**完全没有**该分支的事件（视同断链）
    * disabled     —— 已登记但停用（enabled=0），不参与离线判定
    * unregistered —— 事件里出现了未登记的分支（提示补登记，不阻断入库）

分支身份由采集层注入（Filebeat fields.branch → Logstash → ssp.branch），见 docs/I-13。

对外接口（由 portal_server 路由到本模块）
    GET    /api/branches            列表（含实时 state / last_seen / 事件量）
    POST   /api/branches            登记分支
    PUT    /api/branches/{id}       修改
    DELETE /api/branches/{id}       删除登记（不动已入湖数据）
    POST   /api/branches/probe      手动触发一次健康探测
    GET    /api/branches/stats      汇总（在线/离线/未登记）
"""
import ipaddress
import json
import os
import time
import urllib.error
import urllib.request

import db

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://opensearch:9200").rstrip("/")
EVENTS_ALIAS = os.environ.get("EVENTS_ALIAS", "ssp-events")

STATES = ("ok", "stale", "no_data", "disabled", "unregistered", "unknown")
LINK_TYPES = ("leased", "vpn", "internet")

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _now():
    return int(time.time())


def _os_search(index, body, timeout=20):
    req = urllib.request.Request(
        "%s/%s/_search" % (OPENSEARCH_URL, index),
        data=json.dumps(body).encode("utf-8"),
        method="POST", headers={"Content-Type": "application/json"})
    try:
        with _opener.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return e.code, {"error": "http %s" % e.code}
    except Exception as e:
        return 0, "%s: %s" % (type(e).__name__, e)


# --------------------------------------------------------------------------- #
# 汇聚探测（单次聚合）
# --------------------------------------------------------------------------- #
def _probe_os():
    """返回 {branch: {"count": n, "last_epoch": ts}} 以及全局最新事件时间。

    一次 terms 聚合 + 顶层 max，避免按分支逐个查询。
    """
    body = {
        "size": 0,
        "aggs": {
            "tmax": {"max": {"field": "@timestamp"}},
            "b": {"terms": {"field": "ssp.branch", "size": 200},
                  "aggs": {"last": {"max": {"field": "@timestamp"}},
                           "cnt": {"value_count": {"field": "@timestamp"}}}},
        },
    }
    st, res = _os_search(EVENTS_ALIAS, body)
    if st != 200 or not isinstance(res, dict):
        return None, None, ("OpenSearch 不可达或查询失败: %s"
                            % (res if isinstance(res, str) else (res or {}).get("error")))
    aggs = res.get("aggregations") or {}
    tmax = (aggs.get("tmax") or {}).get("value")
    tmax_epoch = int(tmax / 1000) if tmax else None
    out = {}
    for b in ((aggs.get("b") or {}).get("buckets") or []):
        key = str(b.get("key") or "")
        if not key:
            continue
        last = (b.get("last") or {}).get("value")
        out[key] = {
            "count": int((b.get("cnt") or {}).get("value") or b.get("doc_count") or 0),
            "last_epoch": int(last / 1000) if last else None,
        }
    return out, tmax_epoch, None


def _judge(row, seen, tmax_epoch):
    """按 §判定口径算单个已登记分支的状态。"""
    if not int(row.get("enabled", 1)):
        return "disabled"
    info = seen.get(row["branch_id"])
    if not info:
        return "no_data"
    last = info.get("last_epoch")
    if not last:
        return "no_data"
    if tmax_epoch and (tmax_epoch - last) > int(row.get("expect_interval_seconds") or 3600):
        return "stale"
    return "ok"


def probe(persist=True):
    """执行一次汇聚健康探测；persist=True 时把 state/last_seen 写回业务库。"""
    seen, tmax_epoch, err = _probe_os()
    if err:
        return 502, {"ok": False, "error": err}

    rows = db.query("SELECT * FROM branches")
    now = _now()
    result = []
    for row in rows:
        state = _judge(row, seen, tmax_epoch)
        info = seen.get(row["branch_id"]) or {}
        last_epoch = info.get("last_epoch")
        if persist:
            db.execute("UPDATE branches SET state=?, last_seen=?, updated_at=? WHERE branch_id=?",
                       (state, last_epoch, now, row["branch_id"]))
        result.append({"branch_id": row["branch_id"], "state": state,
                       "last_seen": last_epoch, "events": info.get("count", 0)})

    registered = {r["branch_id"] for r in rows}
    unregistered = sorted(k for k in seen if k not in registered)
    counts = {}
    for r in result:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    return 200, {"ok": True, "probed_at": int(now), "latest_event_epoch": tmax_epoch,
                 "branches": result, "unregistered": unregistered, "state_counts": counts}


# --------------------------------------------------------------------------- #
# 查询 / 列表
# --------------------------------------------------------------------------- #
def list_branches():
    """分支列表：登记项 + 实时探测结果；未登记分支以 synthetic 条目提示。"""
    seen, tmax_epoch, err = _probe_os()
    probe_err = err
    seen = seen or {}
    rows = db.query("SELECT * FROM branches ORDER BY branch_id")
    items = []
    for row in rows:
        state = _judge(row, seen, tmax_epoch) if not err else (row.get("state") or "unknown")
        info = seen.get(row["branch_id"]) or {}
        items.append(_row_out(row, state, info.get("last_epoch"), info.get("count", 0)))
    if not err:
        registered = {r["branch_id"] for r in rows}
        for bid in sorted(k for k in seen if k not in registered):
            info = seen[bid]
            items.append({
                "branch_id": bid, "name": "", "site": "", "cidr": "", "link_type": "",
                "enabled": 1, "expect_interval_seconds": 0,
                "state": "unregistered", "registered": False,
                "last_seen": None, "events": info.get("count", 0), "note": "",
            })
    return 200, {"total": len(items), "probe_error": probe_err, "items": items,
                 "latest_event_epoch": tmax_epoch}


def _row_out(row, state, last_epoch, events):
    return {
        "branch_id": row["branch_id"], "name": row.get("name") or "",
        "site": row.get("site") or "", "cidr": row.get("cidr") or "",
        "link_type": row.get("link_type") or "leased",
        "enabled": int(row.get("enabled", 1)),
        "expect_interval_seconds": int(row.get("expect_interval_seconds") or 3600),
        "state": state, "registered": True,
        "last_seen": last_epoch, "events": events, "note": row.get("note") or "",
    }


def stats():
    st, obj = list_branches()
    if st != 200:
        return st, obj
    counts = {}
    for it in obj["items"]:
        counts[it["state"]] = counts.get(it["state"], 0) + 1
    return 200, {"total": obj["total"], "state_counts": counts,
                 "online": counts.get("ok", 0),
                 "offline": counts.get("no_data", 0) + counts.get("stale", 0),
                 "unregistered": counts.get("unregistered", 0),
                 "probe_error": obj.get("probe_error"),
                 "latest_event_epoch": obj.get("latest_event_epoch")}


# --------------------------------------------------------------------------- #
# 登记维护（CRUD）
# --------------------------------------------------------------------------- #
def _validate(body, require_id=False):
    bid = (body.get("branch_id") or "").strip()
    if require_id and not bid:
        return "branch_id 必填"
    if bid and (len(bid) > 64 or any(c.isspace() for c in bid)):
        return "branch_id 非法（≤64 字符且不含空白）"
    lt = (body.get("link_type") or "leased").strip()
    if lt not in LINK_TYPES:
        return "link_type 非法（应为 %s）" % "/".join(LINK_TYPES)
    cidr = (body.get("cidr") or "").strip()
    for x in cidr.split(","):
        x = x.strip()
        if not x:
            continue
        try:
            ipaddress.ip_network(x, strict=False)
        except ValueError:
            return "非法网段: %s" % x
    try:
        if int(body.get("expect_interval_seconds") or 3600) <= 0:
            return "expect_interval_seconds 必须为正整数"
    except (TypeError, ValueError):
        return "expect_interval_seconds 必须为正整数"
    return None


def _fields(body):
    return (
        (body.get("name") or "").strip(),
        (body.get("site") or "").strip(),
        (body.get("cidr") or "").strip(),
        (body.get("link_type") or "leased").strip(),
        1 if str(body.get("enabled", 1)).lower() not in ("0", "false", "no", "off") else 0,
        int(body.get("expect_interval_seconds") or 3600),
        (body.get("note") or "").strip(),
    )


def create_branch(body):
    err = _validate(body, require_id=True)
    if err:
        return 422, {"ok": False, "error": err}
    bid = body["branch_id"].strip()
    if db.query_one("SELECT 1 AS x FROM branches WHERE branch_id=?", (bid,)):
        return 409, {"ok": False, "error": "分支已存在: %s" % bid}
    name, site, cidr, lt, en, exp, note = _fields(body)
    now = _now()
    db.execute(
        "INSERT INTO branches (branch_id, name, site, cidr, link_type, enabled, "
        "expect_interval_seconds, last_seen, state, note, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (bid, name, site, cidr, lt, en, exp, None, "unknown", note, now, now))
    return 200, {"ok": True, "branch_id": bid}


def update_branch(bid, body):
    row = db.query_one("SELECT * FROM branches WHERE branch_id=?", (bid,))
    if not row:
        return 404, {"ok": False, "error": "分支不存在: %s" % bid}
    err = _validate(body)
    if err:
        return 422, {"ok": False, "error": err}
    name, site, cidr, lt, en, exp, note = _fields(body)
    db.execute(
        "UPDATE branches SET name=?, site=?, cidr=?, link_type=?, enabled=?, "
        "expect_interval_seconds=?, note=?, updated_at=? WHERE branch_id=?",
        (name, site, cidr, lt, en, exp, note, _now(), bid))
    return 200, {"ok": True, "branch_id": bid}


def delete_branch(bid):
    if not db.query_one("SELECT 1 AS x FROM branches WHERE branch_id=?", (bid,)):
        return 404, {"ok": False, "error": "分支不存在: %s" % bid}
    db.execute("DELETE FROM branches WHERE branch_id=?", (bid,))
    return 200, {"ok": True, "deleted": bid}
