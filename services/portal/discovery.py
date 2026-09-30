#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
discovery.py —— 资产测绘（被动识别）引擎 + 候选池（I-12）。

定位
----
在既有「资产仅手工录入 + Excel 导入」（assets.py）之上，**新增自动来源**：
    被动流量识别（Zeek conn.log / 可选 Arkime）→ 候选池 asset_candidates
    → 人工「采纳 / 忽略」→ 合并入 assets（人工字段优先）

设计要点
--------
* 纯标准库（urllib + hashlib + ipaddress），零新增依赖。
* 跑在 portal 进程内（同进程调用 assets/db），复用 SQLite 单连接 + 全局锁，
  **不新建容器/服务**，避免跨进程直连同一 SQLite 造成的锁竞争。
* **不覆盖人工字段**：采纳时只补 first_seen / last_seen / discovered_by / endpoints。
* 候选 id = sha1("ip|port|proto|service")，重复运行幂等（只刷新观测计数，不回退状态）。

对外接口（由 portal_server 路由到本模块）
    GET  /api/discovery/candidates?status=&q=&source=&page=&size=
    GET  /api/discovery/stats
    GET  /api/discovery/config
    PUT  /api/discovery/config
    POST /api/discovery/run        可选 body {"window_minutes": N}
    POST /api/discovery/adopt      body {"ids":[...]}
    POST /api/discovery/ignore     body {"ids":[...]}
"""
import hashlib
import ipaddress
import json
import logging
import os
import time
import urllib.error
import urllib.request

import assets
import db

log = logging.getLogger("portal.discovery")


OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://opensearch:9200").rstrip("/")
ZEEK_INDEX = os.environ.get("DISCOVERY_ZEEK_INDEX", "ssp-zeek-*")

# 配置默认值（可被 config 表覆盖；键名统一 discovery.*）
DEFAULTS = {
    "discovery.cidr_allow": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
    "discovery.min_obs": "3",
    "discovery.window_minutes": "1440",
    "discovery.auto_adopt": "false",
    "discovery.sources": "zeek",
    "discovery.exclude_cidrs": "127.0.0.0/8,169.254.0.0/16,224.0.0.0/4,255.255.255.255/32",
    "discovery.exclude_ips": "",
}
_TRUE = ("1", "true", "yes", "on")

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _now():
    return int(time.time())


def _to_epoch(agg):
    """min/max 聚合返回 epoch_millis；转成 epoch 秒（无值返回 None）。"""
    try:
        v = agg.get("value")
        return int(float(v) / 1000) if v not in (None, "") else None
    except (AttributeError, TypeError, ValueError):
        return None


def _first_key(agg):
    try:
        b = agg.get("buckets") or []
        return b[0]["key"] if b else ""
    except (AttributeError, IndexError, KeyError, TypeError):
        return ""


def _cidrs(s):
    out = []
    for x in (s or "").split(","):
        x = x.strip()
        if not x:
            continue
        try:
            out.append(ipaddress.ip_network(x, strict=False))
        except ValueError:
            continue
    return out


def _ip_allowed(ip, allow, exclude, exclude_ips=()):
    """IP 是否属于「被保护资产」候选：在 allow 内、不在 exclude 内、非显式排除。"""
    if ip in exclude_ips:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in exclude:
        if addr.version == n.version and addr in n:
            return False
    if not allow:
        return True
    for n in allow:
        if addr.version == n.version and addr in n:
            return True
    return False


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #
def get_config():
    out = dict(DEFAULTS)
    try:
        for r in db.query("SELECT key, value FROM config WHERE key LIKE 'discovery.%'"):
            out[r["key"]] = r["value"]
    except Exception as e:
        # 配置读取失败（通常 DB 异常）时不能静默——否则测绘会悄悄用默认配置跑
        log.warning(f"[discovery] 读取配置失败，回退默认: {type(e).__name__}: {e}")
    return out


def set_config(updates):
    if not isinstance(updates, dict) or not updates:
        return 422, {"ok": False, "error": "无更新项"}
    now = _now()
    for k, v in updates.items():
        if k not in DEFAULTS:
            return 422, {"ok": False, "error": "不支持的配置项: %s" % k,
                         "allowed": sorted(DEFAULTS)}
        val = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
        if k == "discovery.min_obs":
            try:
                if int(val) < 0:
                    raise ValueError
            except (TypeError, ValueError):
                return 422, {"ok": False, "error": "min_obs 必须为非负整数"}
        elif k == "discovery.window_minutes":
            try:
                if int(val) <= 0:
                    raise ValueError
            except (TypeError, ValueError):
                return 422, {"ok": False, "error": "window_minutes 必须为正整数"}
        elif k == "discovery.auto_adopt":
            if val.strip().lower() not in _TRUE + ("0", "false", "no", "off"):
                return 422, {"ok": False, "error": "auto_adopt 必须为 true/false"}
        elif k in ("discovery.cidr_allow", "discovery.exclude_cidrs"):
            for x in val.split(","):
                x = x.strip()
                if not x:
                    continue
                try:
                    ipaddress.ip_network(x, strict=False)
                except ValueError:
                    return 422, {"ok": False, "error": "非法网段: %s" % x}
        # upsert（方言无关：先 UPDATE，未命中再 INSERT）
        if not db.execute("UPDATE config SET value=?, updated_at=? WHERE key=?", (val, now, k)):
            db.execute("INSERT INTO config (key, value, updated_at) VALUES (?,?,?)", (k, val, now))
    return 200, {"ok": True, "config": get_config()}


# --------------------------------------------------------------------------- #
# OpenSearch 读写
# --------------------------------------------------------------------------- #
def _os_search(index, body, timeout=30):
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


def _zeek_query(window_minutes):
    """单次聚合：目的主机 → 端口 → (协议/服务/首末时间/计数)。

    字段依据 docs/ecs-field-mapping.md §3（Zeek conn.log → ECS）。
    """
    return {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-%dm" % int(window_minutes)}}},
            {"term": {"event.category": "network"}},
        ]}},
        "aggs": {"dst_host": {
            "terms": {"field": "destination.ip", "size": 2000, "order": {"_count": "desc"}},
            "aggs": {"ports": {
                "terms": {"field": "destination.port", "size": 100},
                "aggs": {
                    "proto":   {"terms": {"field": "network.transport", "size": 3}},
                    "service": {"terms": {"field": "network.protocol", "size": 3}},
                    "first":   {"min": {"field": "@timestamp"}},
                    "last":    {"max": {"field": "@timestamp"}},
                }}}}},
    }


# --------------------------------------------------------------------------- #
# 候选池写入（幂等）
# --------------------------------------------------------------------------- #
def _cand_id(ip, port, proto, service):
    return hashlib.sha1(("%s|%s|%s|%s" % (ip, port, proto, service)).encode("utf-8")).hexdigest()


def _upsert_candidate(ip, port, proto, service, count, first, last, source, evidence, now):
    """返回 created / updated。已 adopted/ignored 的候选**不回退**状态。"""
    cid = _cand_id(ip, port, proto, service)
    row = db.query_one(
        "SELECT id, status, first_seen, last_seen FROM asset_candidates WHERE id=?", (cid,))
    if row:
        new_first = assets._min_ts(row.get("first_seen"), first)
        new_last = assets._max_ts(row.get("last_seen"), last)
        db.execute(
            "UPDATE asset_candidates SET obs_count=?, first_seen=?, last_seen=?, "
            "evidence=?, updated_at=? WHERE id=?",
            (count, new_first, new_last, evidence, now, cid))
        return "updated"
    db.execute(
        "INSERT INTO asset_candidates (id, ip, port, proto, service, obs_count, first_seen, "
        "last_seen, source, evidence, status, asset_id, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (cid, ip, port, proto, service, count, first, last, source, evidence, "pending", "", now, now))
    return "created"


# --------------------------------------------------------------------------- #
# 主流程：run / adopt / ignore / 查询
# --------------------------------------------------------------------------- #
def run(window_minutes=None):
    """执行一次被动测绘：Zeek 连接记录 → 候选池。"""
    cfg = get_config()
    try:
        win = int(window_minutes or cfg["discovery.window_minutes"])
    except (TypeError, ValueError):
        win = 1440
    allow = _cidrs(cfg["discovery.cidr_allow"])
    exclude = _cidrs(cfg["discovery.exclude_cidrs"])
    exclude_ips = {x.strip() for x in (cfg.get("discovery.exclude_ips") or "").split(",") if x.strip()}
    try:
        min_obs = int(cfg["discovery.min_obs"])
    except (TypeError, ValueError):
        min_obs = 0

    st, resp = _os_search(ZEEK_INDEX, _zeek_query(win))
    if st != 200 or not isinstance(resp, dict):
        return 502, {"ok": False, "error": "OpenSearch 不可达或查询失败",
                     "http": st, "detail": resp if isinstance(resp, str) else resp.get("error")}

    buckets = (((resp.get("aggregations") or {}).get("dst_host") or {}).get("buckets") or [])
    now = _now()
    created = updated = 0
    hosts = set()
    evidence = "%s@%dm" % (ZEEK_INDEX, win)
    for hb in buckets:
        ip = str(hb.get("key") or "")
        if not ip or not _ip_allowed(ip, allow, exclude, exclude_ips):
            continue
        for pb in ((hb.get("ports") or {}).get("buckets") or []):
            try:
                port = int(pb.get("key"))
            except (TypeError, ValueError):
                continue
            cnt = int(pb.get("doc_count") or 0)
            if cnt < min_obs:
                continue
            proto = _first_key(pb.get("proto"))
            service = _first_key(pb.get("service"))
            first = _to_epoch(pb.get("first"))
            last = _to_epoch(pb.get("last"))
            action = _upsert_candidate(ip, port, proto, service, cnt, first, last, "passive", evidence, now)
            if action == "created":
                created += 1
            else:
                updated += 1
            hosts.add(ip)

    auto = str(cfg.get("discovery.auto_adopt", "false")).strip().lower() in _TRUE
    auto_res = _auto_adopt(allow, exclude, exclude_ips) if auto else None
    return 200, {"ok": True, "window_minutes": win, "index": ZEEK_INDEX,
                 "scanned_hosts": len(hosts), "created": created, "updated": updated,
                 "auto_adopt": bool(auto), "auto_adopt_result": auto_res, "run_at": now}


def _auto_adopt(allow, exclude, exclude_ips):
    """自动采纳：仅「授权网段内 且 obs_count ≥ min_obs」的待审候选，且只写观测类字段。"""
    rows = db.query(
        "SELECT id FROM asset_candidates WHERE status='pending' AND obs_count >= ? "
        "ORDER BY obs_count DESC LIMIT 500", (_min_obs_from_cfg(),))
    ids = []
    for r in rows:
        c = db.query_one("SELECT ip FROM asset_candidates WHERE id=?", (r["id"],))
        if c and _ip_allowed(c["ip"], allow, exclude, exclude_ips):
            ids.append(r["id"])
    if not ids:
        return {"adopted": 0, "created": 0, "merged": 0}
    _, obj = adopt(ids, operator="auto")
    return {"adopted": obj.get("adopted", 0), "created": obj.get("created", 0),
            "merged": obj.get("merged", 0)}


def _min_obs_from_cfg():
    try:
        return int(get_config()["discovery.min_obs"])
    except (TypeError, ValueError):
        return 0


def list_candidates(status="pending", q="", source="", page=1, size=50):
    where, params = [], []
    if status and status != "all":
        where.append("status=?")
        params.append(status)
    if source:
        where.append("source=?")
        params.append(source)
    if q:
        where.append("(ip LIKE ? OR service LIKE ? OR proto LIKE ?)")
        like = "%" + q + "%"
        params += [like, like, like]
    wh = ("WHERE " + " AND ".join(where)) if where else ""
    total = db.query_one("SELECT COUNT(*) AS n FROM asset_candidates " + wh, params)["n"]
    rows = db.query(
        "SELECT * FROM asset_candidates %s ORDER BY last_seen DESC, obs_count DESC "
        "LIMIT %d OFFSET %d" % (wh, size, (page - 1) * size), params)
    have = set()
    ips = [r["ip"] for r in rows if r.get("ip")]
    if ips:
        ph = ",".join(["?"] * len(ips))
        for a in db.query("SELECT DISTINCT ip FROM assets WHERE ip IN (%s)" % ph, ips):
            have.add(a["ip"])
    items = [_cand_out(r, r["ip"] in have) for r in rows]
    return 200, {"total": total, "page": page, "size": size, "items": items}


def _cand_out(row, in_assets):
    def iso(t):
        return assets._iso(t) if t else ""
    return {
        "id": row["id"], "ip": row["ip"], "port": row.get("port"),
        "proto": row.get("proto") or "", "service": row.get("service") or "",
        "obs_count": row.get("obs_count") or 0,
        "first_seen": iso(row.get("first_seen")), "last_seen": iso(row.get("last_seen")),
        "source": row.get("source") or "passive", "evidence": row.get("evidence") or "",
        "status": row.get("status") or "pending", "asset_id": row.get("asset_id") or "",
        "in_assets": bool(in_assets),
    }


def stats():
    def one(sql, params=()):
        return db.query_one(sql, params)["n"]
    return 200, {
        "total": one("SELECT COUNT(*) AS n FROM asset_candidates"),
        "pending": one("SELECT COUNT(*) AS n FROM asset_candidates WHERE status='pending'"),
        "adopted": one("SELECT COUNT(*) AS n FROM asset_candidates WHERE status='adopted'"),
        "ignored": one("SELECT COUNT(*) AS n FROM asset_candidates WHERE status='ignored'"),
        "adopted_hosts": one("SELECT COUNT(DISTINCT ip) AS n FROM asset_candidates WHERE status='adopted'"),
    }


def adopt(ids, operator=""):
    """采纳候选 → 合并入 assets（人工字段优先，只补观测字段）。全量预校验，任一非法整批拒绝。"""
    cfg = get_config()
    allow = _cidrs(cfg["discovery.cidr_allow"])
    exclude = _cidrs(cfg["discovery.exclude_cidrs"])
    exclude_ips = {x.strip() for x in (cfg.get("discovery.exclude_ips") or "").split(",") if x.strip()}
    ids = [str(x) for x in (ids or []) if str(x).strip()]
    if not ids:
        return 422, {"ok": False, "error": "未选择候选"}
    cands = []
    for cid in ids:
        c = db.query_one("SELECT * FROM asset_candidates WHERE id=?", (cid,))
        if not c:
            return 404, {"ok": False, "error": "候选不存在: %s" % cid}
        if c["status"] != "pending":
            return 409, {"ok": False, "error": "候选状态非待审（%s）: %s" % (c["status"], cid)}
        if not _ip_allowed(c["ip"], allow, exclude, exclude_ips):
            return 422, {"ok": False, "error": "IP 不在授权网段: %s" % c["ip"],
                         "errors": [{"id": cid, "ip": c["ip"], "reason": "不在 discovery.cidr_allow 内"}]}
        cands.append(c)

    created = merged = 0
    now = _now()
    for c in cands:
        ep = {"port": c.get("port"), "proto": c.get("proto") or "",
              "service": c.get("service") or "", "count": c.get("obs_count") or 0,
              "last_seen": c.get("last_seen")}
        aid, action = assets.merge_discovered(c["ip"], [ep], c.get("first_seen"), c.get("last_seen"))
        db.execute("UPDATE asset_candidates SET status='adopted', asset_id=?, updated_at=? WHERE id=?",
                   (aid, now, c["id"]))
        if action == "created":
            created += 1
        else:
            merged += 1
    return 200, {"ok": True, "adopted": len(cands), "created": created, "merged": merged,
                 "operator": operator}


def ignore(ids, operator=""):
    ids = [str(x) for x in (ids or []) if str(x).strip()]
    if not ids:
        return 422, {"ok": False, "error": "未选择候选"}
    now = _now()
    n = 0
    for cid in ids:
        if not db.query_one("SELECT id FROM asset_candidates WHERE id=?", (cid,)):
            continue
        db.execute("UPDATE asset_candidates SET status='ignored', updated_at=? WHERE id=?", (now, cid))
        n += 1
    return 200, {"ok": True, "ignored": n, "operator": operator}
