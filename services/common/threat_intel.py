#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
I-04 MISP 威胁情报对接 —— 轻量适配器 + 本地种子情报（纯标准库，零第三方依赖）

设计要点（对应 PRD F-09 / EARS）：
- 契约：`correlator.py` 运行时惰性加载本模块，调用 `match_alert(evt) -> dict`。
- 双通道情报源：
  1) **本地种子情报**（`threat_intel_seed.json`）—— POC 默认；无需部署 MySQL+Redis 重栈即可端到端实测。
  2) **真实 MISP REST**（`/attributes/restSearch`）—— 配 `MISP_URL` + `MISP_API_KEY` 即启用；
     生产环境只需改这两项即可对接真实 MISP。
- **优雅降级（EARS Unwanted）**：MISP 不可达时**不得阻断主流程** —— 本模块捕获异常、
  标记 `misp_unreachable=true` 并继续用种子情报（或返回"情报未匹配"），告警照常产出。
- 性能：短超时（默认 3s）+ 结果缓存 + 连接失败短期熔断（避免周期任务被拖垮）。

返回结构：
{
  "matched": bool, "enabled": true, "source": "misp"|"seed"|"misp+seed"|"none",
  "misp_configured": bool, "misp_unreachable": bool, "error": str?,
  "indicators": [ {type,value,provider,confidence,first_seen,last_seen,tags} ],
  "indicator": <首个 indicator>
}
"""
import ipaddress
import json
import os
import time
import urllib.error
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MISP_URL = (os.environ.get("MISP_URL") or "").rstrip("/")
MISP_API_KEY = os.environ.get("MISP_API_KEY") or ""
SEED_FILE = os.environ.get("THREAT_SEED_FILE") or os.path.join(BASE_DIR, "threat_intel_seed.json")
TIMEOUT = float(os.environ.get("THREAT_TIMEOUT", "3"))
CACHE_TTL = int(os.environ.get("THREAT_CACHE_TTL", "300"))
# 连接失败后熔断时长（秒）：这段时间内不再尝试连 MISP
DOWN_COOLDOWN = int(os.environ.get("THREAT_MISP_DOWN_COOLDOWN", "60"))

# 内网网段（与 correlator 一致；此处独立实现，避免模块间循环依赖）
_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
)]

_cache = {}          # value -> (expire_ts, [indicators])
_seed_cache = None   # 已加载的种子
_misp_down_until = 0.0


def _is_external(ip):
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if a.is_multicast or a.is_loopback or a.is_link_local or a.is_unspecified:
        return False
    return not any(a in n for n in _PRIVATE_NETS)


# ----------------------------- 种子情报 -----------------------------
def _load_seed():
    global _seed_cache
    if _seed_cache is not None:
        return _seed_cache
    items = []
    try:
        with open(SEED_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        for it in raw.get("indicators", raw) if isinstance(raw, dict) else raw:
            v = str(it.get("value", "")).strip()
            if not v:
                continue
            items.append({
                "type": it.get("type", "unknown"),
                "value": v,
                "value_key": v.lower(),
                "provider": it.get("provider", "seed"),
                "confidence": str(it.get("confidence", "medium")),
                "first_seen": it.get("first_seen"),
                "last_seen": it.get("last_seen"),
                "tags": it.get("tags", []),
            })
    except FileNotFoundError:
        items = []
    except Exception:
        items = []
    _seed_cache = items
    return items


def _seed_match(value):
    key = str(value).lower()
    return [dict(i) for i in _load_seed() if i["value_key"] == key]


# ----------------------------- MISP REST -----------------------------
def _misp_query(value):
    """查询单条 IOC；返回 indicator 列表。网络异常向上抛出，由调用方熔断。"""
    body = json.dumps({
        "returnFormat": "json",
        "value": value,
        "to_ids": False,
        "limit": 10,
        "includeContext": False,
    }).encode("utf-8")
    req = urllib.request.Request(MISP_URL + "/attributes/restSearch", data=body, method="POST")
    req.add_header("Authorization", MISP_API_KEY)
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        raw = resp.read().decode("utf-8", "replace")
    data = json.loads(raw) if raw else {}
    attrs = []
    node = data.get("response", data)
    if isinstance(node, dict):
        attrs = node.get("Attribute", []) or []
    elif isinstance(node, list):
        attrs = node
    out = []
    for a in attrs:
        tags = []
        for t in (a.get("Tag") or []):
            tags.append(t.get("name") if isinstance(t, dict) else str(t))
        out.append({
            "type": a.get("type", "unknown"),
            "value": a.get("value", value),
            "provider": "misp",
            "confidence": "high" if a.get("to_ids") else "medium",
            "first_seen": a.get("first_seen") or a.get("timestamp"),
            "last_seen": a.get("last_seen") or a.get("timestamp"),
            "tags": tags,
        })
    return out


# ----------------------------- IOC 提取 -----------------------------
def extract_iocs(evt):
    """从告警候选抽取 IOC（(type, value) 去重，保持顺序）。"""
    out = []

    def add(t, v):
        if not v:
            return
        v = str(v).strip()
        key = (t, v.lower())
        if key not in [(x["type"], x["value"].lower()) for x in out]:
            out.append({"type": t, "value": v})

    if _is_external(evt.get("source_ip")):
        add("ip-src", evt["source_ip"])
    if _is_external(evt.get("dest_ip")):
        add("ip-dst", evt["dest_ip"])
    for d in (evt.get("domains") or []):
        add("domain", d)
    for h in (evt.get("hashes") or []):
        add("sha256", h)
    return out


# ----------------------------- 主入口 -----------------------------
def match_alert(evt):
    global _misp_down_until
    iocs = extract_iocs(evt)
    misp_configured = bool(MISP_URL and MISP_API_KEY)
    now = time.time()
    indicators = []
    sources = set()
    errors = []
    misp_unreachable = False

    for io in iocs:
        val = io["value"]
        key = f"seed::{val.lower()}"
        exp, cached = _cache.get(key, (0, None))
        hits = cached if cached is not None and exp > now else _seed_match(val)
        _cache[key] = (now + CACHE_TTL, hits)
        for h in hits:
            h2 = {k: v for k, v in h.items() if k != "value_key"}
            indicators.append(h2)
            sources.add("seed")

    if misp_configured:
        if now < _misp_down_until:
            misp_unreachable = True
            errors.append("MISP 处于熔断期（近期连接失败），本次跳过")
        else:
            for io in iocs:
                key = f"misp::{io['value'].lower()}"
                exp, cached = _cache.get(key, (0, None))
                if cached is not None and exp > now:
                    hits = cached
                else:
                    try:
                        hits = _misp_query(io["value"])
                        _cache[key] = (now + CACHE_TTL, hits)
                    except urllib.error.HTTPError as e:
                        hits = []
                        errors.append(f"MISP HTTP {e.code}")
                        _cache[key] = (now + CACHE_TTL, [])
                    except Exception as e:  # 连接失败 / 超时 → 熔断，不阻断
                        misp_unreachable = True
                        _misp_down_until = now + DOWN_COOLDOWN
                        errors.append(f"MISP 不可达: {type(e).__name__}: {e}")
                        break
                for h in hits:
                    indicators.append(h)
                    sources.add("misp")

    # 去重
    seen = set()
    uniq = []
    for ind in indicators:
        k = (ind.get("type"), str(ind.get("value", "")).lower())
        if k not in seen:
            seen.add(k)
            uniq.append(ind)

    source = "+".join(sorted(sources)) if sources else "none"
    res = {
        "matched": bool(uniq),
        "enabled": True,
        "source": source,
        "misp_configured": misp_configured,
        "misp_unreachable": misp_unreachable,
        "indicators": uniq,
    }
    if uniq:
        res["indicator"] = uniq[0]
    if errors:
        res["error"] = "; ".join(errors)[:500]
    return res


def status():
    """供 /health 展示。"""
    return {
        "seed_file": SEED_FILE,
        "seed_size": len(_load_seed()),
        "misp_configured": bool(MISP_URL and MISP_API_KEY),
        "misp_url": MISP_URL or None,
        "misp_circuit_open": time.time() < _misp_down_until,
    }
