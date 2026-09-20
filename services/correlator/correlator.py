#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
I-03 轻量关联分析 —— 关联引擎（纯标准库实现，零第三方依赖）

设计要点（对应 PRD F-08 / F-11 / §12 数据口径 / EARS）：
- 纯标准库：urllib 访问 OpenSearch，http.server 提供 REST；容器用 python:3.12-slim，无需 pip。
- 输入：统一检索别名 ssp-events（= suricata + zeek + wazuh 三类探针事件）。
  为防止"自反馈"，本引擎只读探针事件索引；**必须显式按 log_source 白名单过滤**，
  绝不吃进 ssp-asset / ssp-alerts 等非事件索引。
- 关联：规则化（rule-based）关联，不引入 Metron。逐条规则在窗口内做分组聚合，
  产出「实体级」告警（同一规则 + 同一实体 → 唯一告警，幂等 upsert）。
- 分级：P0 秒级 / P1 1 分钟 / P2 10 分钟 / P3 30 分钟（PRD §12）。
  分级 = 规则基础级别 + 升级因子（多源佐证 / 命中重要资产 / 威胁情报命中）。
- 输出：分级告警写入 ssp-alerts（独立索引，别名 ssp-alerts，**不进 ssp-events**）。
- 威胁情报富化（I-04）：可选加载同目录 threat_intel 模块；若不可用则告警照常产出并
  标记"情报未匹配"，不阻断主流程（PRD Unwanted 验收）。

运行：
  服务模式： python3 correlator.py                # 起 HTTP :8091，可开后台周期关联
  单次模式： python3 correlator.py --once         # 跑一次关联并打印 JSON 摘要（供脚本/测试）
"""
import os
import sys
import re
import json
import time
import hashlib
import datetime
import threading
import ipaddress
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ----------------------------- 配置（环境变量） -----------------------------
OS_URL = os.environ.get("OS_URL", "http://opensearch:9200").rstrip("/")
EVENTS_ALIAS = os.environ.get("EVENTS_ALIAS", "ssp-events")
ALERTS_INDEX = os.environ.get("ALERTS_INDEX", "ssp-alerts")
ASSET_ALIAS = os.environ.get("ASSET_ALIAS", "ssp-assets")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8091"))
# 关联窗口（分钟）：只看窗口内事件
WINDOW_MINUTES = int(os.environ.get("CORR_WINDOW_MINUTES", "30"))
# 后台周期关联间隔（秒）；0 = 关闭（仅手动/接口触发）
CORR_INTERVAL = int(os.environ.get("CORR_INTERVAL_SECONDS", "60"))
# 内网主机外联聚合阈值（R-005）
EGRESS_DISTINCT_THRESHOLD = int(os.environ.get("CORR_EGRESS_THRESHOLD", "3"))
# 事件来源白名单：只有这些 log_source 才算"探针事件"
ALLOWED_SOURCES = [s.strip() for s in os.environ.get(
    "ALLOWED_SOURCES", "suricata,zeek,wazuh").split(",") if s.strip()]
CORS_ALLOW_ORIGIN = os.environ.get("CORS_ALLOW_ORIGIN", "*")

# ----------------------------- 网络地址判定 -----------------------------
# 注意：Python 的 ipaddress.is_private 会把 198.51.100.0/24、203.0.113.0/24（TEST-NET）
# 也判为 private，用 is_private 判"外网"会误伤测试网段。这里显式列出真正的内网段。
_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
    "224.0.0.0/4", "240.0.0.0/4",
)]
# 已知良性外部地址，避免把公共 DNS 等当攻击目标（POC 最小白名单）
EXTERNAL_ALLOWLIST = set(a.strip() for a in os.environ.get(
    "EXTERNAL_ALLOWLIST", "8.8.8.8,8.8.4.4,1.1.1.1,114.114.114.114").split(",") if a.strip())


def is_external(ip):
    """IP 是否为"外网地址"（非 RFC1918 / 非环回 / 非链路本地 / 非组播）。"""
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if a.is_multicast or a.is_loopback or a.is_link_local or a.is_unspecified:
        return False
    return not any(a in n for n in _PRIVATE_NETS)


def is_benign_external(ip):
    return ip in EXTERNAL_ALLOWLIST


# ----------------------------- 分级模型（PRD §12） -----------------------------
GRADE_ORDER = ["P0", "P1", "P2", "P3"]           # 小号 = 更紧急
# SLA 阈值（秒）。PRD §12 口径：P0 秒级 / P1 1 分钟 / P2 10 分钟 / P3 30 分钟。
# POC 把"秒级"量化为**可测**的 30 秒（保留"秒级"标签）——否则 P0 的截止时刻等于生成时刻，
# 任何人工/自动响应都"必然超时"，SLA 指标失去意义。可用 env 覆盖：
#   CORR_SLA_SECONDS='{"P0":30,"P1":60,"P2":600,"P3":1800}'
_DEFAULT_SLA = {"P0": 30, "P1": 60, "P2": 600, "P3": 1800}
try:
    GRADE_SLA_SECONDS = {k: int(v) for k, v in {
        **_DEFAULT_SLA,
        **json.loads(os.environ.get("CORR_SLA_SECONDS", "") or "{}"),
    }.items()}
except Exception:
    GRADE_SLA_SECONDS = dict(_DEFAULT_SLA)
GRADE_SLA_LABEL = {"P0": "秒级", "P1": "1 分钟", "P2": "10 分钟", "P3": "30 分钟"}
GRADE_SEVERITY = {"P0": "critical", "P1": "high", "P2": "medium", "P3": "low"}
GRADE_RISK = {"P0": 90, "P1": 70, "P2": 50, "P3": 30}


def escalate(grade, steps=1):
    """按步长提升告警级别（steps>0 更紧急）。"""
    i = GRADE_ORDER.index(grade)
    return GRADE_ORDER[max(0, i - steps)]


# ----------------------------- 规则定义 -----------------------------
# 每条规则的 base_grade 为"无额外佐证"时的起始级别；佐证会触发升级。
RULES = [
    {"id": "R-001", "name": "跨源外部IP关联",
     "desc": "同一外部 IP 在 >=2 个探针来源中出现（跨源佐证，疑似攻击活动/失陷外联）",
     "base_grade": "P2"},
    {"id": "R-002", "name": "SSH暴力破解/异常认证",
     "desc": "Wazuh 认证失败类规则命中（authentication_failures），源自外部 IP",
     "base_grade": "P1"},
    {"id": "R-003", "name": "恶意载荷下载",
     "desc": "Suricata 检出带哈希的可执行载荷 / 命中恶意下载域名",
     "base_grade": "P0"},
    {"id": "R-004", "name": "主机文件完整性异常",
     "desc": "Wazuh FIM(syscheck) 检出可疑文件落地（如隐藏二进制）",
     "base_grade": "P1"},
    {"id": "R-005", "name": "内网主机外联聚合",
     "desc": "同一内网主机在窗口内连接 >=N 个不同外部 IP（疑似扫描/批量外联）",
     "base_grade": "P3"},
    {"id": "R-006", "name": "IDS高危签名告警",
     "desc": "Suricata 签名告警（event.kind=alert）单源命中",
     "base_grade": "P2"},
    {"id": "R-007", "name": "可疑C2域名查询",
     "desc": "DNS 查询域名命中 C2/恶意特征（dns.question.name）",
     "base_grade": "P1"},
]
RULE_BY_ID = {r["id"]: r for r in RULES}

# 恶意下载/C2 域名特征（POC 关键词匹配；生产应改用威胁情报命中）
MALWARE_URL_HINTS = ("malware", "payload", "c2", "botnet", "exploit", "trojan", "ransom")


def domain_hits_hints(domain):
    """域名按 '.'/'-'/'_' 切分后，任一段命中恶意特征即视为可疑。"""
    if not domain:
        return False
    for label in re.split(r"[.\-_]", str(domain).lower()):
        if any(h in label for h in MALWARE_URL_HINTS):
            return True
    return False


# ----------------------------- 工具函数 -----------------------------
def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_ts(s):
    if not s:
        return None
    if isinstance(s, (int, float)):
        return datetime.datetime.fromtimestamp(s / 1000.0 if s > 1e11 else s,
                                               tz=datetime.timezone.utc)
    txt = str(s).replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(txt)
    except ValueError:
        for f in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                  "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.datetime.strptime(str(s), f)
                break
            except ValueError:
                dt = None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def get_in(d, path, default=None):
    """按 'a.b.c' 路径取值，缺失返回 default。"""
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


# ----------------------------- 窗口解析（含回放锚定） -----------------------------
def latest_event_ts():
    st, res = os_request("GET", f"/{EVENTS_ALIAS}/_search", json.dumps({
        "size": 0, "track_total_hits": True,
        "aggs": {"mx": {"max": {"field": "@timestamp"}}}
    }))
    if st != 200:
        return None, 0
    total = get_in(res, "hits.total.value", 0)
    v = get_in(res, "aggregations.mx.value")
    if v is None:
        return None, total
    return datetime.datetime.fromtimestamp(v / 1000.0, tz=datetime.timezone.utc), total


def resolve_window(window_minutes, anchor_iso=None):
    """确定关联窗口 [start, end]。

    - 若显式给 anchor：以 anchor 为窗口右端。
    - 否则：若最新事件在"现在"附近（活跃数据），锚定 now（实时）；否则锚定最新事件
      （回放/演示场景 —— 样本数据时间陈旧时仍可关联）。
    """
    if anchor_iso:
        anchor = parse_ts(anchor_iso) or now_utc()
        return anchor - datetime.timedelta(minutes=window_minutes), anchor, "explicit"
    latest, _total = latest_event_ts()
    now = now_utc()
    if latest is None:
        return now - datetime.timedelta(minutes=window_minutes), now, "live-empty"
    if latest >= now - datetime.timedelta(minutes=window_minutes):
        return now - datetime.timedelta(minutes=window_minutes), now, "live"
    return latest - datetime.timedelta(minutes=window_minutes), latest, "replay"


def fetch_events(window_start, window_end):
    """拉取窗口内探针事件（按 @timestamp 升序），并按 log_source 白名单过滤。"""
    body = {
        "size": 10000,
        "track_total_hits": False,
        "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"filter": [{"range": {"@timestamp": {
            "gte": iso(window_start), "lte": iso(window_end)}}}]}},
    }
    st, res = os_request("POST", f"/{EVENTS_ALIAS}/_search", json.dumps(body))
    if st != 200:
        return [], f"查询事件失败: {st} {res.get('error')}"
    events = []
    for h in get_in(res, "hits.hits", []):
        src = h.get("_source", {}) or {}
        ls = get_in(src, "fields.log_source")
        if ls not in ALLOWED_SOURCES:
            # 关键防护：非探针来源一律丢弃，杜绝把资产/告警当事件
            continue
        src["_id"] = h.get("_id")
        events.append(src)
    return events, None


# ----------------------------- 资产富化 -----------------------------
def lookup_assets(ips):
    """按 IP 批量查资产库（别名 ssp-assets），返回 {ip: asset_doc}。"""
    ips = [ip for ip in ips if ip]
    if not ips:
        return {}
    body = {"size": 200, "query": {"terms": {"ip": ips}}}
    st, res = os_request("POST", f"/{ASSET_ALIAS}/_search", json.dumps(body))
    out = {}
    if st != 200:
        return out
    for h in get_in(res, "hits.hits", []):
        s = h.get("_source", {}) or {}
        if s.get("ip"):
            out[s["ip"]] = s
    return out


# ----------------------------- 威胁情报富化（I-04 钩子） -----------------------------
def load_threat_intel():
    """尝试加载同目录 threat_intel 模块（I-04 提供）。缺失则返回 None。"""
    try:
        import importlib
        mod = importlib.import_module("threat_intel")
        return mod
    except Exception:
        return None


# ----------------------------- 规则实现 -----------------------------
def _ev_ids(events):
    return [e.get("_id") for e in events if e.get("_id")]


def rule_r001_cross_source(events):
    """R-001 跨源外部IP关联：同一外部 IP 出现在 >=2 个来源。"""
    idx = {}
    for e in events:
        ls = get_in(e, "fields.log_source")
        cand = []
        for p in ("source.ip", "destination.ip"):
            ip = get_in(e, p)
            if isinstance(ip, list):
                cand += ip
            elif ip:
                cand.append(ip)
        for ip in cand:
            if is_external(ip) and not is_benign_external(ip):
                d = idx.setdefault(ip, {"sources": set(), "events": [], "internal": set()})
                d["sources"].add(ls)
                d["events"].append(e)
                # 记录对端内网 IP（用于资产富化）
                other = get_in(e, "destination.ip") if ip == get_in(e, "source.ip") else get_in(e, "source.ip")
                if other and not is_external(other):
                    d["internal"].add(other)
                agent_ip = get_in(e, "wazuh.agent.ip")
                if agent_ip:
                    d["internal"].add(agent_ip)
    alerts = []
    for ip, d in idx.items():
        if len(d["sources"]) >= 2:
            grade = RULE_BY_ID["R-001"]["base_grade"]
            if len(d["sources"]) >= 3:
                grade = escalate(grade, 1)
            alerts.append({
                "rule_id": "R-001", "grade": grade, "entity_key": ip,
                "source_ip": ip, "dest_ip": None,
                "internal_ips": sorted(d["internal"]),
                "log_sources": sorted(d["sources"]),
                "event_ids": _ev_ids(d["events"]),
                "event_count": len(d["events"]),
                "message": f"外部 IP {ip} 在 {len(d['sources'])} 个探针来源"
                           f"（{','.join(sorted(d['sources']))}）中出现，跨源佐证",
            })
    return alerts


def rule_r002_bruteforce(events):
    """R-002 SSH 暴力破解：Wazuh 认证失败类规则。"""
    alerts = []
    for e in events:
        if get_in(e, "fields.log_source") != "wazuh":
            continue
        groups = get_in(e, "wazuh.rule.groups", []) or []
        desc = (get_in(e, "wazuh.rule.description", "") or "").lower()
        if "authentication_failures" in groups or "authentication failures" in desc:
            agent = get_in(e, "wazuh.agent.name", "unknown")
            src = get_in(e, "source.ip") or get_in(e, "wazuh.data.srcip")
            if not (src and is_external(src)):
                continue
            alerts.append({
                "rule_id": "R-002", "grade": RULE_BY_ID["R-002"]["base_grade"],
                "entity_key": f"{src}|{agent}",
                "source_ip": src,
                "dest_ip": get_in(e, "wazuh.agent.ip"),
                "internal_ips": [get_in(e, "wazuh.agent.ip")],
                "log_sources": ["wazuh"],
                "event_ids": _ev_ids([e]), "event_count": 1,
                "message": f"外部 IP {src} 对主机 {agent} 触发认证失败告警（疑似暴力破解）",
            })
    return alerts


def rule_r003_malware_download(events):
    """R-003 恶意载荷下载：Suricata 带哈希载荷 / 恶意域名。"""
    alerts = []
    for e in events:
        if get_in(e, "fields.log_source") != "suricata":
            continue
        sha = get_in(e, "file.hash.sha256") or get_in(e, "eve.fileinfo.sha256")
        fname = get_in(e, "file.name") or get_in(e, "eve.fileinfo.filename")
        domain = get_in(e, "url.domain") or get_in(e, "eve.http.hostname")
        hit_domain = domain_hits_hints(domain)
        if sha or hit_domain:
            src = get_in(e, "source.ip")
            dst = get_in(e, "destination.ip")
            grade = RULE_BY_ID["R-003"]["base_grade"]
            if not (sha and (hit_domain or fname)):
                grade = escalate(grade, 1)   # 证据不完整则降一档
            reason = []
            if sha:
                reason.append(f"载荷哈希={str(sha)[:16]}...")
            if hit_domain:
                reason.append(f"恶意域名={domain}")
            alerts.append({
                "rule_id": "R-003", "grade": grade,
                "entity_key": f"{src}|{dst}|{str(sha)[:12] if sha else (fname or domain or 'unknown')}",
                "source_ip": src, "dest_ip": dst,
                "domains": [str(domain).lower()] if domain else [],
                "hashes": [str(sha).lower()] if sha else [],
                "internal_ips": [src] if not is_external(src) else [],
                "log_sources": ["suricata"],
                "event_ids": _ev_ids([e]), "event_count": 1,
                "message": f"检出可疑载荷下载（{'；'.join(reason)}），源 {src} -> 目的 {dst}",
            })
    return alerts


def rule_r004_fim(events):
    """R-004 主机文件完整性异常：Wazuh syscheck / 'File integrity'。"""
    alerts = []
    for e in events:
        if get_in(e, "fields.log_source") != "wazuh":
            continue
        groups = get_in(e, "wazuh.rule.groups", []) or []
        desc = (get_in(e, "wazuh.rule.description", "") or "")
        if "syscheck" in groups or "file integrity" in desc.lower():
            agent = get_in(e, "wazuh.agent.name", "unknown")
            rid = get_in(e, "wazuh.rule.id") or get_in(e, "rule.id")
            alerts.append({
                "rule_id": "R-004", "grade": RULE_BY_ID["R-004"]["base_grade"],
                "entity_key": f"{agent}|{rid}",
                "source_ip": None, "dest_ip": get_in(e, "wazuh.agent.ip"),
                "internal_ips": [get_in(e, "wazuh.agent.ip")],
                "log_sources": ["wazuh"],
                "event_ids": _ev_ids([e]), "event_count": 1,
                "message": f"主机 {agent} 检出文件完整性异常：{desc}",
            })
    return alerts


def rule_r005_egress(events):
    """R-005 内网主机外联聚合：同一内网源连 >=N 个不同外部 IP。"""
    idx = {}
    for e in events:
        src = get_in(e, "source.ip")
        dst = get_in(e, "destination.ip")
        if src and dst and (not is_external(src)) and is_external(dst) and not is_benign_external(dst):
            idx.setdefault(src, {"dsts": set(), "events": []})
            idx[src]["dsts"].add(dst)
            idx[src]["events"].append(e)
    alerts = []
    for src, d in idx.items():
        if len(d["dsts"]) >= EGRESS_DISTINCT_THRESHOLD:
            alerts.append({
                "rule_id": "R-005", "grade": RULE_BY_ID["R-005"]["base_grade"],
                "entity_key": src,
                "source_ip": src, "dest_ip": None,
                "external_ips": sorted(d["dsts"]),
                "internal_ips": [src],
                "log_sources": sorted({get_in(e, "fields.log_source") for e in d["events"]}),
                "event_ids": _ev_ids(d["events"]), "event_count": len(d["events"]),
                "message": f"内网主机 {src} 在窗口内连接 {len(d['dsts'])} 个不同外部 IP"
                           f"（阈值 {EGRESS_DISTINCT_THRESHOLD}），疑似扫描/批量外联",
            })
    return alerts


def rule_r006_ids_alert(events):
    """R-006 IDS 高危签名告警：Suricata event.kind=alert。"""
    alerts = []
    for e in events:
        if get_in(e, "fields.log_source") != "suricata":
            continue
        if get_in(e, "event.kind") != "alert":
            continue
        src = get_in(e, "source.ip")
        dst = get_in(e, "destination.ip")
        rid = get_in(e, "rule.id") or get_in(e, "eve.alert.signature_id") or "unknown"
        desc = get_in(e, "rule.description") or get_in(e, "eve.alert.signature") or ""
        if not desc:
            desc = get_in(e, "eve.alert.signature", "") or f"signature {rid}"
        alerts.append({
            "rule_id": "R-006", "grade": RULE_BY_ID["R-006"]["base_grade"],
            "entity_key": f"{src}|{dst}|{rid}",
            "source_ip": src, "dest_ip": dst,
            "internal_ips": [dst] if dst and not is_external(dst) else [],
            "log_sources": ["suricata"],
            "event_ids": _ev_ids([e]), "event_count": 1,
            "message": f"IDS 签名命中 [{rid}] {desc}：{src} -> {dst}",
        })
    return alerts


def rule_r007_c2_dns(events):
    """R-007 可疑 C2 域名查询：DNS 查询名命中恶意特征。"""
    alerts = []
    for e in events:
        if get_in(e, "fields.log_source") not in ("suricata", "zeek"):
            continue
        qname = get_in(e, "dns.question.name")
        if domain_hits_hints(qname):
            src = get_in(e, "source.ip")
            dst = get_in(e, "destination.ip")
            alerts.append({
                "rule_id": "R-007", "grade": RULE_BY_ID["R-007"]["base_grade"],
                "entity_key": str(qname).lower(),
                "source_ip": src, "dest_ip": dst,
                "domains": [str(qname).lower()],
                "internal_ips": [src] if src and not is_external(src) else [],
                "log_sources": [get_in(e, "fields.log_source")],
                "event_ids": _ev_ids([e]), "event_count": 1,
                "message": f"DNS 查询命中可疑 C2 域名 {qname}（发起方 {src}）",
            })
    return alerts


RULE_FUNCS = [rule_r001_cross_source, rule_r002_bruteforce, rule_r003_malware_download,
              rule_r004_fim, rule_r005_egress, rule_r006_ids_alert, rule_r007_c2_dns]


# ----------------------------- 告警组装 -----------------------------
def alert_doc_id(rule_id, entity_key):
    raw = f"{rule_id}|{entity_key}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:24]


def apply_escalation(grade, internal_ips, assets, threat_hit):
    """升级因子：命中重要资产 / 威胁情报命中。"""
    factors = []
    if threat_hit:
        grade = "P0"
        factors.append("威胁情报命中→P0")
    else:
        for ip in internal_ips or []:
            a = assets.get(ip)
            if a and a.get("importance") in ("核心", "重要"):
                grade = escalate(grade, 1)
                factors.append(f"命中{a['importance']}资产({a.get('name')})→升1档")
                break
    return grade, factors


def geo_index(events):
    """构建 {IP: geo} 索引：从已地理富化的探针事件中抽取"源/目的"两侧坐标。

    事件由 I-01 的 Logstash 管道富化（ECS: source.geo.location / destination.geo.location）。
    仅收录"外网且非白名单"的地址 —— 私有/保留地址本就查不到坐标，显式过滤可避免把
    8.8.8.8 这类良性对端误标到攻击地图上（PRD §8 攻击地图口径：按源 IP 地理定位聚合告警；
    对"恶意载荷下载"这类源为内网、目的为外网的事件，用目的侧坐标标注攻击者位置）。
    """
    m = {}

    def _put(ip, geo):
        if not ip or not isinstance(geo, dict) or not geo.get("location"):
            return
        if not (is_external(ip) and not is_benign_external(ip)):
            return
        m.setdefault(ip, geo)

    for e in events:
        _put(get_in(e, "source.ip"), get_in(e, "source.geo"))
        _put(get_in(e, "destination.ip"), get_in(e, "destination.geo"))
    return m


def build_alert(evt, window, assets, threat_mod, geo_map=None):
    rule = RULE_BY_ID[evt["rule_id"]]
    internal_ips = evt.get("internal_ips") or []
    # 威胁情报比对（I-04）；缺失则标记"情报未匹配"
    threat = {"matched": False, "indicators": [], "enabled": bool(threat_mod)}
    threat_hit = False
    if threat_mod is not None:
        try:
            threat = threat_mod.match_alert(evt)
            threat_hit = bool(threat.get("matched"))
        except Exception as ex:
            threat = {"matched": False, "indicators": [], "enabled": True,
                      "error": f"情报比对异常: {ex}"}
    grade, factors = apply_escalation(evt["grade"], internal_ips, assets, threat_hit)
    gen = now_utc()
    sla = GRADE_SLA_SECONDS[grade]
    due = gen + datetime.timedelta(seconds=sla)
    _id = alert_doc_id(evt["rule_id"], evt["entity_key"])
    # I-07：把地理富化结果透传进告警（态势大屏"攻击地图"按外网侧坐标聚合）
    src_obj = {"ip": evt.get("source_ip")}
    if geo_map and evt.get("source_ip") and geo_map.get(evt["source_ip"]):
        src_obj["geo"] = geo_map[evt["source_ip"]]
    dst_obj = {"ip": evt.get("dest_ip")}
    if geo_map and evt.get("dest_ip") and geo_map.get(evt["dest_ip"]):
        dst_obj["geo"] = geo_map[evt["dest_ip"]]
    # I-07：汇总本告警涉及的全部"外网侧"地理点（源/目的 + 规则携带的外网 IP），
    # 供态势大屏"攻击地图"标注攻击者位置（如 R-005 外联聚合的多个目的 IP）。
    ext_ips = []
    for _ip in ([evt.get("source_ip"), evt.get("dest_ip")] + list(evt.get("external_ips") or [])):
        if _ip and is_external(_ip) and not is_benign_external(_ip) and _ip not in ext_ips:
            ext_ips.append(_ip)
    geo_points = [{"ip": ip, "geo": (geo_map or {})[ip]} for ip in ext_ips if (geo_map or {}).get(ip)]
    asset_hit = None
    for ip in internal_ips:
        if ip in assets:
            asset_hit = {"ip": ip,
                         "name": assets[ip].get("name"),
                         "importance": assets[ip].get("importance"),
                         "importance_score": assets[ip].get("importance_score"),
                         "risk_score": assets[ip].get("risk_score")}
            break
    doc = {
        "@timestamp": iso(gen),
        "event": {
            "kind": "alert", "category": "intrusion_detection", "module": "ssp-correlator",
            "severity": GRADE_SEVERITY[grade], "risk_score": GRADE_RISK[grade],
        },
        "rule": {"id": evt["rule_id"], "name": rule["name"], "description": rule["desc"]},
        "ssp": {"alert": {
            "id": _id, "rule_id": evt["rule_id"], "rule_name": rule["name"],
            "grade": grade, "grade_label": GRADE_SLA_LABEL[grade],
            "sla_seconds": sla, "sla_label": GRADE_SLA_LABEL[grade],
            "status": "open",
            "generated_at": iso(gen), "due_at": iso(due),
            "first_seen_at": iso(gen), "last_seen_at": iso(gen),
            "resolved_at": None, "response_action": None,
            "window_start": iso(window[0]), "window_end": iso(window[1]),
            "escalation_factors": factors,
        }},
        "source": src_obj,
        "destination": dst_obj,
        "related": {
            "log_sources": evt.get("log_sources", []),
            "event_count": evt.get("event_count", 0),
            "event_ids": evt.get("event_ids", []),
            "entities": {"internal_ips": internal_ips, "external_ips": ext_ips},
            "geo_points": geo_points,
        },
        "threat": threat,
        "asset": asset_hit,
        "message": evt["message"],
        "tags": ["ssp-correlator", evt["rule_id"]],
    }
    return _id, doc


# ----------------------------- 写入（幂等 upsert） -----------------------------
def existing_alerts(ids):
    """批量取已存在告警（保留其 status / first_seen_at / response_action）。"""
    if not ids:
        return {}
    docs = [{"_index": ALERTS_INDEX, "_id": i} for i in ids]
    st, res = os_request("POST", "/_mget", json.dumps({"docs": docs}))
    out = {}
    if st == 200:
        for d in res.get("docs", []):
            if d.get("found"):
                out[d["_id"]] = d.get("_source", {})
    return out


def upsert_alerts(alert_docs):
    """幂等写入：新告警 create；已存在则合并（保留人工处理状态，更新 last_seen/count）。"""
    if not alert_docs:
        return {"created": 0, "updated": 0}
    ids = [i for i, _ in alert_docs]
    old = existing_alerts(ids)
    created = updated = 0
    for _id, doc in alert_docs:
        if _id in old:
            prev = old[_id]
            pa = get_in(prev, "ssp.alert", {}) or {}
            na = doc["ssp"]["alert"]
            # 保留人工处理结果
            na["first_seen_at"] = pa.get("first_seen_at", na["first_seen_at"])
            na["status"] = pa.get("status", na["status"])
            na["resolved_at"] = pa.get("resolved_at")
            na["response_action"] = pa.get("response_action")
            na["ticket_id"] = pa.get("ticket_id")
            # 生成/截止时刻必须"钉住"：SLA 从告警首次生成计时，重复关联不得重置时钟
            na["generated_at"] = pa.get("generated_at", na["generated_at"])
            na["due_at"] = pa.get("due_at", na["due_at"])
            # 合并统计
            na["last_seen_at"] = doc["ssp"]["alert"]["generated_at"]
            na["event_count"] = max(doc["related"]["event_count"], get_in(prev, "related.event_count", 0))
            na["escalation_factors"] = sorted(set(
                (pa.get("escalation_factors") or []) + (na.get("escalation_factors") or [])))
            # 级别取更紧急者
            if GRADE_ORDER.index(pa.get("grade", na["grade"])) < GRADE_ORDER.index(na["grade"]):
                na["grade"] = pa["grade"]
                na["sla_seconds"] = GRADE_SLA_SECONDS[na["grade"]]
                na["sla_label"] = GRADE_SLA_LABEL[na["grade"]]
                doc["event"]["severity"] = GRADE_SEVERITY[na["grade"]]
                doc["event"]["risk_score"] = GRADE_RISK[na["grade"]]
            updated += 1
        else:
            created += 1
    # 批量 index（带 _id，天然幂等）
    lines = []
    for _id, doc in alert_docs:
        lines.append(json.dumps({"index": {"_index": ALERTS_INDEX, "_id": _id}}))
        lines.append(json.dumps(doc, ensure_ascii=False))
    body = "\n".join(lines) + "\n"
    st, res = os_request("POST", "/_bulk?refresh=true", body)
    errors = 0
    error_samples = []
    if st != 200:
        return {"created": created, "updated": updated, "error": f"{st} {res.get('error')}"}
    for it in res.get("items", []):
        err = it.get("index", {}).get("error")
        if err:
            errors += 1
            if len(error_samples) < 3:
                error_samples.append(err.get("reason", str(err))[:300])
    out = {"created": created, "updated": updated, "errors": errors}
    if error_samples:
        out["error_samples"] = error_samples
    return out


# ----------------------------- 主流程 -----------------------------
def run_correlation(window_minutes=None, anchor_iso=None):
    t0 = time.time()
    wm = window_minutes or WINDOW_MINUTES
    window = resolve_window(wm, anchor_iso)
    events, err = fetch_events(window[0], window[1])
    if err:
        return {"ok": False, "error": err, "window": [iso(window[0]), iso(window[1])]}

    # 资产富化
    internal_ips = set()
    for e in events:
        for p in ("source.ip", "destination.ip", "wazuh.agent.ip"):
            ip = get_in(e, p)
            if ip and not is_external(ip):
                internal_ips.add(ip)
    assets = lookup_assets(sorted(internal_ips))

    threat_mod = load_threat_intel()
    geo_map = geo_index(events)   # I-07：外网 IP → 地理富化

    candidates = []
    rule_counts = {}
    rule_errors = []
    for fn in RULE_FUNCS:
        try:
            got = fn(events)
        except Exception as ex:
            rule_errors.append(f"{fn.__name__}: {type(ex).__name__}: {ex}")
            continue
        for c in got:
            rule_counts[c["rule_id"]] = rule_counts.get(c["rule_id"], 0) + 1
            candidates.append(c)

    alert_docs = []
    for c in candidates:
        alert_docs.append(build_alert(c, window, assets, threat_mod, geo_map))

    write_res = upsert_alerts(alert_docs)
    return {
        "ok": True,
        "window": {"start": iso(window[0]), "end": iso(window[1]), "mode": window[2],
                   "minutes": wm},
        "events_scanned": len(events),
        "events_by_source": {s: sum(1 for e in events if get_in(e, "fields.log_source") == s)
                             for s in ALLOWED_SOURCES},
        "assets_matched": len(assets),
        "external_ips_geolocated": len(geo_map),
        "threat_intel_enabled": threat_mod is not None,
        "rule_hits": rule_counts,
        "rule_errors": rule_errors,
        "alerts_total": len(alert_docs),
        "write": write_res,
        "elapsed_ms": int((time.time() - t0) * 1000),
    }


def list_alerts(grade=None, status=None, limit=100):
    must = []
    if grade:
        must.append({"term": {"ssp.alert.grade": grade}})
    if status:
        must.append({"term": {"ssp.alert.status": status}})
    body = {"size": limit, "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": must}} if must else {"match_all": {}}}
    st, res = os_request("POST", f"/{ALERTS_INDEX}/_search", json.dumps(body))
    if st != 200:
        return st, res
    return 200, {"total": get_in(res, "hits.total.value", 0),
                 "alerts": [h.get("_source") for h in get_in(res, "hits.hits", [])]}


# ----------------------------- 数据源健康 -----------------------------
def source_health(stale_minutes=None):
    """各探针数据源健康度：按 fields.log_source 统计最近事件时间，判定 ok/stale/down。

    对应 PRD §10「探针断连：大屏标记该数据源异常，**不影响其他源**」：
      * down  —— 该源在事件别名内**没有任何事件**；
      * stale —— 该源最新事件比"全局最新事件"滞后超过 stale_minutes
                 （用**相对陈旧度**而非绝对当前时间，故历史数据重放同样适用）；
      * ok    —— 其余。
    只用一次聚合查询，不写任何状态，天然不影响其它数据源。
    """
    if stale_minutes is None:
        stale_minutes = int(os.environ.get("SOURCE_STALE_MINUTES", "15"))
    body = {"size": 0, "aggs": {"src": {
        "terms": {"field": "fields.log_source", "size": 50},
        "aggs": {"mx": {"max": {"field": "@timestamp"}}}}}}
    st, res = os_request("POST", f"/{EVENTS_ALIAS}/_search", json.dumps(body))
    buckets = []
    if st == 200 and isinstance(res, dict):
        buckets = (res.get("aggregations", {}) or {}).get("src", {}).get("buckets", []) or []
    stats = {b["key"]: {"events": b["doc_count"], "ms": b["mx"].get("value"),
                        "latest": b["mx"].get("value_as_string")} for b in buckets}
    latest_all = None
    for s in stats.values():
        if s["ms"] and (latest_all is None or s["ms"] > latest_all):
            latest_all = s["ms"]
    names = list(ALLOWED_SOURCES) or sorted(stats)
    for n in stats:
        if n not in names:
            names.append(n)
    out = []
    for name in names:
        s = stats.get(name)
        if not s or not s.get("ms"):
            out.append({"source": name, "state": "down", "events": 0,
                        "latest": None, "lag_seconds": None})
            continue
        lag = int((latest_all - s["ms"]) / 1000) if latest_all else None
        state = "stale" if (lag is not None and lag > stale_minutes * 60) else "ok"
        out.append({"source": name, "state": state, "events": s["events"],
                    "latest": s["latest"], "lag_seconds": lag})
    overall = "ok" if out and all(x["state"] == "ok" for x in out) else "degraded"
    return {"checked_at": iso(now_utc()), "stale_minutes": stale_minutes,
            "latest_event": (iso(datetime.datetime.utcfromtimestamp(latest_all / 1000))
                             if latest_all else None),
            "overall": overall, "sources": out}


# ----------------------------- HTTP 服务 -----------------------------
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
        if path in ("/health", "/"):
            _latest, total = latest_event_ts()
            ti = load_threat_intel()
            ti_status = ti.status() if (ti is not None and hasattr(ti, "status")) else None
            self._send(200, {"status": "ok", "index": ALERTS_INDEX,
                             "events_alias": EVENTS_ALIAS, "events_total": total,
                             "interval_seconds": CORR_INTERVAL,
                             "threat_intel": ti is not None,
                             "threat_intel_status": ti_status})
            return
        if path == "/rules":
            self._send(200, {"rules": RULES, "sla_seconds": GRADE_SLA_SECONDS})
            return
        if path == "/sources/health":
            sm = None
            if "?" in self.path:
                for kv in self.path.split("?", 1)[1].split("&"):
                    if kv.startswith("stale_minutes="):
                        try:
                            sm = int(kv.split("=", 1)[1])
                        except ValueError:
                            sm = None
            self._send(200, source_health(sm))
            return
        if path == "/alerts":
            q = {}
            if "?" in self.path:
                for kv in self.path.split("?", 1)[1].split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        q[k] = v
            st, res = list_alerts(q.get("grade"), q.get("status"),
                                  int(q.get("limit", "100")))
            self._send(st, res)
            return
        self._send(404, {"error": "not found"})

    def _post(self):
        path = self.path.split("?")[0]
        if path == "/correlate":
            b = self._body()
            res = run_correlation(b.get("window_minutes"), b.get("anchor"))
            self._send(200 if res.get("ok") else 500, res)
            return
        self._send(404, {"error": "not found"})


def start_loop():
    def _loop():
        while True:
            time.sleep(CORR_INTERVAL)
            try:
                r = run_correlation()
                print(f"[correlator] 周期关联: 事件={r.get('events_scanned')} "
                      f"告警={r.get('alerts_total')} 写入={r.get('write')}", flush=True)
            except Exception as e:
                print(f"[correlator] 周期关联异常: {e}", flush=True)
    t = threading.Thread(target=_loop, daemon=True)
    t.start()


def main():
    if "--once" in sys.argv:
        res = run_correlation()
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1
    if CORR_INTERVAL > 0:
        start_loop()
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"[correlator] 关联引擎启动 http://{LISTEN_HOST}:{LISTEN_PORT} "
          f"窗口={WINDOW_MINUTES}min 周期={CORR_INTERVAL}s", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
