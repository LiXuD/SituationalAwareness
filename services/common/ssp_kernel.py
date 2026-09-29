#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ssp_kernel.py —— **共享关联内核**（I-14 抽取；纯标准库，零第三方依赖）

为什么要有这一层
----------------
I-14 引入流式关联后，若批式（correlator）与流式（stream）各写一套规则实现，会出现
"规则实现分叉"（见 `docs/I-14-流式关联与外部日志源适配-计划.md` §八 风险表）。
因此把**规则定义、规则执行、分级/升级、告警组装、幂等写入、资产/情报/地理富化、窗口解析、
数据源健康**全部收敛到本模块，两侧只做"取事件 + 调用内核 + 写告警"的执行壳：

    correlator(:8091)  取窗口内事件（OpenSearch 查询）→ kernel.evaluate(engine="batch")
    stream(:8094)      取滑动窗口内事件（Kafka 内存窗口）→ kernel.evaluate(engine="stream")

口径不变项（重要）
------------------
- 索引纪律：只读写 `ssp-events`（探针事件别名）/ `ssp-alerts`；**严禁通配 `ssp-*`**。
- 事件白名单：`ALLOWED_SOURCES`（默认 suricata,zeek,wazuh）——防止把资产/告警当事件（自反馈）。
- 告警 id：`sha1(rule_id|entity_key)` → 批式与流式写同一 `_id`，天然幂等去重（共存不重复计数）。
- 窗口锚定**事件时间**，不是墙钟（否则历史回放数据全部落在窗口外，I-13 已踩过此坑）。
- SLA/分级阈值沿用 PRD §12（P0 秒级 / P1 1 分钟 / P2 10 分钟 / P3 30 分钟）。

共存标记（I-14 新增，便于验收与观测）
--------------------------------------
- `ssp.alert.engines`      ：产生/更新过该告警的引擎集合（batch / stream）
- `ssp.alert.first_engine` ：首个产生该告警的引擎
- `ssp.alert.last_engine`  ：最后更新该告警的引擎
- `ssp.alert.stream_latency_ms`：流式引擎实测时延（事件入 Kafka → 告警落库，毫秒）
"""
import datetime
import hashlib
import importlib
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

# ----------------------------- 配置（环境变量） -----------------------------
OS_URL = os.environ.get("OS_URL", "http://opensearch:9200").rstrip("/")
EVENTS_ALIAS = os.environ.get("EVENTS_ALIAS", "ssp-events")
ALERTS_INDEX = os.environ.get("ALERTS_INDEX", "ssp-alerts")
ASSET_ALIAS = os.environ.get("ASSET_ALIAS", "ssp-assets")
# 关联窗口（分钟）：只看窗口内事件
WINDOW_MINUTES = int(os.environ.get("CORR_WINDOW_MINUTES", "30"))
# 内网主机外联聚合阈值（R-005）
EGRESS_DISTINCT_THRESHOLD = int(os.environ.get("CORR_EGRESS_THRESHOLD", "3"))
# 事件来源白名单：只有这些 log_source 才算"事件"（防自反馈）
ALLOWED_SOURCES = [s.strip() for s in os.environ.get(
    "ALLOWED_SOURCES", "suricata,zeek,wazuh").split(",") if s.strip()]
# 外部日志源（I-14 L2）：适配器投递、经 Logstash 归一后**可选**参与关联。
# 默认**为空**——批式引擎只消费探针事件（保持 I-03 口径与既有回归不受影响）；
# 流式引擎按需用 EXTERNAL_SOURCES=firewall,waf 打开（见 deploy/stream/compose.yml）。
EXTERNAL_SOURCES = [s.strip() for s in os.environ.get(
    "EXTERNAL_SOURCES", "").split(",") if s.strip()]
# related.event_ids 保留上限（批式/流式合并时不无限膨胀）
MAX_EVENT_IDS = int(os.environ.get("CORR_MAX_EVENT_IDS", "50"))

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


# ----------------------------- 规则定义（R-001~R-007） -----------------------------
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
        dt = None
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
    """拉取窗口内事件（按 @timestamp 升序），并按 log_source 白名单过滤。"""
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
        if ls not in allowed_sources():
            # 关键防护：非事件来源一律丢弃，杜绝把资产/告警当事件
            continue
        src["_id"] = h.get("_id")
        events.append(src)
    return events, None


def allowed_sources():
    """事件来源白名单：探针源 + 已启用的外部源。"""
    return list(ALLOWED_SOURCES) + [s for s in EXTERNAL_SOURCES if s not in ALLOWED_SOURCES]


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
_THREAT_CACHE = {"mod": None, "dir": None}


def load_threat_intel():
    """加载 threat_intel 模块（I-04 提供）。缺失则返回 None（不阻断主流程）。

    搜索顺序：THREAT_MODULE_DIR 环境变量 → 本模块所在目录 → sys.path 各目录。
    """
    want = os.environ.get("THREAT_MODULE_DIR") or os.path.dirname(os.path.abspath(__file__))
    dirs = [want] + [p for p in (os.path.dirname(os.path.abspath(__file__)),) if p != want]
    dirs += [p for p in sys.path if p and p not in dirs]
    if _THREAT_CACHE["mod"] is not None and _THREAT_CACHE["dir"] in dirs:
        return _THREAT_CACHE["mod"]
    for d in dirs:
        if not d or not os.path.exists(os.path.join(d, "threat_intel.py")):
            continue
        try:
            if d not in sys.path:
                sys.path.insert(0, d)
            mod = importlib.import_module("threat_intel")
            _THREAT_CACHE.update({"mod": mod, "dir": d})
            return mod
        except Exception:
            continue
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
                "message": f"外部 IP {ip} 在 {len(d['sources'])} 个来源"
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


def run_rules(events):
    """对一批事件执行全部规则，返回 (候选命中, 各规则命中数, 规则异常列表)。"""
    candidates = []
    counts = {}
    errors = []
    for fn in RULE_FUNCS:
        try:
            got = fn(events)
        except Exception as ex:
            errors.append(f"{fn.__name__}: {type(ex).__name__}: {ex}")
            continue
        for c in got:
            counts[c["rule_id"]] = counts.get(c["rule_id"], 0) + 1
            candidates.append(c)
    return candidates, counts, errors


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


def build_alert(evt, window, assets, threat_mod, geo_map=None, branch_by_id=None,
                engine="batch", ingest_ms=None):
    """组装一条分级告警文档（批式/流式共用）。

    engine：产生该告警的引擎（batch / stream），写入 ssp.alert.engines 便于共存观测；
    ingest_ms：该事件进入流式输入（Kafka record timestamp）的毫秒时间戳，
              用于计算**流式实测时延** ssp.alert.stream_latency_ms。
    """
    rule = RULE_BY_ID[evt["rule_id"]]
    internal_ips = evt.get("internal_ips") or []
    # I-13 多分支汇聚：从贡献事件回溯其 ssp.branch，带到告警上
    # （跨分支关联时 related.branches 为完整集合；ssp.branch 取首个用于单值展示/聚合）
    branch_by_id = branch_by_id or {}
    branches = sorted({b for b in (branch_by_id.get(i) for i in evt.get("event_ids", [])) if b})
    if not branches:
        branches = sorted({b for b in (evt.get("branches") or []) if b})
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
    alert = {
        "id": _id, "rule_id": evt["rule_id"], "rule_name": rule["name"],
        "grade": grade, "grade_label": GRADE_SLA_LABEL[grade],
        "sla_seconds": sla, "sla_label": GRADE_SLA_LABEL[grade],
        "status": "open",
        "generated_at": iso(gen), "due_at": iso(due),
        "first_seen_at": iso(gen), "last_seen_at": iso(gen),
        "resolved_at": None, "response_action": None,
        "window_start": iso(window[0]), "window_end": iso(window[1]),
        "escalation_factors": factors,
        # I-14：引擎共存标记与时延实测
        "engines": [engine],
        "first_engine": engine,
        "last_engine": engine,
    }
    if ingest_ms:
        alert["stream_latency_ms"] = max(0, int((gen.timestamp() * 1000) - ingest_ms))
    doc = {
        "@timestamp": iso(gen),
        "event": {
            "kind": "alert", "category": "intrusion_detection", "module": "ssp-correlator",
            "severity": GRADE_SEVERITY[grade], "risk_score": GRADE_RISK[grade],
        },
        "rule": {"id": evt["rule_id"], "name": rule["name"], "description": rule["desc"]},
        "ssp": {
            "branch": (branches[0] if branches else None),
            "alert": alert,
        },
        "source": src_obj,
        "destination": dst_obj,
        "related": {
            "log_sources": evt.get("log_sources", []),
            "branches": branches,
            "event_count": evt.get("event_count", 0),
            "event_ids": evt.get("event_ids", []),
            "entities": {"internal_ips": internal_ips, "external_ips": ext_ips},
            "geo_points": geo_points,
        },
        "threat": threat,
        "asset": asset_hit,
        "message": evt["message"],
        "tags": ["ssp-correlator", evt["rule_id"]] + (["ssp-stream"] if engine == "stream" else []),
    }
    return _id, doc


def evaluate(events, window, assets, threat_mod, engine="batch", ingest_by_id=None,
             branch_by_id=None):
    """对一批事件完成"规则执行 + 告警组装"，返回 (alert_docs, rule_hits, rule_errors, geo_map)。

    批式（correlator）与流式（stream）都调用本函数，保证规则口径完全一致。
    ingest_by_id：{事件 id: 该事件的流式到达时刻(ms)}，用于逐告警计算实测时延。
    """
    geo_map = geo_index(events)
    branch_by_id = dict(branch_by_id or {})
    for e in events:
        b = get_in(e, "ssp.branch")
        if b and e.get("_id"):
            branch_by_id.setdefault(e["_id"], b)
    candidates, counts, errors = run_rules(events)
    ingest_by_id = ingest_by_id or {}
    docs = []
    for c in candidates:
        ims = [ingest_by_id.get(i) for i in (c.get("event_ids") or [])]
        ims = [x for x in ims if x]
        docs.append(build_alert(c, window, assets, threat_mod, geo_map, branch_by_id,
                                engine=engine, ingest_ms=(max(ims) if ims else None)))
    return docs, counts, errors, geo_map


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
    """幂等写入：新告警 create；已存在则合并（保留人工处理状态，更新 last_seen/count）。

    同一 `_id`（= sha1(rule_id|entity_key)）由批式与流式**共用** —— 两侧先后命中同一实体时
    只更新不新增（计划 §五.2 共存策略）。合并时额外并集 engines / branches / log_sources。
    """
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
            na["first_engine"] = pa.get("first_engine") or na.get("first_engine")
            # 生成/截止时刻必须"钉住"：SLA 从告警首次生成计时，重复关联不得重置时钟
            na["generated_at"] = pa.get("generated_at", na["generated_at"])
            na["due_at"] = pa.get("due_at", na["due_at"])
            # I-14：引擎集合并集；流式时延保留已有实测值（首次写出时才有意义）
            na["engines"] = sorted(set((pa.get("engines") or []) + (na.get("engines") or [])))
            if na.get("stream_latency_ms") is None:
                na["stream_latency_ms"] = pa.get("stream_latency_ms")
            # 合并统计
            na["last_seen_at"] = doc["ssp"]["alert"]["generated_at"]
            na["event_count"] = max(doc["related"]["event_count"], get_in(prev, "related.event_count", 0))
            na["escalation_factors"] = sorted(set(
                (pa.get("escalation_factors") or []) + (na.get("escalation_factors") or [])))
            # 证据并集（有上限，避免长期累积膨胀）
            prev_rel = prev.get("related") or {}
            doc["related"]["log_sources"] = sorted(set(
                (prev_rel.get("log_sources") or []) + (doc["related"].get("log_sources") or [])))
            doc["related"]["branches"] = sorted(set(
                (prev_rel.get("branches") or []) + (doc["related"].get("branches") or [])))
            doc["related"]["event_ids"] = sorted(set(
                (prev_rel.get("event_ids") or []) + (doc["related"].get("event_ids") or [])))[:MAX_EVENT_IDS]
            if not doc.get("ssp", {}).get("branch"):
                doc["ssp"]["branch"] = (prev.get("ssp") or {}).get("branch")
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


def enrich_inputs(events):
    """公共富化：内网 IP → 资产库；返回 (assets, threat_mod)。"""
    internal_ips = set()
    for e in events:
        for p in ("source.ip", "destination.ip", "wazuh.agent.ip"):
            ip = get_in(e, p)
            if ip and not is_external(ip):
                internal_ips.add(ip)
    assets = lookup_assets(sorted(internal_ips))
    return assets, load_threat_intel()


# ----------------------------- 批式主流程（correlator 执行壳调用） -----------------------------
def run_correlation(window_minutes=None, anchor_iso=None):
    t0 = time.time()
    wm = window_minutes or WINDOW_MINUTES
    window = resolve_window(wm, anchor_iso)
    events, err = fetch_events(window[0], window[1])
    if err:
        return {"ok": False, "error": err, "window": [iso(window[0]), iso(window[1])]}

    assets, threat_mod = enrich_inputs(events)
    alert_docs, rule_counts, rule_errors, geo_map = evaluate(
        events, window, assets, threat_mod, engine="batch")

    write_res = upsert_alerts(alert_docs)
    return {
        "ok": True,
        "engine": "batch",
        "window": {"start": iso(window[0]), "end": iso(window[1]), "mode": window[2],
                   "minutes": wm},
        "events_scanned": len(events),
        "events_by_source": {s: sum(1 for e in events if get_in(e, "fields.log_source") == s)
                             for s in allowed_sources()},
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
    """各数据源健康度：按 fields.log_source 统计最近事件时间，判定 ok/stale/down。

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
    # 陈旧度基准只取**探针白名单**源的最新事件时间：外部源（firewall 等）的日志时间口径
    # 与探针不同（例如是"当下"而探针数据是历史回放），若混入基准会把探针源误判为 stale。
    probe_times = [s["ms"] for n, s in stats.items() if s["ms"] and n in ALLOWED_SOURCES]
    all_times = [s["ms"] for s in stats.values() if s["ms"]]
    latest_all = max(probe_times) if probe_times else (max(all_times) if all_times else None)
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
            "latest_event": (iso(datetime.datetime.fromtimestamp(latest_all / 1000,
                                                                tz=datetime.timezone.utc))
                             if latest_all else None),
            "overall": overall, "sources": out}
