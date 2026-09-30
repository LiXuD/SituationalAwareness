#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
I-14 外部日志源适配器（**只做协议解析 + 打标，不做 ECS 归一**；纯标准库，零第三方依赖）

分工（与既有链路保持一致，见计划 §五.5）
------------------------------------------
    Filebeat / 适配器  =  只负责「投递 + 打标」     → Kafka ssp-raw（中心汇聚层，I-13）
    Logstash           =  统一「ECS 归一 + 地理富化」→ OpenSearch / Kafka ssp-ecs

因此本适配器**不实现任何 ECS 映射**：它把第三方日志（syslog / CEF / JSON）解析成
结构化字段放进 `ssp.external`，打上 `fields.log_source` / `fields.branch`，
再原样投递到**中心汇聚层** `ssp-raw` 主题 —— 新增一类外部源**不改中心端口与汇聚层**，
归一交给 Logstash（`config/logstash/conf.d/40-external.conf`）。

三个入口
--------
  1. syslog（UDP :5514）  RFC3164 / RFC5424，典型来源：防火墙/交换机系统日志
  2. CEF （TCP :5515）    ArcSight CEF（可裸 CEF，也可 syslog 包裹），典型来源：WAF/IPS
  3. JSON（HTTP :5516）   `POST /ingest/json`（对象或数组），典型来源：现代防火墙 API 推送

默认关闭
--------
`ADAPTER_ENABLED=false` 时进程**不监听任何端口、不产生任何副作用**（EARS State-driven）；
compose 里该服务位于 `external` profile，`make up` 默认不启动，
需显式 `make external-up`（`--profile external`）才启用。

运行
----
    python3 adapter.py                 # 常驻（需 ADAPTER_ENABLED=true）
    python3 adapter.py --check         # 自检：解析内置样例并打印结果（不联网、不投递）

环境变量
--------
    ADAPTER_ENABLED        默认 false
    KAFKA_BOOTSTRAP        kafka:9092
    ADAPTER_TOPIC          ssp-raw（中心汇聚层主题）
    ADAPTER_SYSLOG_UDP_PORT 5514 ｜ ADAPTER_CEF_TCP_PORT 5515 ｜ ADAPTER_JSON_HTTP_PORT 5516
    ADAPTER_DEFAULT_SOURCE firewall ｜ ADAPTER_DEFAULT_BRANCH hq ｜ ADAPTER_DEFAULT_SITE 总部
    ADAPTER_BRANCH_MAP     '10.9.=sh-01,10.7.=bj-01'（按来源 IP 前缀判分支，可空）
"""
import datetime
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
for _d in (os.environ.get("COMMON_DIR", "/srv-common"),
           os.path.join(os.path.dirname(_HERE), "common"),     # 本地开发：services/common
           _HERE):
    if _d and os.path.isdir(_d) and _d not in sys.path:
        sys.path.insert(0, _d)
from kafka_lite import KafkaProducer, KafkaError          # noqa: E402
import logging

log = logging.getLogger("adapter")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S")


VERSION = "1.0"
ENABLED = str(os.environ.get("ADAPTER_ENABLED", "false")).lower() in ("1", "true", "yes", "on")
BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")
TOPIC = os.environ.get("ADAPTER_TOPIC", "ssp-raw")
UDP_PORT = int(os.environ.get("ADAPTER_SYSLOG_UDP_PORT", "5514"))
TCP_PORT = int(os.environ.get("ADAPTER_CEF_TCP_PORT", "5515"))
HTTP_PORT = int(os.environ.get("ADAPTER_JSON_HTTP_PORT", "5516"))
DEFAULT_SOURCE = os.environ.get("ADAPTER_DEFAULT_SOURCE", "firewall")
DEFAULT_BRANCH = os.environ.get("ADAPTER_DEFAULT_BRANCH", "hq")
DEFAULT_SITE = os.environ.get("ADAPTER_DEFAULT_SITE", "总部")
BRANCH_MAP = [kv.split("=", 1) for kv in
              (os.environ.get("ADAPTER_BRANCH_MAP", "") or "").split(",") if "=" in kv]

STATS = {"received": 0, "delivered": 0, "failed": 0, "by_entry": {},
         "last_error": None, "last_at": None, "started_at": None}

# 三方日志文本里出现的内网/外网地址都可能存在；这里只做"是否合法 IP"的清洗
_TS_RE_5424 = re.compile(r"^(\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2}))")
_TS_RE_3164 = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


# --------------------------------------------------------------------------- #
# 协议解析
# --------------------------------------------------------------------------- #
def parse_syslog(line):
    """解析 syslog 报文（RFC3164 / RFC5424），返回 dict。

    返回：{pri, facility, severity, version, timestamp, hostname, app, procid, msgid,
           structured_data, message}
    """
    out = {"raw": line}
    s = line.strip()
    m = re.match(r"^<(\d{1,3})>", s)
    if m:
        pri = int(m.group(1))
        out["pri"] = pri
        out["facility"] = pri // 8
        out["severity"] = pri % 8
        s = s[m.end():]
    # RFC5424：PRI 后紧跟版本号 + 空格
    m = re.match(r"^1\s+", s)
    if m:
        out["version"] = 1
        s = s[m.end():]
        parts = s.split(" ", 4)
        if len(parts) >= 1:
            t = _TS_RE_5424.match(parts[0])
            if t:
                out["timestamp"] = t.group(1)
                s = s[len(parts[0]):].lstrip()
        # HOSTNAME APP-NAME PROCID MSGID
        head = s.split(" ", 4)
        if len(head) >= 4:
            out["hostname"], out["app"], out["procid"], out["msgid"] = head[0], head[1], head[2], head[3]
            rest = head[4] if len(head) > 4 else ""
            # 结构化数据 [..]（POC 仅记录，不展开）
            sd = ""
            if rest.startswith("-"):
                sd, rest = "-", rest[1:].lstrip()
            elif rest.startswith("["):
                depth, i = 0, 0
                for i, ch in enumerate(rest):
                    if ch == "[":
                        depth += 1
                    elif ch == "]":
                        depth -= 1
                        if depth == 0:
                            break
                sd, rest = rest[:i + 1], rest[i + 1:].lstrip()
            out["structured_data"] = sd
            out["message"] = rest
            return out
    # RFC3164：MMM dd HH:MM:SS host tag: msg
    t = _TS_RE_3164.match(s)
    if t:
        out["timestamp"] = t.group(1)
        s = s[t.end():].lstrip()
    else:
        m2 = _TS_RE_5424.match(s)
        if m2:
            out["timestamp"] = m2.group(1)
            s = s[m2.end():].lstrip()
    parts = s.split(" ", 2)
    if len(parts) >= 3:
        out["hostname"], out["app"] = parts[0], parts[1].rstrip(":")
        out["message"] = parts[2]
    elif len(parts) == 2:
        out["hostname"], out["message"] = parts[0], parts[1]
    else:
        out["message"] = s
    return out


def parse_cef(line):
    """解析 ArcSight CEF（可被 syslog 包裹）。

    格式：CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|
          Extension（`key=value` 以空格分隔，值内可含转义 \\= \\| \\\\）
    """
    out = {"raw": line}
    idx = line.find("CEF:")
    if idx < 0:
        out["error"] = "未找到 CEF 头"
        return out
    body = line[idx + 4:]
    # 头 7 段用 '|' 分隔，第 8 段是扩展（不转义）
    fields = re.split(r"(?<!\\)\|", body, maxsplit=7)
    if len(fields) < 8:
        out["error"] = f"CEF 字段不足（{len(fields)}<8）"
        return out
    out["version"] = fields[0]
    out["device_vendor"] = fields[1]
    out["device_product"] = fields[2]
    out["device_version"] = fields[3]
    out["signature_id"] = fields[4]
    out["name"] = fields[5]
    out["severity"] = fields[6]
    out["extension"] = _parse_cef_ext(fields[7])
    return out


def _parse_cef_ext(ext):
    """解析 CEF 扩展区 `k=v k2=v2`；值内空白需转义（POC 按标准分隔）。"""
    out = {}
    for m in re.finditer(r"([A-Za-z0-9_.\[\]]+)=((?:\\.|[^=])*?)(?=\s+[A-Za-z0-9_.\[\]]+=|$)", ext or ""):
        k, v = m.group(1), m.group(2).strip()
        v = re.sub(r"\\([=|\\])", r"\1", v)
        out[k] = v
    return out


def _is_ip(v):
    try:
        ipaddress.ip_address(str(v).strip())
        return True
    except Exception:
        return False


def normalize_json(payload):
    """JSON 入口：接受"常见键名"的第三方告警 JSON，抽出通用字段（仍不做 ECS 归一）。

    识别（任一存在即取）：src/src_ip/source_ip/sourceAddress → src_ip
                          dst/dst_ip/dest_ip/destinationAddress → dst_ip
                          spt/sourcePort/src_port/port → src_port
                          dpt/destinationPort/dst_port → dst_port
                          proto/protocol/transport → protocol
                          act/action/action_name → action
                          msg/message/description → message
    """
    if not isinstance(payload, dict):
        return {}
    def pick(*keys):
        for k in keys:
            v = payload.get(k)
            if v not in (None, ""):
                return v
        return None
    return {
        "src_ip": pick("src", "src_ip", "source_ip", "sourceAddress"),
        "dst_ip": pick("dst", "dst_ip", "dest_ip", "destination_ip", "destinationAddress"),
        "src_port": pick("spt", "src_port", "sourcePort", "source_port"),
        "dst_port": pick("dpt", "dst_port", "destinationPort", "dest_port"),
        "protocol": pick("proto", "protocol", "transport"),
        "action": pick("act", "action", "action_name"),
        "rule_name": pick("name", "rule_name", "signature", "event_name"),
        "rule_id": pick("signature_id", "rule_id", "event_id"),
        "severity": pick("severity", "priority", "level"),
        "message": pick("msg", "message", "description", "event_message"),
        "vendor": pick("device_vendor", "vendor", "manufacturer"),
        "product": pick("device_product", "product", "device"),
    }


def branch_for(src_ip, explicit=None):
    """分支判定：显式指定 > 按来源 IP 前缀映射 > 默认分支。"""
    if explicit:
        return explicit, None
    for pref, br in BRANCH_MAP:
        if src_ip and str(src_ip).startswith(pref):
            return br, None
    return DEFAULT_BRANCH, DEFAULT_SITE


def envelope(entry, source=None, branch=None, site=None, message=None, parsed=None,
             ts=None):
    """构造与 Filebeat 同构的信封（下游 Logstash 无需区分来源）。

    **不设置 event.* / ECS 字段** —— 归一职责在 Logstash（见 40-external.conf），
    本适配器只做协议解析与打标，避免与 Logstash 各写一套 event.* 造成字段重复/分叉。
    """
    src_ip = None
    p = parsed or {}
    src_ip = p.get("src_ip") or (p.get("extension") or {}).get("src")
    b, s = branch_for(src_ip, branch)
    return {
        "@timestamp": ts or datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "message": message if message is not None else "",
        "fields": {
            "log_source": source or DEFAULT_SOURCE,
            "branch": b,
            "branch_site": s or site or DEFAULT_SITE,
            "external": "true",                 # 标记"来自外部源适配器"（可检索/可统计）
            "adapter": entry,                   # syslog | cef | json
            "adapter_version": VERSION,
        },
        "ssp": {"external": {"entry": entry, "parsed": p}},
        "agent": {"type": "ssp-ingest-adapter", "version": VERSION},
        "host": {"name": socket.gethostname()},
    }


# --------------------------------------------------------------------------- #
# 投递（中心汇聚层：Kafka ssp-raw）
# --------------------------------------------------------------------------- #
_PRODUCER = {"p": None, "lock": threading.Lock()}


def producer():
    with _PRODUCER["lock"]:
        if _PRODUCER["p"] is None:
            _PRODUCER["p"] = KafkaProducer(BOOTSTRAP, client_id="ssp-ingest-adapter")
        return _PRODUCER["p"]


def deliver(doc, entry):
    STATS["received"] += 1
    STATS["by_entry"][entry] = STATS["by_entry"].get(entry, 0) + 1
    STATS["last_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        p, off = producer().send_json(TOPIC, doc)
        STATS["delivered"] += 1
        return p, off
    except KafkaError as e:
        with _PRODUCER["lock"]:
            try:
                if _PRODUCER["p"]:
                    _PRODUCER["p"].close()
            except Exception:
                pass
            _PRODUCER["p"] = None
        STATS["failed"] += 1
        STATS["last_error"] = f"{entry}: {e}"
        return None, None


# --------------------------------------------------------------------------- #
# 入口 1/2：syslog(UDP) 与 CEF(TCP)
# --------------------------------------------------------------------------- #
def serve_syslog_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", UDP_PORT))
    log.info(f"[adapter] syslog/UDP 监听 :{UDP_PORT} → Kafka {TOPIC}")
    while True:
        data, addr = s.recvfrom(65535)
        text = data.decode("utf-8", "replace").strip()
        if not text:
            continue
        parsed = parse_syslog(text)
        # syslog 内容体里若含 CEF 头，顺带解析出来（很多防火墙这样发）
        if "CEF:" in parsed.get("message", ""):
            parsed["cef"] = parse_cef(parsed["message"])
        doc = envelope("syslog", source=os.environ.get("ADAPTER_SYSLOG_SOURCE", DEFAULT_SOURCE),
                       message=text, parsed=parsed)
        doc["ssp"]["external"]["peer"] = f"{addr[0]}:{addr[1]}"
        deliver(doc, "syslog")


def serve_cef_tcp():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", TCP_PORT))
    srv.listen(16)
    log.info(f"[adapter] CEF/TCP 监听 :{TCP_PORT} → Kafka {TOPIC}")

    def handle(conn, addr):
        buf = b""
        try:
            while True:
                chunk = conn.recv(65535)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode("utf-8", "replace").strip()
                    if not text:
                        continue
                    parsed = parse_cef(text)
                    if "error" in parsed and not text.startswith("CEF:"):
                        parsed = dict(parse_syslog(text), cef=parse_cef(text))
                    doc = envelope("cef", source=os.environ.get("ADAPTER_CEF_SOURCE", DEFAULT_SOURCE),
                                   message=text, parsed=parsed)
                    doc["ssp"]["external"]["peer"] = f"{addr[0]}:{addr[1]}"
                    deliver(doc, "cef")
        except Exception as e:
            STATS["last_error"] = f"cef: {type(e).__name__}: {e}"
        finally:
            try:
                conn.close()
            except Exception:
                pass

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


# --------------------------------------------------------------------------- #
# 入口 3：JSON(HTTP)
# --------------------------------------------------------------------------- #
class JsonHandler(BaseHTTPRequestHandler):
    server_version = f"ssp-ingest-adapter/{VERSION}"

    def log_message(self, *a):
        pass

    def _send(self, st, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(st)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split("?")[0] in ("/health", "/"):
            self._send(200, {"status": "ok" if ENABLED else "disabled", "enabled": ENABLED,
                             "version": VERSION, "topic": TOPIC, "bootstrap": BOOTSTRAP,
                             "ports": {"syslog_udp": UDP_PORT, "cef_tcp": TCP_PORT,
                                       "json_http": HTTP_PORT},
                             "stats": STATS})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        import urllib.parse
        u = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        if u.path not in ("/ingest/json", "/ingest"):
            self._send(404, {"error": "not found"})
            return
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            payload = json.loads(raw.decode("utf-8") or "null")
        except Exception as e:
            STATS["failed"] += 1
            STATS["last_error"] = f"json: 解析失败 {e}"
            self._send(400, {"error": f"非法 JSON：{e}"})
            return
        items = payload if isinstance(payload, list) else [payload]
        ok = 0
        for it in items:
            parsed = normalize_json(it)
            doc = envelope("json", source=q.get("source"),
                           branch=q.get("branch"), site=q.get("site"),
                           message=json.dumps(it, ensure_ascii=False), parsed=parsed)
            doc["ssp"]["external"]["json"] = it
            doc["ssp"]["external"]["peer"] = self.client_address[0]
            p, off = deliver(doc, "json")
            if off is not None:
                ok += 1
        self._send(200 if ok == len(items) else 503,
                   {"received": len(items), "delivered": ok, "topic": TOPIC})


def serve_json_http():
    srv = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), JsonHandler)
    log.info(f"[adapter] JSON/HTTP 监听 :{HTTP_PORT}（POST /ingest/json?source=&branch=）"
          f" → Kafka {TOPIC}")
    srv.serve_forever()


# --------------------------------------------------------------------------- #
# 自检 & 启动
# --------------------------------------------------------------------------- #
SAMPLES = {
    "syslog": '<134>Oct 11 22:14:15 fw-edge-01 %ASA-4-106023: Deny tcp src outside:203.0.113.77/41000 '
              'dst inside:10.0.0.20/445 by access-group "outside_in"',
    "syslog5424": '<134>1 2026-09-29T09:00:00.000Z fw-edge-01 ASA 1234 IDS - Deny tcp '
                  'src 203.0.113.77 dst 10.0.0.20',
    "cef": 'CEF:0|Vendor|WAF-Prod|1.0|942100|SQL Injection Attempt|8|src=203.0.113.88 dst=10.0.0.30 '
           'spt=52000 dpt=443 proto=TCP act=blocked msg=SQLi detected cs1=OWASP',
    "json": {"src_ip": "203.0.113.99", "dst_ip": "10.0.0.40", "dst_port": 3389,
             "protocol": "TCP", "action": "deny", "name": "RDP brute force",
             "severity": "high", "msg": "Access denied", "vendor": "XX-FW"},
}


def check():
    """--check：解析内置样例并打印（不联网、不投递），用于 CI/自检。"""
    out = {}
    out["syslog_3164"] = parse_syslog(SAMPLES["syslog"])
    out["syslog_5424"] = parse_syslog(SAMPLES["syslog5424"])
    out["cef"] = parse_cef(SAMPLES["cef"])
    out["json"] = normalize_json(SAMPLES["json"])
    out["envelope_sample"] = envelope("cef", message=SAMPLES["cef"], parsed=out["cef"])
    ok = (out["syslog_3164"].get("hostname") == "fw-edge-01"
          and out["syslog_5424"].get("version") == 1
          and out["cef"].get("extension", {}).get("src") == "203.0.113.88"
          and out["json"].get("src_ip") == "203.0.113.99")
    print(json.dumps({"ok": ok, **out}, ensure_ascii=False, indent=2))
    return 0 if ok else 1


def main():
    if "--check" in sys.argv:
        return check()
    if not ENABLED:
        log.info("[adapter] 外部源适配器**已关闭**（ADAPTER_ENABLED=false）——"
                 "不监听端口、不投递任何事件。开启：ADAPTER_ENABLED=true（或 make external-up）")
        return 0
    STATS["started_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    threads = [
        threading.Thread(target=serve_syslog_udp, name="syslog-udp", daemon=True),
        threading.Thread(target=serve_cef_tcp, name="cef-tcp", daemon=True),
        threading.Thread(target=serve_json_http, name="json-http", daemon=True),
    ]
    for t in threads:
        t.start()
    log.info(f"[adapter] 外部源适配器已启动（v{VERSION}）：全部事件投递到 Kafka {TOPIC}，"
          f"归一由 Logstash 完成")
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
