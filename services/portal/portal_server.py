#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
portal_server.py —— 平台统一后端(BFF)：把第三方组件的能力**收进平台**，浏览器只连平台。

背景（用户要求"统一管理查看"，不要各管各的）：
  Arkime Viewer 使用 **digest 鉴权** 且 **不发 CORS 头**，浏览器无法直接调用。
  因此由本服务在服务端完成鉴权并转发，前端只访问 /api/traffic/*，不再跳 Arkime 自己的控制台。

只依赖 Python 标准库（http.server + urllib），运行时零第三方依赖。

接口
----
  GET /health                          平台/Arkime 连通性
  GET /api/traffic/health              Arkime /api/eshealth（集群健康）
  GET /api/traffic/files               Arkime /api/files（已入库 PCAP 文件）
  GET /api/traffic/sessions            会话列表（支持 ip/proto/port/start/end/expression/limit/offset）
  GET /api/traffic/pcap                按条件导出 PCAP（二进制流）

环境变量
--------
  PORTAL_PORT   默认 8093
  ARKIME_URL    默认 http://arkime:8005
  ARKIME_USER   默认 admin
  ARKIME_PASS   默认 REDACTED-ARKIME-PWD
  CORS_ALLOW_ORIGIN 默认 *
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORTAL_PORT = int(os.environ.get("PORTAL_PORT", "8093"))
ARKIME_URL = os.environ.get("ARKIME_URL", "http://arkime:8005").rstrip("/")
ARKIME_USER = os.environ.get("ARKIME_USER", "admin")
ARKIME_PASS = os.environ.get("ARKIME_PASS", "REDACTED-ARKIME-PWD")
CORS = os.environ.get("CORS_ALLOW_ORIGIN", "*")

# digest 鉴权的 opener（首次 401 挑战后自动重放）
_pm = urllib.request.HTTPPasswordMgrWithDefaultRealm()
_pm.add_password(None, ARKIME_URL, ARKIME_USER, ARKIME_PASS)
_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPDigestAuthHandler(_pm),
    urllib.request.HTTPBasicAuthHandler(_pm),
)

_PROTO_MAP = {"6": "tcp", "tcp": "tcp", "17": "udp", "udp": "udp", "1": "icmp", "icmp": "icmp"}


def _arkime_get(path, timeout=30):
    """GET Arkime，返回 (status, headers, bytes)。"""
    req = urllib.request.Request(ARKIME_URL + path, headers={"Accept": "*/*"})
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()
    except Exception as e:
        return 0, {}, json.dumps({"error": f"{type(e).__name__}: {e}"}).encode()


def _arkime_json(path, timeout=30):
    st, _h, body = _arkime_get(path, timeout)
    try:
        return st, json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return st, {"raw": body.decode("utf-8", "replace")[:400]}


def _build_expression(q):
    """把平台友好参数翻译成 Arkime 表达式（用户可直接给 expression 覆盖）。"""
    if q.get("expression"):
        return q["expression"]
    parts = []
    ip = (q.get("ip") or "").strip()
    if ip:
        parts.append(f"ip == {ip}")
    if q.get("src_ip"):
        parts.append(f"ip.src == {q['src_ip'].strip()}")
    if q.get("dst_ip"):
        parts.append(f"ip.dst == {q['dst_ip'].strip()}")
    proto = (q.get("proto") or "").strip().lower()
    if proto:
        p = _PROTO_MAP.get(proto, proto)
        parts.append(f"protocol == {p}")
    port = (q.get("port") or "").strip()
    if port:
        parts.append(f"port == {port}")
    return " && ".join(parts)


def _date_range(q):
    s, e = q.get("start"), q.get("end")
    if s and e:
        return f"{int(float(s))}|{int(float(e))}"
    return "-1"


class Handler(BaseHTTPRequestHandler):
    server_version = "ssp-portal/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[portal] %s - %s\n" % (self.address_string(), fmt % args))

    # ---------- 响应工具 ----------
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", CORS)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")

    def _json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        try:
            self._get()
        except Exception as e:
            self._json(500, {"error": f"{type(e).__name__}: {e}"})

    def _get(self):
        u = urllib.parse.urlparse(self.path)
        path = u.path
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}

        if path in ("/health", "/"):
            st, es = _arkime_json("/api/eshealth", timeout=8)
            self._json(200, {"status": "ok", "portal_port": PORTAL_PORT,
                             "arkime_url": ARKIME_URL, "arkime_reachable": st == 200,
                             "arkime_eshealth": es if st == 200 else None})
            return

        if path == "/api/traffic/health":
            st, es = _arkime_json("/api/eshealth")
            self._json(st or 502, es)
            return

        if path == "/api/traffic/files":
            st, d = _arkime_json("/api/files?length=200")
            self._json(st or 502, d)
            return

        if path == "/api/traffic/sessions":
            expr = _build_expression(q)
            params = {"date": _date_range(q),
                      "length": int(q.get("limit", "100")),
                      "start": int(q.get("offset", "0"))}
            if expr:
                params["expression"] = expr
            st, d = _arkime_json("/api/sessions?" + urllib.parse.urlencode(params))
            if isinstance(d, dict):
                d["_query"] = {"expression": expr or "(all)", "date": params["date"]}
            self._json(st or 502, d)
            return

        if path == "/api/traffic/pcap":
            expr = _build_expression(q)
            params = {"date": _date_range(q)}
            if expr:
                params["expression"] = expr
            st, hdrs, body = _arkime_get("/api/sessions/pcap?" + urllib.parse.urlencode(params), timeout=120)
            ctype = hdrs.get("Content-Type", "application/vnd.tcpdump.pcap")
            name = "ssp-export.pcap"
            self.send_response(st or 502)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(body)))
            self._cors()
            self.end_headers()
            self.wfile.write(body)
            return

        self._json(404, {"error": "not found: %s" % path})


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORTAL_PORT), Handler)
    print(f"[portal] 平台统一后端启动 http://0.0.0.0:{PORTAL_PORT}  arkime={ARKIME_URL} user={ARKIME_USER}",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
