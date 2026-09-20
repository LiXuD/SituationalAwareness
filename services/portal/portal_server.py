#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
portal_server.py —— 平台统一后端（BFF）。

目标（用户要求"统一管理查看"）：**浏览器只连平台这一个后端（:8093）**，
所有第三方组件（OpenSearch / Arkime）都退化为平台内部的**数据源**，不再让前端直连、更不外跳。

为什么必须服务端代理：
  Arkime Viewer 用 **digest 鉴权且不发 CORS 头**，浏览器无法直连；
  统一入口还能把"前端连了哪些后端"这件事收敛到一处。

只依赖 Python 标准库（http.server + urllib），运行时零第三方依赖。

路由
----
  /api/traffic/*   → Arkime（会话/PCAP 回溯，服务端 digest 鉴权 + 友好参数翻译）
  /api/os/*        → OpenSearch（检索/聚合/取文档，原样转发）
  /api/corr/*      → 关联分析服务（correlator:8091）
  /api/asset/*     → 统一资产库（asset:8090）
  /api/soar/*      → SOAR 拉黑审批（soar:8092）
  /health          → 平台与各上游连通性

环境变量
--------
  PORTAL_PORT 8093 | ARKIME_URL http://arkime:8005 | OPENSEARCH_URL http://opensearch:9200
  CORRELATOR_URL http://correlator:8091 | ASSET_URL http://asset:8090 | SOAR_URL http://soar:8092
  ARKIME_USER admin | ARKIME_PASS REDACTED-ARKIME-PWD | CORS_ALLOW_ORIGIN *
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

# 平台内部上游（浏览器不再直连这些端口）
UPSTREAMS = {
    "os":    os.environ.get("OPENSEARCH_URL", "http://opensearch:9200").rstrip("/"),
    "corr":  os.environ.get("CORRELATOR_URL", "http://correlator:8091").rstrip("/"),
    "asset": os.environ.get("ASSET_URL", "http://asset:8090").rstrip("/"),
    "soar":  os.environ.get("SOAR_URL", "http://soar:8092").rstrip("/"),
}

_PROTO_MAP = {"6": "tcp", "tcp": "tcp", "17": "udp", "udp": "udp", "1": "icmp", "icmp": "icmp"}

# 通用 opener（禁代理）；Arkime 用 digest 鉴权
_plain = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_pm = urllib.request.HTTPPasswordMgrWithDefaultRealm()
_pm.add_password(None, ARKIME_URL, ARKIME_USER, ARKIME_PASS)
_arkime = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPDigestAuthHandler(_pm),
    urllib.request.HTTPBasicAuthHandler(_pm),
)


def _open(opener, method, url, body=None, ctype=None, timeout=60):
    """返回 (status, headers, body_bytes)。"""
    hdrs = {}
    if ctype:
        hdrs["Content-Type"] = ctype
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()
    except Exception as e:
        return 0, {}, json.dumps({"error": f"{type(e).__name__}: {e}"}).encode()


def _arkime_json(path, timeout=60):
    st, _h, body = _open(_arkime, "GET", ARKIME_URL + path, timeout=timeout)
    try:
        return st, json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return st, {"raw": body.decode("utf-8", "replace")[:400]}


def _build_expression(q):
    """把平台友好参数翻译成 Arkime 表达式（用户可直接给 expression 覆盖）。"""
    if q.get("expression"):
        return q["expression"]
    parts = []
    if (q.get("ip") or "").strip():
        parts.append(f"ip == {q['ip'].strip()}")
    if (q.get("src_ip") or "").strip():
        parts.append(f"ip.src == {q['src_ip'].strip()}")
    if (q.get("dst_ip") or "").strip():
        parts.append(f"ip.dst == {q['dst_ip'].strip()}")
    proto = (q.get("proto") or "").strip().lower()
    if proto:
        parts.append(f"protocol == {_PROTO_MAP.get(proto, proto)}")
    if (q.get("port") or "").strip():
        parts.append(f"port == {q['port'].strip()}")
    return " && ".join(parts)


def _date_range(q):
    s, e = q.get("start"), q.get("end")
    return f"{int(float(s))}|{int(float(e))}" if (s and e) else "-1"


class Handler(BaseHTTPRequestHandler):
    server_version = "ssp-portal/2.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[portal] %s - %s\n" % (self.address_string(), fmt % args))

    # ---------------- 响应工具 ----------------
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", CORS)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")

    def _send_raw(self, status, body, ctype="application/json; charset=utf-8", extra=None):
        self.send_response(status or 502)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj):
        self._send_raw(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else None

    # ---------------- 路由 ----------------
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._route()

    def do_HEAD(self):
        self._route()

    def do_POST(self):
        self._route()

    def do_PUT(self):
        self._route()

    def do_DELETE(self):
        self._route()

    def _route(self):
        try:
            self._dispatch()
        except Exception as e:
            self._json(500, {"error": f"{type(e).__name__}: {e}"})

    def _dispatch(self):
        u = urllib.parse.urlparse(self.path)
        path = u.path
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}

        if path in ("/health", "/"):
            ups = {}
            for name, base in UPSTREAMS.items():
                st, _h, _b = _open(_plain, "GET", base + "/health", timeout=5)
                if st == 0:   # /health 不存在时退化为探测根路径
                    st, _h, _b = _open(_plain, "GET", base + "/", timeout=5)
                ups[name] = st > 0 and st < 500
            st, _h, _b = _open(_arkime, "GET", ARKIME_URL + "/api/eshealth", timeout=5)
            ups["arkime"] = st == 200
            self._json(200, {"status": "ok", "portal_port": PORTAL_PORT,
                             "upstreams": ups,
                             "note": "前端只连平台后端；OpenSearch/Arkime 均经此代理"})
            return

        # ---- 流量回溯（Arkime，服务端 digest）----
        if path == "/api/traffic/health":
            st, d = _arkime_json("/api/eshealth")
            self._json(st or 502, d)
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
            st, hdrs, body = _open(_arkime, "GET",
                                   ARKIME_URL + "/api/sessions/pcap?" + urllib.parse.urlencode(params),
                                   timeout=180)
            self._send_raw(st, body, hdrs.get("Content-Type", "application/vnd.tcpdump.pcap"),
                           extra={"Content-Disposition": 'attachment; filename="ssp-export.pcap"'})
            return

        # ---- 通用透传：/api/{os|corr|asset|soar}/<rest> ----
        parts = path.split("/")           # ['', 'api', '<name>', '<rest...>']
        if len(parts) >= 4 and parts[1] == "api" and parts[2] in UPSTREAMS:
            base = UPSTREAMS[parts[2]]
            rest = "/".join(parts[3:])
            url = f"{base}/{rest}" + (("?" + u.query) if u.query else "")
            st, hdrs, body = _open(_plain, self.command, url, body=self._body(),
                                   ctype=self.headers.get("Content-Type"), timeout=90)
            self._send_raw(st, body, hdrs.get("Content-Type", "application/json; charset=utf-8"))
            return

        self._json(404, {"error": "not found: %s" % path})


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORTAL_PORT), Handler)
    print(f"[portal] 平台统一后端 v2 启动 http://0.0.0.0:{PORTAL_PORT}", flush=True)
    print(f"[portal] 上游：{UPSTREAMS}  arkime={ARKIME_URL}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
