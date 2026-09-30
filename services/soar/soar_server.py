#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar_server.py —— SOAR 落黑执行器（仅系统级 iptables 操作）。

统一边界：草稿状态机与黑名单已收口到平台业务库（portal 的 db.py），本服务
只保留「落黑执行」这一系统级能力（privileged + nsenter 写宿主 iptables）。
portal 通过以下纯执行接口调用：
    POST /soar/block/apply   {ip, dry_run}   执行落黑（iptables）
    POST /soar/block/remove  {ip}            解除封禁
    GET  /soar/block/list                     当前 iptables 规则
    GET  /health
"""
import json
import ipaddress
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import blocker
import logging

log = logging.getLogger("soar")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S")


LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8092"))

_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
)]
BENIGN = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "114.114.114.114"}


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


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
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

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/health", "/"):
            self._send(200, {"status": "ok", "backend": "iptables-executor",
                             "blocker": blocker.status()})
            return
        if path == "/soar/block/list":
            self._send(200, blocker.list_blocks())
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        b = self._body()
        if path == "/soar/block/apply":
            ip = b.get("ip")
            if not is_blockable(ip):
                self._send(400, {"ok": False, "error": f"非法或不可封禁的 IP: {ip}"})
                return
            old = blocker.MODE
            if b.get("dry_run"):
                blocker.MODE = "dry-run"
            try:
                res = blocker.apply_block(ip)
            finally:
                blocker.MODE = old
            self._send(200 if res.get("ok") else 500, res)
            return
        if path == "/soar/block/remove":
            ip = b.get("ip")
            if not is_blockable(ip):
                self._send(400, {"ok": False, "error": f"非法或不可封禁的 IP: {ip}"})
                return
            res = blocker.remove_block(ip)
            self._send(200 if res.get("ok") else 500, res)
            return
        self._send(404, {"error": "not found"})


def main():
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    log.info(f"[soar] 落黑执行器启动 http://{LISTEN_HOST}:{LISTEN_PORT} blocker={blocker.MODE}")
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
