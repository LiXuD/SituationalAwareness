#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
discovery-run.py —— 触发一次资产测绘（I-12），纯标准库，经平台统一后端 API。

为什么走 API 而不是直接 import discovery：
    测绘引擎跑在 portal 进程内（复用其 SQLite 单连接 + 全局锁，见 docs/I-12）。
    另起进程直连同一 SQLite 会引入跨进程锁竞争。故本脚本只做「登录 + 调 API」。

用法：
    python3 scripts/discovery-run.py                      # 触发一次（默认窗口）
    python3 scripts/discovery-run.py --window 10080       # 指定回溯窗口（分钟）
    python3 scripts/discovery-run.py --stats              # 只看候选统计
    python3 scripts/discovery-run.py --user admin --pass 'REDACTED-SSP-PWD'
"""
import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

PORTAL = os.environ.get("PORTAL_URL", "http://localhost:8093").rstrip("/")
_CTX = ssl.create_default_context()


def _opener(jar):
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                       urllib.request.HTTPCookieProcessor(jar),
                                       urllib.request.HTTPSHandler(context=_CTX))


def _req(opener, method, path, body=None, timeout=120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(PORTAL + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw[:300]}
    except Exception as e:
        return 0, {"error": f"{type(e).__name__}: {e}"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=None, help="回溯窗口（分钟）")
    ap.add_argument("--stats", action="store_true", help="只查看候选统计")
    ap.add_argument("--user", default=os.environ.get("SSP_USER", "admin"))
    ap.add_argument("--pass", dest="pwd", default=os.environ.get("SSP_PASS", "REDACTED-SSP-PWD"))
    args = ap.parse_args()

    jar = CookieJar()
    op = _opener(jar)
    st, d = _req(op, "POST", "/api/auth/login", {"username": args.user, "password": args.pwd})
    if st != 200:
        print(f"[discovery] 登录失败：HTTP {st} {d}", file=sys.stderr)
        return 1

    if args.stats:
        st, d = _req(op, "GET", "/api/discovery/stats")
        print(json.dumps(d, ensure_ascii=False, indent=2))
        return 0 if st == 200 else 1

    body = {}
    if args.window:
        body["window_minutes"] = args.window
    st, d = _req(op, "POST", "/api/discovery/run", body)
    if st != 200:
        print(f"[discovery] 测绘失败：HTTP {st} {json.dumps(d, ensure_ascii=False)}", file=sys.stderr)
        return 1
    print(f"[discovery] 测绘完成：扫描主机 {d.get('scanned_hosts')}，"
          f"新增候选 {d.get('created')}，刷新 {d.get('updated')}（窗口 {d.get('window_minutes')} 分钟）")
    st, s = _req(op, "GET", "/api/discovery/stats")
    if st == 200:
        print(f"[discovery] 候选池：待审核 {s.get('pending')} / 已采纳 {s.get('adopted')} / "
              f"已忽略 {s.get('ignored')}（覆盖主机 {s.get('adopted_hosts')}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
