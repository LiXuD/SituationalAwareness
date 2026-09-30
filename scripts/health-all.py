#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
health-all.py —— 统一健康巡检（P2-②）：聚合各服务 /health 为一张表。

各服务 /health 现返回统一信封（status / service / version / uptime_s）+ 各自专有字段，
本脚本把「身份 + 存活」部分汇总，便于一眼看清全栈状态；服务专有字段仍可用 `curl :PORT/health` 细看。
"""
import json
import sys
import urllib.request

SERVICES = [
    ("portal", "http://localhost:8093", True),
    ("correlator", "http://localhost:8091", True),
    ("stream", "http://localhost:8094", True),
    ("soar", "http://localhost:8092", True),
    ("ingest-adapter", "http://localhost:5516", False),  # 默认关闭，连不通属正常
]

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _fmt_uptime(v):
    if v is None:
        return "-"
    v = int(v)
    if v >= 86400:
        return f"{v // 86400}d{v % 86400 // 3600}h"
    if v >= 3600:
        return f"{v // 3600}h{v % 3600 // 60}m"
    if v >= 60:
        return f"{v // 60}m{v % 60}s"
    return f"{v}s"


def main():
    rows, bad = [], 0
    for name, base, required in SERVICES:
        try:
            with _OPENER.open(base + "/health", timeout=5) as r:
                d = json.loads(r.read().decode("utf-8"))
            status = d.get("status", "?")
            rows.append((name, str(r.status), status, str(d.get("version", "-")),
                         _fmt_uptime(d.get("uptime_s"))))
            if status not in ("ok",):
                bad += 1
        except Exception as e:
            state = "unreachable" + ("" if required else "（可选，未启用）")
            rows.append((name, "-", state, "-", "-"))
            if required:
                bad += 1
            if required:
                print(f"  ! {name}: {type(e).__name__}: {e}", file=sys.stderr)

    w = max(len(r[0]) for r in rows) + 2
    print(f"{'服务'.ljust(w)}{'HTTP':<6}{'状态':<28}{'版本':<10}运行时长")
    print("-" * (w + 48))
    for name, http, status, ver, up in rows:
        print(f"{name.ljust(w)}{http:<6}{status:<28}{ver:<10}{up}")
    print()
    if bad:
        print(f"✘ 有 {bad} 个必需服务异常")
        return 1
    print("✓ 全部必需服务正常")
    return 0


if __name__ == "__main__":
    sys.exit(main())
