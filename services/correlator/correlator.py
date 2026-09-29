#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
I-03 轻量关联分析 —— 关联引擎（**批式执行壳**，纯标准库，零第三方依赖）

I-14 起，规则定义/执行/分级/告警组装/幂等写入等**内核逻辑**统一收敛到
`services/common/ssp_kernel.py`，本文件只保留"批式"特有的部分：

  1. 按**时间窗口**从 OpenSearch（别名 `ssp-events`）拉取探针事件；
  2. 调用内核 `evaluate(engine="batch")` 得到告警文档；
  3. 幂等写入 `ssp-alerts`（与流式引擎共用 `_id = sha1(rule_id|entity_key)`）；
  4. 提供 REST：`/health`、`/rules`、`/sources/health`、`/alerts`、`/correlate`；
  5. 可选后台周期关联（`CORR_INTERVAL_SECONDS`）。

与流式引擎（`services/stream`，:8094）的分工（计划 §五.2）：
  * 流式：事件级/滑动窗口 → **秒级初判**；
  * 批式：长窗口（默认 30min）→ **窗口内跨源深度关联**、兜底补齐；
  * 两者**并存**，写同一索引靠幂等 `_id` 去重，不互相替代。

运行：
  服务模式： python3 correlator.py                # 起 HTTP :8091，可开后台周期关联
  单次模式： python3 correlator.py --once         # 跑一次关联并打印 JSON 摘要（供脚本/测试）
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.environ.get("COMMON_DIR", "/srv-common"))
import ssp_kernel as K                                        # noqa: E402

# 兼容保留：原 correlator 模块级名字（外部脚本/资料库文档引用）
RULES = K.RULES
RULE_BY_ID = K.RULE_BY_ID
RULE_FUNCS = K.RULE_FUNCS
GRADE_ORDER = K.GRADE_ORDER
GRADE_SLA_SECONDS = K.GRADE_SLA_SECONDS
GRADE_SLA_LABEL = K.GRADE_SLA_LABEL
GRADE_SEVERITY = K.GRADE_SEVERITY
GRADE_RISK = K.GRADE_RISK
ALLOWED_SOURCES = K.ALLOWED_SOURCES
ALERTS_INDEX = K.ALERTS_INDEX
EVENTS_ALIAS = K.EVENTS_ALIAS
alert_doc_id = K.alert_doc_id
build_alert = K.build_alert
upsert_alerts = K.upsert_alerts
run_correlation = K.run_correlation
list_alerts = K.list_alerts
source_health = K.source_health
load_threat_intel = K.load_threat_intel

LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8091"))
# 后台周期关联间隔（秒）；0 = 关闭（仅手动/接口触发）
CORR_INTERVAL = int(os.environ.get("CORR_INTERVAL_SECONDS", "60"))
CORS_ALLOW_ORIGIN = os.environ.get("CORS_ALLOW_ORIGIN", "*")


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
            _latest, total = K.latest_event_ts()
            ti = K.load_threat_intel()
            ti_status = ti.status() if (ti is not None and hasattr(ti, "status")) else None
            self._send(200, {"status": "ok", "engine": "batch", "index": K.ALERTS_INDEX,
                             "events_alias": K.EVENTS_ALIAS, "events_total": total,
                             "interval_seconds": CORR_INTERVAL,
                             "allowed_sources": K.allowed_sources(),
                             "threat_intel": ti is not None,
                             "threat_intel_status": ti_status})
            return
        if path == "/rules":
            self._send(200, {"rules": K.RULES, "sla_seconds": K.GRADE_SLA_SECONDS})
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
            self._send(200, K.source_health(sm))
            return
        if path == "/alerts":
            q = {}
            if "?" in self.path:
                for kv in self.path.split("?", 1)[1].split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        q[k] = v
            st, res = K.list_alerts(q.get("grade"), q.get("status"),
                                    int(q.get("limit", "100")))
            self._send(st, res)
            return
        self._send(404, {"error": "not found"})

    def _post(self):
        path = self.path.split("?")[0]
        if path == "/correlate":
            b = self._body()
            res = K.run_correlation(b.get("window_minutes"), b.get("anchor"))
            self._send(200 if res.get("ok") else 500, res)
            return
        self._send(404, {"error": "not found"})


def start_loop():
    def _loop():
        while True:
            time.sleep(CORR_INTERVAL)
            try:
                r = K.run_correlation()
                print(f"[correlator] 周期关联: 事件={r.get('events_scanned')} "
                      f"告警={r.get('alerts_total')} 写入={r.get('write')}", flush=True)
            except Exception as e:
                print(f"[correlator] 周期关联异常: {e}", flush=True)
    t = threading.Thread(target=_loop, daemon=True)
    t.start()


def main():
    if "--once" in sys.argv:
        res = K.run_correlation()
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("ok") else 1
    if CORR_INTERVAL > 0:
        start_loop()
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"[correlator] 批式关联引擎启动 http://{LISTEN_HOST}:{LISTEN_PORT} "
          f"窗口={K.WINDOW_MINUTES}min 周期={CORR_INTERVAL}s", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
