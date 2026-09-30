#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
I-14 流式关联 —— 流式关联引擎（**轻量消费者**路线，纯标准库，零第三方依赖）

定位（计划 §二 G1 / §五）
------------------------
在已有的 Kafka 汇聚层（I-13）之上新增一个消费者，消费**归一后的 ECS 事件流**，
在内存里维护"以事件时间为锚"的滑动窗口，实时执行 R-001~R-007 并把命中写进
`ssp-alerts`：把"事件产生 → 告警落库"的时延从**分钟级（批式窗口扫描）降到秒级**。

输入为什么是 `ssp-ecs`（而不是 `ssp-raw`）
-------------------------------------------
`ssp-raw` 里是**归一前**的原始日志（Filebeat 信封 + 各探针私有字段），若由流式引擎
自行解析，等于把 I-01 的 ECS 归一逻辑再实现一遍 —— 正是计划 §八 风险表里
"流式与批式规则实现分叉"的来源。因此：

    Logstash 归一后**双写**：OpenSearch（检索/批式） + Kafka `ssp-ecs`（流式）

流式引擎消费的文档与批式从 `ssp-events` 读到的**完全同构**，两侧共用同一份规则内核
（`services/common/ssp_kernel.py`），口径天然一致；且流式不再依赖 OpenSearch 的
refresh（1s）才能看到事件，时延更低。

窗口与位点（计划 §五.1 / §五.4）
--------------------------------
* **窗口锚定事件时间**：anchor = 缓冲区中最新事件的 `@timestamp`，
  窗口 = [anchor - STREAM_WINDOW_SECONDS, anchor]；历史回放数据不会把实时事件挤出窗口
  （I-13 已踩过的坑）。
* **位点落盘**：`<OFFSET_DIR>/offsets-<GROUP>.json`，按 group_id 命名空间隔离 ——
  `ssp-stream`（实时，`auto.offset.reset=latest`）与重放用的 `ssp-stream-replay`
  （`earliest`）互不影响。不依赖 Kafka 协调器（POC 单消费者；如需多副本并行消费，
  替换为真 group 协调客户端或 Flink，接口即 kernel.evaluate 的调用点）。
* **不丢事件**：只有在一批消息成功处理并写入告警后才提交位点；fetch 尾部的半截批次
  不解析、不推进位点（见 kafka_lite.decode_record_batches）。

幂等与共存（计划 §五.2）
------------------------
告警 `_id = sha1(rule_id|entity_key)` 与批式**完全相同** → 两侧先后命中同一实体只更新不新增；
合并时并集 `ssp.alert.engines`（batch / stream），并按需记录
`ssp.alert.stream_latency_ms`（事件入 Kafka → 告警落库的实测毫秒数）。

运行
----
    python3 stream_server.py                    # 常驻：消费 + HTTP :8094
    python3 stream_server.py --once --seconds 10  # 只消费 N 秒后打印统计并退出（脚本/测试用）
"""
import datetime
import hashlib
import json
import os
import signal
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
import logging

import ssp_kernel as K  # noqa: E402
from kafka_lite import FileOffsetStore, KafkaConsumer, KafkaError  # noqa: E402

log = logging.getLogger("stream")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S")


# ── 统一 health 信封（P2-②）：所有服务 /health 返回同一组身份/存活字段 ──
SERVICE_NAME = "stream"
VERSION = "2026.09"
_START = time.time()


def _envelope(status="ok", **extra):
    d = {"status": status, "service": SERVICE_NAME, "version": VERSION,
         "uptime_s": round(time.time() - _START, 1)}
    d.update(extra)
    return d


# ----------------------------- 配置 ----------------------------- #
BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")
TOPIC = os.environ.get("STREAM_TOPIC", "ssp-ecs")
GROUP = os.environ.get("STREAM_GROUP", "ssp-stream")
OFFSET_DIR = os.environ.get("STREAM_OFFSET_DIR", "/var/lib/ssp-stream")
AUTO_OFFSET_RESET = os.environ.get("STREAM_AUTO_OFFSET_RESET", "latest").lower()
# 滑动窗口跨度（秒）——与批式 CORR_WINDOW_MINUTES 同口径，只是更短以贴合"实时"
WINDOW_SECONDS = int(os.environ.get("STREAM_WINDOW_SECONDS", "30"))
# 内存窗口上限（条）；超过即按到达顺序淘汰最旧的（保护内存）
BUFFER_SIZE = int(os.environ.get("STREAM_BUFFER_SIZE", "20000"))
# 评估节流：有事件到达时，最多每 N 毫秒评估一次（即**时延上界的抖动项**）
EVAL_INTERVAL_MS = int(os.environ.get("STREAM_EVAL_INTERVAL_MS", "1000"))
# 位点提交间隔（毫秒）
COMMIT_INTERVAL_MS = int(os.environ.get("STREAM_COMMIT_INTERVAL_MS", "2000"))
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8094"))
CORS_ALLOW_ORIGIN = os.environ.get("CORS_ALLOW_ORIGIN", "*")
# 单次 fetch 的最大等待：越小越实时，越大越省 CPU
FETCH_WAIT_MS = int(os.environ.get("STREAM_FETCH_WAIT_MS", "500"))

STOP = threading.Event()
_LAT_SAMPLES = []          # 最近若干次流式时延（ms），用于 p50/最大值观测


class Stats:
    def __init__(self):
        self.started_at = K.iso(K.now_utc())
        self.consumed = 0
        self.bad_records = 0
        self.evals = 0
        self.alerts_created = 0
        self.alerts_updated = 0
        self.write_errors = []
        self.rule_errors = []
        self.bootstrap_mode = None
        self.last_eval_at = None
        self.last_alert_at = None
        self.last_latency_ms = None
        self.max_latency_ms = None
        self.last_event_at = None
        self.reconnects = 0
        self.last_error = None

    def snapshot(self, consumer, window, extra=None):
        out = {
            "engine": "stream",
            "status": "ok",
            "topic": TOPIC,
            "group": GROUP,
            "bootstrap": BOOTSTRAP,
            "bootstrap_mode": self.bootstrap_mode,
            "auto_offset_reset": AUTO_OFFSET_RESET,
            "started_at": self.started_at,
            "consumed_total": self.consumed,
            "bad_records": self.bad_records,
            "evals_total": self.evals,
            "alerts_created_total": self.alerts_created,
            "alerts_updated_total": self.alerts_updated,
            "window_seconds": WINDOW_SECONDS,
            "events_in_window": len(window.items) if window is not None else None,
            "window": window.range_iso() if window is not None else None,
            "eval_interval_ms": EVAL_INTERVAL_MS,
            "last_eval_at": self.last_eval_at,
            "last_event_at": self.last_event_at,
            "last_alert_at": self.last_alert_at,
            "latency_ms": {"last": self.last_latency_ms, "max": self.max_latency_ms,
                           "p50": _p50(_LAT_SAMPLES), "samples": len(_LAT_SAMPLES)},
            "reconnects": self.reconnects,
            "rule_errors": self.rule_errors[-5:],
            "write_errors": self.write_errors[-5:],
            "last_error": self.last_error,
            "allowed_sources": K.allowed_sources(),
            "threat_intel_enabled": K.load_threat_intel() is not None,
        }
        if consumer is not None:
            lag, end = consumer.lag()
            out["partitions"] = [f"{t}:{p}" for t, p in consumer.assigned]
            out["positions"] = {f"{t}:{p}": o for (t, p), o in consumer.positions.items()}
            out["end_offsets"] = {f"{t}:{p}": o for (t, p), o in end.items()}
            out["lag"] = {f"{t}:{p}": v for (t, p), v in lag.items()}
            out["committed_max"] = min(
                [consumer.positions.get((t, p), 0) for (t, p) in consumer.assigned] or [0])
            out["end_min"] = min([v for v in end.values() if v is not None] or [0])
        if extra:
            out.update(extra)
        return out


def _p50(samples):
    if not samples:
        return None
    s = sorted(samples)
    return s[len(s) // 2]


class Window:
    """以**事件时间**为锚的滑动窗口（内存）。

    事件按到达顺序追加；窗口右端 = 缓冲区内最新事件时间；左端 = 右端 - WINDOW_SECONDS。
    淘汰规则：①超出窗口左端的旧事件直接丢弃（可减少内存）；②超过 BUFFER_SIZE 条按到达顺序淘汰。
    """

    def __init__(self, seconds, max_size):
        self.seconds = seconds
        self.max_size = max_size
        self.items = []          # [(event_dt, doc)]
        self.ingest_by_id = {}   # 事件 id -> 入 Kafka 时刻(ms)

    def add(self, ev_dt, doc, ingest_ms):
        self.items.append((ev_dt, doc))
        if doc.get("_id"):
            self.ingest_by_id[doc["_id"]] = ingest_ms
        self._prune()

    def _prune(self):
        if not self.items:
            return
        anchor = max(t for t, _ in self.items)
        lo = anchor - _dt_timedelta(self.seconds)
        self.items = [(t, d) for (t, d) in self.items if t >= lo]
        if len(self.items) > self.max_size:
            self.items = self.items[-self.max_size:]
        live = {d.get("_id") for _, d in self.items if d.get("_id")}
        if len(self.ingest_by_id) > 4 * self.max_size:
            self.ingest_by_id = {k: v for k, v in self.ingest_by_id.items() if k in live}

    def docs(self):
        return [d for _, d in self.items]

    def anchor(self):
        return max((t for t, _ in self.items), default=None)

    def range_iso(self):
        a = self.anchor()
        if a is None:
            return None
        return {"start": K.iso(a - _dt_timedelta(self.seconds)), "end": K.iso(a),
                "anchor": "event-time"}


def _dt_timedelta(seconds):
    return datetime.timedelta(seconds=seconds)


def event_doc_id(doc):
    """给流式事件一个稳定 id（等价于批式从 OpenSearch 拿到的 _id 角色）。

    用文档内容的 sha1：同一事件被重放时 id 相同，`related.event_ids` 可稳定去重。
    """
    txt = json.dumps(doc, ensure_ascii=False, sort_keys=True)
    return "ecs-" + hashlib.sha1(txt.encode("utf-8")).hexdigest()[:20]


class StreamRunner:
    def __init__(self):
        self.stats = Stats()
        self.window = Window(WINDOW_SECONDS, BUFFER_SIZE)
        self.consumer = None
        self.dirty = False
        self._last_eval_ms = 0
        self._last_commit_ms = 0

    # ---- 消费者生命周期 ----
    def connect(self):
        path = os.path.join(OFFSET_DIR, f"offsets-{GROUP}.json")
        store = FileOffsetStore(path)
        self.consumer = KafkaConsumer(BOOTSTRAP, topics=[TOPIC], group_id=GROUP,
                                      offset_store=store, auto_offset_reset=AUTO_OFFSET_RESET,
                                      client_id=f"ssp-{GROUP}")
        self.consumer.start()
        self.stats.bootstrap_mode = self.consumer.bootstrap_mode
        log.info(f"[stream] 已订阅 {TOPIC}（group={GROUP} 位点={path} "
              f"启动模式={self.consumer.bootstrap_mode} 分区={self.consumer.assigned}）")

    def reconnect(self):
        self.stats.reconnects += 1
        try:
            if self.consumer:
                self.consumer.close()
        except Exception:
            pass
        time.sleep(2)
        self.connect()

    # ---- 处理一批 ----
    def poll_once(self):
        try:
            recs, errs = self.consumer.next_batch(timeout_ms=FETCH_WAIT_MS)
        except KafkaError as e:
            self.stats.last_error = f"fetch: {e}"
            log.warning(f"[stream] fetch 异常，重连：{e}")
            self.reconnect()
            return 0
        for e in errs:
            self.stats.last_error = f"fetch: {e}"
        n = 0
        for r in recs:
            doc = r.json(default=None)
            if not isinstance(doc, dict):
                self.stats.bad_records += 1
                continue
            ev_dt = K.parse_ts(K.get_in(doc, "@timestamp"))
            if ev_dt is None:
                ev_dt = K.parse_ts(r.timestamp_ms / 1000.0)
            if ev_dt is None:
                self.stats.bad_records += 1
                continue
            doc["_id"] = doc.get("_id") or event_doc_id(doc)
            self.window.add(ev_dt, doc, r.timestamp_ms or int(time.time() * 1000))
            self.stats.consumed += 1
            self.stats.last_event_at = K.iso(ev_dt)
            self.dirty = True
            n += 1
        return n

    # ---- 评估（节流到一起事件一次）----
    def maybe_evaluate(self, force=False):
        now = int(time.time() * 1000)
        if not self.dirty and not force:
            return
        if not force and (now - self._last_eval_ms) < EVAL_INTERVAL_MS:
            return
        docs = self.window.docs()
        if not docs:
            self.dirty = False
            return
        anchor = self.window.anchor()
        window = (anchor - _dt_timedelta(WINDOW_SECONDS), anchor)
        assets, threat_mod = K.enrich_inputs(docs)
        alerts, hits, errors, _geo = K.evaluate(
            docs, window, assets, threat_mod, engine="stream",
            ingest_by_id=self.window.ingest_by_id)
        self.stats.evals += 1
        self.stats.last_eval_at = K.iso(K.now_utc())
        if errors:
            self.stats.rule_errors.extend(errors)
        res = None
        if alerts:
            res = K.upsert_alerts(alerts)
            self.stats.alerts_created += int(res.get("created", 0) or 0)
            self.stats.alerts_updated += int(res.get("updated", 0) or 0)
            if res.get("error") or res.get("errors"):
                self.stats.write_errors.append(json.dumps(res, ensure_ascii=False)[:200])
            lats = [K.get_in(d[1], "ssp.alert.stream_latency_ms")
                    for d in alerts if K.get_in(d[1], "ssp.alert.stream_latency_ms") is not None]
            if lats:
                last = min(lats)
                self.stats.last_latency_ms = last
                self.stats.max_latency_ms = max(self.stats.max_latency_ms or 0, max(lats))
                _LAT_SAMPLES.append(max(lats))
                del _LAT_SAMPLES[:-500]
            self.stats.last_alert_at = K.iso(K.now_utc())
        self.dirty = False
        self._last_eval_ms = now
        if alerts:
            log.info(f"[stream] 评估: 窗口事件={len(docs)} 命中={hits} 告警={len(alerts)} "
                  f"写入={res} 时延(ms)={self.stats.last_latency_ms}")

    def maybe_commit(self, force=False):
        now = int(time.time() * 1000)
        if not force and (now - self._last_commit_ms) < COMMIT_INTERVAL_MS:
            return
        try:
            self.consumer.commit(force=force)
            self._last_commit_ms = now
        except Exception as e:
            self.stats.last_error = f"commit: {e}"

    # ---- 主循环 ----
    def run(self, seconds=None):
        self.connect()
        t0 = time.time()
        while not STOP.is_set():
            if seconds is not None and (time.time() - t0) >= seconds:
                break
            self.poll_once()
            self.maybe_evaluate()
            self.maybe_commit()
        try:
            self.maybe_evaluate(force=True)
        except Exception as e:
            self.stats.last_error = f"final evaluate: {e}"
        self.maybe_commit(force=True)
        try:
            self.consumer.close()
        except Exception:
            pass


# ----------------------------- HTTP 观测 ----------------------------- #
RUNNER = None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", CORS_ALLOW_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(204, {})

    def do_GET(self):
        try:
            p = self.path.split("?")[0]
            if p in ("/health", "/"):
                st = RUNNER.stats.snapshot(RUNNER.consumer, RUNNER.window)
                lag = st.get("lag") or {}
                worst = max([v for v in lag.values() if v is not None] or [0])
                st["ok"] = worst < 1000
                st.update(_envelope(status=st.get("status") or "ok"))
                self._send(200, st)
                return
            if p == "/stats":
                self._send(200, RUNNER.stats.snapshot(RUNNER.consumer, RUNNER.window))
                return
            if p == "/alerts":
                st, obj = K.list_alerts(limit=50)
                self._send(st, obj)
                return
            if p == "/window":
                self._send(200, {"events": len(RUNNER.window.items),
                                 "range": RUNNER.window.range_iso()})
                return
            self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def do_POST(self):
        try:
            if self.path.split("?")[0] == "/flush":
                RUNNER.maybe_evaluate(force=True)
                RUNNER.maybe_commit(force=True)
                self._send(200, RUNNER.stats.snapshot(RUNNER.consumer, RUNNER.window))
                return
            self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(500, {"error": f"{type(e).__name__}: {e}"})


def _sig(_n, _f):
    STOP.set()


def main():
    global RUNNER
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    RUNNER = StreamRunner()

    if "--once" in sys.argv:
        seconds = None
        for i, a in enumerate(sys.argv):
            if a == "--seconds" and i + 1 < len(sys.argv):
                seconds = float(sys.argv[i + 1])
        RUNNER.run(seconds=seconds if seconds is not None else 5)
        print(json.dumps(RUNNER.stats.snapshot(RUNNER.consumer, RUNNER.window),
                         ensure_ascii=False, indent=2))
        return 0

    t = threading.Thread(target=RUNNER.run, name="stream-consumer", daemon=True)
    t.start()
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    log.info(f"[stream] 流式关联引擎启动 http://{LISTEN_HOST}:{LISTEN_PORT} "
          f"topic={TOPIC} group={GROUP} 窗口={WINDOW_SECONDS}s "
          f"评估节流={EVAL_INTERVAL_MS}ms 来源={K.allowed_sources()}")
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
