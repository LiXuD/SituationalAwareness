#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kafka_lite.py —— 极简 Kafka 客户端（**纯标准库，零第三方依赖**）

I-14 流式关联：POC 采用"轻量消费者"路线（计划 §六 D1 选项 C），
为避免在 x86 私有化交付中引入 pip 依赖与镜像构建网络要求，
这里用标准库直接实现 Kafka 协议的一个**最小可用子集**：

  协议版本（全部使用"非柔性"版本，避免 compact 编码与 tagged fields）
    ApiVersions   v0   握手/能力探测
    Metadata      v1   集群与主题分区（选出分区 leader）
    ListOffsets   v1   取最早/最新位点（-2 / -1）
    Fetch         v4   拉取消息（含 gzip 等压缩批次解压）
    Produce       v3   投递消息（record batch v2 + CRC32C）

  已实现
    · record batch v2 编解码（magic=2）、CRC32C 校验、gzip 解压
    · 多分区自动指派（同一 group 内按 topic 全分区订阅）
    · 位点落盘（JSON 文件，按 group_id 命名空间隔离 → 实时/重放互不影响）
    · 断连续读、offset 越界（OFFSET_OUT_OF_RANGE）按 auto_offset_reset 复位
    · "不完整批次"安全截断（fetch 尾部的半截批次不解析、不推进位点）

  明确不做（POC 范围外，见计划 §三）
    · 消费者组协调（JoinGroup/SyncGroup/心跳）——单消费者无需；位点落盘即可观测
    · 事务 / exactly-once / 幂等生产者
    · SASL / SSL / ACL

  升级路径：若需多副本并行消费或 exactly-once，替换为真 group 协调客户端或 Flink
  （计划 §六 D1 选项 A）。**本模块的对外接口（send / next_batch / commit）即替换点。**

用法
----
    from kafka_lite import KafkaProducer, KafkaConsumer, FileOffsetStore

    p = KafkaProducer("kafka:9092")
    p.send_json("ssp-raw", {"fields": {"log_source": "firewall"}})

    c = KafkaConsumer("kafka:9092", topics=["ssp-ecs"], group_id="ssp-stream",
                      offset_store=FileOffsetStore("/var/lib/ssp-stream/offsets.json"))
    c.start()
    for rec in c.next_batch(timeout_ms=1000):
        print(rec.offset, rec.json())
    c.commit()
"""
import gzip
import json
import os
import socket
import struct
import threading
import time
import logging

_LOG = logging.getLogger(__name__)


__all__ = [
    "crc32c", "KafkaClient", "KafkaProducer", "KafkaConsumer",
    "FileOffsetStore", "Record", "KafkaError", "API_VERSIONS",
]

API_PRODUCE = 0
API_FETCH = 1
API_LIST_OFFSETS = 2
API_METADATA = 3
API_VERSIONS = 18

ERR_NONE = 0
ERR_OFFSET_OUT_OF_RANGE = 1
ERR_UNKNOWN_TOPIC_OR_PARTITION = 3
ERR_LEADER_NOT_AVAILABLE = 5
ERR_NOT_LEADER_OR_FOLLOWER = 6
ERR_GROUP_LOAD_IN_PROGRESS = 14
ERR_UNSUPPORTED_VERSION = 35
ERR_NAMES = {
    0: "NONE", 1: "OFFSET_OUT_OF_RANGE", 2: "CORRUPT_MESSAGE",
    3: "UNKNOWN_TOPIC_OR_PARTITION", 4: "INVALID_FETCH_SIZE", 5: "LEADER_NOT_AVAILABLE",
    6: "NOT_LEADER_OR_FOLLOWER", 7: "REQUEST_TIMED_OUT", 8: "BROKER_NOT_AVAILABLE",
    9: "REPLICA_NOT_AVAILABLE", 10: "MESSAGE_TOO_LARGE", 11: "STALE_CONTROLLER_EPOCH",
    13: "NETWORK_EXCEPTION", 14: "GROUP_LOAD_IN_PROGRESS", 15: "GROUP_COORDINATOR_NOT_AVAILABLE",
    17: "INVALID_TOPIC_EXCEPTION", 19: "NOT_ENOUGH_REPLICAS", 20: "NOT_ENOUGH_REPLICAS_AFTER_APPEND",
    29: "TOPIC_AUTHORIZATION_FAILED", 35: "UNSUPPORTED_VERSION",
    37: "INVALID_PARTITIONS", 38: "INVALID_REPLICATION_FACTOR",
}
# 可重试的瞬时错误（连接/元数据未就绪/leader 切换）
_RETRIABLE = {ERR_LEADER_NOT_AVAILABLE, ERR_NOT_LEADER_OR_FOLLOWER,
              ERR_UNKNOWN_TOPIC_OR_PARTITION, ERR_GROUP_LOAD_IN_PROGRESS, 8, 13, 7}


class KafkaError(Exception):
    def __init__(self, code, msg=""):
        self.code = code
        super().__init__(f"{ERR_NAMES.get(code, code)}: {msg}" if msg else ERR_NAMES.get(code, str(code)))


# --------------------------------------------------------------------------- #
# CRC32C（Castagnoli，Kafka record batch v2 校验用；标准库只有 CRC32，故自建查表）
# --------------------------------------------------------------------------- #
_CRC32C_POLY = 0x82F63B78          # 反射多项式
_CRC32C_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (_CRC32C_POLY if _c & 1 else 0)
    _CRC32C_TABLE.append(_c)


def crc32c(data):
    crc = 0xFFFFFFFF
    tbl = _CRC32C_TABLE
    for b in data:
        crc = (crc >> 8) ^ tbl[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# 编解码
# --------------------------------------------------------------------------- #
def _i8(v):
    return struct.pack(">b", int(v))


def _i16(v):
    return struct.pack(">h", int(v))


def _i32(v):
    return struct.pack(">i", int(v))


def _i64(v):
    return struct.pack(">q", int(v))


def _bool(v):
    return struct.pack(">b", 1 if v else 0)


def _str(s):
    b = ("" if s is None else str(s)).encode("utf-8")
    return _i16(len(b)) + b


def _nstr(s):
    if s is None:
        return _i16(-1)
    return _str(s)


def _bytes(b):
    b = b or b""
    return _i32(len(b)) + b


def _nbytes(b):
    if b is None:
        return _i32(-1)
    return _bytes(b)


def _array(items):
    return _i32(len(items)) + b"".join(items)


def _varint(v):
    """zigzag varint（KV v0 风格整数编码）"""
    v = (v << 1) ^ (v >> 63) if v < 0 else (v << 1)
    out = bytearray()
    while True:
        if v & ~0x7F == 0:
            out.append(v)
            return bytes(out)
        out.append((v & 0x7F) | 0x80)
        v >>= 7


_varlong = _varint                      # 同一算法（Python 整数无位宽）


class _Reader:
    __slots__ = ("b", "i")

    def __init__(self, buf):
        self.b = buf
        self.i = 0

    def take(self, n):
        if self.i + n > len(self.b):
            raise ValueError("buffer underflow")
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def i8(self):
        return struct.unpack(">b", self.take(1))[0]

    def i16(self):
        return struct.unpack(">h", self.take(2))[0]

    def i32(self):
        return struct.unpack(">i", self.take(4))[0]

    def i64(self):
        return struct.unpack(">q", self.take(8))[0]

    def boolean(self):
        return self.i8() != 0

    def string(self):
        n = self.i16()
        return "" if n < 0 else self.take(n).decode("utf-8", "replace")

    def nullable_string(self):
        n = self.i16()
        return None if n < 0 else self.take(n).decode("utf-8", "replace")

    def bytes(self):
        n = self.i32()
        return None if n < 0 else self.take(n)

    def array(self, fn):
        n = self.i32()
        return [fn(self) for _ in range(n)]

    def varint(self):
        shift = 0
        val = 0
        while True:
            b = self.i8()
            val |= (b & 0x7F) << shift
            if not b & 0x80:
                break
            shift += 7
        return (val >> 1) ^ -(val & 1)

    varlong = varint

    def remaining(self):
        return len(self.b) - self.i


# --------------------------------------------------------------------------- #
# record batch v2
# --------------------------------------------------------------------------- #
def encode_record_batch(records, base_timestamp_ms=None):
    """records: [(key|None, value|None, ts_ms)] -> record batch v2（未压缩）bytes

    注意：v2 批次头共 **61 字节**（RECORD_BATCH_OVERHEAD）。除官方文档表格列出的字段外，
    `baseSequence` 之后还有 4 字节 `recordsCount`——漏写会被 broker 判为
    INVALID_RECORD(87)（报错信息为 "Invalid batch record count"），实测踩过。
    """
    if not records:
        return b""
    ts = [r[2] for r in records if r[2]]
    base_ts = base_timestamp_ms if base_timestamp_ms is not None else (min(ts) if ts else int(time.time() * 1000))
    max_ts = max([base_ts] + ts)
    buf = bytearray()
    for i, (k, v, t) in enumerate(records):
        delta = (t or base_ts) - base_ts
        body = _i8(0) + _varlong(delta) + _varint(i)
        body += _varint(-1) if k is None else _varint(len(k)) + k
        body += _varint(-1) if v is None else _varint(len(v)) + v
        body += _varint(0)                      # headers count
        buf += _varint(len(body)) + body
    rec_bytes = bytes(buf)
    body = b""
    body += _i32(-1)                            # partitionLeaderEpoch
    body += _i8(2)                              # magic
    body += _i32(0)                             # crc 占位
    body += _i16(0)                             # attributes（0=无压缩）
    body += _i32(len(records) - 1)              # lastOffsetDelta
    body += _i64(base_ts)
    body += _i64(max_ts)
    body += _i64(-1)                            # producerId
    body += _i16(-1)                            # producerEpoch
    body += _i32(-1)                            # baseSequence
    body += _i32(len(records))                  # recordsCount（易漏！）
    body += rec_bytes
    crc = crc32c(body[9:])                     # crc 覆盖 attributes 及其之后的全部字节
    body = body[:5] + struct.pack(">I", crc) + body[9:]   # 5 = magic 之后的 crc 字段位置
    header = struct.pack(">qi", 0, len(body))   # baseOffset=0, batchLength
    return header + body


_CODECS = {
    0: None,
    1: "gzip",
    2: "snappy",
    3: "lz4",
    4: "zstd",
}


def _decompress(codec, data):
    if codec is None:
        return data
    if codec == "gzip":
        return gzip.decompress(data)
    try:
        if codec == "lz4":
            import lz4.frame as lz4f          # 可选（存在则用）
            return lz4f.decompress(data)
        if codec == "zstd":
            import zstandard
            return zstandard.ZstdDecompressor().decompressobj().decompress(data)
        if codec == "snappy":
            import snappy
            return snappy.decompress(data)
    except Exception as e:
        raise KafkaError(-1, f"压缩批次({codec})解压失败：{e}")
    raise KafkaError(-1, f"不支持的压缩编码：{codec}")


def decode_record_batches(buf, min_offset=None, verify_crc=False):
    """解析 fetch 返回的 record_set。

    返回 [(offset, key, value, timestamp_ms)]。
    尾部不完整批次（被 max_bytes 截断）直接停止 —— 不解析、不推进位点，
    下次 fetch 会重新拉取该批次（计划 §五 幂等与不丢事件要求）。
    """
    out = []
    pos = 0
    n = len(buf)
    while pos + 12 <= n:
        _base = struct.unpack(">q", buf[pos:pos + 8])[0]
        blen = struct.unpack(">i", buf[pos + 8:pos + 12])[0]
        if blen <= 0 or pos + 12 + blen > n:
            break                                   # 不完整批次（尾部被截断）
        body = buf[pos + 12:pos + 12 + blen]
        pos += 12 + blen
        if len(body) < 49:
            continue
        magic = body[4]
        if magic != 2:                              # 仅支持 v2（Filebeat/Logstash 均产出 v2）
            continue
        if verify_crc:
            want = struct.unpack(">I", body[5:9])[0]
            if crc32c(body[9:]) != want:
                raise KafkaError(-1, "record batch CRC32C 校验失败")
        attrs = struct.unpack(">h", body[9:11])[0]
        codec = _CODECS.get(attrs & 0x07)
        last_delta = struct.unpack(">i", body[11:15])[0]
        base_ts = struct.unpack(">q", body[15:23])[0]
        # 注意：v2 批次头 61 字节（含 baseSequence 之后的 recordsCount），
        # 即 body 内偏移 49 起才是 records；漏算 4 字节 recordsCount 会把
        # gzip 流起点算错 4 字节（表现为 "Not a gzipped file (b'\x00\x00')"）。
        rec_blob = _decompress(codec, body[49:]) if codec else body[49:]
        r = _Reader(rec_blob)
        i = 0
        try:
            while r.remaining() > 0 and i <= last_delta:
                rlen = r.varint()
                if rlen < 0:
                    break
                rec = _Reader(r.take(rlen))
                rec.i8()                            # attributes
                ts_delta = rec.varlong()
                off_delta = rec.varint()
                klen = rec.varint()
                key = rec.take(klen) if klen >= 0 else None
                vlen = rec.varint()
                val = rec.take(vlen) if vlen >= 0 else None
                nh = rec.varint()
                for _ in range(max(0, nh)):
                    hk = rec.varint()
                    if hk >= 0:
                        rec.take(hk)
                    hv = rec.varint()
                    if hv >= 0:
                        rec.take(hv)
                offset = _base + off_delta
                if min_offset is not None and offset < min_offset:
                    i += 1
                    continue
                out.append((offset, key, val, base_ts + ts_delta))
                i += 1
        except (ValueError, struct.error):
            continue                                # 批次内损坏/截断：跳过该批次
    return out


# --------------------------------------------------------------------------- #
# 连接
# --------------------------------------------------------------------------- #
class _Conn:
    def __init__(self, host, port, timeout=10, client_id="ssp-kafka-lite"):
        self.host = host
        self.port = int(port)
        self.client_id = client_id
        self.timeout = timeout
        self._cid = 0
        self.sock = socket.create_connection((host, self.port), timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise KafkaError(13, f"连接被对端关闭：{self.host}:{self.port}")
            buf += chunk
        return buf

    def request(self, api_key, api_version, body):
        if self.sock.fileno() < 0:
            raise KafkaError(13, "连接已关闭")
        self._cid += 1
        payload = _i16(api_key) + _i16(api_version) + _i32(self._cid) + _str(self.client_id) + body
        self.sock.sendall(_i32(len(payload)) + payload)
        size = struct.unpack(">i", self._recv_exact(4))[0]
        resp = self._recv_exact(size)
        r = _Reader(resp)
        cid = r.i32()
        if cid != self._cid:
            raise KafkaError(13, f"响应 correlation_id 不匹配（{cid} != {self._cid}）")
        return resp[4:]

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# 客户端
# --------------------------------------------------------------------------- #
class KafkaClient:
    def __init__(self, bootstrap_servers="kafka:9092", client_id="ssp-kafka-lite", timeout=10):
        self.bootstrap = self._parse(bootstrap_servers)
        self.client_id = client_id
        self.timeout = timeout
        self._conns = {}
        self._meta = None
        self._meta_at = 0.0
        self._lock = threading.Lock()

    @staticmethod
    def _parse(servers):
        out = []
        for s in str(servers).split(","):
            s = s.strip()
            if not s:
                continue
            host, _, port = s.partition(":")
            out.append((host, int(port or 9092)))
        return out or [("kafka", 9092)]

    # ---- 连接管理 ----
    @staticmethod
    def _key(node=None, bootstrap=None):
        return tuple(node) if node else tuple(bootstrap)

    def _conn(self, key):
        c = self._conns.get(key)
        if c is None:
            c = _Conn(key[0], key[1], self.timeout, self.client_id)
            self._conns[key] = c
        return c

    def _drop(self, key):
        c = self._conns.pop(key, None)
        if c:
            c.close()

    def close(self):
        with self._lock:
            for c in list(self._conns.values()):
                c.close()
            self._conns.clear()

    def _request(self, api_key, api_version, body, node=None):
        """串行化发送一次请求。

        重要：一个 TCP 连接**不能**被多线程并发读写（否则响应流交叉 →
        表现为 "Bad file descriptor"/解析错乱）。消费者线程与 HTTP 观测线程
        共用本客户端，故这里用全局锁把"取连接 → 收发 → 出错即丢弃重连"整体包住。
        """
        key = self._key(node, self.bootstrap[0])
        with self._lock:
            try:
                return self._conn(key).request(api_key, api_version, body)
            except KafkaError:
                self._drop(key)
                raise
            except OSError as e:
                self._drop(key)
                raise KafkaError(13, f"{e}")

    # ---- ApiVersions ----
    def api_versions(self):
        r = _Reader(self._request(API_VERSIONS, 0, b""))
        err = r.i16()
        keys = r.array(lambda rr: (rr.i16(), rr.i16(), rr.i16()))
        return err, {k: (lo, hi) for k, lo, hi in keys}

    # ---- Metadata ----
    def metadata(self, topics=None, force=False):
        if not force and self._meta and (time.time() - self._meta_at) < 30:
            if not topics or all(t in self._meta["topics"] for t in topics):
                return self._meta
        req = _array([_str(t) for t in topics]) if topics else _i32(-1)
        r = _Reader(self._request(API_METADATA, 1, req))
        brokers = {}
        for _ in range(r.i32()):
            node_id = r.i32()
            host = r.string()
            port = r.i32()
            r.nullable_string()                      # rack
            brokers[node_id] = (host, port)
        r.i32()                                      # controller_id
        topics_map = {}
        for _ in range(r.i32()):
            terr = r.i16()
            name = r.string()
            r.boolean()                              # is_internal
            parts = {}
            for _ in range(r.i32()):
                perr = r.i16()
                pidx = r.i32()
                leader = r.i32()
                r.array(lambda rr: rr.i32())         # replicas
                r.array(lambda rr: rr.i32())         # isr
                parts[pidx] = (perr, leader)
            topics_map[name] = {"error": terr, "partitions": parts}
        self._meta = {"brokers": brokers, "topics": topics_map}
        self._meta_at = time.time()
        return self._meta

    def partitions(self, topic, refresh=False):
        m = self.metadata([topic], force=refresh)
        info = m["topics"].get(topic) or {"error": ERR_UNKNOWN_TOPIC_OR_PARTITION, "partitions": {}}
        return {p: v for p, v in info["partitions"].items()}, info["error"]

    def _leader(self, topic, partition, refresh=False):
        parts, _err = self.partitions(topic, refresh=refresh)
        if partition not in parts:
            raise KafkaError(ERR_UNKNOWN_TOPIC_OR_PARTITION, f"{topic}-{partition}")
        perr, leader = parts[partition]
        if perr != ERR_NONE:
            raise KafkaError(perr, f"{topic}-{partition}")
        m = self.metadata()
        if leader not in m["brokers"]:
            self.metadata([topic], force=True)
            m = self.metadata()
        return m["brokers"].get(leader)

    # ---- ListOffsets ----
    def list_offsets(self, topic, partition, timestamp=-1):
        body = _i32(-1) + _array([_str(topic) + _array([_i32(partition) + _i64(timestamp)])])
        try:
            node = self._leader(topic, partition)     # ListOffsets 也必须问该分区 leader
        except KafkaError:
            node = None
        r = _Reader(self._request(API_LIST_OFFSETS, 1, body, node=node))
        for _ in range(r.i32()):
            r.string()
            for _ in range(r.i32()):
                r.i32()
                err = r.i16()
                ts = r.i64()
                off = r.i64()
                if err != ERR_NONE:
                    raise KafkaError(err, f"{topic}-{partition}")
                return ts, off
        raise KafkaError(-1, "ListOffsets 未返回结果")

    def create_topic(self, topic, partitions=3, replication=1, timeout_ms=5000):
        """POC 便捷：broker 已开自动建主题，这里显式触发一次 Metadata 即可。"""
        self.metadata([topic], force=True)

    # ---- Produce ----
    def produce(self, topic, value, key=None, partition=None, acks=1, timeout_ms=10000, retries=4):
        last = None
        for attempt in range(retries):
            try:
                if partition is None:
                    parts, err = self.partitions(topic, refresh=(attempt > 0))
                    if not parts:
                        raise KafkaError(err or ERR_LEADER_NOT_AVAILABLE, topic)
                    keys = sorted(parts)
                    if key is None:
                        partition = keys[0]
                    else:
                        partition = keys[(sum(key) & 0x7FFFFFFF) % len(keys)]
                node = self._leader(topic, partition, refresh=(attempt > 0))
                if node is None:
                    raise KafkaError(ERR_LEADER_NOT_AVAILABLE, f"{topic}-{partition}")
                ts = int(time.time() * 1000)
                batch = encode_record_batch([(key, value, ts)])
                body = (_nstr(None) + _i16(acks) + _i32(timeout_ms)
                        + _array([_str(topic) + _array([
                            _i32(partition) + _nbytes(batch)])]))
                r = _Reader(self._request(API_PRODUCE, 3, body, node=node))
                # Produce v3 响应：responses[{name, partitions[{index, error_code,
                # base_offset, log_append_time_ms}]}] + throttle_time_ms
                # 注意：Produce 的 throttle_time_ms 在**数组之后**（Fetch 才在前）；
                # log_start_offset 自 v5 起才有，此处不得多读。
                for _ in range(r.i32()):
                    r.string()
                    for _ in range(r.i32()):
                        r.i32()
                        err = r.i16()
                        base_off = r.i64()
                        r.i64()                     # logAppendTime
                        if err != ERR_NONE:
                            raise KafkaError(err, f"{topic}-{partition}")
                        return partition, base_off
            except KafkaError as e:
                last = e
                if e.code in _RETRIABLE:
                    try:
                        self.metadata([topic], force=True)     # 主题/leader 可能刚建好
                    except Exception:
                        pass
                    time.sleep(0.4 * (attempt + 1))
                    continue
                raise
        raise KafkaError(getattr(last, "code", -1), f"投递失败：{last}")

    # ---- Fetch ----
    def fetch(self, assignments, max_wait_ms=500, min_bytes=1, max_bytes=5242880,
              partition_max_bytes=1048576, verify_crc=False):
        """assignments: {(topic, partition): offset} -> {tp: [Record]}"""
        by_node = {}
        for (topic, partition), off in assignments.items():
            node = self._leader(topic, partition)
            by_node.setdefault(tuple(node), []).append((topic, partition, off))
        out = {}
        for node, items in by_node.items():
            topics = {}
            for topic, partition, off in items:
                topics.setdefault(topic, []).append((partition, off))
            body = (_i32(-1) + _i32(max_wait_ms) + _i32(min_bytes) + _i32(max_bytes) + _i8(0)
                    + _array([_str(t) + _array([_i32(p) + _i64(o) + _i32(partition_max_bytes)
                                                for p, o in ps])
                              for t, ps in sorted(topics.items())])
                    + _array([]))
            r = _Reader(self._request(API_FETCH, 4, body, node=node))
            r.i32()                                  # throttle_time_ms
            for _ in range(r.i32()):
                tname = r.string()
                for _ in range(r.i32()):
                    pidx = r.i32()
                    err = r.i16()
                    r.i64()                          # high_watermark
                    r.i64()                          # last_stable_offset
                    r.array(lambda rr: (rr.i64(), rr.i64()))      # aborted_transactions
                    recset = r.bytes() or b""
                    tp = (tname, pidx)
                    if err != ERR_NONE:
                        out.setdefault(tp, [])
                        out[tp].append(KafkaError(err, f"{tname}-{pidx}"))
                        continue
                    recs = [Record(tname, pidx, o, k, v, ts)
                            for o, k, v, ts in decode_record_batches(
                                recset, min_offset=assignments.get(tp), verify_crc=verify_crc)]
                    out.setdefault(tp, []).extend(recs)
        return out


class Record:
    __slots__ = ("topic", "partition", "offset", "key", "value", "timestamp_ms")

    def __init__(self, topic, partition, offset, key, value, timestamp_ms):
        self.topic = topic
        self.partition = partition
        self.offset = offset
        self.key = key
        self.value = value
        self.timestamp_ms = timestamp_ms

    def json(self, default=None):
        try:
            return json.loads(self.value.decode("utf-8"))
        except Exception:
            return default

    def text(self):
        return (self.value or b"").decode("utf-8", "replace")

    def __repr__(self):
        return f"<Record {self.topic}-{self.partition}@{self.offset} {len(self.value or b'')}B>"


# --------------------------------------------------------------------------- #
# 位点存储（落盘；按 group_id 命名空间隔离 → 实时 group 与重放 group 互不影响）
# --------------------------------------------------------------------------- #
class FileOffsetStore:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._data = {}
        self._load()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self._data = json.load(f) or {}
        except Exception:
            self._data = {}

    @staticmethod
    def tp(topic, partition):
        return f"{topic}:{partition}"

    def get(self, group, topic, partition):
        v = (self._data.get(group) or {}).get(self.tp(topic, partition))
        return int(v) if v is not None else None

    def group_offsets(self, group):
        return dict(self._data.get(group) or {})

    def set(self, group, topic, partition, offset):
        with self._lock:
            self._data.setdefault(group, {})[self.tp(topic, partition)] = int(offset)

    def save(self):
        with self._lock:
            d = os.path.dirname(os.path.abspath(self.path))
            if d:
                os.makedirs(d, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)


# --------------------------------------------------------------------------- #
# 生产者
# --------------------------------------------------------------------------- #
class KafkaProducer:
    def __init__(self, bootstrap_servers="kafka:9092", client_id="ssp-producer",
                 acks=1, timeout=10):
        self.client = KafkaClient(bootstrap_servers, client_id, timeout)
        self.acks = acks

    def send(self, topic, value, key=None, partition=None):
        if isinstance(value, str):
            value = value.encode("utf-8")
        if isinstance(key, str):
            key = key.encode("utf-8")
        return self.client.produce(topic, value, key=key, partition=partition, acks=self.acks)

    def send_json(self, topic, obj, key=None):
        return self.send(topic, json.dumps(obj, ensure_ascii=False), key=key)

    def health(self):
        try:
            err, _keys = self.client.api_versions()
            return err == 0
        except Exception:
            return False

    def close(self):
        self.client.close()


# --------------------------------------------------------------------------- #
# 消费者（单进程多分区指派；位点落盘 + 断连续读）
# --------------------------------------------------------------------------- #
class KafkaConsumer:
    def __init__(self, bootstrap_servers="kafka:9092", topics=None, group_id="ssp-stream",
                 offset_store=None, auto_offset_reset="latest", client_id="ssp-consumer",
                 timeout=10, max_bytes=5242880, max_wait_ms=500):
        self.client = KafkaClient(bootstrap_servers, client_id, timeout)
        self.topics = list(topics or [])
        self.group_id = group_id
        self.store = offset_store
        self.auto_offset_reset = auto_offset_reset
        self.max_bytes = max_bytes
        self.max_wait_ms = max_wait_ms
        self.positions = {}          # (topic, partition) -> 下一个待读位点
        self.assigned = []           # [(topic, partition)]
        self.bootstrap_mode = None   # latest | earliest | resume
        self._dirty = False

    # ---- 指派 ----
    def start(self, retries=30, retry_sleep=2.0):
        last = None
        for _ in range(retries):
            try:
                self.assigned = []
                for t in self.topics:
                    parts, err = self.client.partitions(t, refresh=True)
                    if not parts or err != ERR_NONE:
                        raise KafkaError(err or ERR_LEADER_NOT_AVAILABLE, t)
                    self.assigned += [(t, p) for p in sorted(parts)]
                break
            except KafkaError as e:
                last = e
                time.sleep(retry_sleep)
        else:
            raise KafkaError(getattr(last, "code", -1), f"主题指派失败：{last}")
        modes = set()
        for tp in self.assigned:
            stored = self.store.get(self.group_id, *tp) if self.store else None
            if stored is not None:
                self.positions[tp] = stored
                modes.add("resume")
            else:
                _, off = self.client.list_offsets(
                    tp[0], tp[1], -1 if self.auto_offset_reset == "latest" else -2)
                self.positions[tp] = off
                modes.add(self.auto_offset_reset)
        self.bootstrap_mode = "+".join(sorted(modes)) or self.auto_offset_reset
        return self.positions

    def seek(self, topic, partition, offset):
        self.positions[(topic, partition)] = int(offset)

    def end_offsets(self):
        out = {}
        for tp in self.assigned:
            try:
                _, off = self.client.list_offsets(tp[0], tp[1], -1)
                out[tp] = off
            except KafkaError:
                out[tp] = None
        return out

    def lag(self):
        end = self.end_offsets()
        return {tp: (end[tp] - self.positions.get(tp, 0)) if end.get(tp) is not None else None
                for tp in self.assigned}, end

    # ---- 拉取 ----
    def next_batch(self, timeout_ms=None):
        """拉一批消息；内部推进位点（调用方处理成功后再 commit）。返回 ([Record], [KafkaError])。"""
        if not self.assigned:
            self.start()
        out = []
        errs = []
        res = self.client.fetch(self.positions, max_wait_ms=timeout_ms or self.max_wait_ms,
                               max_bytes=self.max_bytes, verify_crc=False)
        for tp, items in res.items():
            for it in items:
                if isinstance(it, KafkaError):
                    if it.code == ERR_OFFSET_OUT_OF_RANGE:
                        _, off = self.client.list_offsets(
                            tp[0], tp[1], -1 if self.auto_offset_reset == "latest" else -2)
                        self.positions[tp] = off
                        self._dirty = True
                    elif it.code in _RETRIABLE:
                        self.client.metadata([tp[0]], force=True)
                    else:
                        errs.append(it)
                    continue
                out.append(it)
                self.positions[tp] = max(self.positions.get(tp, 0), it.offset + 1)
                self._dirty = True
        out.sort(key=lambda r: (r.topic, r.partition, r.offset))
        return out, errs

    def commit(self, force=False):
        if not self.store or (not self._dirty and not force):
            return
        for tp, off in self.positions.items():
            self.store.set(self.group_id, tp[0], tp[1], off)
        self.store.save()
        self._dirty = False

    def close(self):
        try:
            self.commit()
        except Exception as e:
            # 关闭前最后一次提交位点失败：重启后可能从旧位点续读 → 重复消费（非丢数据）
            _LOG.warning(f"[kafka] 关闭前提交位点失败（重启后可能重复消费）: "
                  f"{type(e).__name__}: {e}")
        self.client.close()


if __name__ == "__main__":                       # 自检：crc32c 与 record batch 往返
    import sys
    tb = encode_record_batch([(None, b'{"a":1}', 1700000000000), (b"k", b"v2", 1700000000001)])
    got = decode_record_batches(tb, verify_crc=True)
    ok = (crc32c(b"123456789") == 0xE3069283 and len(got) == 2
          and got[0][2] == b'{"a":1}' and got[1][1] == b"k")
    print(json.dumps({"crc32c_ok": crc32c(b"123456789") == 0xE3069283,
                      "batch_roundtrip": [{"offset": g[0], "v": (g[2] or b"").decode(),
                                           "k": (g[1] or b"").decode()} for g in got],
                      "ok": ok}, ensure_ascii=False, indent=2))
    sys.exit(0 if ok else 1)
