#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kafka_lite 纯逻辑单元测试（CRC32C / zigzag varint / record batch v2 编解码 / 位点落盘）。

只测纯函数，不碰网络。覆盖自研 Kafka 客户端最易出错的字节级部分。
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "services", "common"))

import kafka_lite as K  # noqa: E402


class TestCRC32C(unittest.TestCase):
    def test_known_vector(self):
        # CRC-32C（Castagnoli）标准校验向量
        self.assertEqual(K.crc32c(b"123456789"), 0xE3069283)

    def test_empty(self):
        self.assertEqual(K.crc32c(b""), 0)

    def test_not_zlib_crc32(self):
        # 强调是 CRC32C，不是 zlib 的 CRC32
        import zlib
        self.assertNotEqual(K.crc32c(b"123456789"), zlib.crc32(b"123456789") & 0xFFFFFFFF)


class TestZigzagVarint(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(K._varint(0), b"\x00")
        self.assertEqual(K._varint(-1), b"\x01")
        self.assertEqual(K._varint(1), b"\x02")
        self.assertEqual(K._varint(300), b"\xd8\x04")
        self.assertEqual(K._varint(64), b"\x80\x01")


class TestRecordBatch(unittest.TestCase):
    def test_roundtrip(self):
        records = [(b"k1", b"v1", 1000), (None, b"v2", 1001), (b"k3", None, 1002)]
        buf = K.encode_record_batch(records, base_timestamp_ms=1000)
        got = K.decode_record_batches(buf, verify_crc=True)
        self.assertEqual(len(got), 3)
        self.assertEqual(got[0], (0, b"k1", b"v1", 1000))
        self.assertEqual(got[1], (1, None, b"v2", 1001))
        self.assertEqual(got[2], (2, b"k3", None, 1002))

    def test_crc_corruption_detected(self):
        buf = bytearray(K.encode_record_batch([(b"a", b"b", 1)], base_timestamp_ms=1))
        buf[30] ^= 0xFF  # 篡改记录区一个字节
        with self.assertRaises(K.KafkaError):
            K.decode_record_batches(bytes(buf), verify_crc=True)

    def test_empty_records(self):
        self.assertEqual(K.encode_record_batch([]), b"")


class TestFileOffsetStore(unittest.TestCase):
    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "offsets.json")
            s = K.FileOffsetStore(path)
            self.assertIsNone(s.get("g1", "t", 0))
            s.set("g1", "t", 0, 42)
            s.set("g2", "t", 0, 7)
            s.save()
            # 重新从磁盘加载（模拟进程重启）
            s2 = K.FileOffsetStore(path)
            self.assertEqual(s2.get("g1", "t", 0), 42)
            self.assertEqual(s2.get("g2", "t", 0), 7)
            self.assertEqual(s2.group_offsets("g1"), {"t:0": 42})


if __name__ == "__main__":
    unittest.main()
