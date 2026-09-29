#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ssp_kernel 纯逻辑单元测试（IP 判定 / 分级升级 / 时间解析 / 窗口解析 / 告警幂等 id）。

只测纯函数，不碰 OpenSearch / 网络。共享关联内核是批式与流式两引擎的心脏，
这里把最核心、最容易写错的部分固化下来。
"""
import datetime
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "services", "common"))

import ssp_kernel as K  # noqa: E402


class TestExternalIp(unittest.TestCase):
    def test_is_external(self):
        self.assertTrue(K.is_external("8.8.8.8"))
        self.assertTrue(K.is_external("203.0.113.66"))
        self.assertFalse(K.is_external("10.0.0.1"))
        self.assertFalse(K.is_external("192.168.1.1"))
        self.assertFalse(K.is_external("172.16.0.5"))
        self.assertFalse(K.is_external("127.0.0.1"))
        self.assertFalse(K.is_external(None))
        self.assertFalse(K.is_external("not-an-ip"))

    def test_is_benign(self):
        self.assertTrue(K.is_benign_external("8.8.8.8"))
        self.assertFalse(K.is_benign_external("203.0.113.66"))


class TestGradeEscalation(unittest.TestCase):
    def test_escalate(self):
        self.assertEqual(K.escalate("P0"), "P0")  # 已最高，不越界
        self.assertEqual(K.escalate("P1"), "P0")
        self.assertEqual(K.escalate("P2"), "P1")
        self.assertEqual(K.escalate("P3"), "P2")
        self.assertEqual(K.escalate("P3", 2), "P1")


class TestParseTs(unittest.TestCase):
    def test_iso_z(self):
        dt = K.parse_ts("2026-09-19T03:21:10.001Z")
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 9)
        self.assertEqual(dt.utcoffset(), datetime.timedelta(0))

    def test_naive_becomes_utc(self):
        dt = K.parse_ts("2026-09-19T03:21:10")
        self.assertEqual(dt.utcoffset(), datetime.timedelta(0))

    def test_empty(self):
        self.assertIsNone(K.parse_ts(""))
        self.assertIsNone(K.parse_ts(None))


class TestResolveWindow(unittest.TestCase):
    def test_explicit_anchor(self):
        anchor = "2026-09-19T03:21:10.001Z"
        start, end, mode = K.resolve_window(30, anchor_iso=anchor)
        self.assertEqual(mode, "explicit")
        self.assertEqual((end - start).total_seconds(), 30 * 60)
        self.assertEqual(end, K.parse_ts(anchor))


class TestAlertDocId(unittest.TestCase):
    def test_deterministic_and_unique(self):
        a = K.alert_doc_id("R-006", "1.2.3.4|5.6.7.8|2010935")
        b = K.alert_doc_id("R-006", "1.2.3.4|5.6.7.8|2010935")
        c = K.alert_doc_id("R-006", "9.9.9.9|5.6.7.8|2010935")
        self.assertEqual(a, b)          # 同一实体幂等
        self.assertNotEqual(a, c)       # 不同实体不冲突
        self.assertEqual(len(a), 24)    # sha1[:24]
        self.assertTrue(all(ch in "0123456789abcdef" for ch in a))


if __name__ == "__main__":
    unittest.main()
