#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DB 版本化迁移框架单元测试（SQLite 后端，临时库）。

覆盖三条关键路径：
  1. 全新库 → 建表 + 应用全部迁移 + 记录到 schema_migrations；
  2. 重复 init → 幂等，无新迁移；
  3. "迁移引入前"的旧库 → 安全补跑迁移（幂等补列）并记录。
"""
import importlib
import os
import sqlite3
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "services", "portal"))

EXTRA_COLS = ("first_seen", "last_seen", "discovered_by", "endpoints")


def _load_db(dbpath):
    """以指定 SQLite 路径重新加载 db 模块（其 DSN 在 import 时读取）。"""
    os.environ["PLATFORM_DB"] = "sqlite:///" + dbpath
    sys.modules.pop("db", None)
    return importlib.import_module("db")


class TestDbMigrations(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dbpath = os.path.join(self.tmp.name, "t.db")

    def tearDown(self):
        m = sys.modules.get("db")
        if m is not None:
            try:
                m.close()
            except Exception:
                pass
        sys.modules.pop("db", None)
        os.environ.pop("PLATFORM_DB", None)
        self.tmp.cleanup()

    @staticmethod
    def _cols(db, table):
        cur = db._get_sqlite().cursor()
        cur.execute("PRAGMA table_info(%s)" % table)
        return {r[1] for r in cur.fetchall()}

    def test_fresh_db_applies_and_records(self):
        db = _load_db(self.dbpath)
        applied = db.init_schema()
        self.assertEqual(applied, [1])                     # 全新库应用迁移 1
        cols = self._cols(db, "assets")
        for c in EXTRA_COLS:
            self.assertIn(c, cols)

    def test_rerun_is_idempotent(self):
        db = _load_db(self.dbpath)
        db.init_schema()
        self.assertEqual(db.init_schema(), [])             # 第二次无新迁移

    def test_legacy_db_is_upgraded(self):
        # 造一个"迁移引入前"的旧库：assets 缺列，且没有 schema_migrations 表
        raw = sqlite3.connect(self.dbpath)
        raw.execute("CREATE TABLE assets ("
                    " asset_id TEXT PRIMARY KEY,"
                    " name TEXT NOT NULL DEFAULT '',"
                    " ip TEXT NOT NULL DEFAULT '')")
        raw.commit()
        raw.close()

        db = _load_db(self.dbpath)
        applied = db.init_schema()
        self.assertIn(1, applied)                          # 旧库补跑迁移
        cols = self._cols(db, "assets")
        for c in EXTRA_COLS:
            self.assertIn(c, cols)                         # 缺失列已补齐
        self.assertIn("asset_id", cols)                    # 存量数据列仍在


if __name__ == "__main__":
    unittest.main()
