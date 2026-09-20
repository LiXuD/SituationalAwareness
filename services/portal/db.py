#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
db.py —— 平台业务数据库访问层（SQLite 默认，PostgreSQL 预留）。

设计目标：
  * 业务对象（用户/会话/资产/审批/黑名单/配置/审计）统一落到平台自己的库，
    不再散落在 JSON 文件、内存字典或借用 OpenSearch 当业务库。
  * 当前用 SQLite（Python 标准库 sqlite3，零新增依赖，契合 x86 私有化零部署）。
  * 通过环境变量 PLATFORM_DB 平滑切换到 PostgreSQL：
        PLATFORM_DB=postgresql://user:pass@host:5432/ssp
    切换时仅需安装驱动（pip install psycopg[binary]），业务代码零改动。

并发模型：
  * SQLite：单连接 + 全局锁（POC 低并发下最稳，避免 Docker bind-mount 上多连接锁竞争）。
  * PostgreSQL：每次操作独立连接（独立进程，无文件锁问题）。

关键约束（保证双后端兼容）：
  * 主键一律用业务自然键（TEXT），避免 SQLite AUTOINCREMENT 与 PG SERIAL 差异。
  * 时间戳统一用 epoch 秒（INTEGER），由应用层传值，SQL 里不写方言函数。
  * 参数化占位符通过 qmark() 抽象（SQLite 用 ?，PG 用 %s）。
"""
import os
import sqlite3
import threading

_DSN = os.environ.get("PLATFORM_DB", "sqlite:////data/ssp.db")
_BACKEND = "postgresql" if _DSN.startswith(("postgres://", "postgresql://")) else "sqlite"

_lock = threading.Lock()
_sqlite_conn = None


def backend():
    return _BACKEND


def qmark():
    """当前后端的参数占位符。"""
    return "%s" if _BACKEND == "postgresql" else "?"


def _get_sqlite():
    global _sqlite_conn
    if _sqlite_conn is None:
        path = _DSN.split(":///", 1)[1] if ":///" in _DSN else _DSN
        if path != ":memory:":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        _sqlite_conn = sqlite3.connect(path, check_same_thread=False)
        _sqlite_conn.row_factory = sqlite3.Row
        _sqlite_conn.execute("PRAGMA foreign_keys=ON")
        _sqlite_conn.execute("PRAGMA busy_timeout=5000")
    return _sqlite_conn


def _get_pg():
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as e:
        raise RuntimeError(
            "PLATFORM_DB 指向 PostgreSQL，但缺少驱动。请安装：pip install 'psycopg[binary]'"
        ) from e
    return psycopg.connect(_DSN, row_factory=dict_row)


def _dict_rows(rows):
    return [dict(r) if not isinstance(r, dict) else r for r in rows]


def execute(sql, params=()):
    """执行写操作并提交，返回受影响行数。"""
    if _BACKEND == "sqlite":
        with _lock:
            c = _get_sqlite()
            cur = c.cursor()
            cur.execute(sql, params)
            c.commit()
            return cur.rowcount
    c = _get_pg()
    cur = c.cursor()
    cur.execute(sql, params)
    c.commit()
    return cur.rowcount


def query(sql, params=()):
    """查询，返回 list[dict]。"""
    if _BACKEND == "sqlite":
        with _lock:
            c = _get_sqlite()
            cur = c.cursor()
            cur.execute(sql, params)
            return _dict_rows(cur.fetchall())
    c = _get_pg()
    cur = c.cursor()
    cur.execute(sql, params)
    return _dict_rows(cur.fetchall())


def query_one(sql, params=()):
    rows = query(sql, params)
    return rows[0] if rows else None


def run_in_transaction(fn):
    """在单事务里执行 fn(cur)；成功 commit，异常 rollback 并重新抛出。

    fn 接收一个 cursor，用 cur.execute(sql, params) 写数据。
    """
    if _BACKEND == "sqlite":
        with _lock:
            c = _get_sqlite()
            try:
                fn(c.cursor())
                c.commit()
            except Exception:
                c.rollback()
                raise
        return
    c = _get_pg()
    try:
        fn(c.cursor())
        c.commit()
    except Exception:
        c.rollback()
        raise


def init_schema():
    """建表（幂等）。"""
    if _BACKEND == "sqlite":
        with _lock:
            c = _get_sqlite()
            c.executescript(SCHEMA_SQL)
            c.commit()
        return
    c = _get_pg()
    cur = c.cursor()
    for stmt in [s for s in SCHEMA_SQL.split(";") if s.strip()]:
        cur.execute(stmt)
    c.commit()


def close():
    global _sqlite_conn
    if _sqlite_conn is not None:
        try:
            _sqlite_conn.close()
        except Exception:
            pass
        _sqlite_conn = None


# --------------------------------------------------------------------------- #
# Schema（标准 SQL，双后端兼容；主键用业务自然键，时间用 epoch 秒）
# --------------------------------------------------------------------------- #
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    display       TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL DEFAULT 'analyst',
    salt          TEXT NOT NULL,
    hash          TEXT NOT NULL,
    iterations    INTEGER NOT NULL DEFAULT 200000,
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token         TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    role          TEXT NOT NULL,
    display       TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    ip            TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id      TEXT PRIMARY KEY,
    name          TEXT NOT NULL DEFAULT '',
    ip            TEXT NOT NULL DEFAULT '',
    asset_type    TEXT NOT NULL DEFAULT '',
    importance    TEXT NOT NULL DEFAULT '一般',
    importance_score INTEGER NOT NULL DEFAULT 1,
    risk_score    INTEGER NOT NULL DEFAULT 0,
    owner         TEXT NOT NULL DEFAULT '',
    department    TEXT NOT NULL DEFAULT '',
    location      TEXT NOT NULL DEFAULT '',
    os            TEXT NOT NULL DEFAULT '',
    tags          TEXT NOT NULL DEFAULT '[]',
    description   TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT 'manual',
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS soar_drafts (
    id            TEXT PRIMARY KEY,
    alert_id      TEXT NOT NULL DEFAULT '',
    entity        TEXT NOT NULL DEFAULT '',
    entity_type   TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL DEFAULT 'block',
    grade         TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'pending_approval',
    reason        TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    approver      TEXT NOT NULL DEFAULT '',
    decided_at    INTEGER,
    fail_reason   TEXT NOT NULL DEFAULT '',
    payload       TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS blacklist (
    entity        TEXT PRIMARY KEY,
    entity_type   TEXT NOT NULL DEFAULT 'ip',
    action        TEXT NOT NULL DEFAULT 'block',
    reason        TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS config (
    key           TEXT PRIMARY KEY,
    value         TEXT NOT NULL DEFAULT '',
    updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL,
    target        TEXT NOT NULL DEFAULT '',
    detail        TEXT NOT NULL DEFAULT '',
    ip            TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
CREATE INDEX IF NOT EXISTS idx_drafts_status ON soar_drafts(status);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
"""
