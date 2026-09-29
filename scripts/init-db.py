#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
init-db.py —— 初始化平台业务数据库（建表 + 种子账号）。

用法：
    python3 scripts/init-db.py                 # 用默认路径（宿主机 data/ssp.db）
    PLATFORM_DB=sqlite:////srv/data/ssp.db python3 scripts/init-db.py   # 容器内
    PLATFORM_DB=postgresql://user:pass@host:5432/ssp python3 scripts/init-db.py

行为：
    1) 执行 services/portal/db.py 的 SCHEMA_SQL 建表（幂等）。
    2) 若 users 表为空：优先迁入 services/portal/users.json 的账号；
       否则写入 4 个默认账号（**初始口令取自 deploy/.env**：`SSP_<账号>_PASSWORD` 优先、
       回退 `SSP_DEFAULT_PASSWORD`；仓库内不保存任何可用口令，缺失即中止）。
"""
import hashlib
import json
import os
import secrets
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "services", "portal"))

# 先定 DSN，再 import db（db 在 import 时读 PLATFORM_DB）
_DEFAULT_DB = "sqlite:///" + os.path.join(ROOT, "data", "ssp.db")
os.environ.setdefault("PLATFORM_DB", _DEFAULT_DB)

import db  # noqa: E402
import _env  # noqa: E402

ITER = 200_000
DEFAULT_USERS = [
    ("admin", "技术负责人", "admin"),
    ("analyst", "安全分析师", "analyst"),
    ("asset", "资产管理员", "asset_admin"),
    ("ops", "运维值班", "ops"),
]


def _require_default_password():
    """初始口令来自环境（`SSP_DEFAULT_PASSWORD`，可被 `SSP_<ROLE>_PASSWORD` 覆盖）。

    **仓库里不保存任何可用口令**：本机值在 `deploy/.env`（已 gitignore），
    全新环境由 `make init` 自动生成随机口令（`scripts/gen-env.sh`）。
    """
    missing = _env.load(["SSP_DEFAULT_PASSWORD"])
    if missing:
        print("[init-db] 未配置初始口令，已中止（避免出现'默认口令即全部口令'）。")
        return None
    return os.environ["SSP_DEFAULT_PASSWORD"]


DEFAULT_PASSWORD = _require_default_password()

# I-13 多分支汇聚：默认分支登记（与 logs/branch-*、总部链路一致）
DEFAULT_BRANCHES = [
    # branch_id, name, site, cidr, link_type, expect_interval_seconds
    ("hq", "总部", "总部机房", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", "leased", 3600),
    ("sh-01", "上海分行", "上海", "10.9.0.0/16", "leased", 3600),
    ("bj-01", "北京分行", "北京", "10.7.0.0/16", "leased", 3600),
]


def seed_branches():
    """幂等登记默认分支（表为空时才写，避免覆盖运维既有登记）。"""
    if db.query_one("SELECT 1 AS x FROM branches LIMIT 1"):
        n = db.query_one("SELECT COUNT(*) AS n FROM branches")["n"]
        print(f"[init-db] branches 表已有 {n} 个分支，跳过种子。")
        return
    now = int(time.time())
    for bid, name, site, cidr, lt, exp in DEFAULT_BRANCHES:
        db.execute(
            "INSERT INTO branches (branch_id, name, site, cidr, link_type, enabled, "
            "expect_interval_seconds, last_seen, state, note, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (bid, name, site, cidr, lt, 1, exp, None, "unknown", "", now, now))
    print(f"[init-db] 登记默认分支 {len(DEFAULT_BRANCHES)} 个：{'/'.join(b[0] for b in DEFAULT_BRANCHES)}")


def hash_password(password, salt=None, iterations=ITER):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             bytes.fromhex(salt), iterations)
    return salt, dk.hex(), iterations


def load_users_json():
    p = os.path.join(ROOT, "services", "portal", "users.json")
    if not os.path.exists(p):
        return []
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("users", [])
    except Exception:
        return []


def main():
    print(f"[init-db] 后端={db.backend()}  DSN={os.environ['PLATFORM_DB']}")
    # 建表（幂等）
    db.init_schema()

    now = int(time.time())
    if db.query_one("SELECT 1 AS x FROM users LIMIT 1"):
        n = db.query_one("SELECT COUNT(*) AS n FROM users")["n"]
        print(f"[init-db] users 表已存在 {n} 个账号，跳过种子。")
        seed_branches()
        return 0

    rows = []
    src = load_users_json()
    if src:
        print(f"[init-db] 从 users.json 迁入 {len(src)} 个账号")
        for u in src:
            rows.append((u["username"], u.get("display", u["username"]),
                         u.get("role", "analyst"), u.get("salt", ""), u.get("hash", ""),
                         int(u.get("iterations", ITER)), "active", now, now))
    else:
        print(f"[init-db] 写入默认 {len(DEFAULT_USERS)} 个账号"
              f"（口令取自 deploy/.env：SSP_<账号>_PASSWORD 优先，回退 SSP_DEFAULT_PASSWORD；"
              f"不回显口令值）")
        for username, display, role in DEFAULT_USERS:
            salt, h, it = hash_password(_env.account_password(username))
            rows.append((username, display, role, salt, h, it, "active", now, now))

    q = db.qmark()
    for r in rows:
        db.execute(
            f"INSERT INTO users (username, display, role, salt, hash, iterations, status, created_at, updated_at) "
            f"VALUES ({q},{q},{q},{q},{q},{q},{q},{q},{q})", r)

    cnt = db.query_one("SELECT COUNT(*) AS n FROM users")["n"]
    print(f"[init-db] 完成，共 {cnt} 个账号。")
    seed_branches()
    return 0


if __name__ == "__main__":
    sys.exit(main())
