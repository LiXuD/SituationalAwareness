#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen-portal-user.py —— 生成/维护平台账号（PBKDF2-HMAC-SHA256，纯标准库）。

角色（对齐 PRD §11）：
    analyst      分析师      查看 / 研判 / 下钻
    ops          运维        审批并提交拉黑
    asset_admin  资产管理员  资产增删改 / Excel 导入
    admin        技术负责人  平台配置（全部权限）

用法：
    # 打印一条 JSON（自行粘到 services/portal/users.json）
    python3 scripts/gen-portal-user.py analyst 'REDACTED-SSP-PWD' analyst '分析师A'

    # 直接写入/更新 users.json
    python3 scripts/gen-portal-user.py ops 'REDACTED-SSP-PWD' ops '运维B' --write
"""
import argparse
import datetime
import hashlib
import hmac
import json
import os
import secrets
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS = os.path.join(ROOT, "services", "portal", "users.json")
ROLES = ["analyst", "ops", "asset_admin", "admin"]
ITERATIONS = 200_000


def hash_password(password, salt=None, iterations=ITERATIONS):
    """返回 (salt_hex, hash_hex, iterations)。"""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return salt, dk.hex(), iterations


def entry(username, password, role, display=None):
    salt, h, it = hash_password(password)
    return {"username": username, "display": display or username, "role": role,
            "salt": salt, "hash": h, "iterations": it,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("username")
    ap.add_argument("password")
    ap.add_argument("role", choices=ROLES)
    ap.add_argument("display", nargs="?", default=None)
    ap.add_argument("--write", action="store_true", help="直接写入 services/portal/users.json")
    a = ap.parse_args()

    e = entry(a.username, a.password, a.role, a.display)
    if not a.write:
        print(json.dumps(e, ensure_ascii=False, indent=2))
        return 0

    db = {"users": []}
    if os.path.exists(USERS):
        with open(USERS, encoding="utf-8") as f:
            db = json.load(f)
        db.setdefault("users", [])
    db["users"] = [u for u in db["users"] if u.get("username") != a.username] + [e]
    db["users"].sort(key=lambda u: u.get("username", ""))
    os.makedirs(os.path.dirname(USERS), exist_ok=True)
    with open(USERS, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"[gen-portal-user] 已写入 {os.path.relpath(USERS, ROOT)}：{a.username} ({a.role})，共 {len(db['users'])} 个账号")
    return 0


if __name__ == "__main__":
    sys.exit(main())
