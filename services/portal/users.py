#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
users.py —— 账号管理业务逻辑（落平台业务库 users 表）。

由 portal 统一后端调用（/api/users/*），仅管理员（admin）可访问。
安全约束：
  * 不允许删除自己（避免锁死当前会话）。
  * 不允许删除或停用/降级「最后一个可用的 admin」（避免平台失去管理入口）。
"""
import hashlib
import re
import secrets
import time

import db

ROLES = ["admin", "ops", "analyst", "asset_admin"]
ROLE_LABEL = {"admin": "技术负责人", "ops": "运维值班", "analyst": "安全分析师", "asset_admin": "资产管理员"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
ITER = 200_000


def _now():
    return int(time.time())


def _iso(epoch):
    try:
        import datetime
        return datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


def _hash_password(password, salt=None, iterations=ITER):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return salt, dk.hex(), iterations


def _row_out(r):
    """对外输出（绝不含 salt/hash）。"""
    return {
        "username": r["username"],
        "display": r.get("display") or r["username"],
        "role": r.get("role") or "analyst",
        "role_label": ROLE_LABEL.get(r.get("role"), r.get("role")),
        "status": r.get("status") or "active",
        "created_at": _iso(r.get("created_at")),
        "updated_at": _iso(r.get("updated_at")),
    }


def _active_admin_count(exclude=None):
    rows = db.query("SELECT username FROM users WHERE role='admin' AND status='active'")
    return len([r for r in rows if r["username"] != exclude])


def list_users():
    rows = db.query("SELECT * FROM users ORDER BY username")
    return 200, {"total": len(rows), "users": [_row_out(r) for r in rows]}


def get_user(username):
    r = db.query_one("SELECT * FROM users WHERE username=?", (username,))
    return _row_out(r) if r else None


def create_user(body):
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    display = (body.get("display") or "").strip() or username
    role = (body.get("role") or "").strip()
    if not USERNAME_RE.match(username):
        return 422, {"ok": False, "error": "用户名非法（3-32 位字母/数字/_.-）"}
    if len(password) < 6:
        return 422, {"ok": False, "error": "密码至少 6 位"}
    if role not in ROLES:
        return 422, {"ok": False, "error": "角色非法"}
    if db.query_one("SELECT 1 AS x FROM users WHERE username=?", (username,)):
        return 409, {"ok": False, "error": "用户名已存在: %s" % username}
    salt, h, it = _hash_password(password)
    now = _now()
    db.execute(
        "INSERT INTO users (username, display, role, salt, hash, iterations, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (username, display, role, salt, h, it, "active", now, now))
    return 200, {"ok": True, "user": get_user(username)}


def update_user(username, body):
    r = db.query_one("SELECT * FROM users WHERE username=?", (username,))
    if not r:
        return 404, {"ok": False, "error": "用户不存在: %s" % username}
    sets, params = [], []

    new_role = body.get("role")
    new_status = body.get("status")
    # 保护：不允许把「最后一个可用 admin」降级或停用
    if (("role" in body and body["role"] != "admin") or ("status" in body and body["status"] != "active")) \
            and r["role"] == "admin" and r["status"] == "active" and _active_admin_count(exclude=username) == 0:
        return 409, {"ok": False, "error": "不能降级/停用最后一个管理员"}

    if "display" in body:
        sets.append("display=?")
        params.append(str(body["display"] or "").strip() or username)
    if new_role:
        if new_role not in ROLES:
            return 422, {"ok": False, "error": "角色非法"}
        sets.append("role=?")
        params.append(new_role)
    if new_status:
        if new_status not in ("active", "disabled"):
            return 422, {"ok": False, "error": "状态非法"}
        sets.append("status=?")
        params.append(new_status)
    if body.get("password"):
        if len(body["password"]) < 6:
            return 422, {"ok": False, "error": "密码至少 6 位"}
        salt, h, it = _hash_password(body["password"])
        sets += ["salt=?", "hash=?", "iterations=?"]
        params += [salt, h, it]
    if not sets:
        return 200, {"ok": True, "user": get_user(username)}
    sets.append("updated_at=?")
    params.append(_now())
    params.append(username)
    db.execute("UPDATE users SET " + ", ".join(sets) + " WHERE username=?", params)
    # 角色变更/停用/改密后，使该用户的既有会话失效（安全）
    if new_role or new_status or body.get("password"):
        db.execute("DELETE FROM sessions WHERE username=?", (username,))
    return 200, {"ok": True, "user": get_user(username)}


def delete_user(username, current_user):
    r = db.query_one("SELECT * FROM users WHERE username=?", (username,))
    if not r:
        return 404, {"ok": False, "error": "用户不存在: %s" % username}
    if username == current_user:
        return 409, {"ok": False, "error": "不能删除当前登录账号"}
    if r["role"] == "admin" and r["status"] == "active" and _active_admin_count(exclude=username) == 0:
        return 409, {"ok": False, "error": "不能删除最后一个管理员"}
    db.execute("DELETE FROM users WHERE username=?", (username,))
    db.execute("DELETE FROM sessions WHERE username=?", (username,))
    return 200, {"ok": True, "deleted": username}
