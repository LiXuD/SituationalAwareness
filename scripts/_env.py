#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
_env.py —— 宿主脚本统一加载 `deploy/.env`（**仓库内不保存任何口令**）

设计
----
* `deploy/.env.example`：可入库的模板（只有键名与说明，值留空）。
* `deploy/.env`：**本地运行时配置**，`.gitignore` 已忽略；由 `make init` 自动生成
  （`scripts/gen-env.sh` 填随机口令）或手工从示例复制填写。
* Docker Compose 也会自动读取 `deploy/.env` 做 `${VAR}` 插值（project dir = deploy/），
  所以 compose 与宿主脚本共用同一份配置。

用法（与脚本同目录，直接 import）
--------------------------------
    import _env
    _env.load(["SSP_DEFAULT_PASSWORD"])     # 缺失时打印可执行的修复指引
    pwd = _env.get("SSP_DEFAULT_PASSWORD")
    pwd = _env.account_password("admin")    # 角色级覆盖 → 回退默认口令

优先级：**已存在的环境变量 > deploy/.env > 空**（不覆盖，便于 CI/临时覆盖）。
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(ROOT, "deploy", ".env")
EXAMPLE_FILE = os.path.join(ROOT, "deploy", ".env.example")

_cache = None


def parse(path):
    out = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def load(required=None):
    """把 deploy/.env 注入 os.environ（不覆盖已有值）。返回缺失的必填键列表。"""
    global _cache
    if _cache is None:
        _cache = parse(ENV_FILE)
    for k, v in _cache.items():
        if v and not os.environ.get(k):
            os.environ[k] = v
    missing = [k for k in (required or []) if not os.environ.get(k)]
    if missing:
        print("[config] 缺少必要配置：%s" % ", ".join(missing))
        print(f"[config] 修复：`make init`（会自动生成 {os.path.relpath(ENV_FILE, ROOT)} 并填随机口令），")
        print(f"[config]       或 `cp {os.path.relpath(EXAMPLE_FILE, ROOT)} "
              f"{os.path.relpath(ENV_FILE, ROOT)}` 后手工填写。")
    return missing


def get(key, default=""):
    load()
    return os.environ.get(key) or default


def account_password(role=""):
    """平台账号口令：`SSP_<ROLE>_PASSWORD` 优先，回退 `SSP_DEFAULT_PASSWORD`。"""
    load()
    if role:
        v = os.environ.get("SSP_%s_PASSWORD" % role.upper())
        if v:
            return v
    return os.environ.get("SSP_DEFAULT_PASSWORD") or ""


def describe():
    load()
    keys = sorted(_cache or {})
    return {"env_file": os.path.relpath(ENV_FILE, ROOT),
            "env_file_exists": bool(_cache), "keys": keys}
