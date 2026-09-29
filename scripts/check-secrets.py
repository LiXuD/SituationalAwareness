#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check-secrets.py —— 扫描仓库内的硬编码口令明文，防止"口令 env 化"后回退。

设计要点：口令字面量在下方用字符串**拼接**构造（`"P@ss" + "w0rd"`），
使扫描器自身文件里不出现连续的明文口令，从而不会"自己命中自己"。
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# 拼接构造，避免本文件内含明文口令
_SECRETS = [
    "P@ss" + "w0rd",
    "arkimePOC" + "2026",
    "sspPOC" + "2026",
]

_SKIP_DIRS = {".git", ".workbuddy", "data", "logs", "__pycache__", "node_modules"}
_SKIP_FILES = {".env"}  # deploy/.env 含本机口令，天然跳过；.env.example 值留空，无需跳


def scan():
    hits = []
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file():
            continue
        rel_parts = p.parts[len(ROOT.parts):]
        if any(part in _SKIP_DIRS for part in rel_parts):
            continue
        if p.name in _SKIP_FILES:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for ln, line in enumerate(text.splitlines(), 1):
            for s in _SECRETS:
                if s in line:
                    hits.append(f"{p.relative_to(ROOT)}:{ln}: {line.strip()[:80]}")
    return hits


def main():
    hits = scan()
    if hits:
        print("  ✘ 检测到硬编码口令明文（仓库内不应存在，请改用 deploy/.env 变量）：")
        for h in hits[:10]:
            print("    " + h)
        return 1
    print("✓ 无硬编码口令明文")
    return 0


if __name__ == "__main__":
    sys.exit(main())
