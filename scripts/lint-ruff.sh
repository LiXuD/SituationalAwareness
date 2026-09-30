#!/usr/bin/env bash
# Python 静态检查（ruff）—— **dev 侧工具，不进交付物**。
# 未安装时跳过（不阻断本地开发），并提示安装方式；装了则按 ruff.toml 的克制规则集检查。
set -euo pipefail
export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v ruff >/dev/null 2>&1; then
  echo "· 未检测到 ruff，跳过 Python 静态检查（安装：brew install ruff 或 pip install ruff）"
  exit 0
fi

ruff check .
