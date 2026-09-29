#!/usr/bin/env bash
# git pre-commit 钩子 —— 提交前跑"快速门禁"（秒级），阻止把明显坏掉的代码提交进去。
#
# 为什么只跑快速门禁：全量端到端验收（make verify）约 2 分钟且会重置演示数据，
# 不适合每次提交都跑；请手动在**合并 / 推送前**执行 `make ci`。
#
# 安装：make hooks（把本脚本复制到 .git/hooks/pre-commit）。
# 临时跳过：git commit --no-verify。
set -euo pipefail
export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# 只对涉及 Python / shell 的改动做检查，无相关改动则直接放行（例如纯文档提交）
if ! git diff --cached --name-only --diff-filter=ACM | grep -qE '\.(py|sh)$'; then
  echo "[pre-commit] 本次提交无 .py/.sh 改动，跳过快速门禁。"
  exit 0
fi

echo "[pre-commit] 运行快速门禁（Python/shell 语法 + 硬编码口令扫描）…"
if ! make gate; then
  echo "" >&2
  echo "[pre-commit] ✘ 门禁未通过，已阻止提交。修复后重新提交；确需跳过用 git commit --no-verify。" >&2
  exit 1
fi
echo "[pre-commit] ✓ 快速门禁通过。"
echo "[pre-commit]   提示：合并/推送前请手动跑全量验收：make ci"
