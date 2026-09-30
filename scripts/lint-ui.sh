#!/usr/bin/env bash
# 前端 JS 语法检查（ESM，零依赖：只用 node --check，不引入 npm / eslint）
#
# 为什么用 --input-type=module：ui 的脚本以 `<script type="module">` 加载（ESM），
# 而 node --check 默认按 CommonJS 解析，遇到 import/export 会误报语法错误。
# 无 node 时跳过（不阻断；ESM 语法在后端无关）。
set -euo pipefail
export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v node >/dev/null 2>&1; then
  echo "· 未检测到 node，跳过前端 JS 语法检查"
  exit 0
fi

bad=0
while IFS= read -r f; do
  if ! node --input-type=module --check < "$f" 2>/dev/null; then
    echo "  ✘ JS 语法错误：$f"
    node --input-type=module --check < "$f" 2>&1 | head -5
    bad=1
  fi
done < <(find ui -name '*.js')

[ "$bad" -eq 0 ] || exit 1
echo "✓ JS 语法检查通过（ui/**/*.js）"
