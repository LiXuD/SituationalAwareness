#!/usr/bin/env bash
# 生成本地运行时配置 deploy/.env（不入库）；已存在则不动。
#
# 用法：bash scripts/gen-env.sh [--force]     # --force 覆盖重建（会换掉口令）
#
# 为什么需要：仓库里不允许出现任何可用口令，故默认口令由本脚本**随机生成**写入
# deploy/.env（已 gitignore）。首次 `make init` 会自动调用本脚本。
set -euo pipefail

export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/deploy/.env"
EXAMPLE="$ROOT/deploy/.env.example"
FORCE="${1:-}"

if [ -f "$ENV_FILE" ] && [ "$FORCE" != "--force" ]; then
  echo "[env] deploy/.env 已存在，保持不变（如需重建：bash scripts/gen-env.sh --force）"
  exit 0
fi
[ -f "$EXAMPLE" ] || { echo "[env] 缺少 $EXAMPLE" >&2; exit 1; }

# 随机口令：24 位 URL 安全字符（不含 shell 特殊字符，可直接进 DSN / .env）
rand() { python3 -c "import secrets;print(secrets.token_urlsafe(18))"; }

ADMIN_PW="$(rand)"; OPS_PW="$(rand)"; ANALYST_PW="$(rand)"; ASSET_PW="$(rand)"
ARKIME_PW="$(rand)"; PG_PW="$(rand)"

# 以示例文件为模板逐项替换（保留注释，便于人工核对）
sed \
  -e "s|^SSP_DEFAULT_PASSWORD=.*|SSP_DEFAULT_PASSWORD=${ADMIN_PW}|" \
  -e "s|^SSP_ADMIN_PASSWORD=.*|SSP_ADMIN_PASSWORD=${ADMIN_PW}|" \
  -e "s|^SSP_OPS_PASSWORD=.*|SSP_OPS_PASSWORD=${OPS_PW}|" \
  -e "s|^SSP_ANALYST_PASSWORD=.*|SSP_ANALYST_PASSWORD=${ANALYST_PW}|" \
  -e "s|^SSP_ASSET_PASSWORD=.*|SSP_ASSET_PASSWORD=${ASSET_PW}|" \
  -e "s|^ARKIME_ADMIN_PASSWORD=.*|ARKIME_ADMIN_PASSWORD=${ARKIME_PW}|" \
  -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${PG_PW}|" \
  "$EXAMPLE" > "$ENV_FILE"
chmod 600 "$ENV_FILE"

echo "[env] 已生成 deploy/.env（0600，已 gitignore），含随机口令："
echo "       平台账号 admin/ops/analyst/asset、Arkime(${ARKIME_PW:0:4}…) 、PostgreSQL"
echo "      查看：cat deploy/.env"
