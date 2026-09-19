#!/usr/bin/env bash
# 确保统一检索别名 ssp-events 存在
# 新索引由 ssp-ecs 模板自动挂别名；本脚本对"历史已建索引"做幂等补齐。
set -euo pipefail

OS_HOST="${OS_HOST:-http://localhost:9200}"

echo "[*] 为 ssp-* 索引补齐别名 ssp-events ..."
curl -sS -X POST "${OS_HOST}/_aliases" \
  -H 'Content-Type: application/json' \
  --data-binary '{"actions":[{"add":{"index":"ssp-*","alias":"ssp-events"}}]}'
echo
echo "[*] 校验：curl -s ${OS_HOST}/_cat/aliases/ssp-events?v"
