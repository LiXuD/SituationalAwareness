#!/usr/bin/env bash
# 下发/更新 ECS 索引模板到 OpenSearch
set -euo pipefail

OS_HOST="${OS_HOST:-http://localhost:9200}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/../config/opensearch/ssp-ecs-template.json"

echo "[*] 下发索引模板 ssp-ecs 到 ${OS_HOST} ..."
curl -sS --noproxy '*' -X PUT "${OS_HOST}/_index_template/ssp-ecs" \
  -H 'Content-Type: application/json' \
  --data-binary "@${TEMPLATE}"
echo
echo "[*] 完成。校验：curl -s ${OS_HOST}/_index_template/ssp-ecs"
