#!/usr/env bash
# 下发/更新 资产库 索引模板到 OpenSearch（I-06 统一资产库）
set -euo pipefail

OS_HOST="${OS_HOST:-http://localhost:9200}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/../config/opensearch/ssp-asset-template.json"

echo "[*] 下发资产索引模板 ssp-asset 到 ${OS_HOST} ..."
curl -sS -X PUT "${OS_HOST}/_index_template/ssp-asset" \
  -H 'Content-Type: application/json' \
  --data-binary "@${TEMPLATE}"
echo
echo "[*] 完成。校验：curl -s ${OS_HOST}/_index_template/ssp-asset"
echo "[*] 资产检索别名：ssp-assets（curl -s ${OS_HOST}/ssp-assets/_search?size=0）"
