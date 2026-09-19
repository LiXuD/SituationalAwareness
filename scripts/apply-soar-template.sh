#!/usr/bin/env bash
# 下发/更新 I-05 拉黑草稿索引模板 ssp-soar-drafts 到 OpenSearch
set -euo pipefail

OS_HOST="${OS_HOST:-http://localhost:9200}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/../config/opensearch/ssp-soar-drafts-template.json"

echo "[*] 下发索引模板 ssp-soar-drafts 到 ${OS_HOST} ..."
curl -sS --noproxy '*' -X PUT "${OS_HOST}/_index_template/ssp-soar-drafts" \
  -H 'Content-Type: application/json' \
  --data-binary "@${TEMPLATE}"
echo
echo "[*] 完成。校验：curl -sS --noproxy '*' ${OS_HOST}/_index_template/ssp-soar-drafts"
