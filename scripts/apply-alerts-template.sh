#!/usr/bin/env bash
# 下发/更新 I-03 分级告警索引模板 ssp-alerts 到 OpenSearch
#
# I-14 补充：模板（mappings.dynamic=false）只对**新建索引**生效；对已存在的 ssp-alerts
# 索引，新字段（ssp.alert.engines / first_engine / last_engine / stream_latency_ms）
# 会被静默丢弃。因此这里额外对既有索引做一次**幂等** `_mapping` 增补，
# 避免"先建索引、后升模板"顺序导致字段丢失（本项目的经典坑）。
set -euo pipefail

OS_HOST="${OS_HOST:-http://localhost:9200}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/../config/opensearch/ssp-alerts-template.json"

echo "[*] 下发索引模板 ssp-alerts 到 ${OS_HOST} ..."
curl -sS --noproxy '*' -X PUT "${OS_HOST}/_index_template/ssp-alerts" \
  -H 'Content-Type: application/json' \
  --data-binary "@${TEMPLATE}"
echo

# 既有 ssp-alerts 索引：补 mapping（幂等；索引不存在时忽略）
EXISTS=$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' -I "${OS_HOST}/ssp-alerts" || echo 000)
if [ "${EXISTS}" = "200" ]; then
  echo "[*] 既有 ssp-alerts 索引存在 → 幂等增补 I-14 新增字段 mapping ..."
  python3 - "$TEMPLATE" <<'PY' > /tmp/.ssp-alerts-mapping-patch.json
import json, sys
tpl = json.load(open(sys.argv[1], encoding="utf-8"))
props = tpl["template"]["mappings"]["properties"]["ssp"]["properties"]["alert"]["properties"]
patch = {k: props[k] for k in ("engines", "first_engine", "last_engine", "stream_latency_ms")
         if k in props}
print(json.dumps({"properties": {"ssp": {"properties": {"alert": {"properties": patch}}}}},
                 ensure_ascii=False))
PY
  curl -sS --noproxy '*' -X PUT "${OS_HOST}/ssp-alerts/_mapping" \
    -H 'Content-Type: application/json' \
    --data-binary @/tmp/.ssp-alerts-mapping-patch.json
  echo
else
  echo "[*] 既有 ssp-alerts 索引不存在（HTTP ${EXISTS}），跳过 mapping 增补"
fi

echo "[*] 完成。校验：curl -sS --noproxy '*' ${OS_HOST}/_index_template/ssp-alerts"
