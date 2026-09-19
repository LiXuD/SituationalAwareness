#!/usr/bin/env bash
# 校验四类探针事件是否已按 ECS 归一入湖（I-01 验收辅助）
set -euo pipefail

OS_HOST="${OS_HOST:-http://localhost:9200}"
WAIT="${WAIT:-20}"

echo "[*] 等待 ${WAIT}s 让 Logstash 管道消化样本数据 ..."
sleep "${WAIT}"

echo "== 索引列表 =="
curl -sS "${OS_HOST}/_cat/indices/ssp-*?v" || true
echo

echo "== 各来源文档数 =="
for s in suricata zeek wazuh; do
  cnt="$(curl -sS "${OS_HOST}/ssp-${s}-*/_count" 2>/dev/null | sed -n 's/.*"count":\([0-9]*\).*/\1/p')"
  printf "  ssp-%-9s : %s\n" "${s}" "${cnt:-0}"
done
echo

echo "== 抽样：跨源统一字段 =="
curl -sS "${OS_HOST}/ssp-*/_search?size=1&pretty" \
  -H 'Content-Type: application/json' \
  -d '{"_source":["@timestamp","event.module","event.kind","event.category","source.ip","destination.ip","rule.name"]}' || true
