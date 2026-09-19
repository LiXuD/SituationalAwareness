#!/usr/bin/env bash
# 统一检索 CLI：跨 Suricata / Zeek / Wazuh 归一事件（别名 ssp-events）
# 用法：./scripts/search.sh "evil-c2"           # 关键字（默认 *）
#       SIP=203.0.113.45 ./scripts/search.sh    # 追加源 IP 过滤
#       DIP=8.8.8.8 ./scripts/search.sh "dns"   # 追加目的 IP 过滤
set -euo pipefail

OS_HOST="${OS_HOST:-http://localhost:9200}"
Q="${1:-*}"
SIZE="${SIZE:-20}"

filters=""
if [[ -n "${SIP:-}" ]]; then
  filters="${filters}{\"term\":{\"source.ip\":\"${SIP}\"}},"
fi
if [[ -n "${DIP:-}" ]]; then
  filters="${filters}{\"term\":{\"destination.ip\":\"${DIP}\"}},"
fi
filters="${filters%,}"   # 无过滤时留空 → 生成 "filter": []

curl -sS "${OS_HOST}/ssp-events/_search?pretty" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<JSON
{
  "size": ${SIZE},
  "sort": [{"@timestamp": "desc"}],
  "query": { "bool": { "must": [{"query_string": {"query": "${Q}"}}], "filter": [${filters}] } },
  "_source": ["@timestamp","event.module","event.kind","event.category","source.ip","destination.ip","rule.name","rule.description","url.full","dns.question.name"]
}
JSON
