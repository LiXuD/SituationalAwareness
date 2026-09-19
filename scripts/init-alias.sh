#!/usr/bin/env bash
# 确保统一检索别名 ssp-events 只挂在"探针事件索引"上。
#
# 背景：统一检索别名 ssp-events 面向的是「归一化后的探针事件」，
# 仅包含 suricata / zeek / wazuh 三类来源。
# 【禁止】使用通配 "ssp-*" —— 那会把 ssp-asset（资产库）、ssp-alerts（分级告警）
# 等非事件索引一并挂进来，导致：
#   1) 统一检索把资产/告警当事件返回（口径污染）；
#   2) 关联分析从 ssp-events 读事件时读到自己写出的告警 → 自反馈循环。
#
# 新索引由 ssp-ecs 模板（index_patterns 已收敛为 3 个探针前缀）自动挂别名；
# 本脚本对"历史已建索引"做幂等补齐。
set -euo pipefail

OS_HOST="${OS_HOST:-http://localhost:9200}"

# 仅允许这三类探针事件索引挂 ssp-events
PATTERNS=("ssp-suricata-*" "ssp-zeek-*" "ssp-wazuh-*")

echo "[*] 为探针事件索引补齐别名 ssp-events ..."
{
  printf '{"actions":['
  first=1
  for p in "${PATTERNS[@]}"; do
    [ $first -eq 1 ] || printf ','
    first=0
    printf '{"add":{"index":"%s","alias":"ssp-events"}}' "$p"
  done
  printf ']}'
} > /tmp/.ssp-init-alias-payload.json

curl -sS -X POST "${OS_HOST}/_aliases" \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/.ssp-init-alias-payload.json
echo
echo "[*] 校验：curl -sS --noproxy '*' ${OS_HOST}/_cat/aliases/ssp-events?v"
