#!/usr/bin/env bash
# 确保统一检索别名 ssp-events 只挂在"归一化后的事件索引"上。
#
# 统一检索别名 ssp-events 面向的是「归一化后的事件」，包含：
#   探针源   suricata / zeek / wazuh
#   外部源   firewall / waf / ids / proxy（I-14 L2：经适配器 → Kafka → Logstash 归一入库）
# 【禁止】使用通配 "ssp-*" —— 那会把 ssp-asset（资产库）、ssp-alerts（分级告警）
# 等非事件索引一并挂进来，导致：
#   1) 统一检索把资产/告警当事件返回（口径污染）；
#   2) 关联分析从 ssp-events 读事件时读到自己写出的告警 → 自反馈循环。
#
# 新索引由 ssp-ecs 模板（index_patterns 与本文件的 PATTERNS 保持一致）自动挂别名；
# 本脚本对"历史已建索引"做幂等补齐。
set -euo pipefail

OS_HOST="${OS_HOST:-http://localhost:9200}"

# 仅允许这些事件索引挂 ssp-events（与 config/opensearch/ssp-ecs-template.json 的
# index_patterns 一一对应；新增源类型时两边同改）
PATTERNS=("ssp-suricata-*" "ssp-zeek-*" "ssp-wazuh-*"
          "ssp-firewall-*" "ssp-waf-*" "ssp-ids-*" "ssp-proxy-*")

echo "[*] 为归一化事件索引补齐别名 ssp-events ..."
# 注意：_aliases 的 add 动作不支持"通配模式"本身（索引必须已存在），
# 因此先用 _cat/indices 取实际索引名，再按 PATTERNS 展开匹配
# （新索引由 ssp-ecs 模板自动挂别名，本步只兜底历史索引）。
curl -sS --noproxy '*' "${OS_HOST}/_cat/indices?h=index&format=json" \
  | python3 -c '
import fnmatch, json, sys
pats = sys.argv[1:]
try:
    idx = [i["index"] for i in json.load(sys.stdin)]
except Exception:
    idx = []
hit = sorted({i for i in idx for p in pats if fnmatch.fnmatch(i, p)})
if not hit:
    print("NONE")
else:
    print(json.dumps({"actions": [{"add": {"index": i, "alias": "ssp-events"}} for i in hit]}))
' "${PATTERNS[@]}" > /tmp/.ssp-init-alias-payload.json

if [ "$(cat /tmp/.ssp-init-alias-payload.json)" = "NONE" ]; then
  echo "[*] 无匹配的历史事件索引，跳过（新索引由 ssp-ecs 模板自动挂别名）"
else
  curl -sS -X POST "${OS_HOST}/_aliases" \
    -H 'Content-Type: application/json' \
    --data-binary @/tmp/.ssp-init-alias-payload.json
  echo
fi
echo "[*] 校验：curl -sS --noproxy '*' ${OS_HOST}/_cat/aliases/ssp-events?v"
