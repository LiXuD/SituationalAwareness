#!/usr/bin/env bash
# I-03 关联分析 —— 触发一次关联并打印摘要
set -euo pipefail

CORR_HOST="${CORR_HOST:-http://localhost:8091}"

echo "[*] 触发关联（${CORR_HOST}/correlate）..."
curl -sS --noproxy '*' -X POST "${CORR_HOST}/correlate" \
  -H 'Content-Type: application/json' -d '{}' | python3 -m json.tool

echo
echo "[*] 当前分级告警（前 20）..."
curl -sS --noproxy '*' "${CORR_HOST}/alerts?limit=20" \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('total =',d.get('total'));
[print(f\"  [{a['ssp']['alert']['grade']}] {a['ssp']['alert']['rule_id']} {a['ssp']['alert']['rule_name']} :: {a['message']}\") for a in d.get('alerts',[])]"
