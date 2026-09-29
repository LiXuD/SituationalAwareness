#!/usr/bin/env bash
# I-07 / I-08 演示数据回放 & 复位脚本
#
# 演示数据集（logs/demo/，真实公网 IP、可地理定位）平时**不被采集**；
# 本脚本把它复制进暂存区 logs/demo-stage/ 后强制重建 filebeat，使其被重新读取并入库。
#
# 用法：
#   ./scripts/replay-demo.sh            # 回放演示数据（基础样本 + 演示样本）
#   ./scripts/replay-demo.sh --reset    # 复位：只保留基础样本（logs/ 下的原始探针日志）
#
# 为什么先删探针索引：filebeat 的读取位点在容器可写层，--force-recreate 会重置位点并
# 从头重放被监听的路径。若不先删索引，重放会产生重复文档。因此"重放"= 删索引 + 重建。
#
# 注意：本脚本只重建 filebeat（不动其它容器），符合项目的并行开发纪律。
set -euo pipefail

export PATH="/usr/local/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="$ROOT/deploy/compose.yml"
OS="http://localhost:9200"
CORRELATOR="http://localhost:8091"
CURL=(curl -sS --noproxy '*')

MODE="replay"
[ "${1:-}" = "--reset" ] && MODE="reset"

say() { printf '\033[1;36m[demo]\033[0m %s\n' "$*"; }

search_count() {
  "${CURL[@]}" "$OS/$1/_count" 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0
}

# --- 1. 清理旧的演示文档与派生告警 -------------------------------------------
say "清理探针索引（重建以消除重放重复）与告警/草稿..."
for idx in "ssp-suricata-*" "ssp-zeek-*" "ssp-wazuh-*" "ssp-alerts"; do
  "${CURL[@]}" -X DELETE "$OS/$idx" >/dev/null 2>&1 || true
done

# --- 2. 暂存区准备 -------------------------------------------------------------
STAGE="$ROOT/logs/demo-stage"
if [ "$MODE" = "replay" ]; then
  say "暂存演示数据集 logs/demo/ -> logs/demo-stage/ ..."
  for s in suricata zeek wazuh; do
    mkdir -p "$STAGE/$s"
    case "$s" in
      suricata|wazuh) cp -f "$ROOT/logs/demo/$s"/*.json "$STAGE/$s"/ 2>/dev/null || true ;;
      zeek)           cp -f "$ROOT/logs/demo/$s"/*.log  "$STAGE/$s"/ 2>/dev/null || true ;;
    esac
  done
else
  say "复位：清空暂存区（仅保留基础样本）..."
  rm -f "$STAGE"/suricata/*.json "$STAGE"/zeek/*.log "$STAGE"/wazuh/*.json 2>/dev/null || true
fi

# --- 3. 重建采集端触发重放 -----------------------------------------------------
# 总部 filebeat 与各分支边缘代理都重建：filestream 的读取位点在容器可写层，
# 重建即重置位点、从头重放被监听路径（否则删索引后分支数据不会回填）。
say "强制重建 filebeat 与分支边缘代理（重置读取位点）..."
docker compose -f "$COMPOSE" up -d --force-recreate filebeat filebeat-branch-sh filebeat-branch-bj >/dev/null

# --- 4. 等待入库 ---------------------------------------------------------------
BASE=9
BRANCH=12                                          # sh-01 6 条 + bj-01 6 条（I-13 分支数据）
EXPECT=$BASE
[ "$MODE" = "replay" ] && EXPECT=$((BASE + 15 + BRANCH))   # 演示集 15 条
say "等待事件入库（期望 ≈ ${EXPECT} 条，最多 60s）..."
for i in $(seq 1 30); do
  n="$(search_count "ssp-events")"
  if [ "${n:-0}" -ge "$EXPECT" ]; then break; fi
  sleep 2
done
n="$(search_count "ssp-events")"
say "当前 ssp-events 事件数：$n"

# --- 5. 触发关联 ---------------------------------------------------------------
say "触发关联引擎..."
"${CURL[@]}" -X POST "$CORRELATOR/correlate" -H 'Content-Type: application/json' -d '{}' \
  | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    w=d.get('window',{})
    print(f\"  窗口 {w.get('start')} ~ {w.get('end')} ({w.get('mode')})\")
    print(f\"  扫描事件 {d.get('events_scanned')}  地理富化外网 IP {d.get('external_ips_geolocated')}\")
    print(f\"  规则命中 {d.get('rule_hits')}\")
    print(f\"  告警写入 {d.get('write')}\")
except Exception as e:
    print('  关联调用失败:', e)
"

# --- 6. 汇总 -------------------------------------------------------------------
say "告警分级分布："
"${CURL[@]}" "$OS/ssp-alerts/_search?size=0" -H 'Content-Type: application/json' \
  -d '{"aggs":{"g":{"terms":{"field":"ssp.alert.grade"}}}}' 2>/dev/null \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
tot=d['hits']['total']['value']
print(f'  合计 {tot} 条')
for b in d.get('aggregations',{}).get('g',{}).get('buckets',[]):
    print(f\"  {b['key']}: {b['doc_count']}\")
" 2>/dev/null || true

say "完成。态势大屏： http://localhost:8088/dashboard.html"
