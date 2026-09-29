#!/usr/bin/env bash
# I-13 多分支汇聚 —— 分支数据投放 / 断链模拟 / 状态查看
#
# 用法：
#   bash scripts/replay-branch.sh                 # 重建各分支边缘代理（重新采集分支数据）
#   bash scripts/replay-branch.sh --down sh-01    # 模拟"上海分支专线断"：停代理 + 清该分支事件
#   bash scripts/replay-branch.sh --up sh-01      # 恢复该分支：重建代理（重新采集）
#   bash scripts/replay-branch.sh --status        # 触发一次汇聚探测并打印各分支状态
#
# 说明：分支身份靠事件里的 ssp.branch 区分（Filebeat fields.branch → Logstash）。
#       --down 会同时删除该分支已入湖事件，使健康判定立刻转为 no_data，
#       从而演示"某分支断链不影响其他分支"（其他分支事件量保持不变）。
set -euo pipefail

export PATH="/usr/local/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="$ROOT/deploy/compose.yml"
OS="http://localhost:9200"
PORTAL="http://localhost:8093"
CURL=(curl -sS --noproxy '*')

say() { printf '\033[1;36m[branch]\033[0m %s\n' "$*"; }

svc_of() {
  case "$1" in
    hq)   echo "filebeat" ;;
    sh-01) echo "filebeat-branch-sh" ;;
    bj-01) echo "filebeat-branch-bj" ;;
    *) echo "" ;;
  esac
}

probe() {
  say "触发一次汇聚探测…"
  "${CURL[@]}" -X POST "$PORTAL/api/branches/probe" -H 'Content-Type: application/json' \
    -H "Cookie: ssp_session=${SSP_SESSION:-}" >/dev/null 2>&1 || true
}

status() {
  say "当前各分支状态（经 portal /api/branches）："
  "${CURL[@]}" "$OS/ssp-events/_search" -H 'Content-Type: application/json' \
    -d '{"size":0,"aggs":{"b":{"terms":{"field":"ssp.branch"},"aggs":{"last":{"max":{"field":"@timestamp"}}}}}}' \
    | python3 -c "
import sys,json
d=json.load(sys.stdin)
bs=d.get('aggregations',{}).get('b',{}).get('buckets',[])
print('  事件总数:', d['hits']['total']['value'])
for b in bs:
    print(f\"  {b['key']:<8} 事件 {b['doc_count']:<4} 最新 {b['last'].get('value_as_string','-')}\")
" 2>/dev/null || true
}

MODE="replay"; BRANCH=""
while [ $# -gt 0 ]; do
  case "$1" in
    --down) MODE="down"; BRANCH="${2:-}"; shift 2 ;;
    --up)   MODE="up";   BRANCH="${2:-}"; shift 2 ;;
    --status) MODE="status"; shift ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
done

case "$MODE" in
  status)
    status
    ;;

  down)
    [ -n "$BRANCH" ] || { echo "--down 需指定分支，如 --down sh-01" >&2; exit 2; }
    SVC="$(svc_of "$BRANCH")"
    [ -n "$SVC" ] || { echo "未知分支：$BRANCH（可用 hq / sh-01 / bj-01）" >&2; exit 2; }
    say "模拟分支断链：停用 $BRANCH（服务 $SVC）…"
    docker compose -f "$COMPOSE" stop "$SVC" >/dev/null 2>&1 || true
    say "删除该分支已入湖事件（使健康判定立刻转 no_data）…"
    "${CURL[@]}" -X POST "$OS/ssp-events/_delete_by_query?refresh=true" \
      -H 'Content-Type: application/json' \
      -d "{\"query\":{\"term\":{\"ssp.branch\":\"$BRANCH\"}}}" >/dev/null 2>&1 || true
    say "完成。现在 $BRANCH 应判为 no_data，其他分支不受影响。"
    status
    ;;

  up)
    [ -n "$BRANCH" ] || { echo "--up 需指定分支，如 --up sh-01" >&2; exit 2; }
    SVC="$(svc_of "$BRANCH")"
    [ -n "$SVC" ] || { echo "未知分支：$BRANCH" >&2; exit 2; }
    say "恢复分支 $BRANCH（重建 $SVC，重新采集分支数据）…"
    docker compose -f "$COMPOSE" up -d --force-recreate "$SVC" >/dev/null
    sleep 6
    status
    ;;

  replay)
    say "重建各分支边缘代理（重置读取位点 → 重新采集分支数据）…"
    docker compose -f "$COMPOSE" up -d --force-recreate \
      filebeat filebeat-branch-sh filebeat-branch-bj >/dev/null
    sleep 8
    status
    ;;
esac

say "提示：状态页 http://localhost:8088/#/branches （admin 可登记/探测）"
