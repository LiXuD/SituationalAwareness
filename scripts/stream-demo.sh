#!/usr/bin/env bash
# I-14 流式关联 —— 状态查看 / 端到端演示 / 时延实测
#
# 用法：
#   bash scripts/stream-demo.sh --status     # 只看流式引擎状态（消费速率/位点滞后/时延）
#   bash scripts/stream-demo.sh             # 回放演示数据 → 观察秒级告警 + 时延实测
#   bash scripts/stream-demo.sh --probe      # 直接投递一条"新告警"到 Kafka，实测端到端时延
#
# 说明：流式引擎消费 Kafka `ssp-ecs`（Logstash 归一后的事件流，见 99-outputs.conf），
#       在内存滑动窗口内执行与批式**同一份**规则（services/common/ssp_kernel.py），
#       幂等写入 ssp-alerts（_id 与批式完全相同）→ 与批式共存不重复计数。
set -euo pipefail

export PATH="/usr/local/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="$ROOT/deploy/compose.yml"
OS="http://localhost:9200"
STREAM="http://localhost:8094"
CURL=(curl -sS --noproxy '*')

say() { printf '\033[1;36m[stream]\033[0m %s\n' "$*"; }

status() {
  say "流式关联引擎状态（$STREAM/stats）："
  "${CURL[@]}" "$STREAM/stats" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
except Exception as e:
    print('  引擎未就绪:', e); sys.exit(0)
print(f\"  引擎={d.get('engine')} 主题={d.get('topic')} group={d.get('group')} 启动模式={d.get('bootstrap_mode')}\")
print(f\"  已消费={d.get('consumed_total')} 条  评估={d.get('evals_total')} 次  窗口事件={d.get('events_in_window')}（窗口 {d.get('window_seconds')}s）\")
print(f\"  告警 新增={d.get('alerts_created_total')} 更新={d.get('alerts_updated_total')}\")
print(f\"  时延(ms) 最近={d['latency_ms'].get('last')} p50={d['latency_ms'].get('p50')} 最大={d['latency_ms'].get('max')}\")
print(f\"  位点={d.get('positions')}\")
print(f\"  滞后={d.get('lag')}\")
"
}

probe() {
  # 直接向 ssp-ecs 投递一条归一后的 ECS 事件（等价于 Logstash 的输出），
  # 用于把"事件进入 Kafka → 告警落库"的时延与采集侧抖动解耦后**单独实测**。
  local ip="${1:-203.0.113.66}"
  local ts; ts="$(python3 -c 'import datetime;print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"Z")')"
  local sid=$((2000000 + RANDOM))
  local doc
  doc=$(python3 - "$ip" "$ts" "$sid" <<'PY'
import json, sys
ip, ts, sid = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({
  "@timestamp": ts,
  "event": {"kind": "alert", "category": "intrusion_detection", "module": "suricata",
            "dataset": "suricata.eve", "severity": "high"},
  "rule": {"id": sid, "name": "SSP stream probe", "description": "stream latency probe"},
  "fields": {"log_source": "suricata", "branch": "bj-01", "branch_site": "北京"},
  "ssp": {"branch": "bj-01", "branch_site": "北京"},
  "source": {"ip": ip, "port": 44321},
  "destination": {"ip": "10.7.1.20", "port": 445},
  "network": {"transport": "TCP"},
  "message": f"stream latency probe src={ip}",
}, ensure_ascii=False))
PY
)
  local t0; t0=$(python3 -c 'import time;print(time.time())')
  say "投递探针事件到 Kafka ssp-ecs（src=${ip} rule=${sid}）…"
  printf '%s\n' "$doc" | docker exec -i ssp-kafka /opt/kafka/bin/kafka-console-producer.sh \
    --bootstrap-server localhost:9092 --topic ssp-ecs >/dev/null 2>&1
  say "等待告警落库（轮询 ssp-alerts，最长 15s）…"
  for i in $(seq 1 30); do
    n=$("${CURL[@]}" "$OS/ssp-alerts/_count?refresh=true" -H 'Content-Type: application/json' \
        -d "{\"query\":{\"term\":{\"ssp.alert.rule_id\":\"R-006\"}}}" 2>/dev/null \
        | python3 -c "import sys,json;print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)
    hit=$("${CURL[@]}" "$OS/ssp-alerts/_search?size=1" -H 'Content-Type: application/json' \
        -d "{\"query\":{\"bool\":{\"filter\":[{\"term\":{\"ssp.alert.rule_id\":\"R-006\"}},{\"term\":{\"source.ip\":\"$ip\"}}]}}}" 2>/dev/null \
        | python3 -c "import sys,json;d=json.load(sys.stdin);h=d['hits']['hits'];print(json.dumps(h[0]['_source']['ssp']['alert']) if h else '')" 2>/dev/null || echo "")
    if [ -n "$hit" ]; then
      t1=$(python3 -c 'import time;print(time.time())')
      python3 - "$t0" "$t1" "$hit" <<'PY'
import json, sys
t0, t1, hit = float(sys.argv[1]), float(sys.argv[2]), json.loads(sys.argv[3])
print(f"  ✅ 告警已落库：round-trip {t1-t0:.2f}s（含 Kafka 投递与 OpenSearch 可见性）")
print(f"     引擎={hit.get('engines')} 首产={hit.get('first_engine')} "
      f"规则={hit.get('rule_id')} 级别={hit.get('grade')}")
print(f"     流式实测时延 stream_latency_ms={hit.get('stream_latency_ms')}（事件入 Kafka → 告警落库）")
PY
      return 0
    fi
    sleep 0.5
  done
  say "⚠️ 15s 内未见告警，请检查 ssp-stream 日志：docker logs ssp-stream --tail 50"
  return 1
}

MODE="replay"
case "${1:-}" in
  --status) MODE="status" ;;
  --probe)  MODE="probe" ;;
  --replay|"") MODE="replay" ;;
  *) echo "未知参数：$1（可用 --status / --probe）" >&2; exit 2 ;;
esac

case "$MODE" in
  status)
    status
    ;;
  probe)
    status
    probe "${2:-203.0.113.66}"
    status
    ;;
  replay)
    say "① 回放演示数据（探针 + 分支）…"
    bash "$ROOT/scripts/replay-demo.sh" >/dev/null 2>&1 || { say "回放失败"; exit 1; }
    sleep 3
    say "② 流式引擎状态（应已消费到 ssp-ecs 上的历史+新增事件）…"
    status
    say "③ 实测端到端时延（新事件 → 告警）…"
    probe "203.0.113.77"
    say "④ 分级告警分布（批式 + 流式共存，幂等去重后）："
    "${CURL[@]}" "$OS/ssp-alerts/_search?size=0" -H 'Content-Type: application/json' \
      -d '{"aggs":{"g":{"terms":{"field":"ssp.alert.grade"}},
                   "e":{"terms":{"field":"ssp.alert.engines"}}}}' 2>/dev/null \
      | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('  合计', d['hits']['total']['value'], '条')
for b in d.get('aggregations',{}).get('g',{}).get('buckets',[]):
    print(f\"    {b['key']}: {b['doc_count']}\")
print('  按引擎:', {b['key']: b['doc_count'] for b in d.get('aggregations',{}).get('e',{}).get('buckets',[])})
"
    ;;
esac
