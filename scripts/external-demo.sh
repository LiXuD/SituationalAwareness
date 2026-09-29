#!/usr/bin/env bash
# I-14 L2 外部日志源适配 —— 样例投递 / 端到端验证 / 清理
#
# 用法：
#   bash scripts/external-demo.sh            # 投递 3 类样例（syslog / CEF / JSON）并验证入库与关联
#   bash scripts/external-demo.sh --reset    # 清理外部源演示数据（删除 ssp-firewall-* / ssp-waf-*）
#
# 前提：适配器已启用（make external-up）；否则脚本会提示且不产生任何副作用。
#
# 链路：第三方设备 → ingest-adapter（解析+打标，无 ECS 归一）→ Kafka ssp-raw（中心汇聚层）
#       → Logstash（40-external.conf 归一）→ OpenSearch ssp-firewall-* → 统一检索 + 流式关联
set -euo pipefail

export PATH="/usr/local/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="$ROOT/deploy/compose.yml"
OS="http://localhost:9200"
ADAPTER="http://localhost:5516"
SYSLOG_PORT=5514
CEF_PORT=5515
CURL=(curl -sS --noproxy '*')

say() { printf '\033[1;36m[external]\033[0m %s\n' "$*"; }

reset() {
  say "清理外部源演示数据（ssp-firewall-* / ssp-waf-* / ssp-ids-* / ssp-proxy-*）…"
  for idx in "ssp-firewall-*" "ssp-waf-*" "ssp-ids-*" "ssp-proxy-*"; do
    "${CURL[@]}" -X DELETE "$OS/$idx" >/dev/null 2>&1 || true
  done
  say "完成。当前 ssp-events 总数：$("${CURL[@]}" "$OS/ssp-events/_count" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("count",0))' 2>/dev/null || echo '?')"
}

if [ "${1:-}" = "--reset" ]; then
  reset
  exit 0
fi

say "检查适配器是否启用（默认关闭，需 make external-up）…"
if ! docker ps --format '{{.Names}}' | grep -q '^ssp-ingest-adapter$'; then
  say "适配器未运行 —— 按设计此时**不监听端口、不产生任何副作用**（用例 N13）。"
  say "启用：make external-up ；或临时启动：docker compose -f deploy/compose.yml --profile external up -d ingest-adapter"
  exit 3
fi
ADAPTER_SRC="$(hostname 2>/dev/null || echo host)"
say "适配器在线：$("${CURL[@]}" "$ADAPTER/health" | head -c 200)…"

# ---------------------------------------------------------------- #
say "① 投递 syslog(UDP:$SYSLOG_PORT)：防火墙 deny 日志（Cisco ASA 风格）"
python3 - "$SYSLOG_PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
lines = [
    '<134>Oct 11 22:14:15 fw-edge-01 %ASA-4-106023: Deny tcp src outside:203.0.113.77/41000 '
    'dst inside:10.0.0.20/445 by access-group "outside_in"',
    '<134>1 2026-09-29T09:00:00.000Z fw-edge-01 ASA 1234 IDS - Deny udp src 203.0.113.88 '
    'dst 10.0.0.21',
]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for ln in lines:
    s.sendto(ln.encode(), ("127.0.0.1", port))
print(f"  已发送 {len(lines)} 条 syslog 报文")
PY

say "② 投递 CEF(TCP:$CEF_PORT)：WAF SQL 注入告警"
python3 - "$CEF_PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
line = ('CEF:0|Vendor|WAF-Prod|1.0|942100|SQL Injection Attempt|8|'
        'src=203.0.113.88 dst=10.0.0.30 spt=52000 dpt=443 proto=TCP act=blocked '
        'msg=SQLi detected cs1=OWASP\n')
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall(line.encode())
s.close()
print("  已发送 1 条 CEF 报文")
PY

say "③ 投递 JSON(HTTP:$ADAPTER/ingest/json)：现代防火墙告警"
"${CURL[@]}" -X POST "$ADAPTER/ingest/json?source=waf&branch=bj-01" \
  -H 'Content-Type: application/json' \
  -d '{"src_ip":"203.0.113.77","dst_ip":"10.0.0.40","dst_port":3389,"protocol":"TCP","action":"deny","name":"RDP brute force","severity":"high","msg":"Access denied","vendor":"XX-FW"}' \
  | sed 's/^/  /'
echo

say "④ 等待入库（最多 30s，期望 ssp-firewall-* / ssp-waf-* 出现事件）…"
for i in $(seq 1 30); do
  out=$("${CURL[@]}" "$OS/ssp-firewall-*,ssp-waf-*/_search?size=0" -H 'Content-Type: application/json' \
        -d '{"aggs":{"s":{"terms":{"field":"fields.log_source"}},"b":{"terms":{"field":"ssp.branch"}}}}' 2>/dev/null || echo '{}')
  tot=$(printf '%s' "$out" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("hits",{}).get("total",{}).get("value",0))' 2>/dev/null || echo 0)
  [ "${tot:-0}" -ge 4 ] && break
  sleep 1
done
printf '%s' "$out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print('  外部源事件数 =', d.get('hits',{}).get('total',{}).get('value',0))
print('  按来源:', {b['key']: b['doc_count'] for b in d.get('aggregations',{}).get('s',{}).get('buckets',[])})
print('  按分支:', {b['key']: b['doc_count'] for b in d.get('aggregations',{}).get('b',{}).get('buckets',[])})
"

say "⑤ 抽查一条归一结果（ECS 字段是否就位）："
"${CURL[@]}" "$OS/ssp-firewall-*/_search?size=1" -H 'Content-Type: application/json' \
  -d '{"query":{"exists":{"field":"source.ip"}},"sort":[{"@timestamp":"desc"}]}' 2>/dev/null \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
h=d.get('hits',{}).get('hits') or []
if not h:
    print('  ⚠️ 未见带 source.ip 的归一事件'); raise SystemExit(0)
s=h[0]['_source']
print('  @timestamp =', s.get('@timestamp'))
print('  fields     =', s.get('fields'))
print('  source     =', s.get('source'), ' destination =', s.get('destination'))
print('  event      =', {k: s.get('event',{}).get(k) for k in ('kind','category','action','severity')})
print('  network    =', s.get('network'), ' observer =', s.get('observer'))
"

say "⑥ 关联消费验证（流式引擎：EXTERNAL_SOURCES=firewall,waf）——"
say "   同一外部 IP 出现在 firewall 与 waf 两个来源 → R-001 跨源关联应在 ssp-alerts 出现："
for i in $(seq 1 20); do
  hit=$("${CURL[@]}" "$OS/ssp-alerts/_search?size=1" -H 'Content-Type: application/json' \
        -d '{"query":{"bool":{"filter":[{"term":{"ssp.alert.rule_id":"R-001"}},{"term":{"related.entities.external_ips":"203.0.113.77"}}]}}}' 2>/dev/null \
        | python3 -c "import sys,json;d=json.load(sys.stdin);h=d['hits']['hits'];print(json.dumps(h[0]['_source']) if h else '')" 2>/dev/null || echo "")
  if [ -n "$hit" ]; then
    printf '%s' "$hit" | python3 -c "
import sys,json
s=json.load(sys.stdin); a=s['ssp']['alert']
print('  ✅ R-001 告警已生成：', s['message'][:90])
print('     引擎 =', a.get('engines'), ' 分支 =', s['ssp'].get('branch'), ' 级别 =', a.get('grade'))
print('     related.log_sources =', s['related'].get('log_sources'))
"
    break
  fi
  sleep 1
done

say "完成。清理演示数据：make external-reset ；关闭适配器：make external-down"
