#!/usr/bin/env bash
# Arkime 状态速查：容器 / Viewer 可达性与登录 / arkime 索引 / 样例会话
set -euo pipefail
export PATH=/usr/local/bin:$PATH
cd "$(dirname "$0")/.."

#  Viewer 使用 digest 鉴权（config.ini 未设 authMode，Arkime 默认 digest）。
#  账号由 scripts/arkime-init.sh 创建；口令来自 deploy/.env（仓库内不保存）。
if [ -f deploy/.env ]; then set -a; . deploy/.env; set +a; fi
ADMIN_USER="${ARKIME_ADMIN_USER:-admin}"
ADMIN_PASS="${ARKIME_ADMIN_PASSWORD:-}"
if [ -z "$ADMIN_PASS" ]; then
  echo "[arkime] 未配置 ARKIME_ADMIN_PASSWORD —— 请先 'make init' 生成 deploy/.env" >&2
  exit 1
fi

# 本机访问一律绕过代理：否则 curl 会发出「绝对 URI 请求行」，
# Express 会直接判为 400 Bad Request（症状是鉴权已通过但接口返回 400）。
NOPROXY=(--noproxy '*')

SVC=ssp-arkime
echo "=== container ==="
docker ps --filter "name=$SVC" --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'

echo "=== viewer http (localhost:8005) ==="
code="$(curl -s "${NOPROXY[@]}" -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:8005/ 2>/dev/null || true)"
echo "  未登录 GET / → HTTP ${code:-000}（401 表示 Viewer 已就绪且要求鉴权）"

echo "=== viewer 登录 + 会话检索 ==="
resp="$(curl -s "${NOPROXY[@]}" --digest -u "${ADMIN_USER}:${ADMIN_PASS}" \
  'http://localhost:8005/api/sessions?date=1700000005000&length=100' 2>/dev/null || true)"
python3 - "$resp" <<'PY'
import json, sys
raw = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    d = json.loads(raw)
except Exception:
    print("  登录/检索失败（原始响应）:", raw[:200])
    sys.exit(0)
print("  登录成功；recordsTotal =", d.get("recordsTotal"))
for s in (d.get("data") or [])[:10]:
    proto = s.get("protocol") or "?"
    if isinstance(proto, list):
        proto = proto[0] if proto else "?"
    print("   %-5s %s:%s -> %s:%s  bytes=%s" % (
        proto,
        s.get("source", {}).get("ip"), s.get("source", {}).get("port"),
        s.get("destination", {}).get("ip"), s.get("destination", {}).get("port"),
        s.get("totDataBytes")))
PY

echo "=== arkime_* indices (docs.count) ==="
curl -s "${NOPROXY[@]}" 'http://localhost:9200/_cat/indices/arkime*?v&h=index,docs.count,store.size' 2>/dev/null || echo "  (opensearch not reachable)"

echo "=== 样例会话（OpenSearch 直查；会话字段为 ECS 对齐命名）==="
curl -s "${NOPROXY[@]}" \
  'http://localhost:9200/arkime_sessions3-*/_search?size=1&filter_path=hits.total,hits.hits._source.source.ip,hits.hits._source.destination.ip,hits.hits._source.ipProtocol' \
  2>/dev/null || echo "  (no session yet)"
echo
