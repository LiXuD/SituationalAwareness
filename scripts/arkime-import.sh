#!/usr/bin/env bash
# Arkime PCAP 回放入库：capture -r 读取样本/真实 pcap，会话写入 OpenSearch（arkime_sessions3-*）
#
# 用法：
#   ./scripts/arkime-import.sh                         # 默认回放 samples/pcap/sample.pcap
#   ./scripts/arkime-import.sh /path/to/foo.pcap       # 回放指定文件
#
# 说明：
#   - 样本 pcap 由 scripts/gen-sample-pcap.py 生成（含到 203.0.113.45 的「恶意」C2 流）；
#   - 容器内 /pcap 已挂载 samples/pcap（只读），capture -r 直接读 /pcap/<name>；
#   - 真实流量回放（I-08 验收）同样可用本脚本，传入真实 pcap 路径即可（需先挂进 /pcap 或 docker cp）。
set -euo pipefail
export PATH=/usr/local/bin:$PATH
cd "$(dirname "$0")/.."

SVC=ssp-arkime
PCAP="${1:-samples/pcap/sample.pcap}"
NAME="$(basename "$PCAP")"

if [ ! -f "$PCAP" ]; then
  echo "[import] ERROR: pcap not found: $PCAP" >&2
  exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -qx "$SVC"; then
  echo "[import] ERROR: $SVC 未运行，请先 'cd deploy && docker compose up -d arkime'" >&2
  exit 1
fi

echo "[import] replay '$PCAP' (-> container /pcap/$NAME) via arkime capture -r"
docker exec "$SVC" /opt/arkime/bin/capture -r "/pcap/$NAME" -c /opt/arkime/etc/config.ini

echo "[import] done. 校验："
echo "  curl 'http://localhost:9200/_cat/indices/arkime_sessions3-*?v'"
echo "  curl 'http://localhost:9200/arkime_sessions3-*/_search?size=1'"
