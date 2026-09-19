#!/usr/bin/env bash
# Arkime 初始化（可重跑）：建库（db.pl init）
#
# 设计：
#   - 用「一次性容器」（同镜像 + 接入 ssp 网络）执行 db.pl init，最稳健：
#     不依赖 ssp-arkime 是否处于运行/重启态，也不依赖 OpenSearch 安全插件。
#   - db.pl init 幂等：创建 arkime_sessions3 模板、arkime_sequence、arkime_users_v30（内部用户库）、
#     arkime_fields_v30、arkime_stats_v30 等；重复执行安全。
#   - Arkime 5.8 的 es-adduser 走 OpenSearch /_security（需安全插件），POC 已关闭，
#     故不创建 OpenSearch 登录用户；config.ini 中 passwordSecret 已注释 → Viewer 无鉴权。
#
# 用法：
#   ./scripts/arkime-init.sh
#   环境变量（可选）：ARKIME_PREFIX（默认 arkime_）、ARKIME_NET（默认 ssp-poc_ssp）、ARKIME_IMAGE
set -euo pipefail
export PATH=/usr/local/bin:$PATH
cd "$(dirname "$0")/.."

IMG="${ARKIME_IMAGE:-ghcr.io/arkime/arkime/arkime:v5.8.1}"
NET="${ARKIME_NET:-ssp-poc_ssp}"
ES=http://opensearch:9200
PREFIX="${ARKIME_PREFIX:-arkime_}"
CFG="config/arkime/config.ini"

echo "[init] db.pl --prefix $PREFIX init --ifneeded  (one-off container, net=$NET, es=$ES)"
echo "[init]   —— --ifneeded：已初始化则跳过（可重跑、不误擦数据）；全新安装则建库"
docker run --rm --network "$NET" \
  -v "$PWD/$CFG:/opt/arkime/etc/config.ini:ro" \
  "$IMG" \
  /opt/arkime/bin/docker.sh db.pl --prefix "$PREFIX" "$ES" init --ifneeded

# 创建 Viewer 管理员用户（写入 arkime_users_v30 内部用户库，用 passwordSecret 哈希）
# --createOnly 保证可重跑：用户已存在则跳过。
# 注意：addUser.js 创建用户后不会自行退出（node 事件循环保持），故用 detached 容器启动，
# 轮询 arkime_users_v30 计数确认创建成功后，再强制删除该容器（docker run 才会返回）。
ADMIN_USER="${ARKIME_ADMIN_USER:-admin}"
ADMIN_NAME="${ARKIME_ADMIN_NAME:-Admin}"
ADMIN_PASS="${ARKIME_PASSWORD:-REDACTED-ARKIME-PWD}"
echo "[init] create admin user '$ADMIN_USER' (idempotent via --createOnly)"
CID="arkime-adduser-$$"
docker rm -f "$CID" >/dev/null 2>&1 || true
docker run -d --name "$CID" --network "$NET" \
  -v "$PWD/$CFG:/opt/arkime/etc/config.ini:ro" \
  "$IMG" \
  /opt/arkime/bin/arkime_add_user.sh "$ADMIN_USER" "$ADMIN_NAME" "$ADMIN_PASS" --admin --createOnly >/dev/null
for i in $(seq 1 30); do
  c=$(curl -s --noproxy '*' "$ES/arkime_users_v30/_count" | grep -o '"count":[0-9]*' | grep -o '[0-9]*')
  if [ "${c:-0}" -ge 1 ]; then echo "[init] user '$ADMIN_USER' confirmed (count=$c)"; break; fi
  sleep 1
done
docker rm -f "$CID" >/dev/null 2>&1 || true

echo "[init] done."
echo "[init] 关键产物：arkime_sessions3 模板、arkime_users_v30 内部用户库（用户 $ADMIN_USER 已建）。"
echo "[init] Viewer 登录：http://localhost:8005  用户=$ADMIN_USER 密码=$ADMIN_PASS"
echo "[init] 提示：回放 pcap 后才会生成 arkime_sessions3-* 索引（见 scripts/arkime-import.sh）。"
