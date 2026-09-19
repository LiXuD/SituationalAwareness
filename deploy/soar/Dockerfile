# I-05 SOAR 服务镜像：alpine + python3（标准库）+ iptables（落黑执行）
# 说明：SOAR 服务本身纯标准库；iptables 用于「审批通过后执行落黑」。
FROM alpine:3.20

RUN apk add --no-cache python3 iptables

WORKDIR /srv
# 源码由 compose bind mount 注入（services/soar -> /srv:ro）
CMD ["python3", "/srv/soar_server.py"]
