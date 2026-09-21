# 平台统一后端（portal）—— 运行时镜像
#
# 默认使用 SQLite（Python 标准库，零依赖）；额外预装 psycopg 驱动，
# 以便通过 PLATFORM_DB=postgresql://... 切换到 PostgreSQL 时业务代码零改动。
# 业务代码通过 compose 卷挂载（/srv），本镜像只提供运行时与 PG 驱动。
FROM python:3.12-slim

RUN pip install --no-cache-dir "psycopg[binary]"

WORKDIR /srv
