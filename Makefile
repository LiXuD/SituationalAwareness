# 一体化安全态势感知平台 —— 统一任务入口
#
# 设计：所有运维/生成/验收动作都经 make 调用，无需记住散落的脚本路径。
# Docker 在 /usr/local/bin（macOS 本地），故统一注入 PATH。
SHELL := /bin/bash
export PATH := /usr/local/bin:$(PATH)

COMPOSE := docker compose -f deploy/compose.yml
COMPOSE_PG := $(COMPOSE) -f deploy/portal/compose.pg.yml
PY := python3

.DEFAULT_GOAL := help

.PHONY: help init env up down ps logs templates demo verify health clean \
        pg-up pg-init pg-portal pg-stop lint discover discovery-status \
        branch-demo branch-status branch-down branch-up \
        stream-status stream-demo external-up external-down external-demo external-reset

help: ## 显示所有可用命令
	@grep -E '^[a-zA-Z_-]+:.*## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# ----------------------------- 业务库 ----------------------------- #
env: ## 生成本地运行时配置 deploy/.env（随机口令，不入库；已存在则不动）
	@bash scripts/gen-env.sh

init: ## 初始化业务库（首次自动生成 deploy/.env + 建表 + 种子账号，SQLite）
	@bash scripts/gen-env.sh
	$(PY) scripts/init-db.py

# ----------------------------- 服务编排 ----------------------------- #
up: ## 启动全部服务（缺 deploy/.env 时自动生成）
	@bash scripts/gen-env.sh
	$(COMPOSE) up -d

down: ## 停止全部服务（保留数据卷）
	$(COMPOSE) down

ps: ## 查看服务状态
	$(COMPOSE) ps

logs: ## 跟踪 portal 日志
	$(COMPOSE) logs -f --tail 100 portal

templates: ## 下发 ECS / 告警索引模板 + 别名
	bash scripts/apply-ecs-template.sh
	bash scripts/apply-alerts-template.sh
	bash scripts/init-alias.sh

demo: ## 回放演示数据（探针 → 事件）
	bash scripts/replay-demo.sh

verify: ## 端到端验收（A1~A8 正例 + N1~N4 反例）
	$(PY) scripts/test-cases.py

health: ## 各服务健康检查
	@bash scripts/verify-ingest.sh || true
	@curl -sS --noproxy '*' http://localhost:8093/health && echo

clean: ## 清空运行时回放暂存（logs/demo-stage、logs 根）
	rm -f logs/*/*.json logs/*/*.log 2>/dev/null || true
	@echo "已清理运行时暂存（保留 logs/demo 演示源）"

# ----------------------------- 资产测绘（I-12） ----------------------------- #
discover: ## 触发一次资产被动测绘（Zeek 连接日志 → 候选池）
	$(PY) scripts/discovery-run.py

discovery-status: ## 查看资产测绘候选统计
	$(PY) scripts/discovery-run.py --stats

# ----------------------------- 多分支汇聚（I-13） ----------------------------- #
branch-demo: ## 重建各分支边缘代理，重新采集分支数据（Kafka 汇聚）
	bash scripts/replay-branch.sh

branch-status: ## 查看各分支事件量与最新上报时间
	bash scripts/replay-branch.sh --status

branch-down: ## 模拟某分支断链，如 make branch-down B=sh-01
	bash scripts/replay-branch.sh --down $(B)

branch-up: ## 恢复某分支，如 make branch-up B=sh-01
	bash scripts/replay-branch.sh --up $(B)

# ----------------------------- 流式关联（I-14 L1） ----------------------------- #
stream-status: ## 查看流式关联引擎状态（消费速率 / 位点滞后 / 实测时延）
	@bash scripts/stream-demo.sh --status

stream-demo: ## 回放演示数据并观察「秒级」流式告警（含时延实测）
	@bash scripts/stream-demo.sh

# ----------------------------- 外部日志源适配（I-14 L2，默认关闭） ----------------------------- #
external-up: ## 启用外部日志源适配器（syslog:5514/udp、CEF:5515/tcp、JSON:5516）
	$(COMPOSE) --profile external up -d ingest-adapter

external-down: ## 关闭并移除外部日志源适配器（回到"无副作用"的默认态）
	$(COMPOSE) --profile external rm -sf ingest-adapter

external-demo: ## 投递外部源样例日志（防火墙 syslog / CEF / JSON）并观察入库与关联
	@bash scripts/external-demo.sh

external-reset: ## 清理外部源演示数据（删除 ssp-firewall-* / ssp-waf-* 索引）
	@bash scripts/external-demo.sh --reset

# ----------------------------- PostgreSQL（可选） ----------------------------- #
pg-up: ## 启动 PostgreSQL 容器
	$(COMPOSE) --profile postgres up -d postgres

pg-init: ## 建表 + 种子到 PostgreSQL（DSN 由 deploy/.env 拼装）
	@set -a; if [ -f deploy/.env ]; then . ./deploy/.env; fi; set +a; \
	  : "$${POSTGRES_PASSWORD:?未设置 POSTGRES_PASSWORD —— 请先 make init 生成 deploy/.env}"; \
	  PLATFORM_DB="postgresql://$${POSTGRES_USER:-ssp}:$${POSTGRES_PASSWORD}@localhost:$${POSTGRES_PORT:-5433}/$${POSTGRES_DB:-ssp}" \
	  $(PY) scripts/init-db.py

pg-portal: ## 把 portal 切到 PostgreSQL
	$(COMPOSE_PG) up -d --force-recreate portal

pg-stop: ## 停止 PostgreSQL 容器
	$(COMPOSE) --profile postgres stop postgres

# ----------------------------- 校验 ----------------------------- #
lint: ## Python 语法检查（不写字节码缓存，受限环境也可用）
	$(PY) scripts/lint.py
