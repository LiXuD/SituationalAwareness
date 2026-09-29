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

.PHONY: help init up down ps logs templates demo verify health clean \
        pg-up pg-init pg-portal pg-stop lint discover discovery-status \
        branch-demo branch-status branch-down branch-up

help: ## 显示所有可用命令
	@grep -E '^[a-zA-Z_-]+:.*## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# ----------------------------- 业务库 ----------------------------- #
init: ## 初始化业务库（建表 + 种子账号，SQLite）
	$(PY) scripts/init-db.py

# ----------------------------- 服务编排 ----------------------------- #
up: ## 启动全部服务
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

# ----------------------------- PostgreSQL（可选） ----------------------------- #
pg-up: ## 启动 PostgreSQL 容器
	$(COMPOSE) --profile postgres up -d postgres

pg-init: ## 建表 + 种子到 PostgreSQL
	PLATFORM_DB='postgresql://ssp:REDACTED-PG-PWD@localhost:5433/ssp' $(PY) scripts/init-db.py

pg-portal: ## 把 portal 切到 PostgreSQL
	$(COMPOSE_PG) up -d --force-recreate portal

pg-stop: ## 停止 PostgreSQL 容器
	$(COMPOSE) --profile postgres stop postgres

# ----------------------------- 校验 ----------------------------- #
lint: ## Python 语法检查
	$(PY) -m py_compile services/portal/*.py services/correlator/*.py services/soar/*.py scripts/*.py
	@echo "Python 语法 OK"
