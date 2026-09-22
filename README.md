# 一体化安全态势感知平台（POC）

面向 x86 私有化的轻量安全态势感知平台。目标链路：
**采集归一 → 存储检索 → 关联分析 → 资产/情报 → SOAR 审批拉黑 → 态势大屏**。

验收闭环：探针告警 → MISP 情报匹配 → 人工审批 → 落黑（iptables）→ 大屏可见。

---

## 架构总览

```
                  统一前端 SPA  (ui, nginx :8088)
                            │  同源反代 /api
                统一业务后端 portal (:8093)       ← 身份/会话/资产/审批/审计
                    ├── 业务库 SQLite / PostgreSQL  ← 用户/会话/资产/审批/黑名单/配置/审计
                    └── 检索与时序层（保留）
                          ├── OpenSearch (:9200)   事件 / 告警
                          └── Arkime (:8005)       流量 / PCAP
                采集管道（保留）Filebeat → Logstash
                落黑执行器 soar (:8092, privileged) iptables
                关联引擎 correlator (:8091)
```

**数据分层原则**：业务对象（用户/会话/资产/审批/黑名单/配置/审计）入**平台自有业务库**；
事件/告警/流量等检索型数据留在 OpenSearch/Arkime。

---

## 快速开始

```bash
make init          # 初始化业务库（建表 + 种子账号 admin/ops/analyst/asset，密码 REDACTED-SSP-PWD）
make up            # 起全部服务（docker compose）
make templates     # 下发 ECS/告警索引模板
make demo          # 回放演示数据（探针 → 事件）
make verify        # 端到端验收（A1~A8 正例 + N1~N4 反例）
make health        # 查看各服务健康
```

访问 <http://localhost:8088>，用 `admin / REDACTED-SSP-PWD` 登录。

启用 PostgreSQL（可选，业务量大时）：
```bash
make pg-up         # 起 PG
make pg-init       # 建表 + 种子到 PG
make pg-portal     # 把 portal 切到 PG
```

---

## 目录结构

| 目录 | 说明 |
|---|---|
| `ui/` | 前端工程（无构建 SPA：`index.html` + `src/`）；`deploy/ui/` 为 nginx 入口 |
| `services/` | 后端服务：`portal/`（统一业务后端：`portal_server.py` + `db.py` + `assets/soar/users.py`）、`correlator/`、`soar/`（落黑执行器） |
| `deploy/` | per-service compose（`deploy/compose.yml` 为唯一入口，`include` 聚合） |
| `config/` | OpenSearch 索引模板、Logstash 管道、Arkime 配置 |
| `scripts/` | 运维 / 生成 / 校验脚本（见 `scripts/README.md`，经 `make` 调用） |
| `docs/` | PRD、各迭代（I-01~I-11）技术方案、FAQ、ECS 字段映射 |
| `samples/` | 示例资产 xlsx、示例 pcap |
| `logs/` | `demo/`（演示数据源）；`demo-stage/`、根目录为运行时回放暂存（gitignore） |
| `data/` | 业务库 SQLite 文件（gitignore） |

---

## 关键约定

- **索引命名**：`ssp-<log_source>-YYYY.MM.dd`；别名 `ssp-ecs`（**严禁通配 `ssp-*`**）。
- **写权矩阵**（PRD §11，前端 `perms.canWrite` + 后端双重校验）：
  asset → admin+asset_admin；soar → admin+ops；users → admin；其余仅 admin。
- **占位符**：业务 SQL 统一写 `?`，`db.adapt_sql()` 在 PG 后端自动转 `%s`（业务代码后端无关）。
- **落黑**：草稿状态机在业务库，iptables 执行由特权容器 `soar` 承担。
- 文档产出后先本地评审，再上传项目资料库。
