# 一体化安全态势感知平台（POC）

面向 x86 私有化的轻量安全态势感知平台。目标链路：
**采集归一 → 存储检索 → 关联分析 → 资产/情报 → SOAR 审批拉黑 → 态势大屏**。

验收闭环：探针告警 → MISP 情报匹配 → 人工审批 → 落黑（iptables）→ 大屏可见。

> **新会话 / 新 agent / 新成员请先读 [`docs/PROJECT-STATE.md`](docs/PROJECT-STATE.md)**
> —— 项目现状快照：当前进度、架构现状、关键约定与已知坑、待办阻塞项、文档与事项索引。读完一份即可掌握全貌。

---

## 架构总览

```
                  统一前端 SPA  (ui, nginx :8088)
                            │  同源反代 /api
                统一业务后端 portal (:8093)       ← 身份/会话/资产/测绘/分支/审批/审计
                    ├── 业务库 SQLite / PostgreSQL  ← 用户/会话/资产/候选池/分支/审批/黑名单/配置/审计
                    ├── 资产测绘引擎（进程内）        ← Zeek 流量 → 候选池（I-12）
                    ├── 分支汇聚健康探测（进程内）     ← 按 ssp.branch 判活（I-13）
                    └── 检索与时序层（保留）
                          ├── OpenSearch (:9200)   事件 / 告警
                          └── Arkime (:8005)       流量 / PCAP
                多分支汇聚层  Kafka (:9092, ssp-raw)  ← 各分支边缘代理 + 外部源适配器汇聚
                采集端  Filebeat(总部 hq) + Filebeat(分支 sh-01/bj-01) → Kafka → Logstash(ECS 归一)
                        Logstash 归一后**双写**：OpenSearch ＋ Kafka ssp-ecs（流式输入，I-14）
                关联分析  批式 correlator (:8091)  ＋  流式 stream (:8094)   ← 共用同一份规则内核
                外部日志源 ingest-adapter (:5514/udp、:5515、:5516)  ← 默认关闭（profile external，I-14）
                落黑执行器 soar (:8092, privileged) iptables
```

**数据分层原则**：业务对象（用户/会话/资产/候选池/分支/审批/黑名单/配置/审计）入**平台自有业务库**；
事件/告警/流量等检索型数据留在 OpenSearch/Arkime。

**多分支汇聚（I-13）**：分支身份 `fields.branch` → `ssp.branch`，经 **Kafka(`ssp-raw`)** 汇聚；
单分支断链只影响该分支状态（`no_data`），其他分支与平台不受影响。

**双引擎关联（I-14）**：批式（30min 窗口、周期扫描）与流式（30s 滑动窗口、事件驱动、秒级）
**并存**，共用 `services/common/ssp_kernel.py` 的规则实现，写同一 `ssp-alerts`，
靠 `_id = sha1(rule_id|entity_key)` 幂等去重（`ssp.alert.engines` 标记来源）。

---

## 快速开始

```bash
make init          # 初始化业务库（首次自动生成 deploy/.env 随机口令 + 建表 + 种子账号 + 登记默认分支 hq/sh-01/bj-01）
make up            # 起全部服务（docker compose，含 Kafka 汇聚层与分支边缘代理）
make templates     # 下发 ECS/告警索引模板
make demo          # 回放演示数据（总部 + 分支，探针 → 事件）
make discover      # 触发一次资产测绘（Zeek 连接日志 → 候选池）
make branch-status # 查看各分支事件量与最新上报时间
make verify        # 端到端验收（A1~A18 正例 + N1~N13 反例，当前 21/21）
make health        # 查看各服务健康
```

提交前验证（本地门禁，无需公网 CI）：
```bash
make hooks         # 一次性：安装 git pre-commit 钩子（提交前自动跑 make gate）
make gate          # 快速门禁（秒级）：Python/shell 语法 + 硬编码口令扫描
make ci            # 全量门禁（约 2 分钟，会重置演示数据）：gate + 端到端验收 —— 合并/推送前手动跑
```
`git commit --no-verify` 可临时跳过钩子（应尽量避免）。

分支相关（I-13）：
```bash
make branch-demo          # 重建各分支边缘代理，重新采集分支数据
make branch-down B=sh-01  # 模拟某分支断链（→ 该分支 no_data，其他分支不受影响）
make branch-up   B=sh-01  # 恢复该分支
```

流式关联 / 外部日志源（I-14）：
```bash
make stream-status             # 流式引擎状态（消费量 / 位点滞后 / 实测时延）
make stream-demo               # 回放演示数据并观察「秒级」流式告警（含时延实测）
make stream-demo --probe       # 直接投递一条事件到 ssp-ecs，隔离采集抖动实测端到端时延
make external-up / external-down   # 启用 / 关闭外部日志源适配器（默认关闭）
make external-demo             # 投递防火墙 syslog / WAF CEF / JSON 样例并验证入库与关联
make external-reset            # 清理外部源演示数据
```

访问 <http://localhost:8088>，用 `admin` 登录（口令见 `deploy/.env` 的 `SSP_ADMIN_PASSWORD`，首次由 `make init` 随机生成）。

启用 PostgreSQL（可选，业务量大时）：
```bash
make pg-up         # 起 PG
make pg-init       # 建表 + 种子到 PG
make pg-portal     # 把 portal 切到 PG
```

---

## 凭据与本地配置（`deploy/.env`）

**仓库内不保存任何可用口令**。运行时配置统一走 `deploy/.env`（`.gitignore` 已忽略，
模板见 `deploy/.env.example`）：

| 变量 | 用途 |
|---|---|
| `SSP_DEFAULT_PASSWORD` | 平台账号（admin/ops/analyst/asset）初始口令（`scripts/init-db.py` 种子） |
| `SSP_<账号>_PASSWORD` | 可选：为单个账号指定不同口令（优先于默认口令） |
| `ARKIME_ADMIN_USER` / `ARKIME_ADMIN_PASSWORD` | Arkime Viewer + portal 的 BFF 代理鉴权 |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` / `POSTGRES_PORT` | PostgreSQL 可选后端 |

```bash
make env            # 生成 deploy/.env（随机口令，0600，不入库）；已存在则不动
make init           # 首次会自动调用上一步，再建表 + 种子账号
cp deploy/.env.example deploy/.env   # 也可以手工方式，自行填写
```

- **compose 与宿主脚本读同一份文件**：compose 自动读取 `deploy/.env` 做 `${VAR}` 插值；
  宿主脚本由 `scripts/_env.py` 加载（`import _env`）。已存在的环境变量优先级更高。
- **缺失即报错**：未配置口令时 compose 会直接报错、`scripts/init-db.py` 会中止，
  不会退化成"某个弱默认口令"。
- 生产部署请用强口令并轮换；如需与现有身份系统对接，改 portal 的登录实现即可。

---

## 目录结构

| 目录 | 说明 |
|---|---|
| `ui/` | 前端工程（无构建 SPA：`index.html` + `src/`）；`deploy/ui/` 为 nginx 入口 |
| `services/` | 后端服务：`portal/`（统一业务后端：`portal_server.py` + `db.py` + `assets/soar/users/discovery/branches.py`）、`common/`（**共享关联内核** `ssp_kernel` + 纯标准库 Kafka 客户端 `kafka_lite` + `threat_intel`）、`correlator/`（批式关联执行壳）、`stream/`（**流式关联引擎**）、`ingest-adapter/`（**外部日志源适配器**）、`soar/`（落黑执行器） |
| `deploy/` | per-service compose（`deploy/compose.yml` 为唯一入口，`include` 聚合）；`kafka/` 汇聚层、`branch/` 分支边缘代理、`stream/` 流式引擎、`ingest-adapter/` 外部源适配器（profile `external`） |
| `config/` | OpenSearch 索引模板、Logstash 管道（含外部源归一的 `40-external.conf` 与归一事件流双写的 `99-outputs.conf`）、Arkime 配置 |
| `scripts/` | 运维 / 生成 / 校验脚本（见 `scripts/README.md`，经 `make` 调用） |
| `docs/` | PRD、各迭代（I-01~I-14）技术方案、FAQ、ECS 字段映射 |
| `samples/` | 示例资产 xlsx、示例 pcap |
| `logs/` | `demo/`（演示数据源）、`branch-sh/` `branch-bj/`（分支数据源）；`demo-stage/`、根目录为运行时暂存（gitignore） |
| `data/` | 业务库 SQLite 文件（gitignore） |

---

## 关键约定

- **索引命名**：`ssp-<log_source>-YYYY.MM.dd`；别名 `ssp-ecs`（**严禁通配 `ssp-*`**）。
- **写权矩阵**（PRD §11，前端 `perms.canWrite` + 后端双重校验）：
  asset / discovery → admin+asset_admin；soar → admin+ops；branches / users → admin；其余仅 admin。
- **多分支汇聚（I-13）**：分支身份靠 `fields.branch` → `ssp.branch`（**逻辑区分，非物理端口**）；
  汇聚层是 **Kafka `ssp-raw` 单主题**，新增分支只需加一个边缘代理，中心侧不改端口/管道；
  `beats :5044` 直连入口保留（旁路/调试/R-15 适配器直投）。
- **资产测绘（I-12）**：Zeek 连接日志 → 候选池 `asset_candidates` → 人工采纳/忽略 → 合并入 `assets`；
  **自动发现绝不覆盖人工字段**（名称/重要度/责任人/风险分），同 IP 以人工资产为准。
  配置项（授权网段/阈值/窗口/自动采纳）走 `config` 表，经 `/api/discovery/config`（仅 admin 可改）。
- **占位符**：业务 SQL 统一写 `?`，`db.adapt_sql()` 在 PG 后端自动转 `%s`（业务代码后端无关）。
- **落黑**：草稿状态机在业务库，iptables 执行由特权容器 `soar` 承担。
- **双引擎关联（I-14）**：流式（`services/stream`）消费 Logstash **双写**的 `ssp-ecs`（归一后事件流），
  与批式共用 `services/common/ssp_kernel.py`；两引擎写同一 `ssp-alerts`，`_id = sha1(rule_id|entity_key)`
  幂等去重；`ssp.alert.engines` 标记来源，`ssp.alert.stream_latency_ms` 记录实测时延。
- **外部日志源（I-14）**：适配器**只解析 + 打标、不做归一**（归一同在 Logstash `40-external.conf`），
  投递中心汇聚层 `ssp-raw`；**默认关闭**（compose profile `external`），关闭时不监听端口、零副作用。
- 文档产出后先本地评审，再上传项目资料库。
