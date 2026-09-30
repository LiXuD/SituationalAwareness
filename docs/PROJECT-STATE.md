# 项目现状快照（PROJECT-STATE）

> **用途**：新会话 / 新 agent / 新成员 / 其他机器的**第一份读物**。读完这一份即可掌握项目全貌，不必先读 14 份技术方案。
> **维护**：**每完成一项任务/迭代即更新本文件**（用户明确约定）；本文件是"项目共享真相源"，优先于任何会话内的临时记忆。
> **最后更新**：2026-09-30（P1 全部完成）

---

## 0. 一句话

面向 **x86 私有化**的轻量安全态势感知平台（POC 阶段），已完成 **I-01~I-15** 全部迭代并实测
（`make verify` 21/21）；**工程化改造 P0 与 P1 均已全部完成**，P2（观测/安全加固）待推进。

---

## 1. 定位与验收闭环

- **目标链路**：采集归一 → 存储检索 → 关联分析 → 资产/情报 → SOAR 审批拉黑 → 态势大屏
- **POC 验收闭环**：探针告警 → MISP 情报匹配 → 人工审批 → 落黑（iptables）→ 大屏可见
- **交付形态**：单机 Docker Compose 编排（`deploy/compose.yml` 为唯一入口，per-service 文件 + `include` 聚合）

---

## 2. 当前进度（截至 2026-09-29）

| 迭代 | 主题 | 状态 | 实测 |
|---|---|---|---|
| I-01 | 探针统一接入 + ECS 归一 | ✅ 完成 | A1 PASS |
| I-02 | OpenSearch 存储 + 统一检索（含 Arkime 流量回溯） | ✅ 完成 | 检索/PCAP 可用 |
| I-03 | 轻量关联分析（Wazuh + OpenSearch） | ✅ 完成 | A2/A5 PASS |
| I-04 | MISP 威胁情报对接 | ✅ 完成 | A3/A4 PASS |
| I-05 | SOAR 剧本 + 人工审批拉黑 | ✅ 完成 | A6/A7/N3 PASS |
| I-06 | 统一资产库（CRUD + Excel 导入） | ✅ 完成 | N4 PASS |
| I-07 | 态势大屏（地图/TOP/热力/SLA） | ✅ 完成 | A8 PASS |
| I-08 | POC 验收 Demo | ✅ 完成 | A1~A8 全绿 |
| I-09 | 测试用例与验收 | ✅ 完成 | N1~N4 → 扩展至 16 项 |
| I-10 | 统一平台整合（浏览器只连平台） | ✅ 完成 | 6 视图零错误 |
| I-11 | 统一业务数据库与全量收口 | ✅ 完成 | 回归 5/5；PG 跑通 |
| I-12 | 资产测绘自动化 | ✅ 完成 | 回归 11/11 |
| I-13 | 多分支汇聚（Kafka） | ✅ 完成 | 回归 16/16 |
| **I-14** | 流式关联与外部日志源适配 | ✅ **完成** | **回归 21/21**（A16 秒级 1.05~1.19s；A18 外部源可关联） |
| **I-15** | 项目上下文补齐（9 份文档） | ✅ **完成** | 验收类 4 + 运维类 5，归档资料库并挂事项 |

**当前基线**：`make verify` = **21/21 通过**（P0 正例 A1~A8 + A9~A11 + A13~A18 + 反例 N1~N7 + N10~N13）

---

## 3. 架构现状

```
统一前端 SPA (ui, nginx :8088)  ──同源 /api──▶  统一业务后端 portal :8093
                                                  ├─ 业务库 SQLite(默认)/PostgreSQL(可选)  ── 9 张表
                                                  ├─ 资产测绘引擎（进程内，I-12）
                                                  ├─ 分支汇聚健康探测（进程内，I-13）
                                                  └─ BFF 透传：Arkime / OpenSearch / correlator / soar
多分支汇聚层 Kafka :9092 (主题 ssp-raw)
采集端  Filebeat(总部 hq) + Filebeat(分支 sh-01/bj-01) + 外部源适配器(I-14) ──▶ Kafka ──▶ Logstash :5044(ECS 归一)
        Logstash 归一后**双写**：OpenSearch :9200（检索/批式） + Kafka 主题 **ssp-ecs**（流式，I-14）
存储检索  OpenSearch :9200（事件 ssp-<源>-日期 / 告警 ssp-alerts）· Arkime :8005（会话/PCAP，直连同一集群）
关联分析  批式 correlator :8091（30min 窗口，R-001~R-007） ＋ **流式 stream :8094**（30s 滑动窗口，秒级）
          两者共用 services/common/ssp_kernel.py，写同一 ssp-alerts（_id 幂等去重，engines 标记来源）
外部源     ingest-adapter :5514/udp(syslog) :5515(tcp/CEF) :5516(http/JSON) —— **默认关闭**（profile external）
落黑执行  soar :8092（privileged，iptables 宿主链 SSP_BLACKLIST）
```

**业务库 9 张表**：`users` `sessions` `assets` `asset_candidates` `branches` `soar_drafts` `blacklist` `config` `audit_log`

**端口速查**：前端 8088 ｜ portal 8093 ｜ correlator 8091 ｜ **stream 8094** ｜ soar 8092 ｜ OpenSearch 9200 ｜
Arkime 8005 ｜ Kafka 9092 ｜ Logstash(beats) 5044 ｜ **外部源 5514/udp、5515/tcp、5516/http** ｜ PostgreSQL(宿主) 5433

---

## 4. 关键约定与已知坑（**最容易踩的部分**）

1. **索引命名/别名纪律**：索引 `ssp-<log_source>-YYYY.MM.dd`，检索别名 `ssp-ecs` / `ssp-events`；
   **严禁通配 `ssp-*` 别名**（会污染检索口径并造成关联引擎自反馈）。索引名 ≠ 别名名。
2. **关联窗口以"最新事件时间"为锚**（`resolve_window`）：新增演示数据的时间戳必须落在**同一窗口**内，否则会把既有数据挤出窗口导致规则不命中。
3. **告警模板 `dynamic:false`**：新增字段**必须显式声明**，否则被静默丢弃（如 `ssp.branch`、`related.branches`）。
4. **Arkime 单节点必须固定 hostname**：否则容器重建后 node 名漂移 → PCAP 导出恒 0 字节（极隐蔽）。
   Arkime 无 CORS 头 → 浏览器不能直连 → **必须走 portal BFF 代理**。
5. **GeoIP**：OSS Logstash 无 GeoLite2，用 DB-IP Lite City，且必须用 `scripts/patch-mmdb-type.py`
   把 `database_type` 改成 `GeoLite2-City`（否则 Logstash 抛 `Unsupported database type` 并**停整条 pipeline**）。
6. **业务库后端无关**：业务 SQL 统一写 `?`，`db.adapt_sql()` 在 PG 后端转 `%s`（业务代码零改动）。
7. **`make pg-init` 在宿主执行、宿主无 psycopg** → 对既有 PG 库做迁移须**在容器内**执行。
8. **Docker Desktop(macOS) 绑定挂载**：宿主直写 `data/ssp.db` → 容器内约 **1s 后**才可见（测试须等待）。
9. **落黑**：草稿状态机在业务库，只生成不自动提交；iptables 执行在特权容器 `soar`。
10. **写权矩阵**（前端 `perms.canWrite` + 后端双重校验）：asset/discovery → admin+asset_admin；
    soar → admin+ops；branches/users → **仅 admin**；其余仅 admin。
11. **分支汇聚（I-13）**：分支身份靠 `fields.branch` → `ssp.branch`（**逻辑区分，非物理端口**），
    缺失默认 `hq`；新增分支只需加一个边缘代理，中心侧不改端口/管道。
12. **资产测绘（I-12）**：自动发现**绝不覆盖人工字段**（名称/重要度/责任人/风险分）。
13. **流式关联（I-14）**：流式引擎消费 **`ssp-ecs`**（Logstash 归一后**双写**的主题），
    与批式共用 `services/common/ssp_kernel.py` 的同一份规则实现；窗口**锚定事件时间**；
    位点落盘 `<OFFSET_DIR>/offsets-<GROUP>.json`（group 即命名空间，重放用独立 group）。
    **批式与流式写同一 `ssp-alerts`，靠 `_id = sha1(rule_id|entity_key)` 幂等去重**，
    `ssp.alert.engines` 记录来源（batch/stream），`stream_latency_ms` 记录实测时延。
14. **外部源（I-14）**：适配器**只解析 + 打标，不做 ECS 归一**（归一同在 Logstash `40-external.conf`）；
    默认关闭（compose profile `external` + `ADAPTER_ENABLED=false`），关闭时**不监听端口、零副作用**。
    外部源索引沿用 `ssp-<log_source>-日期`（如 `ssp-firewall-*`），并已纳入 `ssp-events` 别名。
15. **数据源健康基准只取探针源**（`source_health`）：外部源日志时间口径与探针数据不同
    （外部是"当下"、探针常为历史回放），混入基准会把探针源误判为 `stale`。
16. **Kafka 客户端（自研 `kafka_lite`）**：一个 TCP 连接**不可**多线程并发读写（响应流交叉 →
    `Bad file descriptor`），已在 `KafkaClient._request` 内全局串行化；record batch v2 头为
    **61 字节**（`baseSequence` 后还有 4 字节 `recordsCount`，官方文档表格未列出）。
17. **Logstash 不热加载配置**：改 `config/logstash/conf.d/*.conf` 后必须重建 logstash 容器才生效。

---

## 5. 待办与阻塞项

### I-14 流式关联与外部日志源适配（事项 `rVgO1S`）—— ✅ 已完成（2026-09-29）
- 交付：流式关联引擎（`services/stream`，:8094）＋ 共享关联内核（`services/common`）＋ 外部源适配器
  （`services/ingest-adapter`，syslog/CEF/JSON，默认关闭）；实测 `make verify` **21/21**，
  端到端时延 **1.05~1.19s**，流式段 **11~17ms**。
- 决策落定：D1 = C（轻量消费者，预留 Flink 替换点）｜D2 = 保留并存｜D3 = 防火墙 syslog(+WAF CEF+JSON)｜D4 = L1→L2 同期。
- 技术方案：[`I-14-流式关联与外部日志源适配-技术方案.md`](I-14-流式关联与外部日志源适配-技术方案.md)
- **未做（后续可选）**：Flink/exactly-once（D1 选项 A）、大屏"流式告警时延"指标、
  批式引擎默认纳入外部源（只需设 `EXTERNAL_SOURCES=firewall,waf`）。

### I-15 项目上下文补齐（事项 `rUYkpk`）—— ✅ 已完成（2026-09-29）
- 交付：**9 份文档**成文并归档资料库——`需求文档/` 4 份（POC验收报告、迭代验收记录 I-01~I-14、
  迭代评审结论汇总、需求变更记录）＋ `系统文件/` 5 份（部署/运维/故障排查/备份恢复/端口账号清单）；
  `资产库使用指南.pdf` 已移入 `系统文件/`；每份挂到对应事项（验收报告 → I-08，其余 → I-15）。
- 本地：`docs/需求文档/`、`docs/系统文件/`（提交 `504cab3`，已推送公开仓库）。
- **未做（后续可选）**：转 Word/PPT 交付甲方（属另一份任务，需单独排期）。

### 工程化改造（2026-09-29 新增工作流）—— P0 ✅ 完成 / P1~P2 待推进
- **P0（正确性/可复现）已落地**：① 本地 pre-commit 门禁（`make gate`/`ci`/`hooks` + `scripts/pre-commit.sh` +
  `scripts/check-secrets.py` 硬编码口令扫描）；② 自建镜像钉版（`ssp-*:${SSP_IMAGE_TAG:-2026.09}` + `make build`）；
  ③ 单元测试 16 项（`tests/`，纯 stdlib unittest，覆盖 kafka_lite 编解码 + ssp_kernel 核心）；④ 3 处关键静默异常改为告警。
  —— 全量 `make verify` **21/21** 通过，提交 `e04cd62`。
- **P1（可维护性）✅ 全部完成**：DB 版本化迁移（`MIGRATIONS` + `schema_migrations`，替代"猜列"）；
  配置 schema 校验（`scripts/check-env.py` + `make check-env`，模板一致性入 gate）；
  前端 JS 语法检查（`scripts/lint-ui.sh`，零依赖）；**结构化日志**（各服务 `print` → stdlib `logging`，
  格式 `时间 级别 [服务] 消息`，级别由 `LOG_LEVEL` 控制；CLI/JSON 输出保持 print）。
  单测总数 **19**（kafka_lite 8 + ssp_kernel 8 + db 迁移 3）。
- **P2（观测/安全）待推进**：Kafka/OpenSearch 安全认证、统一 health/metrics、ruff + PR gate、镜像漏洞扫描。
- **总原则**：保持「纯标准库 + 少量 dev 侧工具」定位，不引 k8s/Flink/重量观测栈；每项改动必须经 `make verify` 实测。

---

## 6. 文档与资产索引

| 内容 | 位置 | 标识 |
|---|---|---|
| PRD | 资料库 `需求文档/` | file_id `JFHDdSUPpRLV` |
| 技术方案 I-01~I-13 | 资料库 `技术方案/` | 见各事项评论（I-01~I-09 附 PRD/ECS 映射交叉引用） |
| 计划 I-14 / I-15 | 资料库 `项目计划/`（2026-09-29 新建） | `JHjVMqqGwIvm` / `JrzgWlkultmg` |
| ECS 字段映射 | 资料库 `技术方案/` | `JrndPbPfvoRs` |
| 平台技术问答 FAQ | 资料库 `技术方案/` | `JqYKCypXGHdW` |
| 资产库使用指南 | 资料库 `系统文件/` | `JcCytangqOwN`（已由根目录移入） |
| 项目事项 | wb-issues | I-01~I-15（**全部 done**） |
| 本机项目记忆 | `.workbuddy/memory/`（**不进 git**） | `MEMORY.md` + 每日日志 |

---

## 7. 新 agent / 新会话「开工必读」顺序

1. **本文件**（现状、约定、待办）
2. `README.md`（架构与常用命令）
3. `docs/` 下与本次任务相关的技术方案 1~2 份
4. `.workbuddy/memory/MEMORY.md`（本机项目长期约定；**仅本机可见**）
5. 对应事项的评论（有逐迭代的实测证据与提交号）

> **维护约定（用户要求，硬性）**：每完成一项任务/迭代，必须更新本文件（「最后更新」+ 进度表 + 待办 + 常用命令），
> 并同步刷新资料库的 `PROJECT-STATE-项目现状快照`（review-before-upload：先下载最新 → 展示差异 → 再覆盖）。

> ⚠️ 若新任务的工作目录**不是**本项目目录（如 `~/WorkBuddy/<时间戳>`），将读不到 `.workbuddy/memory/`；
> 此时以本文件 + 资料库 + 事项评论为准，并**先把工作目录切到本项目**。

---

## 8. 常用命令

```bash
make init        # 建业务库表 + 种子账号 + 登记默认分支
make up / down   # 起停全部服务（含 Kafka 汇聚层与分支代理）
make build       # 构建自建镜像（portal/soar，钉版 tag）
make templates   # 下发 ECS/告警索引模板
make demo        # 回放演示数据（总部 + 分支）
make verify      # 端到端验收（当前 21/21）
make gate        # 提交前快速门禁（语法 + 单元测试 + 口令扫描 + 配置模板一致）
make ci          # 全量门禁（gate + verify，合并/推送前）
make test        # 单元测试（tests/，纯标准库 unittest）
make check-env   # 校验 deploy/.env 与模板是否符合 schema
make hooks       # 安装 git pre-commit 钩子
make health      # 各服务健康
make branch-status            # 查看各分支上报状态
make branch-down B=sh-01      # 模拟某分支断链
make pg-up / pg-init / pg-portal / pg-stop   # PostgreSQL 后端切换
```

**默认账号**：`admin` / `ops` / `analyst` / `asset`（资产管理员）。
初始口令**不在仓库里**：本地值由 `make init` 首次运行时随机生成并写入 `deploy/.env`
（`.gitignore` 已忽略；模板见 `deploy/.env.example`），变量名 `SSP_<账号>_PASSWORD` / `SSP_DEFAULT_PASSWORD`。
**生产必须轮换**（改用 `deploy/.env` 中的强口令，或接企业统一认证）。

---

## 9. 本文件与其他记忆层的关系

| 层 | 载体 | 可见范围 |
|---|---|---|
| 云端记忆 | 服务端画像 | 跨设备（仅偏好，不含项目内容） |
| 本地用户记忆 | `~/.workbuddy/MEMORY.md` | 本机、跨项目（个人习惯） |
| 项目工作区记忆 | `.workbuddy/memory/` | **本机、同工作目录的 agent**（不进 git） |
| **项目共享真相源** | **本文件 + 资料库 + 事项评论** | **所有成员 / agent / 机器** |

> 约定：**结论进本文件与资料库，过程留在 `.workbuddy/memory/`**。本文件是权威，冲突时以本文件为准。
