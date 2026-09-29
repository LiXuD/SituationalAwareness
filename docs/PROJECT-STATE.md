# 项目现状快照（PROJECT-STATE）

> **用途**：新会话 / 新 agent / 新成员 / 其他机器的**第一份读物**。读完这一份即可掌握项目全貌，不必先读 13 份技术方案。
> **维护**：每完成一个迭代即更新；本文件是"项目共享真相源"，优先于任何会话内的临时记忆。
> **最后更新**：2026-09-29（提交 `3c12dcc`）

---

## 0. 一句话

面向 **x86 私有化**的轻量安全态势感知平台（POC 阶段），已完成 **I-01~I-13** 全部迭代并实测；
当前待办是 **I-14 流式关联与外部日志源适配**、**I-15 项目上下文补齐**（两份计划待拍板）。

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
| I-13 | 多分支汇聚（Kafka） | ✅ 完成 | **回归 16/16** |
| **I-14** | 流式关联与外部日志源适配 | 📋 **计划待拍板** | — |
| **I-15** | 项目上下文补齐（9 份文档） | 📋 **计划待确认** | — |

**当前基线**：`make verify` = **16/16 通过**（P0 正例 A1~A8 + A9~A11 + A13~A15 + 反例 N1~N7 + N10~N11）

---

## 3. 架构现状

```
统一前端 SPA (ui, nginx :8088)  ──同源 /api──▶  统一业务后端 portal :8093
                                                  ├─ 业务库 SQLite(默认)/PostgreSQL(可选)  ── 9 张表
                                                  ├─ 资产测绘引擎（进程内，I-12）
                                                  ├─ 分支汇聚健康探测（进程内，I-13）
                                                  └─ BFF 透传：Arkime / OpenSearch / correlator / soar
多分支汇聚层 Kafka :9092 (主题 ssp-raw)
采集端  Filebeat(总部 hq) + Filebeat(分支 sh-01/bj-01) ──▶ Kafka ──▶ Logstash :5044(ECS 归一) ──▶ OpenSearch :9200
存储检索  OpenSearch :9200（事件 ssp-<源>-日期 / 告警 ssp-alerts）· Arkime :8005（会话/PCAP，直连同一集群）
关联分析  correlator :8091（纯标准库，R-001~R-007，分级 P0~P3）
落黑执行  soar :8092（privileged，iptables 宿主链 SSP_BLACKLIST）
```

**业务库 9 张表**：`users` `sessions` `assets` `asset_candidates` `branches` `soar_drafts` `blacklist` `config` `audit_log`

**端口速查**：前端 8088 ｜ portal 8093 ｜ correlator 8091 ｜ soar 8092 ｜ OpenSearch 9200 ｜ Arkime 8005 ｜ Kafka 9092 ｜ Logstash(beats) 5044 ｜ PostgreSQL(宿主) 5433

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

---

## 5. 待办与阻塞项

### I-14 流式关联与外部日志源适配（事项 `rVgO1S`）
- **前置已满足**：I-13 Kafka 汇聚层在位 → 加消费者即可，**采集侧零改动**
- **待拍板**：D1 实现形态（Flink / 轻量消费者 / 先轻量后重型）｜D2 首个外部源类型（防火墙 syslog / WAF / AD）｜
  D3 优先级（流式关联 L1 vs 外部源适配 L2）｜D4 绝对排期
- **拟新增验收**：A16 流式时延 ≤5s、A17 幂等与批式共存、N12 消费者中断不丢事件、N13 外部源关闭无副作用

### I-15 项目上下文补齐（事项 `rUYkpk`）
- 现状：`需求文档/` 仅 PRD、`系统文件/` 为空 → 拟交付 9 份（验收类 4 + 运维类 5）
- **待确认**：优先级（建议先验收类）、`项目计划/` 目录是否保留、`资产库使用指南.pdf` 是否移入 `系统文件/`、是否转 Word/PPT、绝对排期

---

## 6. 文档与资产索引

| 内容 | 位置 | 标识 |
|---|---|---|
| PRD | 资料库 `需求文档/` | file_id `JFHDdSUPpRLV` |
| 技术方案 I-01~I-13 | 资料库 `技术方案/` | 见各事项评论（I-01~I-09 附 PRD/ECS 映射交叉引用） |
| 计划 I-14 / I-15 | 资料库 `项目计划/`（2026-09-29 新建） | `JHjVMqqGwIvm` / `JrzgWlkultmg` |
| ECS 字段映射 | 资料库 `技术方案/` | `JrndPbPfvoRs` |
| 平台技术问答 FAQ | 资料库 `技术方案/` | `JqYKCypXGHdW` |
| 资产库使用指南 | 资料库根 | `JcCytangqOwN`（建议移入 `系统文件/`） |
| 项目事项 | wb-issues | I-01~I-13（done）＋ I-14 `rVgO1S` / I-15 `rUYkpk`（待开始） |
| 本机项目记忆 | `.workbuddy/memory/`（**不进 git**） | `MEMORY.md` + 每日日志 |

---

## 7. 新 agent / 新会话「开工必读」顺序

1. **本文件**（现状、约定、待办）
2. `README.md`（架构与常用命令）
3. `docs/` 下与本次任务相关的技术方案 1~2 份
4. `.workbuddy/memory/MEMORY.md`（本机项目长期约定；**仅本机可见**）
5. 对应事项的评论（有逐迭代的实测证据与提交号）

> ⚠️ 若新任务的工作目录**不是**本项目目录（如 `~/WorkBuddy/<时间戳>`），将读不到 `.workbuddy/memory/`；
> 此时以本文件 + 资料库 + 事项评论为准，并**先把工作目录切到本项目**。

---

## 8. 常用命令

```bash
make init        # 建业务库表 + 种子账号 + 登记默认分支
make up / down   # 起停全部服务（含 Kafka 汇聚层与分支代理）
make templates   # 下发 ECS/告警索引模板
make demo        # 回放演示数据（总部 + 分支）
make verify      # 端到端验收（当前 16/16）
make health      # 各服务健康
make branch-status            # 查看各分支上报状态
make branch-down B=sh-01      # 模拟某分支断链
make pg-up / pg-init / pg-portal / pg-stop   # PostgreSQL 后端切换
```

**默认账号**：`admin` / `ops` / `analyst` / `asset`（资产管理员），初始口令 `REDACTED-SSP-PWD`（**生产须轮换**）

---

## 9. 本文件与其他记忆层的关系

| 层 | 载体 | 可见范围 |
|---|---|---|
| 云端记忆 | 服务端画像 | 跨设备（仅偏好，不含项目内容） |
| 本地用户记忆 | `~/.workbuddy/MEMORY.md` | 本机、跨项目（个人习惯） |
| 项目工作区记忆 | `.workbuddy/memory/` | **本机、同工作目录的 agent**（不进 git） |
| **项目共享真相源** | **本文件 + 资料库 + 事项评论** | **所有成员 / agent / 机器** |

> 约定：**结论进本文件与资料库，过程留在 `.workbuddy/memory/`**。本文件是权威，冲突时以本文件为准。
