# I-01 探针统一接入与 ECS 归一 —— 技术方案

> 关联需求：F-01（探针统一接入）、F-02（统一事件 Schema / ECS 归一）
> 阶段：POC ｜ 部署形态：x86 私有化、单机 Docker Compose ｜ 关联 PRD：`docs/PRD-...Phase1.md` §5、§12

## 1. 目标
把 Suricata、Zeek、Wazuh 的原始日志统一接入，并按 **ECS 公共 Schema** 归一到同一个 OpenSearch 集群，形成"统一入湖"的数据底座，为后续关联分析（I-03）、情报匹配（I-04）、大屏（I-07）提供标准化事件。

**本切片验收**：四类探针（Suricata / Zeek / Wazuh + Arkime 存储层）事件统一入湖，公共字段（`@timestamp`/`event.*`/`source.ip`/`destination.ip`/`rule.*`）可跨源统一检索。

## 2. 架构与数据流

```
                         ┌──────────────── Logstash:5044 (beats) ────────────────┐
Suricata  eve.json  ─┐   │  00-inputs → 10-suricata / 20-zeek / 30-wazuh → 99-out │
Zeek      *.log     ─┼─ Filebeat ─┤  （按 fields.log_source 分流 + ECS 映射）      ├─► OpenSearch
Wazuh     alerts.json┘   └───────────────────────────────────────────────────────┘   ssp-<src>-YYYY.MM.dd
                                                     ▲
Arkime（全流量 PCAP）── 直连同一 OpenSearch 集群（存储层接入，不经 Logstash）
```

- **采集**：Filebeat 只负责投递，按 `fields.log_source` 给每类日志打标。
- **归一**：Logstash 按来源分流，解析 JSON → 映射 ECS → GeoIP 富化 → 按来源分索引写入。
- **存储**：OpenSearch；索引命名 `ssp-<log_source>-YYYY.MM.dd`，套用 `ssp-ecs` 索引模板（ip/geo_point/long 等类型）。
- **Arkime**：以全流量存储为主，直接写入同一 OpenSearch 集群，不经 Logstash（详见 §5）。

## 3. 组件职责边界
| 组件 | 角色 | 接入方式 |
|---|---|---|
| Suricata | 已知攻击实时告警（`event_type=alert`）+ 协议上下文事件 | eve.json → Filebeat → Logstash |
| Zeek | 会话/协议行为上下文（溯源、狩猎、资产测绘） | *.log(JSON) → Filebeat → Logstash |
| Wazuh | 主机侧 HIDS/EDR 告警（登录、FIM、账号） | alerts.json → Filebeat → Logstash |
| Arkime | 全流量存储与 PCAP 检索 | 直连 OpenSearch（存储层） |

## 4. 目录结构
```
deploy/
  docker-compose.yml          # POC 单机编排：OpenSearch / Dashboards / Logstash / Filebeat
  filebeat/filebeat.yml       # 采集投递配置（三个 input）
config/
  logstash/pipelines.yml      # 单管线，加载 conf.d
  logstash/conf.d/
    00-inputs.conf            # beats 入口
    10-suricata.conf          # Suricata → ECS
    20-zeek.conf              # Zeek → ECS
    30-wazuh.conf             # Wazuh → ECS
    99-outputs.conf           # OpenSearch 分索引输出
  opensearch/ssp-ecs-template.json   # ECS 索引模板
logs/                         # 样本日志（suricata/zeek/wazuh），供离线自测
scripts/
  apply-ecs-template.sh       # 下发索引模板
  verify-ingest.sh            # 校验入湖
docs/
  I-01-探针接入与ECS归一-技术方案.md   # 本文
  ecs-field-mapping.md        # 各源字段 → ECS 映射表
```

## 5. Arkime 为何不经 Logstash
Arkime 的核心价值是**全流量 PCAP 存证与检索**，它把流量元数据写入自身的 OpenSearch 索引（`arkime_sessions3-*`），不是逐条日志。因此 I-01 对 Arkime 的"接入"= 让它与采集管道**共用同一个 OpenSearch 集群**（配置 `db=opensearch`、指向同一节点），并暴露其 Viewer。这样大屏/检索可同时命中"归一事件"与"原始流量会话"。

## 6. 部署与验证（在 x86 目标机执行）
```bash
cd deploy
docker compose up -d
../scripts/apply-ecs-template.sh          # 下发 ssp-ecs 索引模板
docker compose ps                          # 等待 opensearch healthy
../scripts/verify-ingest.sh                # 校验四类事件入湖（默认等 20s）
```
**预期结果**：
- `_cat/indices/ssp-*` 出现 `ssp-suricata-*`、`ssp-zeek-*`、`ssp-wazuh-*`；
- 各来源 `_count` > 0（样本：Suricata 4 条、Zeek 3 条、Wazuh 2 条）；
- 抽样文档含统一字段 `event.module` / `event.kind` / `source.ip` / `destination.ip` / `rule.*`。

接入真实探针时，把各自的输出目录挂载/指向 Filebeat 的 `paths` 即可，无需改归一逻辑。

## 7. 本次完成度与验证（已在本地 Docker 实测通过）
- ✅ 已实装：采集（Filebeat）、归一（Logstash 4 份 conf）、存储（ECS 索引模板）、样本日志、部署与验证脚本。
- ✅ 静态机检通过：JSON/NDJSON 样本、OpenSearch 模板、3 份 YAML、5 份 Logstash conf 括号配平；`docker compose config` 通过。
- ✅ **端到端实测通过**（Docker Desktop，2026-09-19）：
  - 索引 `ssp-suricata-2026.09.19`=4、`ssp-zeek-2026.09.19`=3、`ssp-wazuh-2026.09.19`=3；
  - 跨源聚合 `event.module` = {suricata:4, zeek:3, wazuh:3}，`event.kind` = {event:6, alert:4}；
  - 三源抽样均含统一字段 `event.module` / `event.kind` / `event.category` / `source.ip` / `destination.ip`。
- 🐞 **实测发现并修复的 Bug**：OSS 版 Logstash 未内置 GeoLite2 库，GeoIP 查找失败后仍写入空的 `[source][geo]`，被 `geo_point` 类型拒绝（400 `mapper_parsing_exception`），导致**带源 IP 的事件全部被丢弃**。修复：`geoip` 显式设 `tag_on_failure`，失败时 `remove_field => ["[source][geo]"]`（三份 conf 同步修改，已复测通过）。
- ⚠️ **地理富化（攻击地图）需补 DB**：OSS 镜像不含 `GeoLite2-City.mmdb`，故当前 `source.geo` 为空（已被正确移除）。启用地图需提供 DB 文件并设 `geoip { database => "..." }`，否则不产出坐标。
- ✅ 镜像 tag：`logstash-oss-with-opensearch-output-plugin:7.16.3` 实测可拉取（arm64/x86 均有）。

## 8. 与 ECS 的差异说明（POC 取舍）
- `event.severity` 暂存数值/等级字符串，未做 ECS 数值型规范，待 I-03 关联分级时统一。
- `rule.category`：Suricata 取 `alert.category`；Wazuh 取 `rule.groups`（数组），POC 先原样落库。
- 未引入 ILM/rollover（POC 用日索引 + `manage_template=false`），生产再补生命周期管理。

## 9. 后续衔接
- **I-02**：OpenSearch 检索入口、Logstash 富化增强、PCAP 检索回溯（Arkime）。
- **I-03**：基于统一 ECS 事件做轻量关联规则。
- 生产化：安全插件/TLS/鉴权、ILM、多分支汇聚（R-12'）、外部日志源适配器（R-15）。
