# 一体化安全态势感知平台 · 技术问答（FAQ）

> 适用范围：本平台 POC（技术预研）阶段，x86 私有化交付，单人 OPC 模式。
> 本文汇总平台架构、工程化、部署与排障中的高频技术问题，配合 `技术方案/` 下 I-01~I-10 各组件文档使用。

---

## 一、平台定位与验收

**Q1. 这个平台是什么？目标是什么？**
一体化安全态势感知平台，目标是把"探针采集 → 存储检索 → 关联分析 → 资产/情报 → SOAR → 态势大屏"整条链路在同一个平台内闭环，让安全运营人员在一个界面里完成监测、研判、处置与大屏巡览，而不是各系统各自为政、来回跳转第三方控制台。

**Q2. POC 验收标准是什么？**
端到端跑通「探针告警 → MISP 情报匹配 → Shuffle 人工审批拉黑 → 大屏可见」这一主链路，并满足 PRD §9 的 EARS 断言（A1~A8）。

**Q3. 为什么说"一体化"是核心要求？**
第一轮交付被用户判定"没达标"：Arkime 流量回溯、OpenSearch Dashboards 仍是 `target=_blank` 外跳到第三方控制台。返工后定案为：统一形态＝**同站 SPA + 统一导航 + 平台原生重建**；第三方能力（Arkime 流量、OpenSearch 检索）一律在平台内重建，浏览器只连平台自己的后端（BFF `:8093`）。

---

## 二、总体架构

**Q4. 端到端数据链路是怎样的？**
```
探针(Suricata/Zeek/Wazuh)
   → Filebeat（只投递）
   → Logstash（ECS 归一，落 ssp-<log_source>-YYYY.MM.dd）
   → OpenSearch（存储 + 统一检索 ssp-events）
   → correlator(:8091) 关联分析 → ssp-alerts
   → threat_intel(MISP) 情报匹配（命中即 P0）
   → SOAR(:8092) 生成草稿 → 人工审批 → 宿主 iptables 落黑
   → 态势大屏（四视图）
Arkime 独立存储 PCAP/会话，经 BFF 代理进平台"流量回溯"页
```
前端 `ui/`（SPA）统一经 nginx `:8088` 同源反代到 BFF `:8093`，不直接连任何上游。

**Q5. 关联大脑为什么用 Wazuh+OpenSearch+MISP+Shuffle，而不是 Apache Metron？**
POC 阶段追求轻量、可单机私有化、易排障。Metron 依赖 Kafka/Storm 重集群，运维成本高；而 Wazuh 产出 ECS 对齐的告警、OpenSearch 做存储检索、MISP 做情报、Shuffle 做审批剧本，全用标准库/轻量服务即可满足关联+SOAR 闭环，且都面向 x86 私有化。**关联引擎（correlator）是平台自研纯标准库服务**，不绑定 Metron。

**Q6. 各组件分别承担什么职责？**
- **Filebeat**：轻量采集，只负责把日志投递给 Logstash，不做加工。
- **Logstash**：ECS 字段归一（含 GeoIP  enrichment），写 OpenSearch 按 `log_source` 分索引。
- **OpenSearch**：统一存储与检索（`ssp-events` 别名聚合事件索引）；另存 `ssp-alerts`/`ssp-asset` 等。
- **Arkime**：PCAP 与会话存储层，直连同一 OpenSearch 集群，不走 Logstash 管道。
- **correlator(:8091)**：关联规则引擎 R-001~R-007，输出分级告警 `ssp-alerts`。
- **threat_intel**：本地种子 + MISP 双通道情报匹配（惰性导入，缺失即降级）。
- **SOAR(:8092)**：剧本生成草稿、人工审批、调 blocker 写宿主 iptables 落黑、回写告警。
- **portal(BFF, :8093)**：统一后端，代理 Arkime/OpenSearch/关联/资产/SOAR，并提供 `/api/auth/*` 登录会话。
- **ui(SPA, :8088)**：统一前端，5 个视图 + 统一登录。

**Q7. 部署是怎么编排的？为什么每个服务一个 compose？**
采用 **per-service compose + `include`**：根 `deploy/compose.yml` 是唯一入口，用 `include:` 聚合各 `deploy/<服务>/compose.yml`，并统一定义 `network: ssp` 与 `volume: os-data`。每个服务独立目录便于并行开发与单服务重建，被 include 的文件内相对路径以自身目录为基准（跨级用 `../../`）。约定：**并行流禁止 `docker compose down`**（会杀掉别人的容器），共享根 compose 只做不同锚点的单行插入。

---

## 三、采集与归一（I-01 / I-02）

**Q8. Filebeat 和 Logstash 各自做什么？**
Filebeat 只投递原始日志（含演示数据经 `scripts/replay-demo.sh` 复制到暂存区后被采集）；Logstash 做 ECS 归一与 GeoIP 富化，按 `ssp-<log_source>-YYYY.MM.dd` 写索引，套用模板 `ssp-ecs`。

**Q9. 索引和别名怎么命名？为什么严禁通配 `ssp-*` 别名？**
事件索引物理名 `ssp-suricata-*/ssp-zeek-*/ssp-wazuh-*`，统一检索通过别名 `ssp-events`（模板 `ssp-ecs` 的 `index_patterns` 已收敛到这三类）。严禁建 `ssp-*` 通配别名——它会把 `ssp-asset`/`ssp-alerts` 等非事件索引也挂进 `ssp-events`，既污染统一检索口径，又让关联引擎读到自己写出的告警形成**自反馈循环**。另注意：**索引名不得等于别名名**（OpenSearch 报 `duplicates ... conflicts with index`）。

**Q10. 为什么 `ssp-events` 有时候是空的（Filebeat 显示 acked 但查不到）？**
最隐蔽的根因在 GeoIP：`scripts/patch-mmdb-type.py` 未对 DB-IP 库做 `database_type` 改写时，OSS Logstash 的 `geoip` 过滤器因白名单不含 `DBIP-City-Lite` 抛 `Unsupported database type` 并**停掉整条 pipeline**——事件被 Filebeat acked 却未写入，表现为 `ssp-events` 恒 0。对策：用 `scripts/patch-mmdb-type.py` 把 `database_type` 改写为 `GeoLite2-City`（数据与许可证不变）。GeoIP 失败时还需 `tag_on_failure` + 失败 `remove_field` 防 `mapper_parsing_exception` 丢事件。

**Q11. 告警索引 `ssp-alerts` 为什么静默丢字段？**
告警模板是 `dynamic:false`，未在模板里显式声明的字段会被**静默丢弃**（例如后来加的 `related.geo_points` 汇总坐标）。新增字段必须先在索引模板显式声明 mapping，否则检索/绘图取不到。

---

## 四、关联分析与情报（I-03 / I-04）

**Q12. 关联引擎有哪些规则？怎么分级？**
R-001 跨源外部 IP / R-002 SSH 暴破 / R-003 载荷下载 / R-004 FIM / R-005 外联聚合 / R-006 IDS 签名 / R-007 C2 域名。分级 P0(秒级)/P1(60s)/P2(600s)/P3(1800s)；升级因子：命中重要资产升 1 档，情报命中直接 P0。输出索引 `ssp-alerts`（**物理名、不设别名**），`_id=sha1(rule_id+entity_key)` 幂等 upsert，保留人工 `status/response_action`。

**Q13. 情报命中为什么直接置 P0？**
威胁情报命中代表高置信恶意（如已知 C2 域名、恶意 IP、恶意样本哈希），按处置优先级应立即进入最高级响应，故关联引擎在情报命中时强制 P0。

**Q14. MISP 挂了会不会阻断整个平台？**
不会。`threat_intel` 对 MISP 调用做了降级：超时 3s + 缓存 300s + 连接失败熔断 60s；MISP 不可达时本地种子情报仍生效，告警照常产生（验收项 A4 已验证：`threat.misp_configured=true & misp_unreachable=true`）。

---

## 五、资产与 SOAR（I-05 / I-06）

**Q15. 资产从哪来？Excel 导入失败会怎样？**
来源为手工录入 + Excel 导入（无 CMDB）。导入遵循**「全成或全败」**：逐行校验，任一非法整批拒绝并返回逐行报错，不写入任何文档（验收项 N4 验证：含非法行的样本导入后资产数 10→10 不变）。

**Q16. SOAR 落黑点是怎么实现的？为什么用 `nsenter`？**
落黑点是**宿主（Docker VM）netns 的 iptables 自定义链 `SSP_BLACKLIST`**（从 `DOCKER-USER` 挂跳转）。macOS 无 iptables，且 Docker Desktop 的 `--network host` 端口不外发，故采用 **bridge 容器 + `nsenter -t 1 -n iptables`** 写宿主 netns，需 `pid:host` + `privileged:true`（仅加 cap 不够）。

**Q17. 为什么"草稿只生成、不自动提交"？**
安全处置必须人工确认。剧本只生成 `ssp-soar-drafts` 草稿，审批/驳回/解除走 API + 409 状态机；未审批前绝不自动提交落黑（验收项 A6/N2 已验证：待审批草稿存在但 iptables 规则数不变）。

**Q18. 审批后为什么有时查不到回写结果？**
OpenSearch 默认 `refresh_interval=1s`，审批后立刻查询可能读到旧版本，表现为"iptables 已生效但 `ssp-alerts` 里 `status` 仍 `open`"。对策：审批写入后 `POST /ssp-alerts/_refresh` 并轮询等待再断言。

---

## 六、态势大屏（I-07）

**Q19. 大屏展示哪四个指标？**
攻击地图、告警 TOP、资产热力、SLA 达成率（告警分级 SLA＝P0 秒级 / P1 1 分 / P2 10 分 / P3 30 分）。

**Q20. 攻击地图的底图和数据从哪来？**
底图用 Natural Earth 1:110m 等距圆柱投影的 `ui/assets/world-land.svg`（**无 CDN 依赖**）；坐标来自 ECS `source.geo.location`/`destination.geo.location`，关联引擎经 `geo_index()` 透传并汇总进 `related.geo_points`（含 R-005 外联聚合的多个目的 IP）。GeoIP 全链路：Logstash `geoip`（DB-IP 库）→ ECS → correlator 透传 → 大屏绘图。

**Q21. 数据源健康（绿/黄/红）怎么判定？**
correlator 的 `GET /sources/health` 按 `fields.log_source` 聚合各源最新事件时间，以"相对**全局最新事件**的滞后"判定 `ok/stale/down`（`SOURCE_STALE_MINUTES` 默认 15m）。用相对陈旧度而非绝对当前时间，故**历史数据重放同样适用**。大屏顶部渲染「数据源 ●suricata ●zeek ●wazuh」。

---

## 七、统一平台与前端工程化（I-10）

**Q22. 为什么要做"前端工程化"（SPA）而不是散落 HTML？**
散落多页（`ui/dashboard.html` 等）各写各的 JS、外跳第三方、无统一登录与权限，既难维护也不满足"一体化"。返工后改为**原生 ES Modules SPA（无构建步骤）**：`ui/index.html` 入口 + `ui/src/` 模块化（main/router/layout/session/perms/api/utils + `pages/*`），适合 x86 私有化交付（无需 node 构建链），并统一登录、会话、角色权限。旧的 `ui/*.html` 与 `ui/assets/nav.js` 已删除。

**Q23. 统一登录/会话/角色是怎么实现的？4 个角色权限矩阵？**
BFF `services/portal/portal_server.py` 提供 `/api/auth/*`（login/logout/me）：会话用 **HttpOnly Cookie `ssp_sid`**，密码 **PBKDF2** 哈希（由 `scripts/gen-portal-user.py` 生成，存 `services/portal/users.json`）。4 角色（PRD §11）：`admin`(技术负责人)/`ops`(运维值班)/`analyst`(安全分析师)/`asset_admin`(资产管理员)。写权矩阵 `perms.canWrite(key)`：
- 资产 `asset` → `admin` + `asset_admin`
- SOAR `soar` → `admin` + `ops`
- 流量回溯 `traffic` → `admin` + `ops` + `analyst`
- 其余（检索/关联/大屏）→ 仅 `admin` 可写（实际这些视图以读为主）

OpenSearch 的 `_search`/`_count` 在后端视为**读**操作，不触发写权限校验。

**Q24. 前端为什么只连一个后端（BFF :8093）？同源反代解决什么？**
所有 OpenSearch/Arkime/关联/资产/SOAR 调用都经 BFF 通用透传（`/api/os|corr|asset|soar/*`），Arkime 专用逻辑在 `/api/traffic/*`（服务端 digest 鉴权 + 参数翻译）。nginx `:8088` 把 `/api/` **同源反代**到 `portal:8093`，使会话 Cookie 成为第一方 Cookie，**规避跨域 CORS / SameSite 痛点**，浏览器永不直连上游。

**Q25. Arkime / OpenSearch 为什么不能浏览器直连、必须服务端代理？**
关键看组件**是否发 CORS 头**：Arkime 用 digest 鉴权且**不发 CORS 头**，浏览器 `fetch` 直连会被同源策略拦截，这是"只能跳出去"的技术根因——必须服务端代理。OpenSearch 同理经 BFF 透传。

**Q26. 平台内下钻（检索结果 → 流量回溯）是怎么实现的？**
统一检索结果里外网 IP 带「⇄ 流量」入口，大屏攻击地图散点可点击，均跳本平台 `#/traffic?ip=&start=&end=`（hash 路由），在平台内"流量回溯"页用同一 BFF 拉 Arkime 会话，不再外跳第三方。

**Q27. Arkime PCAP 导出为什么会是 0 字节？最隐蔽的坑。**
Arkime 的**节点名＝容器 hostname**，写进会话/文件 `node` 字段；单节点取包用 `isLocalView(node)` 判断，不一致就**代理到 `http://<node>:8005`**。容器重建后 hostname 变成新容器 ID → 与历史数据 node 不匹配 → `getaddrinfo ENOTFOUND` → **导出恒为空**。对策：`deploy/arkime/compose.yml` 固定 `hostname: arkime` + `extra_hosts`，清 `arkime_sessions3-*`/`arkime_files_v30` 后重导。修复后全量/按 IP 导出均为合法 pcap。

---

## 八、运维与验收

**Q28. 怎么跑端到端验收（A1~A8）？**
`scripts/acceptance-demo.py`（纯标准库，一键，退出码 0/1）：A1 采集归一 / A2 关联告警 / A3 情报匹配 / A4 情报降级 / A5 分级 SLA / A6 草稿生成·不自动提交 / A7 人工审批落黑回写 / A8 大屏四视图。**实测 8/8 通过**，闭环时延约 12.8s。

**Q29. 有哪些反例/边界测试（N1~N4）？**
`scripts/test-cases.py`（纯标准库）：N1 探针断连（删 `ssp-wazuh-*`→health 标 `down`、其他源不变）/ N2 审批超时（不审批→草稿仍 `pending`、不落黑）/ N3 落黑失败（注入 `SSP_HOST_PID=999999`→nsenter 必败、告警保持 `open`）/ N4 Excel 导入回滚（含非法行→422 + 整批不写）。**实测 5/5 全通过**。

**Q30. 怎么重放演示数据？**
演示数据在 `logs/demo/`（真实可定位公网 IP，标记 `fields.demo="true"`），由 `scripts/replay-demo.sh` 复制到 `logs/demo-stage/` 才被 Filebeat 采集（暂存区 gitignore）。注意 `docker compose restart` 不清 Filebeat 读取位点，要重放必须 `up -d --force-recreate`。

**Q31. 怎么新增/重置平台账号？**
用 `scripts/gen-portal-user.py`（PBKDF2）生成账号条目，写入 `services/portal/users.json`（4 个内置账号：admin/ops/analyst/asset_admin）。改完重启 portal 服务生效。

**Q32. GeoIP 库怎么更新？**
OSS Logstash 无 GeoLite2，统一用 **DB-IP Lite City**（免费无需账号）。经本机代理从 jsDelivr 镜像拉取：
`https://cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz`（实测 ~15MB/s）。下载后务必跑 `scripts/patch-mmdb-type.py` 把 `database_type` 改写为 `GeoLite2-City`，否则 Logstash pipeline 会被停。

---

## 九、本机环境速查（开发/排障）

- docker CLI 在 `/usr/local/bin/docker`，沙箱 PATH 不含 → 命令前 `export PATH=/usr/local/bin:$PATH`。
- 本机真实代理端口 `127.0.0.1:7897`（旧 7890 已失效）；本机访问一律 `--noproxy '*'`（否则 `curl` 走代理发绝对 URI 请求行被 Express 判 400）。
- Compose 解析期会插值 healthcheck 里的 `$VAR` → 字面 `$` 须写 `$$`。
- busybox `wget` 遇 401 退出码是 6（非 8），鉴权类 healthcheck 一并放行 6。
