# I-08 POC 验收 Demo —— 端到端闭环（技术方案 / 验收报告）

> 目标：按 PRD §9 验收标准（EARS）逐条驱动**真实链路**并断言，端到端跑通
> 「探针告警 → 情报匹配 → 人工审批拉黑 → 大屏可见」闭环。
> 一键入口：`python3 scripts/acceptance-demo.py`

---

## 1. 闭环流程（与 PRD §6 对应）

```
① 探针事件 ──Filebeat──▶ Logstash(ECS 归一 + GeoIP 富化) ──▶ OpenSearch ssp-events
        (演示集 logs/demo → 暂存区 logs/demo-stage 回放)
                                    │
② 关联分析 correlator(7 规则) ◀─────┘   + 威胁情报(MISP/种子) 实时比对
        └──▶ ssp-alerts（分级 P0~P3 + SLA + related.geo_points）
                                    │
③ SOAR 剧本（周期 60s）◀────────────┘  达级别(P0)告警 → 生成**拉黑草稿**（不自动提交）
        └──▶ ssp-soar-drafts(status=pending_approval)
                                    │
④ 运维在 ui/soar.html 审批 ──────────┘  approve → blocker(本机 iptables, 宿主 netns SSP_BLACKLIST)
        └──▶ 回写 ssp-alerts: status=blocked / resolved_at / response_action
                                    │
⑤ 态势大屏 ui/dashboard.html ◀────────┘  攻击地图 / 告警TOP / 资产热力 / SLA 达成率 刷新
```

## 2. 验收项 ↔ PRD §9（EARS）映射

| 步骤 | 覆盖的 EARS 条目 | 断言（脚本实测） |
|------|------------------|------------------|
| **A1** 采集归一 | Ubiquitous：统一以 ECS 存储所有探针事件 | `ssp-events ≥ 24`；样本含 `@timestamp`/`event.kind`/`fields.log_source`；来源 = suricata/zeek/wazuh |
| **A2** 关联告警 | Event-driven：检测到攻击→生成统一告警写入 OpenSearch | `/correlate` 正常返回；R-001~R-007 有命中；`ssp-alerts > 0` |
| **A3** 情报匹配 | Event-driven：源IP/域名/哈希与情报实时比对并标注 | `threat.matched=true` 的告警 > 0，列出命中指标 |
| **A4** 情报降级 | Unwanted：MISP 不可达仍照常告警、不阻断 | 以不可达 MISP 重建 correlator 后 `/correlate` 正常、告警仍产生，`threat.misp_configured=true & misp_unreachable=true` |
| **A5** 分级 SLA | State-driven：按级别统计 SLA | 实测 `grade→sla_seconds` = P0 30 / P1 60 / P2 600 / P3 1800 |
| **A6** 草稿生成 | State-driven：达级别生成草稿；**系统不应自动提交** | 生成待审批草稿；**前后 iptables 规则数不变** |
| **A7** 人工审批 | Event-driven：运维确认→执行落黑并回写，大屏可见 | iptables 链含该 IP；告警 `status=blocked`、写 `resolved_at`/`response_action` |
| **A8** 大屏四视图 | Ubiquitous：展示攻击地图/告警TOP/资产热力/SLA | 四类数据源均非空；页面 HTTP 200 |

> 资产相关条目（"资产导入→热力刷新"、"Excel 导入失败回滚"）由 **I-06** 的实测覆盖，见
> `docs/I-06-统一资产库-技术方案.md`；本 Demo 复用其资产库作为"资产热力"数据源。

## 3. 运行方式

```bash
# 全量验收（会重放演示数据 → 关联 → 情报 → 草稿 → 审批落黑 → 大屏）
python3 scripts/acceptance-demo.py

python3 scripts/acceptance-demo.py --no-replay     # 复用现有事件，不重放
python3 scripts/acceptance-demo.py --skip-misp     # 跳过 A4（不重启 correlator）
python3 scripts/acceptance-demo.py --reset         # 仅复位（解除封禁 + 清草稿）后退出
```

脚本行为：开始先**复位**（解除全部 iptables 封禁、清理 `ssp-soar-drafts`），
避免上一轮状态残留；退出码 `0`=全通过。

## 4. 实测结果（macOS / Docker Desktop，2026-09）

```
✔ A1  采集归一      PASS   ssp-events=24，ECS 字段齐全，来源=['suricata','zeek','wazuh']
✔ A2  关联告警      PASS   命中 R-001:3 R-002:3 R-003:4 R-004:2 R-005:1 R-006:3 R-007:3；ssp-alerts=17
✔ A3  情报匹配      PASS   命中告警=8 条；指标=['203.0.113.45','evil-c2.example.com',
                           'malware-download.example.net','9f2a7c1e…7d19']
✔ A4  情报降级      PASS   MISP 不可达时告警仍产生；threat={misp_configured:true, misp_unreachable:true}
✔ A5  分级 SLA      PASS   {P0:30, P1:60, P2:600, P3:1800}
✔ A6  草稿生成      PASS   待审批草稿=3；iptables 规则数 0→0（未自动提交）
✔ A7  人工审批落黑  PASS   封禁 185.220.101.5 生效；告警 status=blocked；审批耗时 0.03s
✔ A8  大屏四视图    PASS   ①攻击地图 8 点 ②分级 P0:12/P1:3/P2:1/P3:1 ③资产 10 项 ④SLA 见 A5
----------  8/8 通过  ----------
```

**闭环时延（告警生成 → 拉黑提交）= 12.803 s**（度量口径见 PRD §13）。
> 该时延主要来自"等待人工审批"的演示节奏 + 索引刷新，非系统处理瓶颈；
> 落黑动作本身（nsenter + iptables）耗时 **0.03 s**。

**落黑证据**（主机 netns 自定义链）：

```
$ curl -s localhost:8092/soar/blocks
{"ok":true,"exists":true,"chain":"SSP_BLACKLIST",
 "rules":[{"ip":"185.220.101.5","direction":"src",
           "spec":"-A SSP_BLACKLIST -s 185.220.101.5/32 -j DROP"}]}
```

**回写证据**（`ssp-alerts`，_id = sha1(rule_id+entity_key)）：

```json
{ "ssp": { "alert": { "rule_id": "R-002", "grade": "P0", "status": "blocked",
  "resolved_at": "2026-09-19T19:56:49.355Z",
  "response_action": "block:iptables:SSP_BLACKLIST" } } }
```

## 5. 演示脚本清单（复用）

| 脚本 | 作用 |
|------|------|
| `scripts/acceptance-demo.py` | **I-08 一键验收**（本轮新增） |
| `scripts/replay-demo.sh` | 回放/复位演示数据集（清索引 + 重建 filebeat + 触发关联） |
| `scripts/gen-demo-data.py` | 生成多国团伙攻击演示集（真实可定位公网 IP） |
| `scripts/gen-world-map.py` | 生成大屏攻击地图底图资产 |

## 6. 踩坑记录

- 🐞 **断言不能"审批完立刻查库"**：OpenSearch `index.refresh_interval=1s`，
  审批后 0.02s 查询会读到**旧版本**（表现为"iptables 已生效但 status 仍 open"，
  极易误判为回写 Bug）。**对策**：查询前 `POST /ssp-alerts/_refresh` 并**轮询等待**
  （见 `acceptance-demo.py` A7）。
- 🐞 **`docker compose up` 不支持 `-e`**（那是 `docker run`/`compose run` 的参数）。
  要给某服务临时注入环境变量做降级演练，需写 **compose override 文件** 并用
  `docker compose -f base.yml -f override.yml up -d --force-recreate <svc>`，
  演练完再用原文件重建还原（A4 采用此法）。
- ⚠️ **演练 `dry_run` 与真实落黑要分清**：审批接口支持 `dry_run`（只记录不执行）。
  验收必须用 `dry_run=false`，否则"落黑"是假的（A7 显式传 `dry_run:false`）。

## 7. 与后续事项的接口

- **I-09 测试用例**：本 Demo 的 A1~A8 即验收用例的"正例"骨架；I-09 在此基础上补齐
  **反例/边界**（MISP 不可达已由 A4 覆盖；其余如探针断连、审批超时、落黑失败、Excel 导入失败）。
- **落黑失败路径**（PRD §10）：`blocker` 失败时 SOAR 保持草稿未闭环、告警保持 `open`（待处置），
  该分支由 I-09 的反例用例覆盖。
