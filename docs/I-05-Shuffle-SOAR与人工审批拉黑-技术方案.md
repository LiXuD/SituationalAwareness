# I-05 Shuffle SOAR + 人工审批拉黑 —— 技术方案

> 版本：v1.0 ｜ 阶段：POC ｜ 对应功能：F-10（含人工审批）
> 关联：PRD §6.2–6.4 / §7 / §10；`docs/I-03-轻量关联分析-技术方案.md`、`docs/I-04-MISP威胁情报对接-技术方案.md`
> 状态：**已实现并实测通过**

## 1. 目标与范围
实现响应层闭环：**关联告警 → 自动生成拉黑草稿 → 人工审批 → 执行落黑 → 回写大屏可见**。

- **落黑点（PRD §6.4 三选一）→ 选定「本机 iptables」**（另两项：防火墙 API / 动态写 Suricata 规则）。
- 实现方式：独立服务 `services/soar/`（纯标准库），等价于「Shuffle 剧本 + 审批节点」的轻量实现；
  生产可平滑替换为真实 Shuffle，剧本逻辑与接口不变。

## 2. 铁律：不得自动提交（EARS State-driven）
> 「当告警达到自动处置级别时，Shuffle 应生成拉黑草稿；**系统不应自动提交**，除非运维人员确认。」

- 周期剧本（`SOAR_INTERVAL_SECONDS`，默认 60s）**只生成草稿**（`status=pending_approval`）；
- 任何封禁动作只能由 `POST /soar/drafts/{id}/approve` 触发，且该接口由**人工**在审批界面点击调用；
- 实测：生成草稿后 `iptables` 自定义链**不存在 / 为空**，证明未自动提交。

## 3. 落黑实现：宿主 netns 自定义链
本机为 macOS，iptables 仅存在于 Docker Desktop 的 Linux VM。方案：

```
soar 容器（bridge，:8092，可被浏览器访问）
   └─ nsenter -t 1 -n iptables ...      # 进入宿主(VM)网络命名空间
         └─ 自定义链 SSP_BLACKLIST  ←── DOCKER-USER 挂一跳转
```
- **独立自定义链**：只增删本链规则，可查、可回滚，不污染 `DOCKER-USER` 等系统链；
- 链为空时跳转为 no-op，不影响平台自身网络；
- 需 `pid: host` + `privileged: true`（实测仅 `--cap-add SYS_ADMIN,NET_ADMIN` 无法打开 `/proc/1/ns/net`）；
- 入参 IP 经 `ipaddress` 校验，非法直接拒绝（防注入/误封）；
- 适配器可插拔：`blocker.py` 暴露 `apply_block / remove_block / list_blocks`，
  `BLOCKER_MODE=iptables|dry-run`；生产替换为防火墙 API 时只换实现。

### 为什么不是「宿主机 macOS 上跑 iptables」
macOS 无 iptables（其包过滤是 pf）。POC 的「本机」= 承载平台容器的 Linux VM；
其 netns 的 `DOCKER-USER`/`FORWARD` 即平台容器流量的真实过滤面，是有效落黑点。

## 4. 数据与状态机
- 草稿索引 `ssp-soar-drafts`（独立，模板 `ssp-soar-drafts-template.json`，`dynamic:false`）。
- 草稿状态：`pending_approval` →（approve）`executed` | `failed`；（reject）`rejected`；（unblock）`reverted`。
- **同一 IP 去重**：`find_active_draft_by_ip` 保证一个 IP 只保留一个未闭环草稿（待审批/已执行）。
- **幂等**：`draft_id = sha1(alert_id + "|" + ip)[:20]`。
- 审计：草稿内 `history[]` 记录每次动作（`draft_created / approved / approve_failed / rejected / unblocked`）与操作人。

### 回写 `ssp-alerts`（供大屏）
| 结果 | 告警 `ssp.alert.status` | `response_action` |
|---|---|---|
| 审批通过 + 落黑成功 | `blocked` | `block:iptables:SSP_BLACKLIST` |
| 驳回 | `rejected` | `reject` |
| 落黑失败 | **保持 `open`（待处置）** | `block_failed:<原因>` |
| 解除封禁 | `open` | `unblock` |

> I-03 的 upsert 会**保留** `status / response_action / ticket_id`，故关联重跑不会覆盖人工处理结果。

## 5. 接口
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/soar/drafts/generate` | 运行剧本：扫描达级别告警生成草稿（幂等） |
| GET | `/soar/drafts?status=&limit=` | 草稿列表 |
| GET | `/soar/drafts/{id}` | 草稿详情 |
| POST | `/soar/drafts/{id}/approve` | **人工审批通过 → 执行落黑**（`{operator, dry_run}`） |
| POST | `/soar/drafts/{id}/reject` | 驳回 |
| GET | `/soar/blocks` | 当前封禁规则 |
| POST | `/soar/blocks/remove` | 解除封禁（`{ip, operator}`） |
| GET | `/soar/rules` · `/health` | 剧本配置 / 健康（含 blocker 状态） |

**审批界面**：`ui/soar.html`（`http://localhost:8088/soar.html`）——草稿列表 + 详情 + 通过/驳回 + 封禁规则与解除。

## 6. 实测结果（全路径）
| 场景 | 结果 |
|---|---|
| A 剧本生成 | 8 条告警 → 生成 **1** 条草稿（按 IP 去重）；此时 iptables 链**不存在** ⇒ **未自动提交** |
| B 人工审批 | 落黑成功；**独立特权容器**验证宿主 netns：`-A SSP_BLACKLIST -s 203.0.113.45/32 -j DROP` + `-A DOCKER-USER -j SSP_BLACKLIST`；告警回写 `blocked` |
| C 解除封禁 | 规则删除（仅剩 `-N SSP_BLACKLIST`）；草稿 `reverted`，history 含 `unblocked`；告警回 `open` |
| D 落黑失败 | 挂载到不存在的链 → `draft=failed`、`block_error` 记录原因、**告警保持 `open`** + `block_failed:...`（PRD §10） |
| E 驳回 | `rejected`、`decided_by=lixd`；iptables 无规则；对已闭环草稿再审批返回 **409** |

## 7. 踩坑记录
- 🐞 **OpenSearch 禁止文档体内出现元数据字段 `_id`**：`get_draft` 注入的 `_id` 被原样写回 →
  `mapper_parsing_exception: Field [_id] is a metadata field and cannot be added inside a document`，
  且因忽略返回值而**静默失败**（表现为「审批返回 executed 但库里仍是 pending_approval」）。
  修复：`save_draft` 剔除所有 `_` 前缀键；并**对写入返回值做校验**。
- 🐞 **Docker Desktop 的 host 网络端口不外发**：`--network host` 容器监听端口在 macOS 侧不可达
  （`host.docker.internal` 也被沙箱代理干扰）。故不能用「host-net 容器 + HTTP API」，
  改用 **bridge 容器 + `nsenter`** —— API 可达，同时作用于宿主 netns。
- 🐞 **`docker build` 受沙箱限制**：buildx 写 `~/.docker/buildx/activity` 报 `operation not permitted`；
  改用 **`DOCKER_BUILDKIT=0`**（legacy builder）可绕过。
- 🐞 **JSON 模板不能有注释**：`ssp-soar-drafts-template.json` 首行写了 `#` 注释 → OpenSearch `json_parse_exception`。

## 8. 运维速查
```bash
# 生成草稿（剧本）
curl -sS --noproxy '*' -X POST http://localhost:8092/soar/drafts/generate -H 'Content-Type: application/json' -d '{}'
# 审批通过（人工）
curl -sS --noproxy '*' -X POST http://localhost:8092/soar/drafts/<id>/approve -H 'Content-Type: application/json' -d '{"operator":"lixd"}'
# 查看/解除封禁
curl -sS --noproxy '*' http://localhost:8092/soar/blocks
curl -sS --noproxy '*' -X POST http://localhost:8092/soar/blocks/remove -H 'Content-Type: application/json' -d '{"ip":"203.0.113.45"}'
```
