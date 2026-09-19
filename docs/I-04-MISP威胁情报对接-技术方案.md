# I-04 MISP 威胁情报对接 —— 技术方案

> 版本：v1.0 ｜ 阶段：POC ｜ 对应功能：F-09（IP/域名/哈希实时匹配）
> 关联：`docs/I-03-轻量关联分析-技术方案.md`
> 状态：**已实现并实测通过**

## 1. 目标与范围
把告警中的 IOC（源 IP / 域名 / 哈希）与威胁情报**实时比对**并标注命中，为分级（命中即置 P0）与 I-05 响应提供依据。

- 双通道情报源：
  1. **本地种子情报** `services/correlator/threat_intel_seed.json` —— POC 默认，无需部署 MySQL+Redis 重栈即可端到端实测；
  2. **真实 MISP REST**（`/attributes/restSearch`）—— 配 `MISP_URL` + `MISP_API_KEY` 即启用。
- **生产切换**：只需填 `MISP_URL` / `MISP_API_KEY` 两项环境变量，代码零改动。

## 2. 契约
`services/correlator/threat_intel.py` 暴露两个接口，由关联引擎惰性加载：

```python
match_alert(evt) -> {
  "matched": bool, "enabled": true,
  "source": "misp" | "seed" | "misp+seed" | "none",
  "misp_configured": bool, "misp_unreachable": bool, "error": str?,
  "indicators": [ {type,value,provider,confidence,first_seen,last_seen,tags} ],
  "indicator": <首个 indicator>
}
status() -> {seed_file, seed_size, misp_configured, misp_url, misp_circuit_open}
```

- 引擎侧无需感知情报细节：`threat_intel` **不存在**时自动降级（`matched=false`），存在即调用。
- IOC 提取（`extract_iocs`）：`source_ip`→`ip-src`、`dest_ip`→`ip-dst`（仅外部地址）、
  `domains`→`domain`、`hashes`→`sha256`。

## 3. 优雅降级（EARS Unwanted 验收）
> 「若 MISP 不可达，则系统应照常产生告警并标记"情报未匹配"，不得阻断主流程。」

三重保障：
1. **短超时**（`THREAT_TIMEOUT`，默认 3s）；
2. **结果缓存**（`THREAT_CACHE_TTL`，默认 300s）——同 IOC 不重复查；
3. **连接失败熔断**（`THREAT_MISP_DOWN_COOLDOWN`，默认 60s）——首次连接失败后，本轮剩余 IOC
   不再尝试连 MISP，避免周期任务被超时拖垮。

异常处理：`HTTPError`→记 `error` 继续；连接类异常→置 `misp_unreachable=true` 并熔断。
**种子情报始终参与匹配**，故 MISP 挂掉时仍能命中本地情报。

## 4. 输出字段（写入 `ssp-alerts` 的 `threat.*`）
| 字段 | 说明 |
|---|---|
| `threat.matched` | 是否命中情报 |
| `threat.source` | 命中来源：`misp` / `seed` / `misp+seed` / `none` |
| `threat.misp_configured` / `threat.misp_unreachable` | MISP 配置与可达状态 |
| `threat.error` | 降级原因（不可达/熔断/HTTP 码） |
| `threat.indicator{,.type,.value,.provider,.confidence,.first_seen,.last_seen,.tags}` | 首个命中指标（便于大屏/溯源直取） |
| `threat.indicators[]` | 全部命中指标 |

命中情报 → **升级因子直接置 P0**（见 I-03 §5）。

## 5. 实测结果
| 场景 | 结果 |
|---|---|
| 常规（种子情报，无 MISP） | 8 条告警；5 条命中情报并置 P0（`source=seed`），含 IP / 域名 / SHA256 三类指标；1 条无情报 → P2（对照） |
| **MISP 配置为不可达**（`http://misp.invalid:8080`） | **仍产出 8 条告警**，耗时 **172ms**（熔断生效，仅 1 次 DNS 尝试）；`misp_unreachable=true`，`error` 记录原因；种子命中不受影响 |
| **无种子 + 无 MISP** | `matched=false`、`source=none`、无异常 → 标记"情报未匹配"，不阻断 |

## 6. 配置项
| 环境变量 | 默认 | 说明 |
|---|---|---|
| `THREAT_SEED_FILE` | 模块同目录 `threat_intel_seed.json` | 种子情报文件 |
| `THREAT_TIMEOUT` | 3 | MISP 查询超时（秒） |
| `THREAT_CACHE_TTL` | 300 | 查询缓存（秒） |
| `THREAT_MISP_DOWN_COOLDOWN` | 60 | 连接失败熔断时长（秒） |
| `MISP_URL` / `MISP_API_KEY` | 空 | 填上即切到真实 MISP |

## 7. 踩坑记录
- 🐞 **`ssp-alerts` 模板需同步补字段**：`dynamic:false` 下未声明的 `threat.source / misp_configured /
  misp_unreachable` 会被丢弃；改模板后**已有索引不会自动更新**，POC 直接删索引重建（告警可再生）。
- 🐞 **Docker Desktop bind mount 偶发陈旧文件**：改源码后 `restart` 可能仍跑旧代码，必须
  `up -d --force-recreate <svc>`；排查用 `docker exec <c> grep -nE ...` 核对容器内文件。

## 8. 运维速查
```bash
# 启用真实 MISP（不改代码）
MISP_URL=https://misp.example.com MISP_API_KEY=xxxx \
  docker compose -f deploy/compose.yml up -d --force-recreate correlator
# 查看情报源状态
curl -sS --noproxy '*' http://localhost:8091/health | python3 -m json.tool
```
