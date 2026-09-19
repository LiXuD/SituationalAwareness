# 探针字段 → ECS 映射表

> 关联需求：F-02（统一事件 Schema / ECS 归一）
> 作用：定义各探针原始字段如何映射到 Elastic Common Schema，作为关联分析、检索、大屏的**统一数据契约**。
> 实现位置：`config/logstash/conf.d/{10-suricata,20-zeek,30-wazuh}.conf`

## 1. 公共 ECS 字段（三源统一）
| ECS 字段 | 类型 | 含义 |
|---|---|---|
| `@timestamp` | date | 事件发生时间（优先取探针自带时间戳，非采集时间） |
| `event.kind` | keyword | `alert` / `event` |
| `event.category` | keyword | `intrusion_detection` / `network` / `web` / `file` / `host` |
| `event.module` | keyword | 来源探针：`suricata` / `zeek` / `wazuh` |
| `event.dataset` | keyword | 数据集中标识（如 `suricata.eve`） |
| `event.type` | keyword | 事件细化类型 |
| `source.ip` / `source.port` / `source.geo` | ip / long / geo_point | 源侧 |
| `destination.ip` / `destination.port` | ip / long | 目的侧 |
| `network.transport` / `network.protocol` / `network.bytes` | keyword / keyword / long | 网络层 |
| `host.name` / `host.ip` | keyword / ip | 主机侧 |
| `rule.id` / `rule.name` / `rule.category` / `rule.description` | keyword/text | 规则/告警 |
| `event.severity` | keyword | 严重度（POC 原样落库，I-03 统一分级） |

## 2. Suricata（eve.json）→ ECS
| 原始字段 | ECS 字段 | 说明 |
|---|---|---|
| `timestamp` | `@timestamp` | ISO8601 |
| `event_type` | 驱动映射分支 | `alert` / `dns` / `http` / `tls` / `fileinfo` |
| `src_ip` / `src_port` | `source.ip` / `source.port` | |
| `dest_ip` / `dest_port` | `destination.ip` / `destination.port` | |
| `proto` | `network.transport` | |
| `alert.signature` | `rule.name` | 仅 `event_type=alert` |
| `alert.signature_id` | `rule.id` | |
| `alert.category` | `rule.category` | |
| `alert.severity` | （保留在 `eve.alert.severity`） | 待 I-03 映射 `event.severity` |
| `dns.rrname` | `dns.question.name` | `event_type=dns` |
| `http.hostname` / `http.url` | `url.domain` / `url.full` | `event_type=http` |
| `tls.sni` | `tls.client.server_name` | `event_type=tls` |
| `fileinfo.filename` / `fileinfo.sha256` | `file.name` / `file.hash.sha256` | `event_type=fileinfo` |
| `alert` 分支 → `event.kind=alert`，`event.category=intrusion_detection` | | |

## 3. Zeek（conn.log JSON）→ ECS
> 注意：Zeek JSON 使用点号扁平键（`id.orig_h`）。Logstash 引用时中括号内的点号按字面处理，写作 `[zeek][id.orig_h]`。

| 原始字段 | ECS 字段 | 说明 |
|---|---|---|
| `ts` | `@timestamp` | epoch（UNIX） |
| `id.orig_h` / `id.orig_p` | `source.ip` / `source.port` | |
| `id.resp_h` / `id.resp_p` | `destination.ip` / `destination.port` | |
| `proto` | `network.transport` | |
| `service` | `network.protocol` | 应用层协议（http/dns/ssl…） |
| `orig_bytes` | `network.bytes` | 源字节数 |
| — | `event.kind=event`，`event.category=network`，`event.module=zeek` | 固定 |

> 当前 POC 只归一 `conn.log`；后续按需扩展 `dns.log` / `http.log` / `ssl.log` 等（映射规则同构）。

## 4. Wazuh（alerts.json）→ ECS
| 原始字段 | ECS 字段 | 说明 |
|---|---|---|
| `timestamp` | `@timestamp` | ISO8601 |
| `rule.description` | `rule.description` | |
| `rule.id` | `rule.id` | |
| `rule.groups` | `rule.category` | 数组原样 |
| `rule.level` | `event.severity` | 数值等级 |
| `agent.name` / `agent.ip` | `host.name` / `host.ip` | |
| `manager.name` | `observer.name` | |
| `full_log` | `log.original` | |
| `data.srcip` | `source.ip` | 有则映射 |
| — | `event.kind=alert`，`event.category=host`，`event.module=wazuh` | 固定 |

## 5. Arkime
Arkime 不经 ECS 归一管道，其会话元数据保留在自有索引 `arkime_sessions3-*`。跨源检索时以 `arkime_sessions3-*` 为一等数据源，与大屏/检索并列，不做字段级映射。

## 6. 待办（POC → 生产）
- `event.severity` 统一为数值分级（P0–P3），与 I-03 分级 SLA 对齐。
- `rule.category` 归一为受控词表（当前取值口径不一）。
- 补 Zeek 其他日志类型、Suricata flow/stats 事件的映射。
