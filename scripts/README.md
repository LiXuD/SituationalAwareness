# scripts/ 脚本索引

统一经 **`make`** 调用（见根 `Makefile`）；下表按用途分组。

| 脚本 | 用途 | 常用命令 |
|---|---|---|
| **初始化 / 库** | | |
| `init-db.py` | 建业务库表 + 种子账号（SQLite/PG） | `make init` |
| `init-alias.sh` | 下发 `ssp-ecs` 别名 | `make templates` |
| **索引模板** | | |
| `apply-ecs-template.sh` | 下发 ECS 索引模板 | `make templates` |
| `apply-alerts-template.sh` | 下发告警索引模板 | `make templates` |
| **采集 / 回放** | | |
| `replay-demo.sh` | 回放演示数据（探针 → 事件） | `make demo` |
| `verify-ingest.sh` | 校验探针事件入湖 | `make health` |
| **Arkime** | | |
| `arkime-init.sh` | 初始化 Arkime（视图/用户） | — |
| `arkime-import.sh` | 导入 PCAP | — |
| `arkime-status.sh` | 查看 Arkime 状态 | — |
| **GeoIP / 地图** | | |
| `fetch-geoip.py` | 下载 DB-IP Lite 城市库 | — |
| `patch-mmdb-type.py` | 修正 mmdb `database_type`（Logstash 白名单） | — |
| `gen-world-map.py` | 生成大屏世界底图 | — |
| **数据/样例生成** | | |
| `gen-demo-data.py` | 生成演示事件数据 | — |
| `gen-asset-template.py` | 生成资产 Excel 导入模板 | — |
| `gen-sample-pcap.py` | 生成示例 PCAP | — |
| **校验 / 验收** | | |
| `acceptance-demo.py` | I-08 端到端正例（A1~A8） | `make verify` |
| `test-cases.py` | I-09 反例/边界（N1~N4）+ 正例回归 | `make verify` |
| **其他** | | |
| `run-correlator.sh` | 本地直接跑关联引擎（开发用） | — |
| `search.sh` | 命令行检索 OpenSearch | — |
