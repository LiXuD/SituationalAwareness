# scripts/ 脚本索引

统一经 **`make`** 调用（见根 `Makefile`）；下表按用途分组。

| 脚本 | 用途 | 常用命令 |
|---|---|---|
| **初始化 / 库** | | |
| `gen-env.sh` | 生成 `deploy/.env`（随机口令、0600、**不入库**；已存在则不动） | `make env`（`make init`/`make up` 自动调用） |
| `_env.py` | 宿主脚本统一加载 `deploy/.env`（`import _env`；仓库内不保存任何口令） | 被 init-db / test-cases / acceptance-demo / discovery-run 引用 |
| `init-db.py` | 建业务库表 + 种子账号（SQLite/PG；口令取自 `deploy/.env`） | `make init` |
| `init-alias.sh` | 下发 `ssp-ecs` 别名 | `make templates` |
| **索引模板** | | |
| `apply-ecs-template.sh` | 下发 ECS 索引模板 | `make templates` |
| `apply-alerts-template.sh` | 下发告警索引模板 | `make templates` |
| **采集 / 回放** | | |
| `replay-demo.sh` | 回放演示数据（探针 → 事件） | `make demo` |
| `verify-ingest.sh` | 校验探针事件入湖 | `make health` |
| **资产测绘（I-12）** | | |
| `discovery-run.py` | 触发一次资产被动测绘（经 portal API）；`--stats` 看候选统计 | `make discover` / `make discovery-status` |
| **多分支汇聚（I-13）** | | |
| `replay-branch.sh` | 重建分支边缘代理 / 模拟分支断链 / 查看各分支状态 | `make branch-demo` `make branch-down B=sh-01` `make branch-status` |
| **流式关联 / 外部源（I-14）** | | |
| `stream-demo.sh` | 流式引擎状态（`--status`）/ 回放并观测秒级告警 / `--probe` 隔离采集抖动实测时延 | `make stream-status` `make stream-demo` |
| `external-demo.sh` | 投递外部源样例（syslog/CEF/JSON）并验证入库与关联；`--reset` 清理外部源数据 | `make external-demo` `make external-reset` |
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
| `test-cases.py` | I-09 反例/边界（N1~N4）+ I-12 资产测绘（A9~A11 / N5~N7）+ I-13 多分支汇聚（A13~A15 / N10~N11）+ **I-14 流式关联与外部源（A16~A18 / N12~N13）** + 正例回归 | `make verify` |
| `lint.py` | 零副作用语法检查（不写 `__pycache__`） | `make lint` |
| **其他** | | |
| `run-correlator.sh` | 本地直接跑关联引擎（开发用） | — |
| `search.sh` | 命令行检索 OpenSearch | — |
