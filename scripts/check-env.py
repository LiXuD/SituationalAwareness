#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check-env.py —— 运行时配置 schema 校验（`deploy/.env` 与 `deploy/.env.example`）

解决的问题：`deploy/.env` 的键此前没有集中声明，容易出现
（a）拼错的键被静默忽略、（b）`make init` 生成的模板与代码实际读取的键**漂移**。
本脚本把键集中声明为 SCHEMA，并做两项校验：

    python3 scripts/check-env.py            # 校验 deploy/.env（不存在则跳过）+ 模板一致性
    python3 scripts/check-env.py --example  # 只校验 .env.example 覆盖度（无需 .env，可进 gate）

退出码：0=通过；1=有问题。**不回显任何配置值**，只报告键名。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _env  # noqa: E402

# key -> (required, default, desc)
#   required=True 表示"对应功能必须取值，否则该功能不可用"（如 Arkime 口令不填 → portal 报错）
SCHEMA = {
    "SSP_DEFAULT_PASSWORD": (True, "", "平台账号初始口令（make init 种子；生产须轮换）"),
    "SSP_ADMIN_PASSWORD": (False, "", "admin 专有口令（可选，覆盖默认）"),
    "SSP_OPS_PASSWORD": (False, "", "ops 专有口令（可选）"),
    "SSP_ANALYST_PASSWORD": (False, "", "analyst 专有口令（可选）"),
    "SSP_ASSET_PASSWORD": (False, "", "asset 专有口令（可选）"),
    "ARKIME_ADMIN_USER": (False, "admin", "Arkime 管理账号"),
    "ARKIME_ADMIN_PASSWORD": (True, "", "Arkime 口令（portal 流量回溯 + arkime-init 需要）"),
    "POSTGRES_USER": (False, "ssp", "PostgreSQL 账号（仅 pg-* 需要）"),
    "POSTGRES_PASSWORD": (False, "", "PostgreSQL 口令（仅 pg-* 需要）"),
    "POSTGRES_DB": (False, "ssp", "PostgreSQL 库名"),
    "POSTGRES_PORT": (False, "5433", "PostgreSQL 宿主端口"),
    "SSP_IMAGE_TAG": (False, "2026.09", "自建镜像（portal/soar）版本 tag"),
    "LOG_LEVEL": (False, "INFO", "各服务日志级别（DEBUG/INFO/WARNING/ERROR）"),
}


def _keys(path):
    return set(_env.parse(path).keys())


def check_example():
    """`.env.example` 与 SCHEMA 必须**键集一致**（防模板漂移）。"""
    errs = []
    keys, want = _keys(_env.EXAMPLE_FILE), set(SCHEMA)
    for k in sorted(want - keys):
        errs.append(f".env.example 缺少声明键：{k}（{SCHEMA[k][2]}）")
    for k in sorted(keys - want):
        errs.append(f".env.example 存在未声明键：{k}（请在 check-env.py 的 SCHEMA 中登记）")
    return errs


def check_env():
    """校验实际 `deploy/.env`：键名合法 + 必填项非空。"""
    if not os.path.exists(_env.ENV_FILE):
        print(f"· 未找到 {os.path.relpath(_env.ENV_FILE)}（跳过实例校验，先 `make init` 生成）")
        return []
    vals = _env.parse(_env.ENV_FILE)
    errs = []
    for k in sorted(set(vals) - set(SCHEMA)):
        errs.append(f"deploy/.env 存在未声明键：{k}")
    for k, (required, _d, desc) in SCHEMA.items():
        if required and not vals.get(k):
            errs.append(f"必备项未配置：{k} —— {desc}")
    return errs


def main():
    example_only = "--example" in sys.argv[1:]
    errs = check_example()
    if not example_only:
        errs += check_env()
    if errs:
        print("  ✘ 配置 schema 校验未通过：")
        for e in errs:
            print("    - " + e)
        return 1
    print("✓ 配置 schema 校验通过（模板一致性"
          + ("；实例校验已跳过）" if example_only else "；deploy/.env 键与必填项）"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
