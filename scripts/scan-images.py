#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan-images.py —— 镜像漏洞扫描（trivy）**dev 侧工具，不进交付物**。

扫的是什么：`deploy/compose.yml` 解析出的**全部运行镜像**（含 profile external/postgres），
外加两个自建镜像 `ssp-portal`/`ssp-soar`。目的：把风险面从"代码"延伸到"镜像层"。

用法：
    python3 scripts/scan-images.py                  # 报告模式：只汇总，不因漏洞失败
    SCAN_FAIL_ON=CRITICAL python3 scripts/scan-images.py   # 发现 CRITICAL 即退出码 1
    SCAN_SEVERITY=MEDIUM,HIGH,CRITICAL python3 scripts/scan-images.py

产物：`reports/image-scan-<时间戳>/`（每镜像一份 trivy JSON + 一份 summary.md）；`reports/` 已 gitignore。
未安装 trivy 时跳过（退出 0），保证本地可移植。
"""
import datetime
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEVERITY = os.environ.get("SCAN_SEVERITY", "HIGH,CRITICAL")
FAIL_ON = os.environ.get("SCAN_FAIL_ON", "").strip().upper()   # 空=仅报告


def compose_images():
    r = subprocess.run(["docker", "compose", "-f", "deploy/compose.yml",
                        "--profile", "external", "--profile", "postgres",
                        "config", "--images"],
                       cwd=ROOT, capture_output=True, text=True)
    imgs = {ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()}
    # 自建镜像（compose 里以 tag 出现，确保存在）
    for extra in ("ssp-portal:2026.09", "ssp-soar:2026.09"):
        if subprocess.run(["docker", "image", "inspect", extra],
                          capture_output=True).returncode == 0:
            imgs.add(extra)
    return sorted(imgs)


def scan(image, outdir):
    """返回 (ok, data|None, err)"""
    safe = image.replace("/", "_").replace(":", "_")
    out = os.path.join(outdir, safe + ".json")
    r = subprocess.run(["trivy", "image", "--quiet", "--scanners", "vuln",
                        "--severity", SEVERITY, "--format", "json", "--output", out, image],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return False, None, (r.stderr or r.stdout or "").strip()[:300]
    try:
        with open(out, encoding="utf-8") as f:
            return True, json.load(f), None
    except OSError as e:
        return False, None, str(e)


def counts(data):
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    top = []
    for res in (data or {}).get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            sev = (v.get("Severity") or "UNKNOWN").upper()
            c[sev] = c.get(sev, 0) + 1
            if sev == "CRITICAL":
                top.append((v.get("VulnerabilityID", "?"), v.get("PkgName", "?"),
                            v.get("FixedVersion") or "-", res.get("Target", "?")))
    return c, top


def main():
    if not shutil.which("trivy"):
        print("· 未检测到 trivy，跳过镜像漏洞扫描（安装：brew install trivy）")
        return 0

    imgs = compose_images()
    if not imgs:
        print("✘ 未解析到镜像（docker/compose 是否可用？）")
        return 1

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = os.path.join(ROOT, "reports", f"image-scan-{ts}")
    os.makedirs(outdir, exist_ok=True)
    print(f"扫描 {len(imgs)} 个镜像（severity={SEVERITY}），产物：reports/image-scan-{ts}/\n")

    rows, failed = [], []
    for img in imgs:
        print(f"→ {img}", flush=True)
        ok, data, err = scan(img, outdir)
        if not ok:
            failed.append((img, err))
            rows.append((img, None, None))
            continue
        c, top = counts(data)
        rows.append((img, c, top))

    lines = [f"# 镜像漏洞扫描报告（{ts}）", "",
             f"- severity 过滤：`{SEVERITY}`", f"- 镜像数：{len(imgs)}", ""]
    lines += ["| 镜像 | CRITICAL | HIGH | MEDIUM | 扫描 |", "|---|---:|---:|---:|---|"]
    tot = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for img, c, _t in rows:
        if c is None:
            lines.append(f"| `{img}` | - | - | - | ✘ 失败 |")
            continue
        for k in tot:
            tot[k] += c.get(k, 0)
        lines.append(f"| `{img}` | {c.get('CRITICAL', 0)} | {c.get('HIGH', 0)} | {c.get('MEDIUM', 0)} | ✓ |")
    lines += ["", f"**合计**：CRITICAL {tot['CRITICAL']} ｜ HIGH {tot['HIGH']} ｜ MEDIUM {tot['MEDIUM']}"]

    crit = [(img, t) for img, c, t in rows if t]
    if crit:
        lines += ["", "## CRITICAL 明细（可按 FixedVersion 升级镜像/基础镜像解决）", ""]
        for img, tops in crit:
            lines.append(f"### `{img}`")
            lines += ["| CVE | 包 | 修复版本 | 目标 |", "|---|---|---|---|"]
            for cid, pkg, fixed, target in sorted(set(tops))[:20]:
                lines.append(f"| {cid} | {pkg} | {fixed} | {target} |")
            lines.append("")

    if failed:
        lines += ["", "## 扫描失败的镜像", ""]
        for img, err in failed:
            lines.append(f"- `{img}`：{err}")
        if any("download vulnerability DB" in (e or "") for _i, e in failed):
            lines += ["", "> **提示**：trivy 首次运行需联网下载漏洞库。若报 `failed to download vulnerability DB`，"
                          "通常是本机代理不通——`trivy` 会遵循 `HTTPS_PROXY`，指定一个可用代理再跑，例如：",
                      "> ```bash",
                      "> HTTPS_PROXY=http://127.0.0.1:7897 make scan",
                      "> ```"]

    with open(os.path.join(outdir, "summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print()
    print(f"{'镜像':<62}{'CRITICAL':>9}{'HIGH':>7}{'MEDIUM':>8}")
    print("-" * 88)
    for img, c, _t in rows:
        if c is None:
            print(f"{img:<62}{'FAILED':>9}")
            continue
        print(f"{img:<62}{c.get('CRITICAL', 0):>9}{c.get('HIGH', 0):>7}{c.get('MEDIUM', 0):>8}")
    print("-" * 88)
    print(f"{'合计':<62}{tot['CRITICAL']:>9}{tot['HIGH']:>7}{tot['MEDIUM']:>8}")
    print(f"\n报告：reports/image-scan-{ts}/summary.md")

    if FAIL_ON:
        n = tot.get(FAIL_ON, 0)
        if n:
            print(f"\n✘ SCAN_FAIL_ON={FAIL_ON}，发现 {n} 项 → 退出码 1")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
