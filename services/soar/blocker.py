#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
I-05 落黑执行适配器 —— 本机 iptables（纯标准库）

设计（PRD §6.4「落黑点：防火墙 API / 本机 iptables / 动态写 Suricata 规则，POC 确定其一」→ 选定 **本机 iptables**）：
- 本机为 macOS，iptables 仅存在于 Docker Desktop 的 Linux VM。故通过
  `nsenter -t <host_pid> -n iptables ...` 进入 **宿主（VM）网络命名空间** 执行，
  直接作用于平台容器流量的真实过滤面（DOCKER-USER / FORWARD）。
- 采用**独立自定义链** `SSP_BLACKLIST`，并从 `DOCKER-USER` 挂一条跳转；
  只操作本链 → 可查、可删、可整体回滚，绝不污染其它链。
- 适配器可插拔：`BLOCKER_MODE=iptables`（默认）/ `dry-run`（只记录不执行），
  生产亦可替换为防火墙 API 实现（保持 apply_block/remove_block/list_blocks 三接口）。

安全：
- 入参 IP 必须先通过 `ipaddress` 校验，非法直接拒绝（防命令注入/误封）。
- 链为空时跳转为 no-op，不影响平台自身网络。
"""
import ipaddress
import os
import re
import subprocess

CHAIN = os.environ.get("SSP_CHAIN", "SSP_BLACKLIST")
HOOK_CHAIN = os.environ.get("SSP_HOOK_CHAIN", "DOCKER-USER")  # 挂载点；置空则不挂
HOST_PID = os.environ.get("SSP_HOST_PID", "1")
MODE = os.environ.get("BLOCKER_MODE", "iptables")            # iptables | dry-run
DIRECTION = os.environ.get("SSP_BLOCK_DIRECTION", "src")     # src=封来源 | dst=封目的 | both
CMD_TIMEOUT = float(os.environ.get("SSP_CMD_TIMEOUT", "10"))


def _valid_ip(ip):
    try:
        ipaddress.ip_address(str(ip).strip())
        return True
    except ValueError:
        return False


def _run(args):
    """执行 iptables 命令（经宿主 netns）。返回 (rc, stdout+stderr)。"""
    if MODE == "dry-run":
        return 0, f"[dry-run] iptables {' '.join(args)}"
    cmd = ["nsenter", "-t", str(HOST_PID), "-n", "iptables"] + list(args)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=CMD_TIMEOUT)
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 127, "nsenter/iptables 不可用（镜像缺 iptables 或未授权 host 命名空间）"
    except subprocess.TimeoutExpired:
        return 124, "iptables 命令超时"
    except Exception as e:
        return 1, f"{type(e).__name__}: {e}"


def specs_for(ip):
    """按方向生成规则规格列表 [(direction, args)]。"""
    out = []
    if DIRECTION in ("src", "both"):
        out.append(("src", ["-s", f"{ip}/32"]))
    if DIRECTION in ("dst", "both"):
        out.append(("dst", ["-d", f"{ip}/32"]))
    return out


def ensure_chain():
    """确保链存在，并在需要时从 HOOK_CHAIN 挂跳转。幂等。"""
    rc, out = _run(["-N", CHAIN])
    created = rc == 0
    hooked = False
    if HOOK_CHAIN:
        rc_c, _ = _run(["-C", HOOK_CHAIN, "-j", CHAIN])
        if rc_c != 0:
            rc_i, out_i = _run(["-I", HOOK_CHAIN, "1", "-j", CHAIN])
            hooked = rc_i == 0
            if not hooked:
                return {"ok": False, "error": f"挂载 {HOOK_CHAIN} 失败: {out_i}"}
    return {"ok": True, "chain_created": created, "hooked": hooked, "chain": CHAIN,
            "hook_chain": HOOK_CHAIN or None}


def apply_block(ip, direction=None):
    """下发封禁（幂等）。"""
    if not _valid_ip(ip):
        return {"ok": False, "error": f"非法 IP: {ip}"}
    ip = str(ip).strip()
    ens = ensure_chain()
    if not ens.get("ok"):
        return ens
    inserted, existed, rules = [], [], []
    for _dir, match in specs_for(ip):
        rc_c, _ = _run(["-C", CHAIN] + match + ["-j", "DROP"])
        if rc_c == 0:
            existed.append(" ".join(match))
            continue
        rc_i, out_i = _run(["-I", CHAIN, "1"] + match + ["-j", "DROP"])
        if rc_i != 0:
            return {"ok": False, "error": f"下发失败: {out_i}", "partial": inserted}
        rule = f"-A {CHAIN} {' '.join(match)} -j DROP"
        inserted.append(" ".join(match))
        rules.append(rule)
    return {"ok": True, "ip": ip, "inserted": inserted, "existed": existed,
            "rules": rules, "backend": f"iptables:{CHAIN}", "mode": MODE}


def remove_block(ip, direction=None):
    """解除封禁（回滚）。"""
    if not _valid_ip(ip):
        return {"ok": False, "error": f"非法 IP: {ip}"}
    ip = str(ip).strip()
    removed, missing = [], []
    for _dir, match in specs_for(ip):
        rc, out = _run(["-D", CHAIN] + match + ["-j", "DROP"])
        (removed if rc == 0 else missing).append(" ".join(match))
    return {"ok": True, "ip": ip, "removed": removed, "not_found": missing,
            "backend": f"iptables:{CHAIN}"}


def list_blocks():
    """列出当前封禁规则。"""
    rc, out = _run(["-S", CHAIN])
    if rc != 0:
        return {"ok": True, "exists": False, "rules": [], "raw": out}
    rules = []
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"^-A\s+%s\s+(?:-s\s+(\S+)|-d\s+(\S+))\s+-j\s+DROP" % re.escape(CHAIN), line)
        if m:
            rules.append({"ip": (m.group(1) or m.group(2)).split("/")[0],
                          "direction": "src" if m.group(1) else "dst",
                          "spec": line})
    return {"ok": True, "exists": True, "chain": CHAIN, "rules": rules, "raw": out}


def status():
    rc, out = _run(["-S", CHAIN])
    return {"mode": MODE, "chain": CHAIN, "hook_chain": HOOK_CHAIN or None,
            "host_pid": HOST_PID, "available": rc in (0, 1) or MODE == "dry-run",
            "last_probe": out[:200]}
