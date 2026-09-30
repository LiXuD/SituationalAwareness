#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""I-07 / I-08 演示数据集生成器 —— "多国团伙攻击"回放样本。

为什么单独一份数据集：
- 基础样本 logs/{suricata,zeek,wazuh}/ 使用 RFC5737 文档网段（203.0.113.x / 198.51.100.x），
  只用于验证采集归一管道本身，**不可地理定位**（GeoIP 查不到坐标）；
- 本演示集使用**真实公网源 IP**，可被 GeoIP（DB-IP Lite City）定位，
  用于态势大屏「攻击地图」与 I-08 端到端闭环演示。
- 两者文件完全独立，基础样本不被改动。

时间轴锚定在基础样本同一窗口内（2026-09-19 03:0x UTC），
使「基础样本 + 演示样本」能被同一次 30 分钟关联窗口一起覆盖。

生成物（logs/demo/）：
  suricata/eve.json   NDJSON（Suricata eve 格式）
  zeek/conn.log       Zeek TSV 头 + JSON 行
  wazuh/alerts.json   NDJSON（Wazuh alerts 格式）

用法：  python3 scripts/gen-demo-data.py
"""
import datetime
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "logs", "demo")
BASE = datetime.datetime(2026, 9, 19, 3, 0, 0, tzinfo=datetime.timezone.utc)

# 演示用真实公网"攻击者"地址（分属不同国家/地区，便于攻击地图呈现散布）
ATTACKERS = {
    "45.155.205.233": "RU",   # SSH 扫描 / 暴破主攻（跨三源）
    "41.79.62.5":     "KE",   # IDS 签名命中
    "185.220.101.5":  "DE",   # 出口节点暴破
    "191.96.150.2":   "BR",   # 恶意载荷托管
    "91.240.118.168": "RU",   # C2
    "14.225.5.10":    "VN",   # 外联目标
    "103.145.13.7":   "IN",   # 外联目标
    "221.194.47.219": "CN",   # 外联目标
}


def iso_z(off):
    return (BASE + datetime.timedelta(seconds=off)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def iso_suri(off):
    """Suricata eve 时间戳格式：2026-09-19T03:02:11.001000+0000"""
    return (BASE + datetime.timedelta(seconds=off)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


def epoch(off):
    return (BASE + datetime.timedelta(seconds=off)).timestamp()


# --------------------------------------------------------------------------- #
# Suricata：IDS 签名告警 + DNS/HTTP/FILE 上下文
# 覆盖规则：R-006(签名) / R-007(C2域名) / R-003(载荷下载)
# --------------------------------------------------------------------------- #
SURICATA = [
    dict(off=131, event_type="alert", src=("45.155.205.233", 44122),
         dst=("10.0.0.20", 22), proto="TCP",
         alert=dict(action="allowed", gid=1, signature_id=2001219, rev=22,
                    signature="ET SCAN Potential SSH Scan",
                    category="Attempted Information Leak", severity=2)),
    dict(off=227, event_type="alert", src=("41.79.62.5", 51990),
         dst=("10.20.30.40", 3306), proto="TCP",
         alert=dict(action="allowed", gid=1, signature_id=2010935, rev=3,
                    signature="ET POLICY Suspicious inbound to MySQL port 3306",
                    category="Potentially Bad Traffic", severity=2)),
    dict(off=302, event_type="dns", src=("10.0.0.31", 51234),
         dst=("8.8.8.8", 53), proto="UDP",
         dns=dict(type="query", rrname="cdn.botnet-panel.top", rcode="NOERROR")),
    dict(off=391, event_type="dns", src=("10.0.0.31", 51235),
         dst=("8.8.8.8", 53), proto="UDP",
         dns=dict(type="query", rrname="evil-c2.example.com", rcode="NOERROR")),
    dict(off=499, event_type="http", src=("10.0.0.31", 53001),
         dst=("191.96.150.2", 80), proto="TCP",
         http=dict(hostname="malware-download.example.net", url="/payload.bin",
                   http_method="GET", status=200)),
    dict(off=501, event_type="fileinfo", src=("10.0.0.31", 53001),
         dst=("191.96.150.2", 80), proto="TCP",
         fileinfo=dict(filename="payload.bin",
                       sha256="9f2a7c1e5b3d4f60a1c8e2d7b9f0431a6c5e8d2b7f1a3c9e4d6b8f0a2c5e7d19",
                       size=214560)),
]

# --------------------------------------------------------------------------- #
# Zeek：会话上下文（跨源佐证 + 内网外联聚合）
# --------------------------------------------------------------------------- #
ZEEK = [
    # 45.155.205.233 主动连内网 → 与 suricata/wazuh 构成 R-001 三源佐证
    dict(off=132, orig=("45.155.205.233", 44122), resp=("10.0.0.20", 22), proto="tcp", service="ssh", dur=120.4, ob=4096, rb=8192),
    dict(off=270, orig=("10.0.0.31", 54001), resp=("14.225.5.10", 443), proto="tcp", service="ssl", dur=3.2, ob=1024, rb=6144),
    dict(off=281, orig=("10.0.0.31", 54002), resp=("103.145.13.7", 8080), proto="tcp", service="http", dur=1.8, ob=512, rb=2048),
    dict(off=292, orig=("10.0.0.31", 54003), resp=("221.194.47.219", 443), proto="tcp", service="ssl", dur=2.4, ob=768, rb=4096),
    dict(off=430, orig=("10.0.0.31", 54010), resp=("91.240.118.168", 443), proto="tcp", service="ssl", dur=45.7, ob=2048, rb=10240),
    dict(off=545, orig=("45.155.205.233", 44130), resp=("10.20.30.40", 3306), proto="tcp", service="mysql", dur=8.1, ob=1536, rb=3072),
]

# --------------------------------------------------------------------------- #
# Wazuh：主机侧 HIDS 告警
# --------------------------------------------------------------------------- #
WAZUH = [
    dict(off=140, rule=dict(id="5710", level=5,
                            description="sshd: Attempt to login using a non-existent user",
                            groups=["syslog", "sshd", "authentication_failures"]),
         agent=("web-prod-01", "10.0.0.20"), srcip="45.155.205.233"),
    dict(off=255, rule=dict(id="2502", level=10,
                            description="Multiple authentication failures followed by a success",
                            groups=["syslog", "sshd", "authentication_failures"]),
         agent=("web-prod-01", "10.0.0.20"), srcip="185.220.101.5"),
    dict(off=475, rule=dict(id="5501", level=7,
                            description="File integrity: unexpected binary added",
                            groups=["ossec", "syscheck"]),
         agent=("web-prod-01", "10.0.0.20"), srcip=None),
]


def write_suricata():
    path = os.path.join(OUT, "suricata", "eve.json")
    with open(path, "w", encoding="utf-8") as f:
        for e in SURICATA:
            doc = {
                "timestamp": iso_suri(e["off"]),
                "flow_id": 900000 + e["off"],
                "event_type": e["event_type"],
                "src_ip": e["src"][0], "src_port": e["src"][1],
                "dest_ip": e["dst"][0], "dest_port": e["dst"][1],
                "proto": e["proto"],
            }
            for k in ("alert", "dns", "http", "fileinfo"):
                if k in e:
                    doc[k] = e[k]
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")
    return path


def write_zeek():
    path = os.path.join(OUT, "zeek", "conn.log")
    header = (
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tconn\n"
        "#open\t" + (BASE + datetime.timedelta(seconds=120)).strftime("%Y-%m-%d-%H-%M-%S") + "\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        for i, e in enumerate(ZEEK):
            doc = {
                "ts": round(epoch(e["off"]), 6),
                "uid": f"D1demo{i:04d}",
                "id.orig_h": e["orig"][0], "id.orig_p": e["orig"][1],
                "id.resp_h": e["resp"][0], "id.resp_p": e["resp"][1],
                "proto": e["proto"], "service": e["service"],
                "duration": e["dur"], "orig_bytes": e["ob"], "resp_bytes": e["rb"],
                "conn_state": "SF",
            }
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")
    return path


def write_wazuh():
    path = os.path.join(OUT, "wazuh", "alerts.json")
    with open(path, "w", encoding="utf-8") as f:
        for e in WAZUH:
            data = {}
            if e["srcip"]:
                data["srcip"] = e["srcip"]
            doc = {
                "timestamp": iso_z(e["off"]),
                "rule": e["rule"],
                "agent": {"id": "001", "name": e["agent"][0], "ip": e["agent"][1]},
                "manager": {"name": "wazuh-manager"},
                "data": data,
                "full_log": f"{e['rule']['description']} from {e['srcip'] or 'local'}",
            }
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")
    return path


def main():
    for sub in ("suricata", "zeek", "wazuh"):
        os.makedirs(os.path.join(OUT, sub), exist_ok=True)
    p1 = write_suricata()
    p2 = write_zeek()
    p3 = write_wazuh()
    print(f"suricata: {len(SURICATA)} 条 -> {os.path.relpath(p1, ROOT)}")
    print(f"zeek    : {len(ZEEK)} 条 -> {os.path.relpath(p2, ROOT)}")
    print(f"wazuh   : {len(WAZUH)} 条 -> {os.path.relpath(p3, ROOT)}")
    print("攻击者 IP 国家分布：" + "、".join(f"{ip}({c})" for ip, c in ATTACKERS.items()))


if __name__ == "__main__":
    main()
