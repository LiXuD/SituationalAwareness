#!/usr/bin/env python3
"""
生成最小样本 pcap（纯标准库，无第三方依赖）。

用途：在无法获取外部真实流量时，为 Arkime 提供可回放的最小流量样本，
用于验证「全流量会话入库 + PCAP 回溯」（F-06 / R-06）。

样本包含：
  - 一条到 203.0.113.45:80 的「恶意」C2 通信流（TCP 三次握手 + HTTP GET/200），
    与 I-01 归一事件里的 203.0.113.45 / evil-c2 叙事对齐，便于后续事件→会话 pivot 演示。
  - 一条到 8.8.8.8:53 的 DNS 查询（UDP）。
  - 一条到 1.1.1.1:443 的普通 TCP 流（benign，作为对照）。

输出：samples/pcap/sample.pcap（classic pcap，little-endian，Ethernet 链路层）。
"""
import struct
import socket
import sys

OUT = "samples/pcap/sample.pcap"

# ---------- 通用工具 ----------
def ip2int(ip):
    return socket.inet_aton(ip)

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def eth(src, dst, payload_proto=0x0800):
    return src + dst + struct.pack("!H", payload_proto)

def ipv4(src_ip, dst_ip, proto, payload):
    src = ip2int(src_ip)
    dst = ip2int(dst_ip)
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s",
                       0x45, 0,            # version+IHL, tos
                       total,              # total length
                       0,                  # id
                       0,                  # flags+frag
                       64,                 # ttl
                       proto,              # protocol (6=TCP,17=UDP)
                       0,                  # checksum (filled later)
                       src, dst)
    csum = checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload

def tcp(src_ip, dst_ip, sport, dport, flags, seq, ack, payload):
    pseudo = ip2int(src_ip) + ip2int(dst_ip) + b"\x00" + bytes([6]) + struct.pack("!H", 20 + len(payload))
    hdr = struct.pack("!HHIIBBHHH",
                      sport, dport, seq, ack,
                      0x50,          # data offset=5 (no options)
                      flags,         # flags
                      65535,         # window
                      0,             # checksum (filled later)
                      0)             # urgent ptr
    seg = hdr + payload
    csum = checksum(pseudo + seg)
    seg = seg[:16] + struct.pack("!H", csum) + seg[18:]
    return ipv4(src_ip, dst_ip, 6, seg)

def udp(src_ip, dst_ip, sport, dport, payload):
    length = 8 + len(payload)
    pseudo = ip2int(src_ip) + ip2int(dst_ip) + b"\x00" + bytes([17]) + struct.pack("!H", length)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)  # checksum=0 placeholder
    seg = hdr + payload
    csum = checksum(pseudo + seg)
    if csum == 0:
        csum = 0xFFFF
    seg = seg[:6] + struct.pack("!H", csum) + seg[8:]
    return ipv4(src_ip, dst_ip, 17, seg)

# ---------- pcap 封装 ----------
def pcap_global_header():
    return struct.pack("<IHHiIII",
                       0xA1B2C3D4,   # magic (little-endian)
                       2, 4,          # version
                       0,             # thiszone
                       0,             # sigfigs
                       65535,         # snaplen
                       1)             # network = Ethernet

def pcap_record(ts_sec, ts_usec, raw):
    return struct.pack("<IIII", ts_sec, ts_usec, len(raw), len(raw)) + raw

# ---------- 构造样本 ----------
MAC_CLIENT = bytes.fromhex("020000000005")
MAC_SERVER = bytes.fromhex("020000000045")
MAC_DNS    = bytes.fromhex("020000000008")
MAC_CDN    = bytes.fromhex("020000000011")

C2_IP = "203.0.113.45"
DNS_IP = "8.8.8.8"
CDN_IP = "1.1.1.1"
CLIENT_IP = "10.0.0.5"

def build():
    pkts = []
    t = 1700000000.0  # 固定基准时间（秒，含小数），保证可复现

    # 目的 IP → 目的 MAC 映射，用于为每个 IP 包补上以太网头
    mac_by_ip = {
        CLIENT_IP: MAC_CLIENT,
        C2_IP: MAC_SERVER,
        DNS_IP: MAC_DNS,
        CDN_IP: MAC_CDN,
    }

    def push(frame, dt=100000):
        nonlocal t
        # 传入的 frame 以 IPv4 头开头（无以太网头），而 pcap 全局头声明
        # linktype=1 (Ethernet)。若不补以太网头，libpcap 会按以太网解析、
        # 读到非法 ethertype，解析器（如 Arkime）会丢弃全部包。
        # IPv4 头中 dst IP 位于偏移 16..19。
        dst_ip = socket.inet_ntoa(frame[16:20])
        dst_mac = mac_by_ip.get(dst_ip, MAC_SERVER)
        src_mac = MAC_SERVER if dst_mac == MAC_CLIENT else MAC_CLIENT
        # dt 的单位是微秒，而 t 以秒累计；必须换算，否则每个包会跳约 1 天，
        # 导致会话被写进多个按天滚动的索引里。
        ts_sec = int(t)
        ts_usec = int(round((t - ts_sec) * 1_000_000))
        pkts.append((ts_sec, ts_usec, eth(src_mac, dst_mac) + frame))
        t += dt / 1_000_000.0

    # ---- 流1：到 203.0.113.45 的「恶意」C2（TCP + HTTP） ----
    push(tcp(CLIENT_IP, C2_IP, 41952, 80, 0x02, 1000, 0, b""))                       # SYN
    push(tcp(C2_IP, CLIENT_IP, 80, 41952, 0x12, 5000, 1001, b""))                     # SYN-ACK
    push(tcp(CLIENT_IP, C2_IP, 41952, 80, 0x10, 1001, 5001, b""))                     # ACK
    http_get = (b"GET /c2/beacon?host=" + CLIENT_IP.encode() +
                b" HTTP/1.1\r\nHost: " + C2_IP.encode() +
                b"\r\nUser-Agent: EvilAgent/1.0\r\n\r\n")
    push(tcp(CLIENT_IP, C2_IP, 41952, 80, 0x18, 1001, 5001, http_get))                # PSH+ACK GET
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 28\r\n\r\nCommand: download payload.bin\n"
    push(tcp(C2_IP, CLIENT_IP, 80, 41952, 0x18, 5001, 1001 + len(http_get), http_resp))  # PSH+ACK 200
    push(tcp(CLIENT_IP, C2_IP, 41952, 80, 0x11, 1001 + len(http_get), 5001 + len(http_resp), b""))  # FIN+ACK

    # ---- 流2：DNS 查询（UDP） ----
    dns_q = (b"\x12\x34"            # txid
             b"\x01\x00"            # flags: standard query
             b"\x00\x01"            # qdcount=1
             b"\x00\x00"            # ancount
             b"\x00\x00"            # nscount
             b"\x00\x00"            # arcount
             b"\x03c2\x05evil\x04test\x00"   # QNAME c2.evil.test
             b"\x00\x01"            # QTYPE A
             b"\x00\x01")           # QCLASS IN
    push(udp(CLIENT_IP, DNS_IP, 33567, 53, dns_q))

    # ---- 流3：到 1.1.1.1:443 的普通 TCP（benign 对照） ----
    push(tcp(CLIENT_IP, CDN_IP, 51000, 443, 0x02, 2000, 0, b""))                      # SYN
    push(tcp(CDN_IP, CLIENT_IP, 443, 51000, 0x12, 9000, 2001, b""))                   # SYN-ACK
    push(tcp(CLIENT_IP, CDN_IP, 51000, 443, 0x10, 2001, 9001, b"") )                  # ACK
    push(tcp(CLIENT_IP, CDN_IP, 51000, 443, 0x11, 2001, 9001, b"\x16\x03\x01\x00\x05hello"))  # FIN+ACK (TLS-ish)

    return pkts

def main():
    pkts = build()
    out = pcap_global_header()
    for ts_sec, ts_usec, frame in pkts:
        out += pcap_record(ts_sec, ts_usec, frame)
    with open(OUT, "wb") as f:
        f.write(out)
    print(f"[gen-sample-pcap] wrote {len(pkts)} packets -> {OUT} ({len(out)} bytes)")
    # 概要
    print("  流1 C2  : TCP 10.0.0.5:41952 -> 203.0.113.45:80 (HTTP GET /c2/beacon)")
    print("  流2 DNS : UDP 10.0.0.5:33567 -> 8.8.8.8:53 (c2.evil.test)")
    print("  流3 CDN : TCP 10.0.0.5:51000 -> 1.1.1.1:443")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        OUT = sys.argv[1]
    main()
