#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch-mmdb-type.py — 改写 MaxMind DB (.mmdb) 元数据中的 database_type。

用途：OSS Logstash(7.x) 的 geoip 过滤器对 database_type 做**白名单**校验，
只接受 GeoIP2-City/GeoLite2-City/GeoIP2-Country/GeoLite2-Country/GeoIP2-ASN/GeoLite2-ASN 等；
DB-IP 的免费库 database_type 为 "DBIP-City-Lite"，会被判为
`Unsupported database type DBIP-City-Lite` 而**停掉整条 pipeline**。
本工具把该字段改写为 Logstash 认得的等价类型（数据本身不变，许可证也随之不变）。

原理：mmdb 末尾的元数据段以魔数 `\\xab\\xcd\\xefMaxMind.com` 起始，读取器靠
"在文件末尾 128KB 内回搜该魔数"来定位元数据（**不是**靠偏移），因此重编码
元数据（长度可变）是安全的——只要魔数仍在、元数据仍可解析。

用法：
    python3 scripts/patch-mmdb-type.py <in.mmdb> <out.mmdb> [--type GeoLite2-City]
"""
import argparse
import sys

MARKER = b"\xab\xcd\xefMaxMind.com"

# ---- MMDB 数据类型编号 -------------------------------------------------------
T_POINTER, T_STRING, T_DOUBLE, T_BYTES = 1, 2, 3, 4
T_UINT16, T_UINT32, T_MAP, T_INT32 = 5, 6, 7, 8
T_UINT64, T_UINT128, T_ARRAY, T_BOOLEAN, T_FLOAT = 9, 10, 11, 14, 15


def _read_size(buf, pos, size_bits):
    if size_bits < 29:
        return size_bits, pos
    if size_bits == 29:
        return 29 + buf[pos], pos + 1
    if size_bits == 30:
        return 285 + int.from_bytes(buf[pos:pos + 2], "big"), pos + 2
    return 65821 + int.from_bytes(buf[pos:pos + 3], "big"), pos + 3


def decode(buf, pos):
    """解码一个数据项，返回 ((type_id, value), next_pos)。"""
    ctrl = buf[pos]
    pos += 1
    t = (ctrl >> 5) & 0x7
    size_bits = ctrl & 0x1F
    if t == 0:                      # 扩展类型：下一字节 = type - 7
        t = buf[pos] + 7
        pos += 1
    size, pos = _read_size(buf, pos, size_bits)

    if t == T_STRING:
        v = buf[pos:pos + size].decode("utf-8", "replace")
        return (t, v), pos + size
    if t == T_MAP:
        d = {}
        for _ in range(size):
            (kt, kv), pos = decode(buf, pos)
            vv, pos = decode(buf, pos)
            d[kv] = vv
        return (t, d), pos
    if t == T_ARRAY:
        arr = []
        for _ in range(size):
            item, pos = decode(buf, pos)
            arr.append(item)
        return (t, arr), pos
    if t in (T_UINT16, T_UINT32, T_UINT64, T_UINT128):
        v = int.from_bytes(buf[pos:pos + size], "big")
        return (t, v), pos + size
    if t == T_INT32:
        v = int.from_bytes(buf[pos:pos + size], "big", signed=True)
        return (t, v), pos + size
    if t == T_BOOLEAN:
        return (t, size != 0), pos
    if t == T_BYTES:
        return (t, buf[pos:pos + size]), pos + size
    if t == T_DOUBLE:
        import struct
        return (t, struct.unpack(">d", buf[pos:pos + 8])[0]), pos + 8
    if t == T_FLOAT:
        import struct
        return (t, struct.unpack(">f", buf[pos:pos + 4])[0]), pos + 4
    raise ValueError(f"unsupported type {t} at {pos}")


def _enc_ctrl(t, size):
    out = bytearray()
    if size < 29:
        sb, extra = size, b""
    elif size < 285:
        sb, extra = 29, bytes([size - 29])
    elif size < 65821:
        sb, extra = 30, (size - 285).to_bytes(2, "big")
    else:
        sb, extra = 31, (size - 65821).to_bytes(3, "big")
    if t <= 7:
        out.append((t << 5) | sb)
    else:                            # 扩展类型
        out.append(sb & 0x1F)
        out.append(t - 7)
    out += extra
    return bytes(out)


def encode(node):
    t, v = node
    if t == T_STRING:
        b = v.encode("utf-8")
        return _enc_ctrl(t, len(b)) + b
    if t in (T_UINT16, T_UINT32, T_UINT64, T_UINT128):
        n = max(1, (int(v).bit_length() + 7) // 8)
        return _enc_ctrl(t, n) + int(v).to_bytes(n, "big")
    if t == T_INT32:
        n = 4
        return _enc_ctrl(t, n) + int(v).to_bytes(n, "big", signed=True)
    if t == T_BOOLEAN:
        return _enc_ctrl(t, 1 if v else 0)
    if t == T_MAP:
        body = b""
        for k, val in v.items():
            kb = k.encode("utf-8")
            body += _enc_ctrl(T_STRING, len(kb)) + kb
            body += encode(val)
        return _enc_ctrl(t, len(v)) + body
    if t == T_ARRAY:
        return _enc_ctrl(t, len(v)) + b"".join(encode(x) for x in v)
    if t == T_BYTES:
        return _enc_ctrl(t, len(v)) + v
    raise ValueError(f"cannot encode type {t}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--type", default="GeoLite2-City")
    args = ap.parse_args()

    buf = open(args.src, "rb").read()
    m = buf.rfind(MARKER)
    if m < 0:
        print("未找到 mmdb 魔数，可能不是合法的 MaxMind DB")
        return 1
    meta_start = m + len(MARKER)
    print(f"魔数位置 {m}，元数据起始 {meta_start}，文件大小 {len(buf)}")

    (mtype, meta), end = decode(buf, meta_start)
    assert mtype == T_MAP, f"元数据不是 map（type={mtype}）"
    old = meta.get("database_type")
    print(f"原 database_type = {old[1] if old else '(缺失)'}")
    meta["database_type"] = (T_STRING, args.type)

    new_meta = encode((T_MAP, meta))
    out = buf[:meta_start] + new_meta
    open(args.dst, "wb").write(out)
    print(f"新 database_type = {args.type}；写出 {args.dst}（{len(out)} 字节，原 {len(buf)}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
