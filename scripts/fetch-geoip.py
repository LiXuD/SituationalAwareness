#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fetch-geoip.py — 健壮、可续传的 DB-IP Lite City mmdb 下载器（纯标准库）。

设计要点
--------
* **并行分段**：把远端文件切成 PARTS 段，用线程池并发拉取（默认 16 并发），
  单连接被限速时靠并发把总吞吐拉上来。
* **可续传**：每段落盘为 `part.<i>`，记录在 manifest；重跑时按已有字节数
  从断点续拉，**追加**写入（append），不丢弃已完成字节。
* **布局守卫**：manifest 记录 SIZE/PARTS/CHUNK，三者任一变化即视为缓存失效
  （分段边界变了，旧分片不可复用），自动清空重下。
* **直连**：显式禁用所有代理（ProxyHandler({})），走直连；db-ip 支持 Range。
* **原子落盘**：全部段拼装后再 gunzip，校验 mmdb magic，最后原子 mv。
* **断点可重入**：任何时刻 Ctrl-C / 被杀，已完成段仍在，可继续。

用法
----
    python3 scripts/fetch-geoip.py [--parts 40] [--workers 16] [--month 2026-09]

环境变量
--------
    GEOIP_URL   覆盖下载地址（默认按 --month 拼 db-ip 免费 City Lite）
    GEOIP_PROXY 若需走代理（如 http://127.0.0.1:7890），设为该值即可
"""
import argparse
import gzip
import json
import os
import ssl
import sys
import threading
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GEOIP_DIR = os.path.join(ROOT, "config", "logstash", "geoip")
DL_DIR = os.path.join(GEOIP_DIR, ".dl")
OUT_MMDB = os.path.join(GEOIP_DIR, "dbip-city-lite.mmdb")

_lock = threading.Lock()
_done = set()
_bytes = 0


def log(msg):
    with _lock:
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()


def opener(proxy=None):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))  # 禁用所有代理 -> 直连
    ctx = ssl.create_default_context()
    # 平台注入的自签 CA（可选）：若存在则一并信任，避免 SSL 校验失败
    ca = os.path.expanduser("~/.workbuddy/system-ca-bundle.pem")
    if os.path.exists(ca):
        try:
            ctx.load_verify_locations(ca)
        except Exception:
            pass
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def probe_size(op, url):
    """探测远端文件总大小（优先 content-length）。"""
    req = urllib.request.Request(url, headers={"Range": "bytes=0-0",
                                               "Accept-Encoding": "identity",
                                               "User-Agent": "curl/8"})
    with op.open(req, timeout=40) as r:
        cr = r.headers.get("Content-Range")  # e.g. bytes 0-0/60287600
        cl = r.headers.get("Content-Length")
    if cr and "/" in cr:
        return int(cr.rsplit("/", 1)[1])
    if cl:
        return int(cl)
    raise RuntimeError("无法探测远端大小")


def fetch_part(op, url, idx, start, end, fpath):
    """拉取 [start,end] 区间，按已有长度断点续传（追加）。"""
    global _bytes
    want = end - start + 1
    for attempt in range(1, 15):
        have = os.path.getsize(fpath) if os.path.exists(fpath) else 0
        if have >= want:
            with _lock:
                _done.add(idx)
            log(f"  part.{idx:>2} OK ({have}/{want})")
            return
        ns = start + have
        req = urllib.request.Request(url, headers={
            "Range": f"bytes={ns}-{end}",
            "Accept-Encoding": "identity",
            "User-Agent": "curl/8",
        })
        try:
            with op.open(req, timeout=60) as r:
                with open(fpath, "ab") as f:
                    while True:
                        chunk = r.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                        with _lock:
                            _bytes += len(chunk)
        except Exception as e:
            log(f"  part.{idx:>2} attempt{attempt} err: {type(e).__name__} {e}")
        time.sleep(0.5)
    have = os.path.getsize(fpath) if os.path.exists(fpath) else 0
    if have >= want:
        with _lock:
            _done.add(idx)
        log(f"  part.{idx:>2} OK ({have}/{want})")
    else:
        log(f"  part.{idx:>2} INCOMPLETE ({have}/{want})")


def assemble(parts, chunk, size, gz):
    with open(gz, "wb") as out:
        for i in range(parts):
            fp = os.path.join(DL_DIR, f"part.{i}")
            if os.path.exists(fp):
                with open(fp, "rb") as f:
                    while True:
                        b = f.read(1 << 20)
                        if not b:
                            break
                        out.write(b)


def verify(gz, chunk):
    """流式 gunzip，返回 (ok, failing_offset)。"""
    import zlib
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    total = 0
    try:
        with open(gz, "rb") as f:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                d.decompress(b)
                total += len(b)
        if not d.eof:
            return False, total
        return True, total
    except zlib.error as e:
        off = total - len(getattr(d, "unconsumed_tail", b""))
        log(f"  gunzip error: {e}")
        return False, off


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parts", type=int, default=40)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--month", default="2026-09")
    ap.add_argument("--url", default=None)
    ap.add_argument("--repair", action="store_true",
                    help="拼装校验失败时，定位并重下损坏分片，循环直至通过")
    ap.add_argument("--repair-rounds", type=int, default=20)
    args = ap.parse_args()

    url = args.url or os.environ.get("GEOIP_URL") or \
        f"https://download.db-ip.com/free/dbip-city-lite-{args.month}.mmdb.gz"
    proxy = os.environ.get("GEOIP_PROXY") or None
    op = opener(proxy)
    os.makedirs(DL_DIR, exist_ok=True)
    man = os.path.join(DL_DIR, "manifest")

    # 1) 探测大小 + 布局守卫
    try:
        size = probe_size(op, url)
    except Exception as e:
        if os.path.exists(man):
            size = int(dict(x.split("=", 1) for x in open(man).read().strip().split(";"))["SIZE"])
            log(f"探测失败({e})，沿用 manifest SIZE={size}")
        else:
            log(f"探测失败且无 manifest：{e}")
            return 1

    parts = args.parts
    chunk = (size + parts - 1) // parts
    layout = f"SIZE={size};PARTS={parts};CHUNK={chunk}"
    if os.path.exists(man) and open(man).read().strip() != layout:
        log(f"布局变化，清空缓存：{open(man).read().strip()} -> {layout}")
        for f in os.listdir(DL_DIR):
            if f.startswith("part."):
                os.remove(os.path.join(DL_DIR, f))
    with open(man, "w") as f:
        f.write(layout)

    log(f"URL   : {url}")
    log(f"proxy : {proxy or '(direct)'}")
    log(f"layout: {layout}")
    log(f"local : {DL_DIR}")

    # 2) 并发拉取
    t0 = time.time()
    threads = []
    tasks = []
    workers = max(1, args.workers)
    # 简单轮转分配：先补齐未完成的段
    idxs = []
    for i in range(parts):
        start = i * chunk
        end = min((i + 1) * chunk, size) - 1
        if start > end:
            continue
        idxs.append((i, start, end))
    # 优先未完成的
    def remaining(t):
        i, s, e = t
        fp = os.path.join(DL_DIR, f"part.{i}")
        have = os.path.getsize(fp) if os.path.exists(fp) else 0
        return (e - s + 1) - have

    idxs.sort(key=remaining, reverse=True)
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(fetch_part, op, url, i, s, e, os.path.join(DL_DIR, f"part.{i}"))
                for (i, s, e) in idxs]
        for fu in futs:
            fu.result()

    log(f"下载完成，用时 {time.time()-t0:.1f}s，累计 {_bytes/1e6:.1f} MB")

    # 3) 校验完整性
    total = 0
    for i in range(parts):
        fp = os.path.join(DL_DIR, f"part.{i}")
        if not os.path.exists(fp):
            start = i * chunk
            end = min((i + 1) * chunk, size) - 1
            if start <= end:
                log(f"缺少 part.{i}")
                return 1
            continue
        total += os.path.getsize(fp)
    if total != size:
        log(f"拼装大小不符：{total} != {size}")
        return 1

    # 4) 拼装 + 校验；失败时（--repair）定位损坏分片并重下，循环
    gz = os.path.join(DL_DIR, "db.mmdb.gz")
    for rnd in range(1, args.repair_rounds + 1):
        assemble(parts, chunk, size, gz)
        ok, off = verify(gz, chunk)
        if ok:
            log(f"gzip 校验通过（第 {rnd} 轮），拼装 {os.path.getsize(gz)} bytes")
            break
        bad = off // chunk
        log(f"第 {rnd} 轮校验失败 @ 输入偏移 {off} => part.{bad}（已就绪 {os.path.getsize(os.path.join(DL_DIR, f'part.{bad}')) if os.path.exists(os.path.join(DL_DIR, f'part.{bad}')) else 0}）")
        if not args.repair:
            return 1
        # 重下损坏分片（连同其前一个，覆盖边界偏移）
        targets = sorted({max(0, bad - 1), bad, min(parts - 1, bad + 1)})
        for i in targets:
            fp = os.path.join(DL_DIR, f"part.{i}")
            if os.path.exists(fp):
                os.remove(fp)
            start = i * chunk
            end = min((i + 1) * chunk, size) - 1
            if start > end:
                continue
            log(f"  重下 part.{i} [{start}-{end}]")
            fetch_part(op, url, i, start, end, fp)
    else:
        log("达到最大修复轮次仍未通过")
        return 1

    # 5) gunzip + mmdb magic 校验 + 原子落盘
    tmp = OUT_MMDB + ".tmp"
    try:
        with gzip.open(gz, "rb") as fi, open(tmp, "wb") as fo:
            while True:
                b = fi.read(1 << 20)
                if not b:
                    break
                fo.write(b)
    except Exception as e:
        log(f"gunzip 失败：{e}")
        return 1
    with open(tmp, "rb") as f:
        f.seek(-16, os.SEEK_END)
        tail = f.read()
    if b"MaxMind.com" not in tail:
        log("mmdb magic 校验失败")
        return 1
    os.replace(tmp, OUT_MMDB)
    log(f"✅ 完成：{OUT_MMDB} ({os.path.getsize(OUT_MMDB)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
