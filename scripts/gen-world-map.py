#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成态势大屏「攻击地图」用的世界陆地底图（自包含，无 CDN 依赖）。

数据源：Natural Earth 1:110m land（公有领域 / public domain），GeoJSON。
投影：等距圆柱（equirectangular）——
    x = (lon + 180) / 360 * W ,  y = (90 - lat) / 180 * H
大屏侧用同一套公式把告警的经纬度映射到同一坐标系，底图与散点天然对齐。

产物：ui/assets/world-land.svg（单个 <path>，含所有陆地环，evenodd 处理内湖）
      ui/assets/world-meta.json（投影参数，供大屏读取）

用法： python3 scripts/gen-world-map.py
"""
import json
import os
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.join(ROOT, "scripts", ".cache")
SRC_URL = ("https://raw.githubusercontent.com/nvkelso/natural-earth-vector/"
           "master/geojson/ne_110m_land.geojson")
OUT_DIR = os.path.join(ROOT, "ui", "assets")
W, H = 1000.0, 500.0


def fetch_src():
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, "ne_110m_land.geojson")
    if not os.path.exists(path) or os.path.getsize(path) < 10000:
        print(f"下载 {SRC_URL} ...")
        with urllib.request.urlopen(SRC_URL, timeout=120) as r, open(path, "wb") as f:
            f.write(r.read())
    return path


def project(lon, lat):
    x = (lon + 180.0) / 360.0 * W
    y = (90.0 - lat) / 180.0 * H
    return round(x, 1), round(y, 1)


def ring_to_path(ring):
    pts = []
    for lon, lat in ring:
        x, y = project(lon, lat)
        pts.append(f"{x} {y}")
    return "M" + "L".join(pts) + "Z"


def main():
    src = fetch_src()
    with open(src, encoding="utf-8") as f:
        gj = json.load(f)

    d_parts = []
    for feat in gj.get("features", []):
        geom = feat.get("geometry") or {}
        gtype = geom.get("type")
        coords = geom.get("coordinates") or []
        polys = coords if gtype == "MultiPolygon" else [coords]
        for poly in polys:
            for ring in poly:
                if len(ring) >= 4:
                    d_parts.append(ring_to_path(ring))

    d = "".join(d_parts)
    os.makedirs(OUT_DIR, exist_ok=True)
    svg_path = os.path.join(OUT_DIR, "world-land.svg")
    with open(svg_path, "w", encoding="utf-8") as f:
        f.write(
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {int(W)} {int(H)}">'
            f'<path d="{d}" fill-rule="evenodd"/></svg>'
        )
    meta_path = os.path.join(OUT_DIR, "world-meta.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump({"width": W, "height": H, "projection": "equirectangular",
                   "source": "Natural Earth 1:110m land (public domain)"},
                  f, ensure_ascii=False, indent=2)

    print(f"陆地环 {len(d_parts)} 个")
    print(f"{os.path.relpath(svg_path, ROOT)}  ({os.path.getsize(svg_path) / 1024:.1f} KB)")
    print(f"{os.path.relpath(meta_path, ROOT)}")


if __name__ == "__main__":
    main()
