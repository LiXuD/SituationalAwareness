#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
I-06 统一资产库 —— 资产服务（纯标准库实现，零第三方依赖）

设计要点（对应 PRD F-04 / EARS）：
- 纯标准库：http.server + urllib 提供 REST；zipfile + xml.etree 解析 xlsx。
  容器镜像用 python:3.12-slim，无需 pip install，离线可跑。
- 数据落同一个 OpenSearch 集群（OS_URL，默认 http://opensearch:9200），
  索引 ssp-asset，别名 ssp-assets，mapping 见 config/opensearch/ssp-asset-template.json。
- 资产是「独立域」，不是日志事件；含 重要度分级(importance/importance_score)
  与 风险评分(risk_score)，供 I-07 态势大屏按重要度×风险着色/聚合。
- Excel 导入「全成或全败」：先全量解析+逐行校验，任一非法则整批拒绝（4xx +
  errors 明细），保证一个文档都不写入；全部合法才批量写，并对 bulk 失败做回滚。
"""
import os
import sys
import json
import re
import uuid
import ipaddress
import datetime
import urllib.request
import urllib.error
from io import BytesIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import zipfile
import xml.etree.ElementTree as ET

# ----------------------------- 配置（环境变量） -----------------------------
OS_URL = os.environ.get("OS_URL", "http://opensearch:9200").rstrip("/")
ASSET_INDEX = os.environ.get("ASSET_INDEX", "ssp-asset")
ASSET_ALIAS = os.environ.get("ASSET_ALIAS", "ssp-assets")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8090"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_FILE = os.path.join(BASE_DIR, "templates", "asset-import-template.xlsx")

# ----------------------------- 资产模型常量 -----------------------------
IMPORTANCE_MAP = {"核心": 3, "重要": 2, "一般": 1}
ASSET_TYPES = {"服务器", "网络设备", "安全设备", "终端设备", "应用系统", "数据库", "其他"}
# Excel 表头（scripts/gen-asset-template.py 与之保持一致）
H_ASSET_ID = "资产编号(可选)"
H_NAME = "资产名称"
H_IP = "IP地址"
H_TYPE = "资产类型"
H_IMPORTANCE = "重要度"
H_RISK = "风险评分"
H_OWNER = "责任人"
H_DEPT = "所属部门"
H_LOC = "位置/机房"
H_OS = "操作系统"
H_TAGS = "标签"
H_DESC = "备注"
REQUIRED_HEADERS = [H_NAME, H_IP, H_IMPORTANCE, H_RISK]

CORS_ALLOW_ORIGIN = os.environ.get("CORS_ALLOW_ORIGIN", "*")


# ----------------------------- 工具函数 -----------------------------
def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def send_json(handler, status, obj, extra_headers=None):
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", CORS_ALLOW_ORIGIN)
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type,Content-Length")
    if extra_headers:
        for k, v in extra_headers.items():
            handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(body)


def send_bytes(handler, status, data, content_type, filename=None):
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Access-Control-Allow-Origin", CORS_ALLOW_ORIGIN)
    if filename:
        handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    handler.end_headers()
    handler.wfile.write(data)


def os_request(method, path, body=None, as_json=True, timeout=10):
    """极简 OpenSearch REST 客户端（urllib）。"""
    url = OS_URL + path
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(raw) if as_json else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw}
    except Exception as e:  # 连接失败等
        return 503, {"error": str(e)}


# ----------------------------- xlsx 解析（标准库） -----------------------------
def _col_to_idx(ref):
    m = re.match(r"([A-Z]+)", ref or "")
    if not m:
        return 0
    s = m.group(1)
    idx = 0
    for ch in s:
        idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return idx - 1


def parse_xlsx(buf):
    """返回行列表，每行是单元格值(list)。处理共享字符串/空单元格/数字文本混排。"""
    ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    z = zipfile.ZipFile(BytesIO(buf))
    names = set(z.namelist())

    shared = []
    if "xl/sharedStrings.xml" in names:
        root = ET.fromstring(z.read("xl/sharedStrings.xml"))
        for si in root.findall(ns + "si"):
            shared.append("".join(t.text or "" for t in si.iter(ns + "t")))

    sheet_path = "xl/worksheets/sheet1.xml"
    if sheet_path not in names:
        for n in names:
            if n.startswith("xl/worksheets/sheet") and n.endswith(".xml"):
                sheet_path = n
                break
    if sheet_path not in names:
        raise ValueError("xlsx 中未找到 worksheet")

    root = ET.fromstring(z.read(sheet_path))
    rows = []
    for row in root.iter(ns + "row"):
        cells = {}
        maxcol = -1
        for c in row.findall(ns + "c"):
            col = _col_to_idx(c.get("r"))
            t = c.get("t")
            val = None
            if t == "s":
                v = c.find(ns + "v")
                if v is not None and v.text is not None:
                    try:
                        val = shared[int(v.text)]
                    except (ValueError, IndexError):
                        val = None
            elif t == "inlineStr":
                is_el = c.find(ns + "is")
                if is_el is not None:
                    val = "".join(tt.text or "" for tt in is_el.iter(ns + "t"))
            else:
                v = c.find(ns + "v")
                if v is not None and v.text is not None:
                    val = v.text
            cells[col] = val
            if col > maxcol:
                maxcol = col
        rows.append([cells.get(i) for i in range(maxcol + 1)])
    return rows


# ----------------------------- 校验逻辑 -----------------------------
def _build_header_index(headers):
    idx = {}
    for h in (H_ASSET_ID, H_NAME, H_IP, H_TYPE, H_IMPORTANCE, H_RISK,
              H_OWNER, H_DEPT, H_LOC, H_OS, H_TAGS, H_DESC):
        try:
            idx[h] = headers.index(h)
        except ValueError:
            idx[h] = -1
    return idx


def _cell(row, i, default=None):
    if i is None or i < 0 or i >= len(row):
        return default
    v = row[i]
    return v.strip() if isinstance(v, str) else v


def validate_row(row, hi, sheet_row):
    """校验单行；返回 (doc_or_None, errors)。errors: [{row, field, reason}]。"""
    errors = []
    name = _cell(row, hi[H_NAME])
    ip = _cell(row, hi[H_IP])
    importance = _cell(row, hi[H_IMPORTANCE])
    risk = _cell(row, hi[H_RISK])
    atype = _cell(row, hi[H_TYPE])
    aid = _cell(row, hi[H_ASSET_ID])

    if not name:
        errors.append({"row": sheet_row, "field": H_NAME, "reason": "必填为空"})
    if not ip:
        errors.append({"row": sheet_row, "field": H_IP, "reason": "必填为空"})
    elif True:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            errors.append({"row": sheet_row, "field": H_IP, "reason": "IP 格式非法: %s" % ip})

    if not importance:
        errors.append({"row": sheet_row, "field": H_IMPORTANCE, "reason": "必填为空"})
    elif importance not in IMPORTANCE_MAP:
        errors.append({"row": sheet_row, "field": H_IMPORTANCE,
                       "reason": "重要度枚举非法: %s（应为 核心/重要/一般）" % importance})

    if not risk:
        errors.append({"row": sheet_row, "field": H_RISK, "reason": "必填为空"})
    else:
        try:
            rv = int(str(risk).strip())
            if rv < 0 or rv > 100:
                errors.append({"row": sheet_row, "field": H_RISK, "reason": "风险评分超出 0-100: %s" % risk})
        except ValueError:
            errors.append({"row": sheet_row, "field": H_RISK, "reason": "风险评分非整数: %s" % risk})

    if atype and atype not in ASSET_TYPES:
        # 非致命：归为「其他」，不阻断导入
        atype = "其他"

    if errors:
        return None, errors

    doc = {
        "asset_id": (aid if aid else uuid.uuid4().hex),
        "name": name,
        "ip": ip,
        "asset_type": atype or "其他",
        "importance": importance,
        "importance_score": IMPORTANCE_MAP[importance],
        "risk_score": int(str(risk).strip()),
        "owner": _cell(row, hi[H_OWNER]) or "",
        "department": _cell(row, hi[H_DEPT]) or "",
        "location": _cell(row, hi[H_LOC]) or "",
        "os": _cell(row, hi[H_OS]) or "",
        "tags": [t.strip() for t in (_cell(row, hi[H_TAGS]) or "").split(",") if t.strip()],
        "description": _cell(row, hi[H_DESC]) or "",
    }
    return doc, []


# ----------------------------- OpenSearch 写入 -----------------------------
def bulk_index(docs):
    now = now_iso()
    lines = []
    for d in docs:
        d["created_at"] = now
        d["updated_at"] = now
        lines.append(json.dumps({"index": {"_index": ASSET_INDEX, "_id": d["asset_id"]}}, ensure_ascii=False))
        lines.append(json.dumps(d, ensure_ascii=False))
    body = ("\n".join(lines) + "\n").encode("utf-8")
    status, resp = os_request("POST", "/_bulk", body)
    return status, resp


def rollback_bulk(ok_ids):
    if not ok_ids:
        return
    lines = [json.dumps({"delete": {"_index": ASSET_INDEX, "_id": i}}, ensure_ascii=False) for i in ok_ids]
    body = ("\n".join(lines) + "\n").encode("utf-8")
    os_request("POST", "/_bulk", body)


# ----------------------------- multipart 解析 -----------------------------
def parse_multipart(body, content_type):
    m = re.search(r"boundary=([^;]+)", content_type or "")
    if not m:
        return {}
    boundary = ("--" + m.group(1).strip()).encode()
    fields = {}
    for part in body.split(boundary):
        if part in (b"", b"--", b"--\r\n", b"\r\n"):
            continue
        if part.startswith(b"--"):
            continue
        if b"\r\n\r\n" not in part:
            continue
        head, _, payload = part.partition(b"\r\n\r\n")
        head_str = head.decode("utf-8", "replace")
        cd = re.search(r'Content-Disposition: form-data; name="([^"]+)"(?:; filename="([^"]*)")?', head_str)
        if not cd:
            continue
        name = cd.group(1)
        filename = cd.group(2)
        data = payload
        if data.endswith(b"\r\n"):
            data = data[:-2]
        fields[name] = (filename, data)
    return fields


# ----------------------------- 业务处理 -----------------------------
def do_import_xlsx(buf):
    """返回 (status, obj)。全成或全败 + 逐行错误报告。"""
    try:
        rows = parse_xlsx(buf)
    except Exception as e:
        return 400, {"ok": False, "error": "xlsx 解析失败: %s" % e}

    if len(rows) < 2:
        return 400, {"ok": False, "error": "文件无数据行（需表头 + 至少 1 行数据）",
                     "errors": [{"row": 0, "field": "-", "reason": "空文件"}]}

    headers = rows[0]
    hi = _build_header_index(headers)
    missing = [h for h in REQUIRED_HEADERS if hi[h] < 0]
    if missing:
        return 400, {"ok": False, "error": "缺少必需表头: %s" % ", ".join(missing),
                     "errors": [{"row": 1, "field": h, "reason": "表头缺失"} for h in missing]}

    all_errors = []
    docs = []
    for i, row in enumerate(rows[1:], start=2):  # sheet 行号（含表头）
        doc, errs = validate_row(row, hi, i)
        if errs:
            all_errors.extend(errs)
        else:
            docs.append(doc)

    if all_errors:
        # 关键：任一非法则整批拒绝，一个文档都不写入
        return 422, {"ok": False, "imported": 0,
                     "error": "导入被拒绝：存在 %d 处非法单元格，已回滚（未写入任何文档）" % len(all_errors),
                     "errors": all_errors}

    if not docs:
        return 422, {"ok": False, "imported": 0, "error": "无合法数据行", "errors": []}

    status, resp = bulk_index(docs)
    if status >= 400 or (isinstance(resp, dict) and resp.get("errors")):
        # bulk 级失败：收集成功 id 并回滚，保证全成或全败
        ok_ids = []
        bulk_errors = []
        if isinstance(resp, dict):
            for item in resp.get("items", []):
                op = item.get("index", {})
                if op.get("status", 0) >= 400:
                    bulk_errors.append({"row": 0, "field": "_id",
                                         "reason": "%s: %s" % (op.get("_id"), op.get("error", {}).get("type", "bulk失败"))})
                else:
                    ok_ids.append(op.get("_id"))
        rollback_bulk(ok_ids)
        return 422, {"ok": False, "imported": 0,
                     "error": "批量写入失败，已回滚", "errors": bulk_errors or [{"row": 0, "field": "-", "reason": "ES bulk 错误"}]}

    return 200, {"ok": True, "imported": len(docs),
                 "message": "成功导入 %d 条资产" % len(docs)}


def do_list(q, importance, page, size):
    must = []
    filt = []
    if q:
        filt.append({"multi_match": {"query": q,
                       "fields": ["name^2", "name.keyword", "ip", "owner",
                                  "department", "asset_type", "tags", "description"]}})
    if importance:
        filt.append({"term": {"importance": importance}})
    query = {"bool": {"must": must or [{"match_all": {}}], "filter": filt}}
    body = {
        "from": (page - 1) * size, "size": size,
        "sort": [{"updated_at": {"order": "desc"}}],
        "query": query,
        "_source": ["asset_id", "name", "ip", "asset_type", "importance",
                    "importance_score", "risk_score", "owner", "department",
                    "location", "os", "tags", "description", "created_at", "updated_at"],
    }
    status, resp = os_request("POST", "/%s/_search" % ASSET_INDEX, json.dumps(body))
    if status >= 400:
        return status, resp
    hits = resp.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    items = [h.get("_source", {}) for h in hits.get("hits", [])]
    return 200, {"total": total, "page": page, "size": size, "items": items}


def do_create(body):
    name = (body.get("name") or "").strip()
    ip = (body.get("ip") or "").strip()
    importance = (body.get("importance") or "").strip()
    risk = body.get("risk_score", body.get("risk_score"))
    errors = []
    if not name:
        errors.append({"field": "name", "reason": "必填为空"})
    if not ip:
        errors.append({"field": "ip", "reason": "必填为空"})
    elif _bad_ip(ip):
        errors.append({"field": "ip", "reason": "IP 格式非法: %s" % ip})
    if not importance:
        errors.append({"field": "importance", "reason": "必填为空"})
    elif importance not in IMPORTANCE_MAP:
        errors.append({"field": "importance", "reason": "重要度枚举非法"})
    try:
        rv = int(risk)
        if rv < 0 or rv > 100:
            errors.append({"field": "risk_score", "reason": "风险评分超出 0-100"})
    except (TypeError, ValueError):
        errors.append({"field": "risk_score", "reason": "风险评分非整数"})
    if errors:
        return 422, {"ok": False, "error": "校验失败", "errors": errors}

    aid = (body.get("asset_id") or "").strip() or uuid.uuid4().hex
    atype = (body.get("asset_type") or "").strip() or "其他"
    if atype not in ASSET_TYPES:
        atype = "其他"
    now = now_iso()
    doc = {
        "asset_id": aid,
        "name": name, "ip": ip, "asset_type": atype, "importance": importance,
        "importance_score": IMPORTANCE_MAP[importance], "risk_score": rv,
        "owner": (body.get("owner") or "").strip(),
        "department": (body.get("department") or "").strip(),
        "location": (body.get("location") or "").strip(),
        "os": (body.get("os") or "").strip(),
        "tags": [t.strip() for t in ((body.get("tags") or []) if isinstance(body.get("tags"), list)
                                     else str(body.get("tags") or "").split(",")) if t.strip()],
        "description": (body.get("description") or "").strip(),
        "created_at": now, "updated_at": now,
    }
    status, resp = os_request("POST", "/%s/_doc/%s" % (ASSET_INDEX, aid),
                              json.dumps(doc, ensure_ascii=False))
    if status >= 400:
        return status, resp
    return 200, {"ok": True, "asset_id": aid, "asset": doc}


def _bad_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return False
    except ValueError:
        return True


def do_update(aid, body):
    now = now_iso()
    doc = {}
    if "name" in body: doc["name"] = str(body["name"]).strip()
    if "ip" in body:
        if _bad_ip(str(body["ip"]).strip()):
            return 422, {"ok": False, "errors": [{"field": "ip", "reason": "IP 格式非法"}]}
        doc["ip"] = str(body["ip"]).strip()
    if "importance" in body:
        imp = str(body["importance"]).strip()
        if imp not in IMPORTANCE_MAP:
            return 422, {"ok": False, "errors": [{"field": "importance", "reason": "重要度枚举非法"}]}
        doc["importance"] = imp
        doc["importance_score"] = IMPORTANCE_MAP[imp]
    if "risk_score" in body:
        try:
            rv = int(body["risk_score"])
            if rv < 0 or rv > 100:
                return 422, {"ok": False, "errors": [{"field": "risk_score", "reason": "风险评分超出 0-100"}]}
            doc["risk_score"] = rv
        except (TypeError, ValueError):
            return 422, {"ok": False, "errors": [{"field": "risk_score", "reason": "风险评分非整数"}]}
    for f in ("asset_type", "owner", "department", "location", "os", "description"):
        if f in body:
            doc[f] = str(body[f]).strip() if body[f] is not None else ""
    if "tags" in body:
        doc["tags"] = [t.strip() for t in (body["tags"] if isinstance(body["tags"], list)
                                           else str(body["tags"]).split(",")) if t.strip()]
    doc["updated_at"] = now
    status, resp = os_request("POST", "/%s/_update/%s" % (ASSET_INDEX, aid),
                              json.dumps({"doc": doc}, ensure_ascii=False))
    if status >= 400:
        return status, resp
    return 200, {"ok": True, "asset_id": aid, "updated": doc}


def do_delete(aid):
    status, resp = os_request("DELETE", "/%s/_doc/%s" % (ASSET_INDEX, aid))
    if status == 404:
        return 404, {"ok": False, "error": "资产不存在: %s" % aid}
    if status >= 400:
        return status, resp
    return 200, {"ok": True, "deleted": aid}


LANDING = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"/>
<title>统一资产库 · 服务</title>
<style>body{background:#0f1420;color:#e6ebf5;font:14px/1.6 -apple-system,Segoe UI,sans-serif;padding:40px}
a{color:#3b82f6} code{background:#1e2536;padding:2px 6px;border-radius:4px}</style></head>
<body>
<h1>🛡 统一资产库服务（I-06）</h1>
<p>资产库管理 UI：<a href="http://localhost:8088/assets.html">http://localhost:8088/assets.html</a></p>
<p>健康检查：<code>GET /healthz</code></p>
<ul>
<li><code>GET /api/assets?q=&amp;importance=&amp;page=&amp;size=</code> 列表</li>
<li><code>POST /api/assets</code> 手工新增</li>
<li><code>PUT /api/assets/{id}</code> 修改</li>
<li><code>DELETE /api/assets/{id}</code> 删除</li>
<li><code>POST /api/assets/import</code> Excel 导入（multipart, 字段名 file）</li>
<li><code>GET /api/assets/template.xlsx</code> 模板下载</li>
</ul>
<p>索引：<code>%s</code> ｜ 别名：<code>%s</code> ｜ 后端：<code>%s</code></p>
</body></html>""" % (ASSET_INDEX, ASSET_ALIAS, OS_URL)


# ----------------------------- HTTP Handler -----------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "ssp-asset/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[asset] " + (fmt % args) + "\n")

    def _send_cors_preflight(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", CORS_ALLOW_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Content-Length")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_OPTIONS(self):
        self._send_cors_preflight()

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def _parse_qs(self):
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query)
        return {k: v[0] for k, v in q.items()}

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            send_bytes(self, 200, LANDING.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/healthz":
            st, _ = os_request("GET", "/_cluster/health")
            ok = st == 200
            send_json(self, 200, {"status": "ok" if ok else "degraded",
                                   "opensearch": OS_URL, "opensearch_reachable": ok})
            return
        if path == "/api/assets/template.xlsx":
            if not os.path.exists(TEMPLATE_FILE):
                send_json(self, 404, {"error": "模板文件缺失: %s" % TEMPLATE_FILE})
                return
            with open(TEMPLATE_FILE, "rb") as f:
                send_bytes(self, 200, f.read(),
                           "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                           "asset-import-template.xlsx")
            return
        if path == "/api/assets":
            qs = self._parse_qs()
            try:
                page = max(1, int(qs.get("page", "1")))
                size = min(200, max(1, int(qs.get("size", "20"))))
            except ValueError:
                page, size = 1, 20
            st, obj = do_list(qs.get("q", "").strip(), qs.get("importance", "").strip(), page, size)
            send_json(self, st, obj)
            return
        send_json(self, 404, {"error": "not found: %s" % path})

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/api/assets":
            try:
                body = json.loads(self._read_body().decode("utf-8") or "{}")
            except Exception as e:
                send_json(self, 400, {"ok": False, "error": "JSON 解析失败: %s" % e})
                return
            st, obj = do_create(body)
            send_json(self, st, obj)
            return
        if path == "/api/assets/import":
            ct = self.headers.get("Content-Type", "")
            raw = self._read_body()
            fields = parse_multipart(raw, ct)
            f = fields.get("file")
            if not f or not f[1]:
                send_json(self, 400, {"ok": False, "error": "未收到文件字段 file"})
                return
            st, obj = do_import_xlsx(f[1])
            send_json(self, st, obj)
            return
        send_json(self, 404, {"error": "not found: %s" % path})

    def do_PUT(self):
        m = re.match(r"^/api/assets/([^/]+)$", self.path.split("?")[0])
        if m:
            aid = m.group(1)
            try:
                body = json.loads(self._read_body().decode("utf-8") or "{}")
            except Exception as e:
                send_json(self, 400, {"ok": False, "error": "JSON 解析失败: %s" % e})
                return
            st, obj = do_update(aid, body)
            send_json(self, st, obj)
            return
        send_json(self, 404, {"error": "not found"})

    def do_DELETE(self):
        m = re.match(r"^/api/assets/([^/]+)$", self.path.split("?")[0])
        if m:
            st, obj = do_delete(m.group(1))
            send_json(self, st, obj)
            return
        send_json(self, 404, {"error": "not found"})


def main():
    httpd = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print("[asset] listening on %s:%d  OS=%s  index=%s" %
          (LISTEN_HOST, LISTEN_PORT, OS_URL, ASSET_INDEX), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


if __name__ == "__main__":
    main()
