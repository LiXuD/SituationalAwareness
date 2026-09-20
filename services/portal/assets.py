#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
assets.py —— 统一资产库业务逻辑（落平台业务库，见 db.py 的 assets 表）。

由 portal 统一后端直接调用，不再透传独立的 asset_server / 不再借用 OpenSearch 当业务库。
对外字段与原 ssp-asset 文档保持一致，前端（assets.js / dashboard.js）零改动。

接口（portal 路由到本模块）：
    GET    /api/assets?q=&importance=&page=&size=
    POST   /api/assets                 手工新增
    PUT    /api/assets/{id}            修改
    DELETE /api/assets/{id}            删除
    POST   /api/assets/import          Excel 导入（multipart，字段 file，全成或全败）
"""
import datetime
import ipaddress
import json
import re
import time
import uuid
import zipfile
import xml.etree.ElementTree as ET
from io import BytesIO

import db

IMPORTANCE_MAP = {"核心": 3, "重要": 2, "一般": 1}
ASSET_TYPES = {"服务器", "网络设备", "安全设备", "终端设备", "应用系统", "数据库", "其他"}

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


def _now():
    return int(time.time())


def _iso(epoch):
    try:
        return datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


def _to_doc(row):
    """SQLite 行 -> 对外文档（tags JSON 字符串转 list，时间转 ISO）。"""
    try:
        tags = json.loads(row.get("tags") or "[]")
    except Exception:
        tags = []
    return {
        "asset_id": row["asset_id"],
        "name": row.get("name") or "",
        "ip": row.get("ip") or "",
        "asset_type": row.get("asset_type") or "其他",
        "importance": row.get("importance") or "一般",
        "importance_score": row.get("importance_score") or IMPORTANCE_MAP.get(row.get("importance") or "一般", 1),
        "risk_score": row.get("risk_score") or 0,
        "owner": row.get("owner") or "",
        "department": row.get("department") or "",
        "location": row.get("location") or "",
        "os": row.get("os") or "",
        "tags": tags,
        "description": row.get("description") or "",
        "created_at": _iso(row["created_at"]),
        "updated_at": _iso(row["updated_at"]),
    }


def _bad_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return False
    except ValueError:
        return True


def parse_multipart(body, content_type):
    """极简 multipart/form-data 解析，返回 {name: (filename, data)}。"""
    m = re.search(r"boundary=([^;]+)", content_type or "")
    if not m:
        return {}
    boundary = ("--" + m.group(1).strip()).encode()
    fields = {}
    for part in body.split(boundary):
        if part in (b"", b"--", b"--\r\n", b"\r\n") or part.startswith(b"--"):
            continue
        if b"\r\n\r\n" not in part:
            continue
        head, _, payload = part.partition(b"\r\n\r\n")
        cd = re.search(r'Content-Disposition: form-data; name="([^"]+)"(?:; filename="([^"]*)")?',
                       head.decode("utf-8", "replace"))
        if not cd:
            continue
        data = payload
        if data.endswith(b"\r\n"):
            data = data[:-2]
        fields[cd.group(1)] = (cd.group(2), data)
    return fields


def _validate(name, ip, importance, risk):
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
        errors.append({"field": "importance", "reason": "重要度枚举非法（应为 核心/重要/一般）"})
    rv = None
    if risk in ("", None):
        errors.append({"field": "risk_score", "reason": "必填为空"})
    else:
        try:
            rv = int(str(risk).strip())
            if rv < 0 or rv > 100:
                errors.append({"field": "risk_score", "reason": "风险评分超出 0-100"})
        except (TypeError, ValueError):
            errors.append({"field": "risk_score", "reason": "风险评分非整数"})
    return errors, rv


def do_list(q="", importance="", page=1, size=20):
    where, params = [], []
    if q:
        where.append("(name LIKE ? OR ip LIKE ? OR owner LIKE ? OR department LIKE ? OR asset_type LIKE ? OR description LIKE ?)")
        like = "%" + q + "%"
        params += [like, like, like, like, like, like]
    if importance:
        where.append("importance = ?")
        params.append(importance)
    wh = ("WHERE " + " AND ".join(where)) if where else ""
    total = db.query_one("SELECT COUNT(*) AS n FROM assets " + wh, params)["n"]
    ph = db.qmark()
    rows = db.query(
        f"SELECT * FROM assets {wh} ORDER BY updated_at DESC LIMIT {size} OFFSET {(page - 1) * size}",
        params)
    return 200, {"total": total, "page": page, "size": size, "items": [_to_doc(r) for r in rows]}


def do_create(body):
    name = (body.get("name") or "").strip()
    ip = (body.get("ip") or "").strip()
    importance = (body.get("importance") or "").strip()
    risk = body.get("risk_score", body.get("risk_score"))
    errors, rv = _validate(name, ip, importance, risk)
    if errors:
        return 422, {"ok": False, "error": "校验失败", "errors": errors}

    aid = (body.get("asset_id") or "").strip() or uuid.uuid4().hex
    atype = (body.get("asset_type") or "").strip() or "其他"
    if atype not in ASSET_TYPES:
        atype = "其他"
    tags = body.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    now = _now()
    try:
        db.execute(
            "INSERT INTO assets (asset_id, name, ip, asset_type, importance, importance_score, "
            "risk_score, owner, department, location, os, tags, description, source, status, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, name, ip, atype, importance, IMPORTANCE_MAP[importance], rv,
             (body.get("owner") or "").strip(), (body.get("department") or "").strip(),
             (body.get("location") or "").strip(), (body.get("os") or "").strip(),
             json.dumps(tags, ensure_ascii=False), (body.get("description") or "").strip(),
             "manual", "active", now, now))
    except Exception as e:
        return 409, {"ok": False, "error": "写入失败: %s" % e}
    row = db.query_one("SELECT * FROM assets WHERE asset_id=?", (aid,))
    return 200, {"ok": True, "asset_id": aid, "asset": _to_doc(row)}


def do_update(aid, body):
    row = db.query_one("SELECT * FROM assets WHERE asset_id=?", (aid,))
    if not row:
        return 404, {"ok": False, "error": "资产不存在: %s" % aid}
    # 先做字段校验
    if "ip" in body and body["ip"] not in ("", None) and _bad_ip(str(body["ip"]).strip()):
        return 422, {"ok": False, "errors": [{"field": "ip", "reason": "IP 格式非法"}]}
    if "importance" in body and str(body["importance"]).strip() not in IMPORTANCE_MAP:
        return 422, {"ok": False, "errors": [{"field": "importance", "reason": "重要度枚举非法"}]}
    if "risk_score" in body:
        try:
            rv = int(body["risk_score"])
            if rv < 0 or rv > 100:
                return 422, {"ok": False, "errors": [{"field": "risk_score", "reason": "风险评分超出 0-100"}]}
        except (TypeError, ValueError):
            return 422, {"ok": False, "errors": [{"field": "risk_score", "reason": "风险评分非整数"}]}

    sets, params = [], []
    for f in ("name", "asset_type", "owner", "department", "location", "os", "description"):
        if f in body:
            sets.append(f + "=?")
            params.append(str(body[f]).strip() if body[f] is not None else "")
    if "ip" in body:
        sets.append("ip=?"); params.append(str(body["ip"]).strip())
    if "importance" in body:
        imp = str(body["importance"]).strip()
        sets.append("importance=?"); params.append(imp)
        sets.append("importance_score=?"); params.append(IMPORTANCE_MAP[imp])
    if "risk_score" in body:
        sets.append("risk_score=?"); params.append(int(body["risk_score"]))
    if "tags" in body:
        tags = body["tags"]
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        sets.append("tags=?"); params.append(json.dumps(tags, ensure_ascii=False))
    if not sets:
        return 200, {"ok": True, "asset_id": aid, "updated": {}}
    sets.append("updated_at=?"); params.append(_now())
    params.append(aid)
    db.execute("UPDATE assets SET " + ", ".join(sets) + " WHERE asset_id=?", params)
    row = db.query_one("SELECT * FROM assets WHERE asset_id=?", (aid,))
    return 200, {"ok": True, "asset_id": aid, "updated": _to_doc(row)}


def do_delete(aid):
    row = db.query_one("SELECT asset_id FROM assets WHERE asset_id=?", (aid,))
    if not row:
        return 404, {"ok": False, "error": "资产不存在: %s" % aid}
    db.execute("DELETE FROM assets WHERE asset_id=?", (aid,))
    return 200, {"ok": True, "deleted": aid}


# ----------------------------- xlsx 解析（标准库） -----------------------------
def _col_to_idx(ref):
    m = re.match(r"([A-Z]+)", ref or "")
    if not m:
        return 0
    idx = 0
    for ch in m.group(1):
        idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return idx - 1


def parse_xlsx(buf):
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


def do_import_xlsx(buf):
    try:
        rows = parse_xlsx(buf)
    except Exception as e:
        return 400, {"ok": False, "error": "xlsx 解析失败: %s" % e}

    if len(rows) < 2:
        return 400, {"ok": False, "error": "文件无数据行", "errors": [{"row": 0, "field": "-", "reason": "空文件"}]}

    headers = rows[0]
    hi = _build_header_index(headers)
    missing = [h for h in REQUIRED_HEADERS if hi[h] < 0]
    if missing:
        return 400, {"ok": False, "error": "缺少必需表头: %s" % ", ".join(missing),
                     "errors": [{"row": 1, "field": h, "reason": "表头缺失"} for h in missing]}

    all_errors, docs, seen = [], [], set()
    for i, row in enumerate(rows[1:], start=2):
        name = _cell(row, hi[H_NAME])
        ip = _cell(row, hi[H_IP])
        importance = _cell(row, hi[H_IMPORTANCE])
        risk = _cell(row, hi[H_RISK])
        errors, rv = _validate(name, ip, importance, risk)
        if errors:
            all_errors.extend({"row": i, **e} for e in errors)
            continue
        atype = _cell(row, hi[H_TYPE])
        if atype and atype not in ASSET_TYPES:
            atype = "其他"
        aid = _cell(row, hi[H_ASSET_ID]) or uuid.uuid4().hex
        if aid in seen:
            all_errors.append({"row": i, "field": H_ASSET_ID, "reason": "资产编号在文件内重复: %s" % aid})
            continue
        seen.add(aid)
        tags = [t.strip() for t in (_cell(row, hi[H_TAGS]) or "").split(",") if t.strip()]
        docs.append({
            "asset_id": aid, "name": name, "ip": ip, "asset_type": atype or "其他",
            "importance": importance, "importance_score": IMPORTANCE_MAP[importance],
            "risk_score": rv,
            "owner": _cell(row, hi[H_OWNER]) or "", "department": _cell(row, hi[H_DEPT]) or "",
            "location": _cell(row, hi[H_LOC]) or "", "os": _cell(row, hi[H_OS]) or "",
            "tags": tags, "description": _cell(row, hi[H_DESC]) or "",
        })

    if all_errors:
        return 422, {"ok": False, "imported": 0,
                     "error": "导入被拒绝：存在 %d 处非法单元格，已回滚（未写入任何文档）" % len(all_errors),
                     "errors": all_errors}
    if not docs:
        return 422, {"ok": False, "imported": 0, "error": "无合法数据行", "errors": []}

    now = _now()

    def _write(cur):
        for d in docs:
            # 覆盖语义：先删同 id 再插（标准 SQL，兼容 SQLite/PG）
            cur.execute("DELETE FROM assets WHERE asset_id=?", (d["asset_id"],))
            cur.execute(
                "INSERT INTO assets (asset_id, name, ip, asset_type, importance, importance_score, "
                "risk_score, owner, department, location, os, tags, description, source, status, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (d["asset_id"], d["name"], d["ip"], d["asset_type"], d["importance"],
                 d["importance_score"], d["risk_score"], d["owner"], d["department"],
                 d["location"], d["os"], json.dumps(d["tags"], ensure_ascii=False), d["description"],
                 "import", "active", now, now))
    try:
        db.run_in_transaction(_write)
    except Exception as e:
        return 422, {"ok": False, "imported": 0, "error": "写入失败已回滚: %s" % e, "errors": []}
    return 200, {"ok": True, "imported": len(docs), "message": "成功导入 %d 条资产" % len(docs)}
