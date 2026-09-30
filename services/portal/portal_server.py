#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
portal_server.py —— 平台统一后端（BFF）+ 统一登录 / 会话 / 角色权限。

定位（用户要求"统一管理查看"且"前端要成工程"）：
  * **浏览器只访问平台一个源**（经 nginx 反代 /api → 本服务），第三方组件全部是内部数据源；
  * 未登录一律 401；已登录按 PRD §11 的角色做**接口级授权**。

角色（PRD §11）
    analyst      分析师      查看 / 研判 / 下钻
    ops          运维        审批并提交拉黑
    asset_admin  资产管理员  资产增删改 / Excel 导入
    admin        技术负责人  平台配置（全部权限）

只依赖 Python 标准库（http.server + urllib + hashlib）。

路由
----
  POST /api/auth/login    登录（种会话 Cookie）
  POST /api/auth/logout   退出
  GET  /api/auth/me       当前用户
  /api/traffic/*          Arkime（会话/PCAP，服务端 digest 鉴权 + 参数翻译）
  /api/os/*               OpenSearch
  /api/corr/*             关联分析
  /api/asset/*            统一资产库
  /api/soar/*             SOAR 拉黑审批
  /api/discovery/*        资产测绘（候选池 / 采纳 / 忽略 / 配置 / 触发）
  /api/branches/*         多分支汇聚（分支登记 / 汇聚健康 / 探测）
  GET  /health            平台与上游连通性

环境变量
--------
  PORTAL_PORT 8093 | USERS_FILE /srv/users.json | SESSION_TTL_SECONDS 28800
  OPENSEARCH_URL | CORRELATOR_URL | ASSET_URL | SOAR_URL | ARKIME_URL/ARKIME_USER/ARKIME_PASS
  DISCOVERY_INTERVAL_SECONDS 3600（资产测绘定时；0=关闭）
  BRANCH_HEALTH_INTERVAL_SECONDS 300（分支汇聚健康探测；0=关闭）
"""
import hashlib
import hmac
import http.cookies
import json
import logging
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import assets
import db
import soar
import users

log = logging.getLogger("portal")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S")


PORTAL_PORT = int(os.environ.get("PORTAL_PORT", "8093"))
SESSION_TTL = int(os.environ.get("SESSION_TTL_SECONDS", "28800"))
COOKIE_NAME = os.environ.get("SESSION_COOKIE", "ssp_session")

ARKIME_URL = os.environ.get("ARKIME_URL", "http://arkime:8005").rstrip("/")
ARKIME_USER = os.environ.get("ARKIME_USER", "admin")
# Arkime 口令只从环境注入（compose 由 deploy/.env 插值）——**代码里不留任何默认口令**
ARKIME_PASS = os.environ.get("ARKIME_PASS", "")

UPSTREAMS = {
    "os":    os.environ.get("OPENSEARCH_URL", "http://opensearch:9200").rstrip("/"),
    "corr":  os.environ.get("CORRELATOR_URL", "http://correlator:8091").rstrip("/"),
    "soar":  os.environ.get("SOAR_URL", "http://soar:8092").rstrip("/"),
}

ROLE_LABEL = {"analyst": "分析师", "ops": "运维", "asset_admin": "资产管理员", "admin": "技术负责人"}
READ_ROLES = {"analyst", "ops", "asset_admin", "admin"}
WRITE_ROLES = {                      # 写操作授权（未列出的模块默认仅 admin）
    "os":      {"admin"},
    "traffic": {"admin"},
    "corr":    {"admin"},
    "asset":   {"asset_admin", "admin"},
    "soar":    {"ops", "admin"},
    "discovery": {"asset_admin", "admin"},   # I-12 资产测绘：采纳/忽略/触发
    "branches":  {"admin"},                  # I-13 多分支汇聚：分支登记/探测
}

_PROTO_MAP = {"6": "tcp", "tcp": "tcp", "17": "udp", "udp": "udp", "1": "icmp", "icmp": "icmp"}

_plain = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_pm = urllib.request.HTTPPasswordMgrWithDefaultRealm()
_pm.add_password(None, ARKIME_URL, ARKIME_USER, ARKIME_PASS)
_arkime = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPDigestAuthHandler(_pm),
    urllib.request.HTTPBasicAuthHandler(_pm),
)

# --------------------------------------------------------------------------- #
# 账号 / 会话 / 审计（统一落到平台业务库，见 db.py）
# --------------------------------------------------------------------------- #
def _verify_password(u, password):
    try:
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(u["salt"]), int(u.get("iterations", 200000)))
        return hmac.compare_digest(dk.hex(), u["hash"])
    except Exception:
        return False


def _now():
    return int(time.time())


def _open(opener, method, url, body=None, ctype=None, timeout=60):
    hdrs = {}
    if ctype:
        hdrs["Content-Type"] = ctype
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()
    except Exception as e:
        return 0, {}, json.dumps({"error": f"{type(e).__name__}: {e}"}).encode()


def _arkime_json(path, timeout=60):
    st, _h, body = _open(_arkime, "GET", ARKIME_URL + path, timeout=timeout)
    try:
        return st, json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return st, {"raw": body.decode("utf-8", "replace")[:400]}


def _build_expression(q):
    if q.get("expression"):
        return q["expression"]
    parts = []
    if (q.get("ip") or "").strip():
        parts.append(f"ip == {q['ip'].strip()}")
    if (q.get("src_ip") or "").strip():
        parts.append(f"ip.src == {q['src_ip'].strip()}")
    if (q.get("dst_ip") or "").strip():
        parts.append(f"ip.dst == {q['dst_ip'].strip()}")
    proto = (q.get("proto") or "").strip().lower()
    if proto:
        parts.append(f"protocol == {_PROTO_MAP.get(proto, proto)}")
    if (q.get("port") or "").strip():
        parts.append(f"port == {q['port'].strip()}")
    return " && ".join(parts)


def _date_range(q):
    s, e = q.get("start"), q.get("end")
    return f"{int(float(s))}|{int(float(e))}" if (s and e) else "-1"


# OpenSearch 用 POST 承载的**只读**接口（语义是"查"而非"写"）
OS_READ_HINTS = ("_search", "_count", "_msearch", "_field_caps", "_analyze",
                 "_validate", "_explain", "_rank_eval", "_cat")


def is_write(key, method, rest):
    """判定是否属于"写操作"。

    不能只看 HTTP 方法：OpenSearch 的检索/计数都是用 POST 发的（`_search` / `_count`），
    语义上仍是读。若把它们当写，分析师连大屏和检索都用不了。
    """
    if method in ("GET", "HEAD"):
        return False
    if key == "os":
        return not any(h in rest for h in OS_READ_HINTS)
    return True


class Handler(BaseHTTPRequestHandler):
    server_version = "ssp-portal/3.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[portal] %s - %s\n" % (self.address_string(), fmt % args))

    # ---------------- 基础 ----------------
    def _json(self, status, obj, cookie=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_raw(self, status, body, ctype="application/json; charset=utf-8", extra=None):
        self.send_response(status or 502)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else None

    def _json_body(self):
        try:
            return json.loads((self._body() or b"{}").decode("utf-8") or "{}")
        except Exception:
            return {}

    def _session(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            c = http.cookies.SimpleCookie(raw)
            tok = c[COOKIE_NAME].value if COOKIE_NAME in c else None
        except Exception:
            return None
        if not tok:
            return None
        return db.query_one(
            "SELECT token, username, role, display FROM sessions WHERE token=? AND expires_at>?",
            (tok, _now()))

    def _audit(self, username, action, target="", detail=""):
        try:
            import uuid
            db.execute(
                "INSERT INTO audit_log (id, username, action, target, detail, ip, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, username, action, target, detail,
                 self.client_address[0], _now()))
        except Exception as e:
            # 审计日志是安全相关记录：写入失败不能静默，至少留痕
            log.warning(f"[portal] 审计日志写入失败: {type(e).__name__}: {e}")

    # ---------------- 路由 ----------------
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._route()

    def do_HEAD(self):
        self._route()

    def do_POST(self):
        self._route()

    def do_PUT(self):
        self._route()

    def do_DELETE(self):
        self._route()

    def _route(self):
        try:
            self._dispatch()
        except Exception as e:
            self._json(500, {"error": f"{type(e).__name__}: {e}"})

    def _dispatch(self):
        u = urllib.parse.urlparse(self.path)
        path = u.path
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        write = self.command not in ("GET", "HEAD")

        # ---- 公开：健康检查 ----
        if path in ("/health", "/") and not write:
            ups = {}
            for name, base in UPSTREAMS.items():
                st, _h, _b = _open(_plain, "GET", base + "/", timeout=5)
                ups[name] = 0 < st < 500
            st, _h, _b = _open(_arkime, "GET", ARKIME_URL + "/api/eshealth", timeout=5)
            ups["arkime"] = st == 200
            try:
                n_users = db.query_one("SELECT COUNT(*) AS n FROM users")["n"]
                ups["db"] = True
            except Exception:
                n_users, ups["db"] = 0, False
            self._json(200, {"status": "ok", "portal_port": PORTAL_PORT,
                             "backend": db.backend(), "users": n_users, "upstreams": ups})
            return

        # ---- 认证 ----
        if path == "/api/auth/login" and write:
            b = self._json_body()
            name = (b.get("username") or "").strip()
            pwd = b.get("password") or ""
            usr = db.query_one(
                "SELECT username, display, role, salt, hash, iterations, status "
                "FROM users WHERE username=?", (name,))
            if not usr or usr.get("status") != "active" or not _verify_password(usr, pwd):
                time.sleep(0.4)               # 轻微延时，抑制暴力猜测
                self._audit(name, "login_failed", "session", "用户名或密码错误")
                self._json(401, {"error": "用户名或密码错误"})
                return
            tok = secrets.token_urlsafe(32)
            now = _now()
            db.execute(
                "INSERT INTO sessions (token, username, role, display, created_at, expires_at, ip, user_agent) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (tok, usr["username"], usr["role"], usr.get("display") or usr["username"],
                 now, now + SESSION_TTL, self.client_address[0],
                 self.headers.get("User-Agent", "")))
            self._audit(usr["username"], "login", "session", "登录成功")
            ck = f"{COOKIE_NAME}={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"
            self._json(200, {"ok": True, "user": {"username": usr["username"],
                                                  "role": usr["role"],
                                                  "role_label": ROLE_LABEL.get(usr["role"], usr["role"]),
                                                  "display": usr.get("display") or usr["username"]}},
                       cookie=ck)
            return

        if path == "/api/auth/logout" and write:
            raw = self.headers.get("Cookie")
            tok = None
            try:
                c = http.cookies.SimpleCookie(raw or "")
                if COOKIE_NAME in c:
                    tok = c[COOKIE_NAME].value
            except Exception:
                pass
            if tok:
                s = db.query_one("SELECT username FROM sessions WHERE token=?", (tok,))
                db.execute("DELETE FROM sessions WHERE token=?", (tok,))
                if s:
                    self._audit(s["username"], "logout", "session", "退出登录")
            self._json(200, {"ok": True}, cookie=f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
            return

        if path == "/api/auth/me" and not write:
            s = self._session()
            if not s:
                self._json(401, {"error": "未登录或会话已过期", "need_login": True})
                return
            self._json(200, {"user": {"username": s["username"], "role": s["role"],
                                      "role_label": ROLE_LABEL.get(s["role"], s["role"]),
                                      "display": s["display"]}})
            return

        # ---- 以下全部需要登录 ----
        sess = self._session()
        if not sess:
            self._json(401, {"error": "未登录或会话已过期", "need_login": True})
            return

        # ---- 流量回溯 ----
        if path == "/api/traffic/health" and not write:
            st, d = _arkime_json("/api/eshealth")
            self._json(st or 502, d)
            return
        if path == "/api/traffic/files" and not write:
            st, d = _arkime_json("/api/files?length=200")
            self._json(st or 502, d)
            return
        if path == "/api/traffic/sessions" and not write:
            expr = _build_expression(q)
            params = {"date": _date_range(q), "length": int(q.get("limit", "100")),
                      "start": int(q.get("offset", "0"))}
            if expr:
                params["expression"] = expr
            st, d = _arkime_json("/api/sessions?" + urllib.parse.urlencode(params))
            if isinstance(d, dict):
                d["_query"] = {"expression": expr or "(all)", "date": params["date"]}
            self._json(st or 502, d)
            return
        if path == "/api/traffic/pcap" and not write:
            expr = _build_expression(q)
            params = {"date": _date_range(q)}
            if expr:
                params["expression"] = expr
            st, hdrs, body = _open(_arkime, "GET",
                                   ARKIME_URL + "/api/sessions/pcap?" + urllib.parse.urlencode(params),
                                   timeout=180)
            self._send_raw(st, body, hdrs.get("Content-Type", "application/vnd.tcpdump.pcap"),
                           extra={"Content-Disposition": 'attachment; filename="ssp-export.pcap"'})
            return

        # ---- 统一资产库（落业务库，替代 asset_server 透传；前端路径 /api/asset/api/assets*）----
        if path.startswith("/api/asset/api/assets"):
            sub = path[len("/api/asset/api/assets"):]
            if sub == "/template.xlsx" and not write:
                tpl = os.environ.get("ASSET_TEMPLATE_FILE", "/srv/templates/asset-import-template.xlsx")
                if os.path.exists(tpl):
                    with open(tpl, "rb") as f:
                        self._send_raw(200, f.read(),
                                       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                       extra={"Content-Disposition": 'attachment; filename="asset-import-template.xlsx"'})
                else:
                    self._json(404, {"error": "模板文件缺失"})
                return
            if write and sess["role"] not in WRITE_ROLES["asset"]:
                self._json(403, {"error": "当前角色无权执行该操作", "role": sess["role"],
                                 "required": sorted(WRITE_ROLES["asset"])})
                return
            if sub in ("", "/"):
                if write:
                    st, obj = assets.do_create(self._json_body())
                    if st == 200:
                        self._audit(sess["username"], "POST", "/api/assets", obj.get("asset_id", ""))
                else:
                    page = max(1, int(q.get("page", "1") or "1"))
                    size = min(200, max(1, int(q.get("size", "20") or "20")))
                    st, obj = assets.do_list(q.get("q", "").strip(), q.get("importance", "").strip(), page, size)
                self._json(st, obj)
                return
            if sub == "/import" and write:
                fields = assets.parse_multipart(self._body(), self.headers.get("Content-Type", ""))
                f = fields.get("file")
                if not f or not f[1]:
                    self._json(400, {"ok": False, "error": "未收到文件字段 file"})
                    return
                st, obj = assets.do_import_xlsx(f[1])
                if st == 200:
                    self._audit(sess["username"], "POST", "/api/assets/import",
                                "导入 %d 条" % obj.get("imported", 0))
                self._json(st, obj)
                return
            if sub.startswith("/") and len(sub) > 1 and sub != "/import":
                aid = sub[1:]
                if self.command == "PUT":
                    st, obj = assets.do_update(aid, self._json_body())
                    if st == 200:
                        self._audit(sess["username"], "PUT", "/api/assets/" + aid, "")
                elif self.command == "DELETE":
                    st, obj = assets.do_delete(aid)
                    if st == 200:
                        self._audit(sess["username"], "DELETE", "/api/assets/" + aid, "")
                else:
                    st, obj = 404, {"error": "not found"}
                self._json(st, obj)
                return

        # ---- SOAR 拉黑审批（落业务库，替代 soar_server 透传）----
        if path.startswith("/api/soar/soar"):
            sub = path[len("/api/soar"):]  # 例如 /soar/drafts、/soar/blocks
            soar_write = sess["role"] in WRITE_ROLES["soar"]
            if sub in ("/soar/drafts",) and not write:
                st, obj = soar.list_drafts(q.get("status"), int(q.get("limit", "100") or "100"))
                self._json(st, obj)
                return
            if sub == "/soar/blocks" and not write:
                self._json(200, soar.list_blocks())
                return
            if sub == "/soar/rules" and not write:
                self._json(200, {"block_grades": soar.BLOCK_GRADES, "auto_execute": False,
                                 "note": "达到级别的告警自动生成草稿；提交封禁必须人工审批"})
                return
            if sub == "/soar/drafts/generate" and write:
                if not soar_write:
                    self._json(403, {"error": "当前角色无权执行该操作", "role": sess["role"],
                                     "required": sorted(WRITE_ROLES["soar"])})
                    return
                obj = soar.generate_drafts()
                self._audit(sess["username"], "POST", "/soar/drafts/generate", "新增草稿 %d" % obj.get("created_count", 0))
                self._json(200, obj)
                return
            if sub.endswith("/approve") and write and sub.startswith("/soar/drafts/"):
                if not soar_write:
                    self._json(403, {"error": "当前角色无权执行该操作", "role": sess["role"],
                                     "required": sorted(WRITE_ROLES["soar"])})
                    return
                b = self._json_body()
                code, obj = soar.approve_draft(sub.split("/")[-2], b.get("operator"), bool(b.get("dry_run")))
                if code == 200:
                    self._audit(sess["username"], "approve", "/soar/drafts/" + sub.split("/")[-2], "")
                self._json(code, obj)
                return
            if sub.endswith("/reject") and write and sub.startswith("/soar/drafts/"):
                if not soar_write:
                    self._json(403, {"error": "当前角色无权执行该操作", "role": sess["role"],
                                     "required": sorted(WRITE_ROLES["soar"])})
                    return
                b = self._json_body()
                code, obj = soar.reject_draft(sub.split("/")[-2], b.get("operator"))
                if code == 200:
                    self._audit(sess["username"], "reject", "/soar/drafts/" + sub.split("/")[-2], "")
                self._json(code, obj)
                return
            if sub == "/soar/blocks/remove" and write:
                if not soar_write:
                    self._json(403, {"error": "当前角色无权执行该操作", "role": sess["role"],
                                     "required": sorted(WRITE_ROLES["soar"])})
                    return
                b = self._json_body()
                code, obj = soar.unblock(b.get("ip"), b.get("operator"))
                if code == 200:
                    self._audit(sess["username"], "unblock", "/soar/blocks/remove", b.get("ip", ""))
                self._json(code, obj)
                return
            if sub.startswith("/soar/drafts/") and not write:
                d = soar.get_draft(sub.split("/")[-1])
                self._json(200 if d else 404, d or {"error": "not found"})
                return

        # ---- 账号管理（仅管理员；落业务库）----
        if path.startswith("/api/users"):
            if sess["role"] != "admin":
                self._json(403, {"error": "仅管理员可管理账号", "role": sess["role"]})
                return
            sub = path[len("/api/users"):]
            if sub in ("", "/"):
                if write:
                    st, obj = users.create_user(self._json_body())
                    if st == 200:
                        self._audit(sess["username"], "user_create",
                                    obj.get("user", {}).get("username", ""), "")
                else:
                    st, obj = users.list_users()
                self._json(st, obj)
                return
            uname = sub.lstrip("/")
            if self.command == "PUT":
                st, obj = users.update_user(uname, self._json_body())
                if st == 200:
                    self._audit(sess["username"], "user_update", uname, "")
            elif self.command == "DELETE":
                st, obj = users.delete_user(uname, sess["username"])
                if st == 200:
                    self._audit(sess["username"], "user_delete", uname, "")
            elif self.command in ("GET", "HEAD"):
                u = users.get_user(uname)
                st, obj = (200, u) if u else (404, {"error": "用户不存在"})
            else:
                st, obj = 405, {"error": "method not allowed"}
            self._json(st, obj)
            return

        # ---- 资产测绘（I-12：被动识别 → 候选池 → 采纳/忽略；落业务库）----
        if path.startswith("/api/discovery"):
            import discovery
            sub = path[len("/api/discovery"):]
            disc_write = WRITE_ROLES.get("discovery", {"admin"})

            def _need_write():
                if sess["role"] in disc_write:
                    return True
                self._json(403, {"error": f"当前角色「{ROLE_LABEL.get(sess['role'], sess['role'])}」"
                                          f"无权执行该操作", "role": sess["role"],
                                 "required": sorted(disc_write)})
                return False

            if sub == "/candidates" and not write:
                page = max(1, int(q.get("page", "1") or "1"))
                size = min(200, max(1, int(q.get("size", "50") or "50")))
                st, obj = discovery.list_candidates(q.get("status", "pending").strip(),
                                                    q.get("q", "").strip(),
                                                    q.get("source", "").strip(), page, size)
                self._json(st, obj)
                return
            if sub == "/stats" and not write:
                self._json(*discovery.stats())
                return
            if sub == "/config":
                if not write:
                    self._json(200, discovery.get_config())
                    return
                if sess["role"] != "admin":
                    self._json(403, {"error": "仅管理员可修改测绘配置", "role": sess["role"]})
                    return
                st, obj = discovery.set_config(self._json_body())
                if st == 200:
                    self._audit(sess["username"], "PUT", "/api/discovery/config", "")
                self._json(st, obj)
                return
            if sub == "/run" and write:
                if not _need_write():
                    return
                b = self._json_body()
                st, obj = discovery.run(b.get("window_minutes"))
                if st == 200:
                    self._audit(sess["username"], "POST", "/api/discovery/run",
                                "新增候选 %s / 刷新 %s" % (obj.get("created"), obj.get("updated")))
                self._json(st, obj)
                return
            if sub == "/adopt" and write:
                if not _need_write():
                    return
                st, obj = discovery.adopt(self._json_body().get("ids") or [], sess["username"])
                if st == 200:
                    self._audit(sess["username"], "discovery_adopt", "/api/discovery/adopt",
                                "采纳 %s（新增 %s / 合并 %s）" % (obj.get("adopted"), obj.get("created"),
                                                                obj.get("merged")))
                self._json(st, obj)
                return
            if sub == "/ignore" and write:
                if not _need_write():
                    return
                st, obj = discovery.ignore(self._json_body().get("ids") or [], sess["username"])
                if st == 200:
                    self._audit(sess["username"], "discovery_ignore", "/api/discovery/ignore",
                                "忽略 %s" % obj.get("ignored"))
                self._json(st, obj)
                return

        # ---- 多分支汇聚（I-13：分支登记 + 汇聚健康；落业务库）----
        if path.startswith("/api/branches"):
            import branches
            sub = path[len("/api/branches"):]

            def _need_admin():
                if sess["role"] == "admin":
                    return True
                self._json(403, {"error": "仅管理员可维护分支登记与探测",
                                 "role": sess["role"], "required": ["admin"]})
                return False

            if sub in ("", "/") and not write:
                self._json(*branches.list_branches())
                return
            if sub == "/stats" and not write:
                self._json(*branches.stats())
                return
            if sub == "/probe" and write:
                if not _need_admin():
                    return
                st, obj = branches.probe()
                if st == 200:
                    self._audit(sess["username"], "branch_probe", "/api/branches/probe",
                                "在线 %s / 离线 %s" % (obj.get("state_counts", {}).get("ok", 0),
                                                     obj.get("state_counts", {}).get("no_data", 0)))
                self._json(st, obj)
                return
            if write:
                if not _need_admin():
                    return
                if sub in ("", "/"):
                    st, obj = branches.create_branch(self._json_body())
                    if st == 200:
                        self._audit(sess["username"], "branch_create", obj.get("branch_id", ""), "")
                    self._json(st, obj)
                    return
                bid = sub.lstrip("/")
                if self.command == "PUT":
                    st, obj = branches.update_branch(bid, self._json_body())
                    if st == 200:
                        self._audit(sess["username"], "branch_update", bid, "")
                    self._json(st, obj)
                    return
                if self.command == "DELETE":
                    st, obj = branches.delete_branch(bid)
                    if st == 200:
                        self._audit(sess["username"], "branch_delete", bid, "")
                    self._json(st, obj)
                    return

        # ---- 通用透传 + 授权 ----
        parts = path.split("/")
        if len(parts) >= 4 and parts[1] == "api" and parts[2] in UPSTREAMS:
            key = parts[2]
            rest = "/".join(parts[3:])
            allowed = (WRITE_ROLES.get(key, {"admin"})
                       if is_write(key, self.command, rest) else READ_ROLES)
            if sess["role"] not in allowed:
                self._json(403, {"error": f"当前角色「{ROLE_LABEL.get(sess['role'], sess['role'])}」"
                                          f"无权执行该操作", "role": sess["role"],
                                 "required": sorted(allowed)})
                return
            if is_write(key, self.command, rest):
                self._audit(sess["username"], self.command, f"/api/{key}/{rest}", "")
            base = UPSTREAMS[key]
            url = f"{base}/{rest}" + (("?" + u.query) if u.query else "")
            st, hdrs, body = _open(_plain, self.command, url, body=self._body(),
                                   ctype=self.headers.get("Content-Type"), timeout=90)
            self._send_raw(st, body, hdrs.get("Content-Type", "application/json; charset=utf-8"))
            return

        self._json(404, {"error": "not found: %s" % path})


def _start_discovery_timer():
    """I-12：后台定时执行资产测绘（默认每小时；DISCOVERY_INTERVAL_SECONDS=0 关闭）。"""
    try:
        interval = int(os.environ.get("DISCOVERY_INTERVAL_SECONDS", "3600"))
    except ValueError:
        interval = 3600
    if interval <= 0:
        log.info("[portal] 资产测绘定时任务：已关闭（DISCOVERY_INTERVAL_SECONDS=0）")
        return
    import threading

    import discovery

    def loop():
        while True:
            time.sleep(interval)
            try:
                st, obj = discovery.run()
                log.info(f"[portal] 资产测绘定时执行：HTTP {st} 主机 {obj.get('scanned_hosts')} "
                      f"新增 {obj.get('created')} 刷新 {obj.get('updated')}")
            except Exception as e:
                log.warning(f"[portal] 资产测绘定时执行失败：{type(e).__name__}: {e}")

    threading.Thread(target=loop, name="discovery", daemon=True).start()
    log.info(f"[portal] 资产测绘定时任务已启动：每 {interval}s")


def _start_branch_timer():
    """I-13：后台定时探测分支汇聚健康（默认 5 分钟；BRANCH_HEALTH_INTERVAL_SECONDS=0 关闭）。"""
    try:
        interval = int(os.environ.get("BRANCH_HEALTH_INTERVAL_SECONDS", "300"))
    except ValueError:
        interval = 300
    if interval <= 0:
        log.info("[portal] 分支汇聚健康探测：已关闭（BRANCH_HEALTH_INTERVAL_SECONDS=0）")
        return
    import threading

    import branches

    def loop():
        while True:
            time.sleep(interval)
            try:
                st, obj = branches.probe()
                if st == 200:
                    sc = obj.get("state_counts") or {}
                    log.info(f"[portal] 分支汇聚探测：在线 {sc.get('ok', 0)} / 离线 "
                          f"{sc.get('no_data', 0)} / 未登记 {len(obj.get('unregistered') or [])}")
                else:
                    log.warning(f"[portal] 分支汇聚探测失败：HTTP {st} {obj.get('error')}")
            except Exception as e:
                log.warning(f"[portal] 分支汇聚探测异常：{type(e).__name__}: {e}")

    threading.Thread(target=loop, name="branch-health", daemon=True).start()
    log.info(f"[portal] 分支汇聚健康探测已启动：每 {interval}s")


def main():
    try:
        n = db.query_one("SELECT COUNT(*) AS n FROM users")["n"]
    except Exception:
        n = 0
    if not n:
        log.warning("[portal] ⚠️ users 表为空——请先运行 scripts/init-db.py")
    srv = ThreadingHTTPServer(("0.0.0.0", PORTAL_PORT), Handler)
    log.info(f"[portal] 平台统一后端 v4 启动 http://0.0.0.0:{PORTAL_PORT}  账号 {n} 个  业务库={db.backend()}")
    log.info(f"[portal] 上游：{UPSTREAMS}  arkime={ARKIME_URL}")
    if not ARKIME_PASS:
        log.warning("[portal] ⚠️ 未提供 ARKIME_PASS —— 流量回溯（/api/traffic/*）会因 Arkime 鉴权失败返回 401。"
              "请在 deploy/.env 配置 ARKIME_ADMIN_PASSWORD 后重启 portal（可先执行 make init）。")
    _start_discovery_timer()
    _start_branch_timer()
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
