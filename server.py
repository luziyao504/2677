#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================
 少女导航站 · lolsp 私密入口网关
 零第三方依赖：Python 3.8+ 标准库 + SQLite（无需 pip install）

 功能：
   1. 托管整个静态站点（当前目录）
   2. 账号密码 / 卡密 登录，HttpOnly Cookie 会话
   3. 登录后反向代理内部服务，真实地址对浏览器完全隐藏
   4. /admin 卡密与账号管理后台、使用记录

 启动：  python server.py
 ============================================================
"""

import os
import re
import ssl
import gzip
import zlib
import json
import time
import hmac
import base64
import sqlite3
import secrets
import hashlib
import logging
import mimetypes
import posixpath
import urllib.parse
import http.client
from http.cookies import SimpleCookie
from datetime import datetime, timedelta
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ============================================================
#  ★★★ 部署前请检查这一段配置 ★★★
# ============================================================

HOST = "0.0.0.0"          # 监听地址；本机调试可用 127.0.0.1
PORT = 8090               # 对外端口（云服务器需在安全组/防火墙放行）

SESSION_TTL = 8 * 3600    # 登录有效期（秒），默认 8 小时
COOKIE_SECURE = False     # 配了 HTTPS/域名后改成 True，更安全

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lolsp.db")
WEB_ROOT = os.path.dirname(os.path.abspath(__file__))

# 受保护的内部服务：id 会出现在访问路径 /sp/<id>/ 中，target 永远不暴露给浏览器
# 部署到 103.217.186.164 后用 127.0.0.1（同机）；本机联调用 httpbin/假服务
UPSTREAMS = [
    {"id": "lsp",  "name": "lsp",  "target": "http://127.0.0.1:5201", "color": "cadetblue"},
    {"id": "mt",   "name": "mt",   "target": "http://127.0.0.1:148",  "color": "rgb(255, 196, 0)"},
    {"id": "elqq", "name": "2677", "target": "http://127.0.0.1:2677", "color": "rgb(227, 156, 195)"},
]

# ------------------------------------------------------------
#  超级管理员凭证（只在首次建库时使用，之后以数据库为准）
#  保密方案（三层兜底，优先级从高到低）：
#   1. secret_config.py（与 server.py 同目录，已加入 .gitignore，绝不要提交）
#   2. 环境变量 LOLSP_SUPERADMIN_USER / LOLSP_SUPERADMIN_PASSWORD
#   3. 随机生成 16 位强密码，只在首次启动时打印一次到控制台
#  数据库里只存 PBKDF2-SHA256(20万次迭代) 加盐哈希，任何地方不落明文。
# ------------------------------------------------------------
SUPERADMIN_USERNAME = None
SUPERADMIN_PASSWORD = None
try:
    import secret_config  # 私密配置文件（不提交 git）
    SUPERADMIN_USERNAME = getattr(secret_config, "SUPERADMIN_USERNAME", None)
    SUPERADMIN_PASSWORD = getattr(secret_config, "SUPERADMIN_PASSWORD", None)
except ImportError:
    pass
SUPERADMIN_USERNAME = SUPERADMIN_USERNAME or os.environ.get("LOLSP_SUPERADMIN_USER")
SUPERADMIN_PASSWORD = SUPERADMIN_PASSWORD or os.environ.get("LOLSP_SUPERADMIN_PASSWORD")

# 首次启动自动写入的初始普通账号：(用户名, 密码, 角色)
# 角色: superadmin(超管) / admin(管理员，默认可否管用户由后台授权) / user(用户)
INIT_ACCOUNTS = [
    ("admin", "lolsp2026", "admin"),
    ("xiaoling", "520520", "user"),
]
INIT_CARDS = [
    "LOLSP-8F3K-92LM-Q7ZP",
    "LOLSP-2H7X-5RD1-V6NT",
    "LOLSP-K9W4-TY8P-3CEB",
    "LOLSP-M7Q2-G6AS-D4XW",
    "LOLSP-5J9N-RT2L-B8KY",
]

# 本机联调时，如果上游不在本机，可临时把下面改成外网地址
# （例如 LOCAL_DEV_UPSTREAM_HOST = "103.217.186.164"）
LOCAL_DEV_UPSTREAM_HOST = None

# ============================================================

UPSTREAM_MAP = {u["id"]: u for u in UPSTREAMS}
PROTECTED_PAGES = ("/lolsp.html",)
HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("lolsp")


# ------------------------------------------------------------
#  数据库
# ------------------------------------------------------------

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS accounts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            pwd_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            can_manage_users INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            expires_at INTEGER,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cards(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_key TEXT UNIQUE NOT NULL,
            label TEXT DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            valid_until INTEGER,
            created_at TEXT NOT NULL,
            used_at TEXT,
            used_ip TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY,
            identity TEXT NOT NULL,
            method TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            ip TEXT,
            created_at TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS usage_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            identity TEXT,
            action TEXT,
            detail TEXT,
            ip TEXT
        );
        CREATE TABLE IF NOT EXISTS settings(
            k TEXT PRIMARY KEY,
            v TEXT
        );
        """)
        # 旧库自动补列（已部署过的服务器升级时用，首次安装不受影响）
        def has_column(table, col):
            return any(r["name"] == col for r in c.execute(
                "PRAGMA table_info(%s)" % table).fetchall())
        if not has_column("accounts", "expires_at"):
            c.execute("ALTER TABLE accounts ADD COLUMN expires_at INTEGER")
        if not has_column("cards", "valid_until"):
            c.execute("ALTER TABLE cards ADD COLUMN valid_until INTEGER")
        # 超级管理员：只在首次建库时写入，库中只存哈希
        has_super = c.execute(
            "SELECT 1 FROM accounts WHERE role='superadmin'").fetchone()
        if not has_super:
            su_user = SUPERADMIN_USERNAME or "admin504"
            su_pwd = SUPERADMIN_PASSWORD
            generated = False
            if not su_pwd:
                su_pwd = secrets.token_urlsafe(12)
                generated = True
            salt_hex, hash_hex = hash_password(su_pwd)
            c.execute(
                "INSERT INTO accounts(username,salt,pwd_hash,role,can_manage_users,created_at) "
                "VALUES(?,?,?,?,1,?)",
                (su_user, salt_hex, hash_hex, "superadmin", now_str()),
            )
            if generated:
                log.warning("★ 超管账号已创建: %s / 随机密码: %s （只显示这一次，请立即记录并登录后台修改）",
                            su_user, su_pwd)
            else:
                log.info("超管账号已创建: %s（密码来自 secret_config.py / 环境变量，请登录后尽快修改）", su_user)

        # 初始账号
        for username, pwd, role in INIT_ACCOUNTS:
            exists = c.execute("SELECT 1 FROM accounts WHERE username=?", (username,)).fetchone()
            if not exists:
                salt_hex, hash_hex = hash_password(pwd)
                c.execute(
                    "INSERT INTO accounts(username,salt,pwd_hash,role,created_at) VALUES(?,?,?,?,?)",
                    (username, salt_hex, hash_hex, role, now_str()),
                )
                log.info("已创建初始账号: %s（%s）", username,
                         {"admin": "管理员", "user": "用户"}.get(role, role))
        # 初始卡密
        for key in INIT_CARDS:
            key = normalize_card(key)
            exists = c.execute("SELECT 1 FROM cards WHERE card_key=?", (key,)).fetchone()
            if not exists:
                c.execute(
                    "INSERT INTO cards(card_key,label,created_at) VALUES(?,?,?)",
                    (key, "初始卡密", now_str()),
                )


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------
#  密码 / 卡密
# ------------------------------------------------------------

def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex(), dk.hex()


def verify_password(password: str, salt_hex: str, expected_hex: str):
    _, dk = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(dk, expected_hex)


def normalize_card(key: str) -> str:
    return re.sub(r"\s+", "", key or "").upper()


_CARD_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # 去掉易混淆字符

def generate_card_key() -> str:
    parts = []
    for _ in range(3):
        parts.append("".join(secrets.choice(_CARD_ALPHABET) for _ in range(4)))
    return "LOLSP-" + "-".join(parts)


# ------------------------------------------------------------
#  会话
# ------------------------------------------------------------

COOKIE_NAME = "lolsp_session"

SUPER_TTL = 10 * 365 * 24 * 3600   # 超管会话：10 年（等同永久）


def get_setting(key, default=""):
    with db() as c:
        row = c.execute("SELECT v FROM settings WHERE k=?", (key,)).fetchone()
        return row["v"] if row else default


def set_setting(key, value):
    with db() as c:
        c.execute(
            "INSERT INTO settings(k,v) VALUES(?,?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, str(value)),
        )


def session_ttl() -> int:
    """普通会话时长（秒），超管可在后台在线修改，范围 0.5 小时 ~ 30 天。"""
    try:
        hours = float(get_setting("session_hours", str(SESSION_TTL / 3600)))
        return max(1800, min(30 * 24 * 3600, int(hours * 3600)))
    except (TypeError, ValueError):
        return SESSION_TTL


def create_session(identity: str, method: str, ip: str):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with db() as c:
        # 超级管理员会话不过期（给 10 年），其他身份按后台设置的时长
        ttl = session_ttl()
        if method == "password":
            acc = c.execute(
                "SELECT role FROM accounts WHERE username=?", (identity,)).fetchone()
            if acc and acc["role"] == "superadmin":
                ttl = SUPER_TTL
        c.execute(
            "INSERT INTO sessions(token,identity,method,ip,created_at,expires_at) "
            "VALUES(?,?,?,?,?,?)",
            (token, identity, method, ip, now_str(), now + ttl),
        )
        c.execute(
            "INSERT INTO usage_log(ts,identity,action,detail,ip) VALUES(?,?,?,?,?)",
            (now_str(), identity, "login", method, ip),
        )
    return token, ttl


def get_session(token: str):
    """返回会话 dict；账号会话的角色/权限实时从 accounts 表解析，
    保证超管改权限、停用账号后立即生效。卡密会话视为 user。"""
    if not token:
        return None
    with db() as c:
        row = c.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
        if not row:
            return None
        if row["expires_at"] < int(time.time()):
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
            return None
        sess = dict(row)
        now_ts = int(time.time())
        if row["method"] == "password":
            acc = c.execute(
                "SELECT role, can_manage_users, enabled, expires_at FROM accounts "
                "WHERE username=?",
                (row["identity"],),
            ).fetchone()
            if not acc or not acc["enabled"]:
                c.execute("DELETE FROM sessions WHERE token=?", (token,))
                return None
            # 账号有效期：到期立即失效
            if acc["expires_at"] and acc["expires_at"] < now_ts:
                c.execute("DELETE FROM sessions WHERE token=?", (token,))
                return None
            sess["role"] = acc["role"]
            sess["can_manage_users"] = bool(acc["can_manage_users"])
            sess["account_expires_at"] = acc["expires_at"]
        else:
            card = c.execute(
                "SELECT enabled, valid_until FROM cards WHERE card_key=?",
                (row["identity"],),
            ).fetchone()
            if not card or not card["enabled"]:
                c.execute("DELETE FROM sessions WHERE token=?", (token,))
                return None
            # 卡密有效期：到期立即失效
            if card["valid_until"] and card["valid_until"] < now_ts:
                c.execute("DELETE FROM sessions WHERE token=?", (token,))
                return None
            sess["role"] = "user"
            sess["can_manage_users"] = False
            sess["account_expires_at"] = card["valid_until"]
        return sess


def is_superadmin(sess) -> bool:
    return bool(sess) and sess.get("role") == "superadmin"


def can_manage(sess) -> bool:
    """是否有管理后台权限：超管，或被授权的管理员"""
    if not sess:
        return False
    return sess.get("role") == "superadmin" or (
        sess.get("role") == "admin" and sess.get("can_manage_users")
    )


def destroy_session(token: str):
    if not token:
        return
    with db() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))


def write_log(identity, action, detail, ip):
    with db() as c:
        c.execute(
            "INSERT INTO usage_log(ts,identity,action,detail,ip) VALUES(?,?,?,?,?)",
            (now_str(), identity, action, detail, ip),
        )


# ------------------------------------------------------------
#  HTTP 处理器
# ------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "LolspGateway/1.0"
    protocol_version = "HTTP/1.1"

    # 静默默认日志，用自己的
    def log_message(self, fmt, *args):
        pass

    # ---------- 工具 ----------

    @property
    def client_ip(self):
        fwd = self.headers.get("X-Forwarded-For")
        if fwd:
            return fwd.split(",")[0].strip()
        return self.client_address[0]

    def cookie_token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return None
        morsel = jar.get(COOKIE_NAME)
        return morsel.value if morsel else None

    def current_session(self):
        return get_session(self.cookie_token())

    def send_json(self, obj, status=200, extra_headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0 or length > 64 * 1024:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def session_cookie_header(self, token, max_age=SESSION_TTL):
        parts = [
            f"{COOKIE_NAME}={token}",
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            f"Max-Age={max_age}",
        ]
        if COOKIE_SECURE:
            parts.append("Secure")
        return "Set-Cookie", "; ".join(parts)

    def clear_cookie_header(self):
        return "Set-Cookie", f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def deny_for_page(self):
        self.redirect("/lolsp-login.html")

    # ---------- 路由 ----------

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        if path.startswith("/sp/"):
            return self.handle_proxy(parsed)
        if path == "/api/me":
            return self.api_me()
        if path == "/api/admin/cards":
            return self.api_admin_cards_get()
        if path == "/api/admin/accounts":
            return self.api_admin_accounts_get()
        if path == "/api/admin/logs":
            return self.api_admin_logs_get()
        if path == "/api/admin/stats":
            return self.api_admin_stats_get()
        if path == "/api/admin/sessions":
            return self.api_admin_sessions_get()
        if path == "/api/admin/settings":
            return self.api_admin_settings_get()

        # 需要登录才能看的页面
        if path in PROTECTED_PAGES:
            if not self.current_session():
                return self.deny_for_page()
        # 管理后台页面需要管理员
        if path == "/admin.html":
            sess = self.current_session()
            if not can_manage(sess):
                return self.deny_for_page()

        return self.serve_static(path)

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        if path == "/api/login":
            return self.api_login()
        if path == "/api/logout":
            return self.api_logout()
        if path == "/api/account/password":
            return self.api_change_password()
        if path == "/api/admin/cards":
            return self.api_admin_cards_post()
        if path.startswith("/api/admin/cards/"):
            return self.api_admin_card_action(path.rsplit("/", 1)[-1])
        if path == "/api/admin/accounts":
            return self.api_admin_account_post()
        if path.startswith("/api/admin/accounts/"):
            return self.api_admin_account_action(path.rsplit("/", 1)[-1])
        if path == "/api/admin/sessions/kick":
            return self.api_admin_session_kick()
        if path == "/api/admin/settings":
            return self.api_admin_settings_post()

        return self.send_json({"ok": False, "message": "Not Found"}, 404)

    # ---------- API：登录/登出/状态 ----------

    def api_login(self):
        data = self.read_json()
        mode = (data.get("mode") or "").strip()
        identity = method = None

        if mode == "password":
            username = (data.get("username") or "").strip()
            password = data.get("password") or ""
            if not username or not password:
                return self.send_json({"ok": False, "message": "请输入账号和密码"}, 400)
            with db() as c:
                row = c.execute(
                    "SELECT * FROM accounts WHERE username=?", (username,)
                ).fetchone()
            if not row or not row["enabled"] or not verify_password(
                password, row["salt"], row["pwd_hash"]
            ):
                write_log(username or "?", "login_fail", "账号或密码错误", self.client_ip)
                return self.send_json({"ok": False, "message": "账号或密码不正确"}, 401)
            if row["expires_at"] and row["expires_at"] < int(time.time()):
                write_log(username, "login_fail", "账号已到期", self.client_ip)
                return self.send_json({"ok": False, "message": "账号已到期，请联系管理员续期"}, 403)
            identity, method = username, "password"

        elif mode == "card":
            key = normalize_card(data.get("card"))
            if not key:
                return self.send_json({"ok": False, "message": "请输入卡密"}, 400)
            with db() as c:
                row = c.execute("SELECT * FROM cards WHERE card_key=?", (key,)).fetchone()
                if not row or not row["enabled"]:
                    write_log(key[:13] + "****", "login_fail", "卡密无效", self.client_ip)
                    return self.send_json(
                        {"ok": False, "message": "卡密无效，请检查后重试"}, 401
                    )
                if row["valid_until"] and row["valid_until"] < int(time.time()):
                    write_log(key[:13] + "****", "login_fail", "卡密已过期", self.client_ip)
                    return self.send_json(
                        {"ok": False, "message": "卡密已过期"}, 403
                    )
                if not row["used_at"]:
                    c.execute(
                        "UPDATE cards SET used_at=?, used_ip=? WHERE id=?",
                        (now_str(), self.client_ip, row["id"]),
                    )
            identity, method = key, "card"
        else:
            return self.send_json({"ok": False, "message": "未知的登录方式"}, 400)

        token, ttl = create_session(identity, method, self.client_ip)
        sess = get_session(token)
        body = {
            "ok": True,
            "identity": identity,
            "method": method,
            "role": sess["role"],
            "can_manage": can_manage(sess),
            "is_admin": can_manage(sess),   # 兼容旧前端字段
            "expires_in": ttl,
        }
        return self.send_json(body, 200, [self.session_cookie_header(token, ttl)])

    def api_logout(self):
        token = self.cookie_token()
        sess = get_session(token)
        if sess:
            write_log(sess["identity"], "logout", "", self.client_ip)
        destroy_session(token)
        return self.send_json({"ok": True}, 200, [self.clear_cookie_header()])

    def api_me(self):
        sess = self.current_session()
        if not sess:
            return self.send_json({"ok": False}, 401)
        disp = sess["identity"]
        if sess["method"] == "card" and len(disp) > 10:
            disp = disp[:9] + "****" + disp[-4:]
        return self.send_json({
            "ok": True,
            "identity": sess["identity"],
            "display": disp,
            "method": sess["method"],
            "role": sess["role"],
            "can_manage": can_manage(sess),
            "is_admin": can_manage(sess),   # 兼容字段
            "expires_in": max(0, sess["expires_at"] - int(time.time())),
            "account_expires_at": sess.get("account_expires_at"),
            "notice": get_setting("notice", ""),
            "links": [
                {"id": u["id"], "name": u["name"], "color": u["color"],
                 "href": "/sp/%s/" % u["id"]}
                for u in UPSTREAMS
            ],
        })

    def api_change_password(self):
        sess = self.current_session()
        if not sess or sess["method"] != "password":
            return self.send_json({"ok": False, "message": "未登录"}, 401)
        data = self.read_json()
        old, new = data.get("old") or "", data.get("new") or ""
        if len(new) < 6:
            return self.send_json({"ok": False, "message": "新密码至少 6 位"}, 400)
        with db() as c:
            row = c.execute(
                "SELECT * FROM accounts WHERE username=?", (sess["identity"],)
            ).fetchone()
            if not verify_password(old, row["salt"], row["pwd_hash"]):
                return self.send_json({"ok": False, "message": "原密码不正确"}, 400)
            salt_hex, hash_hex = hash_password(new)
            c.execute(
                "UPDATE accounts SET salt=?, pwd_hash=? WHERE id=?",
                (salt_hex, hash_hex, row["id"]),
            )
        write_log(sess["identity"], "change_password", "", self.client_ip)
        return self.send_json({"ok": True})

    # ---------- API：管理后台 ----------

    def require_manager(self):
        """管理后台通用权限：超管 或 被授权的管理员"""
        sess = self.current_session()
        if not can_manage(sess):
            self.send_json({"ok": False, "message": "需要管理权限"}, 403)
            return None
        return sess

    def require_super(self):
        """仅超级管理员"""
        sess = self.current_session()
        if not is_superadmin(sess):
            self.send_json({"ok": False, "message": "需要超级管理员权限"}, 403)
            return None
        return sess

    # ---- 卡密：仅超管 ----

    def api_admin_cards_get(self):
        if not self.require_super():
            return
        with db() as c:
            rows = c.execute(
                "SELECT * FROM cards ORDER BY id DESC"
            ).fetchall()
        return self.send_json({"ok": True, "cards": [dict(r) for r in rows]})

    def api_admin_cards_post(self):
        if not self.require_super():
            return
        data = self.read_json()
        try:
            count = max(1, min(int(data.get("count", 1)), 50))
        except (TypeError, ValueError):
            count = 1
        label = (data.get("label") or "").strip()[:30]
        # 有效天数：空/0 = 永久
        valid_until = None
        try:
            days = int(data.get("valid_days") or 0)
            if days > 0:
                valid_until = int(time.time()) + min(days, 3650) * 86400
        except (TypeError, ValueError):
            pass
        created = []
        with db() as c:
            for _ in range(count):
                for _try in range(10):
                    key = generate_card_key()
                    try:
                        c.execute(
                            "INSERT INTO cards(card_key,label,valid_until,created_at) "
                            "VALUES(?,?,?,?)",
                            (key, label, valid_until, now_str()),
                        )
                        created.append(key)
                        break
                    except sqlite3.IntegrityError:
                        continue
        return self.send_json({"ok": True, "cards": created})

    def api_admin_card_action(self, card_id):
        sess = self.require_super()
        if not sess:
            return
        action = self.read_json().get("action")
        with db() as c:
            row = c.execute("SELECT * FROM cards WHERE id=?", (card_id,)).fetchone()
            if not row:
                return self.send_json({"ok": False, "message": "卡密不存在"}, 404)
            if action == "enable":
                c.execute("UPDATE cards SET enabled=1 WHERE id=?", (card_id,))
            elif action == "disable":
                c.execute("UPDATE cards SET enabled=0 WHERE id=?", (card_id,))
                c.execute("DELETE FROM sessions WHERE identity=? AND method='card'",
                          (row["card_key"],))
            elif action == "delete":
                c.execute("DELETE FROM cards WHERE id=?", (card_id,))
                c.execute("DELETE FROM sessions WHERE identity=? AND method='card'",
                          (row["card_key"],))
            else:
                return self.send_json({"ok": False, "message": "未知操作"}, 400)
        write_log(sess["identity"], "card_" + action, row["card_key"], self.client_ip)
        return self.send_json({"ok": True})

    # ---- 账号：超管管所有人；被授权的管理员只能管普通用户 ----

    def api_admin_accounts_get(self):
        sess = self.require_manager()
        if not sess:
            return
        with db() as c:
            if is_superadmin(sess):
                rows = c.execute(
                    "SELECT id,username,role,can_manage_users,enabled,expires_at,created_at "
                    "FROM accounts ORDER BY id"
                ).fetchall()
            else:
                # 被授权的管理员只能看到普通用户
                rows = c.execute(
                    "SELECT id,username,role,can_manage_users,enabled,expires_at,created_at "
                    "FROM accounts WHERE role='user' ORDER BY id"
                ).fetchall()
        return self.send_json({"ok": True, "accounts": [dict(r) for r in rows]})

    def api_admin_account_post(self):
        sess = self.require_manager()
        if not sess:
            return
        data = self.read_json()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        role = (data.get("role") or "user").strip()
        # 超管可建 admin/user；管理员只能建 user；任何人都不能通过 API 建超管
        if role not in ("admin", "user"):
            return self.send_json({"ok": False, "message": "非法角色"}, 400)
        if role == "admin" and not is_superadmin(sess):
            return self.send_json(
                {"ok": False, "message": "只有超级管理员能创建管理员"}, 403)
        if not re.match(r"^[A-Za-z0-9_@.\-]{2,20}$", username):
            return self.send_json(
                {"ok": False, "message": "账号需 2-20 位字母数字及 _@.-"}, 400)
        if len(password) < 6:
            return self.send_json({"ok": False, "message": "密码至少 6 位"}, 400)
        # 有效天数：空/0 = 永久
        expires_at = None
        try:
            days = int(data.get("expires_days") or 0)
            if days > 0:
                expires_at = int(time.time()) + min(days, 3650) * 86400
        except (TypeError, ValueError):
            pass
        salt_hex, hash_hex = hash_password(password)
        try:
            with db() as c:
                c.execute(
                    "INSERT INTO accounts(username,salt,pwd_hash,role,expires_at,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (username, salt_hex, hash_hex, role, expires_at, now_str()),
                )
        except sqlite3.IntegrityError:
            return self.send_json({"ok": False, "message": "账号已存在"}, 400)
        write_log(sess["identity"], "account_create", "%s(%s)" % (username, role),
                  self.client_ip)
        return self.send_json({"ok": True})

    def api_admin_account_action(self, account_id):
        sess = self.require_manager()
        if not sess:
            return
        data = self.read_json()
        action = data.get("action")
        with db() as c:
            row = c.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
            if not row:
                return self.send_json({"ok": False, "message": "账号不存在"}, 404)
            target_role = row["role"]
            target_name = row["username"]

            # 权限边界：超管任何人不可被 API 停用/改密（只能自己改自己密码）
            if target_role == "superadmin":
                return self.send_json(
                    {"ok": False, "message": "不能操作超级管理员账号"}, 403)
            # 管理员（非超管）只能操作普通用户
            if not is_superadmin(sess) and target_role != "user":
                return self.send_json(
                    {"ok": False, "message": "管理员只能管理普通用户"}, 403)

            if action == "disable":
                if target_name == sess["identity"]:
                    return self.send_json(
                        {"ok": False, "message": "不能停用当前登录账号"}, 400)
                c.execute("UPDATE accounts SET enabled=0 WHERE id=?", (account_id,))
                c.execute("DELETE FROM sessions WHERE identity=? AND method='password'",
                          (target_name,))
            elif action == "enable":
                c.execute("UPDATE accounts SET enabled=1 WHERE id=?", (account_id,))
            elif action == "reset":
                new_pwd = data.get("password") or ""
                if len(new_pwd) < 6:
                    return self.send_json({"ok": False, "message": "密码至少 6 位"}, 400)
                salt_hex, hash_hex = hash_password(new_pwd)
                c.execute(
                    "UPDATE accounts SET salt=?, pwd_hash=?, enabled=1 WHERE id=?",
                    (salt_hex, hash_hex, account_id),
                )
                c.execute("DELETE FROM sessions WHERE identity=? AND method='password'",
                          (target_name,))
            elif action == "grant":
                # 授权管理员可管理用户（仅超管，目标必须是 admin）
                if not is_superadmin(sess):
                    return self.send_json(
                        {"ok": False, "message": "只有超级管理员能授权"}, 403)
                if target_role != "admin":
                    return self.send_json(
                        {"ok": False, "message": "只能给管理员授权"}, 400)
                c.execute("UPDATE accounts SET can_manage_users=1 WHERE id=?",
                          (account_id,))
            elif action == "revoke":
                # 收回管理员的用户管理权限（其会话还在，但下次校验即失去后台）
                if not is_superadmin(sess):
                    return self.send_json(
                        {"ok": False, "message": "只有超级管理员能收权"}, 403)
                if target_role != "admin":
                    return self.send_json(
                        {"ok": False, "message": "只能收回管理员权限"}, 400)
                c.execute("UPDATE accounts SET can_manage_users=0 WHERE id=?",
                          (account_id,))
            elif action == "expire":
                # 设置账号有效期：days>0 从现在起 N 天；days<=0 或缺省 = 永久
                try:
                    days = int(data.get("days", 0))
                except (TypeError, ValueError):
                    days = 0
                if days > 0:
                    new_exp = int(time.time()) + min(days, 3650) * 86400
                    expire_detail = "%s 有效期至 %s" % (
                        target_name,
                        datetime.fromtimestamp(new_exp).strftime("%Y-%m-%d %H:%M"))
                else:
                    new_exp = None
                    expire_detail = "%s 设为永久有效" % target_name
                c.execute("UPDATE accounts SET expires_at=? WHERE id=?",
                          (new_exp, account_id))
            else:
                return self.send_json({"ok": False, "message": "未知操作"}, 400)
        if action == "expire":
            write_log(sess["identity"], "account_expire", expire_detail, self.client_ip)
        else:
            write_log(sess["identity"], "account_" + action, target_name, self.client_ip)
        return self.send_json({"ok": True})

    def api_admin_logs_get(self):
        if not self.require_manager():
            return
        with db() as c:
            rows = c.execute(
                "SELECT ts,identity,action,detail,ip FROM usage_log "
                "ORDER BY id DESC LIMIT 200"
            ).fetchall()
        return self.send_json({"ok": True, "logs": [dict(r) for r in rows]})

    # ---- 概览统计 ----

    def api_admin_stats_get(self):
        sess = self.require_manager()
        if not sess:
            return
        today = datetime.now().strftime("%Y-%m-%d") + " 00:00:00"
        now_ts = int(time.time())
        with db() as c:
            online = c.execute(
                "SELECT COUNT(*) AS n FROM sessions WHERE expires_at>?", (now_ts,)
            ).fetchone()["n"]
            logins_today = c.execute(
                "SELECT COUNT(*) AS n FROM usage_log "
                "WHERE action='login' AND ts>=?", (today,)
            ).fetchone()["n"]
            users = c.execute(
                "SELECT COUNT(*) AS n FROM accounts WHERE role='user'"
            ).fetchone()["n"]
            stats = {"online": online, "logins_today": logins_today, "users": users}
            if is_superadmin(sess):
                stats["admins"] = c.execute(
                    "SELECT COUNT(*) AS n FROM accounts WHERE role='admin'"
                ).fetchone()["n"]
                stats["cards_total"] = c.execute(
                    "SELECT COUNT(*) AS n FROM cards").fetchone()["n"]
                stats["cards_enabled"] = c.execute(
                    "SELECT COUNT(*) AS n FROM cards WHERE enabled=1").fetchone()["n"]
                stats["cards_used"] = c.execute(
                    "SELECT COUNT(*) AS n FROM cards WHERE used_at IS NOT NULL"
                ).fetchone()["n"]
        return self.send_json({"ok": True, "stats": stats})

    # ---- 在线会话 / 强制下线 ----

    def _visible_sessions(self, c, now_ts):
        rows = c.execute(
            "SELECT s.token, s.identity, s.method, s.ip, s.created_at, "
            "s.expires_at, a.role AS role "
            "FROM sessions s LEFT JOIN accounts a "
            "ON s.method='password' AND a.username=s.identity "
            "WHERE s.expires_at>? ORDER BY s.expires_at DESC",
            (now_ts,),
        ).fetchall()
        return rows

    def api_admin_sessions_get(self):
        sess = self.require_manager()
        if not sess:
            return
        my_token = self.cookie_token()
        now_ts = int(time.time())
        with db() as c:
            rows = self._visible_sessions(c, now_ts)
            out = []
            for r in rows:
                role = r["role"] if r["method"] == "password" else "card"
                # 管理员只能看到普通用户和卡密会话
                if not is_superadmin(sess) and role not in ("user", "card"):
                    continue
                identity = r["identity"]
                if r["method"] == "card" and len(identity) > 10:
                    identity = identity[:9] + "****" + identity[-4:]
                out.append({
                    "token": r["token"],
                    "identity": identity,
                    "method": r["method"],
                    "role": role,
                    "ip": r["ip"],
                    "created_at": r["created_at"],
                    "remain": max(0, r["expires_at"] - now_ts),
                    "is_self": r["token"] == my_token,
                })
        return self.send_json({"ok": True, "sessions": out})

    def api_admin_session_kick(self):
        sess = self.require_manager()
        if not sess:
            return
        token = self.read_json().get("token") or ""
        my_token = self.cookie_token()
        if not token or token == my_token:
            return self.send_json(
                {"ok": False, "message": "不能下线自己"}, 400)
        with db() as c:
            row = c.execute(
                "SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
            if not row or row["expires_at"] < int(time.time()):
                return self.send_json({"ok": False, "message": "会话不存在或已过期"}, 404)
            if row["method"] == "password":
                acc = c.execute(
                    "SELECT role FROM accounts WHERE username=?",
                    (row["identity"],)).fetchone()
                target_role = acc["role"] if acc else None
                # 管理员只能踢普通用户；超管账号谁也踢不动
                if target_role in ("superadmin", "admin") and not is_superadmin(sess):
                    return self.send_json(
                        {"ok": False, "message": "只能下线普通用户"}, 403)
                if target_role == "superadmin":
                    return self.send_json(
                        {"ok": False, "message": "不能下线超级管理员"}, 403)
            target_name = row["identity"]
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
        write_log(sess["identity"], "session_kick", target_name, self.client_ip)
        return self.send_json({"ok": True})

    # ---- 系统设置（仅超管） ----

    def api_admin_settings_get(self):
        if not self.require_super():
            return
        return self.send_json({"ok": True, "settings": {
            "session_hours": get_setting(
                "session_hours", str(SESSION_TTL / 3600)),
            "notice": get_setting("notice", ""),
        }})

    def api_admin_settings_post(self):
        sess = self.require_super()
        if not sess:
            return
        data = self.read_json()
        try:
            hours = float(data.get("session_hours"))
        except (TypeError, ValueError):
            return self.send_json(
                {"ok": False, "message": "会话时长需为数字（小时）"}, 400)
        if not (0.5 <= hours <= 720):
            return self.send_json(
                {"ok": False, "message": "会话时长范围 0.5 ~ 720 小时"}, 400)
        notice = (data.get("notice") or "").strip()
        if len(notice) > 200:
            return self.send_json(
                {"ok": False, "message": "公告最多 200 字"}, 400)
        set_setting("session_hours", hours)
        set_setting("notice", notice)
        write_log(sess["identity"], "settings_update",
                  "会话%.1f小时, 公告%d字" % (hours, len(notice)), self.client_ip)
        return self.send_json({"ok": True})

    # ---------- 反向代理 ----------

    def handle_proxy(self, parsed):
        # /sp/<id>/xxx  →  upstream /xxx
        sess = self.current_session()
        if not sess:
            if "application/json" in (self.headers.get("Accept") or ""):
                return self.send_json({"ok": False, "message": "未登录"}, 401)
            return self.deny_for_page()

        m = re.match(r"^/sp/([A-Za-z0-9_\-]+)(/.*)?$", parsed.path)
        if not m:
            return self.send_error(404)
        conf = UPSTREAM_MAP.get(m.group(1))
        if not conf:
            return self.send_error(404)
        rest = m.group(2) or "/"
        return self.proxy_request(conf, rest, parsed.query, sess)

    def proxy_request(self, conf, rest, query, sess):
        target = urllib.parse.urlsplit(conf["target"])
        host = LOCAL_DEV_UPSTREAM_HOST or target.hostname
        port = target.port
        prefix = "/sp/%s" % conf["id"]

        # WebSocket 升级不支持（标准库限制）
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self.send_json(
                {"ok": False, "message": "该服务使用 WebSocket，需在反代层另行配置"}, 502)
            return

        # 构造上游请求头
        fwd_headers = {}
        for k, v in self.headers.items():
            if k.lower() in HOP_HEADERS or k.lower() == "host" \
               or k.lower() == "content-length" or k.lower() == "cookie":
                continue
            fwd_headers[k] = v
        fwd_headers["Host"] = target.netloc
        fwd_headers["X-Forwarded-For"] = self.client_ip
        fwd_headers["X-Forwarded-Proto"] = "https" if COOKIE_SECURE else "http"
        fwd_headers["X-Forwarded-Host"] = self.headers.get("Host", "")
        fwd_headers["X-Forwarded-Prefix"] = prefix

        body = None
        if self.command not in ("GET", "HEAD"):
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                body = self.rfile.read(length)

        upstream_path = target.path.rstrip("/") + rest
        if query:
            upstream_path += "?" + query

        conn = http.client.HTTPConnection(host, port, timeout=90)
        try:
            conn.request(self.command, upstream_path, body=body, headers=fwd_headers)
            resp = conn.getresponse()
        except (OSError, http.client.HTTPException) as e:
            log.warning("代理 %s 失败: %s", conf["id"], e)
            self.send_json(
                {"ok": False, "message": "内部服务暂不可用 (%s)" % conf["name"]}, 502)
            return

        content_type = ""
        content_length = None
        content_encoding = ""
        out_headers = []
        for k, v in resp.getheaders():
            lk = k.lower()
            if lk in HOP_HEADERS:
                continue
            if lk == "content-length":
                content_length = int(v)
                continue
            if lk == "content-encoding":
                content_encoding = v.lower()
                continue
            if lk == "location":
                # 重定向回网关前缀
                if v.startswith(conf["target"]):
                    v = prefix + v[len(conf["target"].rstrip("/")):]
                elif v.startswith("/") and not v.startswith("//"):
                    v = prefix + v
            if lk == "set-cookie":
                v = re.sub(r";\s*Path=[^;]*", "; Path=%s/" % prefix, v, flags=re.I)
            if lk == "content-type":
                content_type = v
            out_headers.append((k, v))

        is_html = "text/html" in content_type.lower()
        decodable = content_encoding in ("", "gzip", "deflate")
        MAX_REWRITE = 5 * 1024 * 1024
        do_rewrite = (is_html and decodable
                      and (content_length is None or content_length <= MAX_REWRITE))

        self.send_response(resp.status, resp.reason)
        for k, v in out_headers:
            self.send_header(k, v)

        def finish_headers(extra):
            for k, v in extra:
                self.send_header(k, v)
            self.end_headers()

        enc_header = [("Content-Encoding", content_encoding)] if content_encoding else []

        if self.command == "HEAD":
            finish_headers(
                [("Content-Length", str(content_length or 0))] + enc_header)
            resp.read()
            conn.close()
            return

        if do_rewrite:
            # HTML：缓冲、解压（如需要）、重写路径、重算长度
            payload = resp.read(MAX_REWRITE + 1)
            if len(payload) <= MAX_REWRITE:
                if "gzip" in content_encoding:
                    payload = gzip.decompress(payload)
                elif "deflate" in content_encoding:
                    payload = zlib.decompress(payload)
                payload = self.rewrite_html(payload, prefix)
                finish_headers([("Content-Length", str(len(payload)))])
                try:
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                conn.close()
                return
            # 超限：放弃重写，走下面的流式逻辑（payload 前缀数据要继续写出）
            first_chunk = payload
        else:
            first_chunk = b""

        # 非 HTML / 过大：流式转发
        try:
            if content_length is not None:
                finish_headers(
                    [("Content-Length", str(content_length))] + enc_header)
                if first_chunk:
                    self.wfile.write(first_chunk)
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            else:
                # 上游 chunked/未知长度：由我们重新做 chunked 传输
                finish_headers(
                    [("Transfer-Encoding", "chunked")] + enc_header)
                def write_chunk(data):
                    if data:
                        self.wfile.write(("%X\r\n" % len(data)).encode("ascii"))
                        self.wfile.write(data)
                        self.wfile.write(b"\r\n")
                if first_chunk:
                    write_chunk(first_chunk)
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    write_chunk(chunk)
                self.wfile.write(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError):
            pass
        conn.close()

    @staticmethod
    def rewrite_html(payload: bytes, prefix: str) -> bytes:
        html = payload.decode("utf-8", errors="replace")
        # 注入 <base>，让相对路径资源自动走前缀
        base_tag = '<base href="%s/">' % prefix
        if re.search(r"<head[^>]*>", html, re.I):
            html = re.sub(r"(<head[^>]*>)",
                          lambda mm: mm.group(1) + base_tag, html, count=1, flags=re.I)
        else:
            html = base_tag + html
        # 根绝对路径替换：href="/x" src="/x" action="/x"（不碰 // 与已带前缀的）
        html = re.sub(
            r'(href|src|action)(\s*=\s*)(["\'])/(?!/)(?!sp/)([^"\'<>?#]*)(["\'])',
            lambda mm: '%s%s%s%s/%s%s' % (
                mm.group(1), mm.group(2), mm.group(3), prefix,
                mm.group(4), mm.group(5)),
            html,
            flags=re.I,
        )
        return html.encode("utf-8")

    # ---------- 静态文件 ----------

    def serve_static(self, url_path):
        if url_path == "/":
            url_path = "/index.html"
        # 防目录穿越
        rel = urllib.parse.unquote(url_path.split("?", 1)[0])
        rel = posixpath.normpath(rel).lstrip("/")
        fs_path = os.path.join(WEB_ROOT, *rel.split("/"))
        if not fs_path.startswith(WEB_ROOT):
            return self.send_error(403)
        if not os.path.isfile(fs_path):
            return self.send_error(404)

        ctype = mimetypes.guess_type(fs_path)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in (
            "application/javascript", "application/json"
        ):
            ctype += "; charset=utf-8"
        try:
            st = os.stat(fs_path)
            with open(fs_path, "rb") as f:
                data = f.read()
        except OSError:
            return self.send_error(404)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Last-Modified",
                         self.date_time_string(st.st_mtime))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)


def main():
    init_db()
    mimetypes.add_type("image/svg+xml", ".svg")
    # Windows 下 SO_REUSEADDR 允许重复绑定导致旧进程残留时新进程静默失效，禁掉它
    ThreadingHTTPServer.allow_reuse_address = False
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    log.info("==============================================")
    log.info(" lolsp 网关已启动")
    log.info(" 本机访问:   http://127.0.0.1:%d/lolsp.html", PORT)
    log.info(" 管理后台:   http://127.0.0.1:%d/admin.html", PORT)
    log.info(" 上游服务:   %d 个 -> %s", len(UPSTREAMS),
             ", ".join("%s(%s)" % (u["id"], u["target"]) for u in UPSTREAMS))
    log.info("==============================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info("正在关闭…")
        httpd.server_close()


if __name__ == "__main__":
    main()
