from __future__ import annotations

import base64
import binascii
import html
import hmac
import json
import math
import os
import sqlite3
import threading
import time
import webbrowser
from datetime import date, datetime
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "gestao.db"
WEB_PATH = ROOT / "web"
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
APP_USERNAME = os.getenv("APP_USERNAME", "admin")
APP_PASSWORD = os.getenv("APP_PASSWORD", "")
SECOND_ADMIN_USERNAME = os.getenv("SECOND_ADMIN_USERNAME", "").strip()
SECOND_ADMIN_PASSWORD = os.getenv("SECOND_ADMIN_PASSWORD", "")
SECOND_ADMIN_NAME = os.getenv("SECOND_ADMIN_NAME", "Cliente").strip() or "Cliente"
APP_SESSION_SECRET = os.getenv("APP_SESSION_SECRET", APP_PASSWORD).encode("utf-8")
SESSION_COOKIE = "atelie_session"
SESSION_TTL = 12 * 60 * 60
HOST = os.getenv("HOST", "0.0.0.0" if os.getenv("PORT") else "127.0.0.1")
PORT = int(os.getenv("PORT", "8765"))


def optional_amount(value):
    if value is None or value == "":
        return None
    amount = float(value)
    if not math.isfinite(amount) or amount < 0:
        raise ValueError("Valor deve ser um número não negativo.")
    return amount


def valid_month(value):
    value = str(value)
    parsed = datetime.strptime(value, "%Y-%m")
    if parsed.strftime("%Y-%m") != value:
        raise ValueError("Competência inválida.")
    return value


class PostgresConnection:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if exc_type is None:
                self.connection.commit()
            else:
                self.connection.rollback()
        finally:
            self.connection.close()

    def execute(self, query, params=()):
        return self.connection.execute(query.replace("?", "%s"), params)

    def executescript(self, script):
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)


def connect():
    if DATABASE_URL:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("Instale as dependências do arquivo requirements.txt.") from exc
        return PostgresConnection(psycopg.connect(DATABASE_URL, row_factory=dict_row))
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize():
    if DATABASE_URL:
        with connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS students (
                    id BIGSERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    phone TEXT DEFAULT '',
                    monthly_fee DOUBLE PRECISION,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS payments (
                    id BIGSERIAL PRIMARY KEY,
                    student_id BIGINT NOT NULL REFERENCES students(id),
                    month TEXT NOT NULL,
                    amount DOUBLE PRECISION,
                    status TEXT NOT NULL DEFAULT 'a_marcar'
                        CHECK(status IN ('a_marcar','pago','pendente','isento')),
                    paid_at TEXT,
                    note TEXT DEFAULT '',
                    UNIQUE(student_id, month)
                );
                CREATE TABLE IF NOT EXISTS demands (
                    id BIGSERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'Pessoal',
                    amount DOUBLE PRECISION,
                    due_date TEXT,
                    status TEXT NOT NULL DEFAULT 'aberta'
                        CHECK(status IN ('aberta','concluida')),
                    note TEXT DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)
        return
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT DEFAULT '',
                monthly_fee REAL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL REFERENCES students(id),
                month TEXT NOT NULL,
                amount REAL,
                status TEXT NOT NULL DEFAULT 'a_marcar'
                    CHECK(status IN ('a_marcar','pago','pendente','isento')),
                paid_at TEXT,
                note TEXT DEFAULT '',
                UNIQUE(student_id, month)
            );
            CREATE TABLE IF NOT EXISTS demands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'Pessoal',
                amount REAL,
                due_date TEXT,
                status TEXT NOT NULL DEFAULT 'aberta'
                    CHECK(status IN ('aberta','concluida')),
                note TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_PATH), **kwargs)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def session_token(self, username, display_name):
        expires = int(time.time()) + SESSION_TTL
        payload = json.dumps({"username": username, "name": display_name, "expires": expires}, separators=(",", ":")).encode("utf-8")
        encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        signature = hmac.new(APP_SESSION_SECRET, payload, "sha256").hexdigest()
        return f"{encoded}.{signature}"

    def configured_admins(self):
        admins = [(APP_USERNAME, "Dayane Bettinelli", APP_PASSWORD)]
        if SECOND_ADMIN_USERNAME and SECOND_ADMIN_PASSWORD and SECOND_ADMIN_USERNAME != APP_USERNAME:
            admins.append((SECOND_ADMIN_USERNAME, SECOND_ADMIN_NAME, SECOND_ADMIN_PASSWORD))
        return admins

    def valid_session(self, token):
        if not token or not APP_SESSION_SECRET:
            return None
        try:
            encoded, signature = token.rsplit(".", 1)
            payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            expected = hmac.new(APP_SESSION_SECRET, payload, "sha256").hexdigest()
            session = json.loads(payload.decode("utf-8"))
            username = str(session["username"])
            if not (hmac.compare_digest(signature, expected) and int(session["expires"]) > int(time.time())):
                return None
            for configured_username, display_name, _password in self.configured_admins():
                if hmac.compare_digest(username, configured_username):
                    return {"username": username, "name": display_name, "role": "admin"}
            return None
        except (ValueError, UnicodeDecodeError, binascii.Error, KeyError, TypeError):
            return None

    def send_login_page(self, message="", status=200):
        notice = f'<p class="error">{html.escape(message)}</p>' if message else ""
        body = '''<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#12352e"><link rel="manifest" href="/manifest.webmanifest"><link rel="icon" type="image/png" sizes="192x192" href="/icons/icon-192.png"><link rel="apple-touch-icon" href="/icons/icon-192.png"><title>Entrar · Ateliê Gestão Pilates</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:linear-gradient(145deg,#f7f8f5,#eaf2ed);font:15px Arial,sans-serif;color:#20302b}.login{width:min(100%,420px);padding:34px;background:#fff;border:1px solid #e7ece8;border-radius:22px;box-shadow:0 22px 70px #18392b18}.brand{display:flex;align-items:center;gap:12px;margin-bottom:30px;color:#12352e}.login-logo{display:block;width:58px;height:58px;object-fit:cover;border-radius:16px;box-shadow:0 3px 10px #12352e20}.brand b{display:block;font:800 23px Arial,sans-serif}.brand small{display:block;margin-top:2px;font-size:9px;letter-spacing:.16em;color:#718078}.kicker{font-size:10px;font-weight:700;letter-spacing:.13em;color:#628173}h1{margin:8px 0;font:800 27px Arial,sans-serif}.hint{margin:0 0 23px;color:#77837d;font-size:13px;line-height:1.5}label{display:block;margin:15px 0 7px;font-size:12px;font-weight:700}input{width:100%;height:46px;padding:0 13px;border:1px solid #dfe7e2;border-radius:10px;background:#fbfcfa;font:inherit;outline:none}input:focus{border-color:#43856d;box-shadow:0 0 0 3px #e7f2ec}button{width:100%;height:47px;margin-top:21px;border:0;border-radius:10px;background:#1d6a55;color:#fff;font-weight:700;font-size:14px}.error{padding:10px 12px;border-radius:9px;background:#fff0ef;color:#a9433d;font-size:12px}@media(max-width:480px){body{padding:16px}.login{padding:26px 22px;border-radius:18px}h1{font-size:24px}}</style></head><body><main class="login"><div class="brand"><img class="login-logo" src="/logo.png" alt="Logo de Pilates"><div><b>ateliê</b><small>GESTÃO PILATES</small></div></div><div class="kicker">SEU ESPAÇO DE TRABALHO</div><h1>Que bom ter você aqui.</h1><p class="hint">Entre com os dados de acesso do seu painel financeiro.</p>__NOTICE__<form method="post" action="/login"><label for="username">Usuário</label><input id="username" name="username" autocomplete="username" required value="__USERNAME__"><label for="password">Senha</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus><button type="submit">Entrar no painel</button></form></main><script>if ("serviceWorker" in navigator) window.addEventListener("load", () => navigator.serviceWorker.register("/sw.js").catch(() => {}));</script></body></html>'''
        body = body.replace("__NOTICE__", notice).replace("__USERNAME__", html.escape(APP_USERNAME, quote=True)).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_redirect(self, path, cookie=None):
        self.send_response(303)
        self.send_header("Location", path)
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
    def require_auth(self):
        self.current_user = None
        if not APP_PASSWORD:
            self.current_user = {"username": APP_USERNAME, "name": "Dayane Bettinelli", "role": "admin"}
            return True
        try:
            cookies = SimpleCookie(self.headers.get("Cookie", ""))
            session = cookies.get(SESSION_COOKIE)
            if session:
                user = self.valid_session(session.value)
                if user:
                    self.current_user = user
                    return True
        except Exception:
            pass
        header = self.headers.get("Authorization", "")
        if header.lower().startswith("basic "):
            try:
                credentials = base64.b64decode(header.split(None, 1)[1], validate=True).decode("utf-8")
                username, password = credentials.split(":", 1)
                for configured_username, display_name, configured_password in self.configured_admins():
                    if hmac.compare_digest(username, configured_username) and hmac.compare_digest(password, configured_password):
                        self.current_user = {"username": username, "name": display_name, "role": "admin"}
                        return True
            except (ValueError, UnicodeDecodeError):
                pass
        if urlparse(self.path).path.startswith("/api/"):
            self.send_json({"error": "Sessão expirada. Entre novamente no painel."}, 401)
            return False
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        return False

    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            return self.send_json({"ok": True})
        if parsed.path == "/login":
            return self.send_login_page()
        if parsed.path == "/logout":
            cookie = f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax" + ("; Secure" if os.getenv("RENDER") else "")
            return self.send_redirect("/login", cookie)

        if parsed.path in {"/manifest.webmanifest", "/sw.js", "/logo.png", "/icons/icon-192.png", "/icons/icon-512.png"}:
            return super().do_GET()
        if not self.require_auth():
            return
        if not parsed.path.startswith("/api/"):
            if parsed.path == "/":
                self.path = "/index.html"
            return super().do_GET()
        if parsed.path == "/api/session":
            return self.send_json(self.current_user or {})
        query = parse_qs(parsed.query)
        month = query.get("month", [date.today().strftime("%Y-%m")])[0]
        with connect() as db:
            if parsed.path == "/api/dashboard":
                counts = {r["status"]: r["count"] for r in db.execute(
                    "SELECT p.status, COUNT(*) count FROM payments p JOIN students s ON s.id=p.student_id WHERE p.month=? AND s.active=1 GROUP BY p.status", (month,))}
                students = db.execute("SELECT COUNT(*) AS value FROM students WHERE active=1").fetchone()["value"]
                money = db.execute("""SELECT
                    SUM(CASE WHEN p.status='pago' THEN COALESCE(p.amount,s.monthly_fee,0) ELSE 0 END) received,
                    SUM(CASE WHEN COALESCE(p.status,'pendente')<>'pago' THEN COALESCE(p.amount,s.monthly_fee,0) ELSE 0 END) to_receive,
                    SUM(CASE WHEN p.status='pago' AND COALESCE(p.amount,s.monthly_fee) IS NULL THEN 1 ELSE 0 END) received_missing,
                    SUM(CASE WHEN COALESCE(p.status,'pendente')<>'pago' AND COALESCE(p.amount,s.monthly_fee) IS NULL THEN 1 ELSE 0 END) pending_missing
                    FROM students s LEFT JOIN payments p ON p.student_id=s.id AND p.month=? WHERE s.active=1""", (month,)).fetchone()
                open_demands = db.execute("SELECT COUNT(*) AS value FROM demands WHERE status='aberta'").fetchone()["value"]
                demand_total = db.execute("SELECT SUM(amount) AS value FROM demands WHERE status='aberta'").fetchone()["value"] or 0
                self.send_json({"month": month, "students": students,
                    "paid": counts.get("pago", 0), "pending": max(0, students - counts.get("pago", 0)),
                    "unmarked": 0, "exempt": 0,
                    "received": money["received"] or 0, "to_receive": money["to_receive"] or 0,
                    "received_missing": money["received_missing"] or 0, "pending_missing": money["pending_missing"] or 0,
                    "open_demands": open_demands, "demand_total": demand_total})
                return
            if parsed.path == "/api/students":
                include_inactive = query.get("all", ["0"])[0] == "1"
                sql = """SELECT s.id,s.name,s.phone,s.monthly_fee,s.active,
                    CASE WHEN p.status='pago' THEN 'pago' ELSE 'pendente' END payment_status,p.amount,p.paid_at,p.note
                    FROM students s LEFT JOIN payments p ON p.student_id=s.id AND p.month=?"""
                if not include_inactive:
                    sql += " WHERE s.active=1"
                sql += " ORDER BY LOWER(s.name)"
                rows = [dict(r) for r in db.execute(sql, (month,))]
                self.send_json(rows)
                return
            if parsed.path == "/api/arrears":
                today = date.today().isoformat()
                current_month = date.today().strftime("%Y-%m")
                overdue_clause = ("CAST(p.month || '-10' AS DATE) < CAST(? AS DATE)"
                    if DATABASE_URL else "date(p.month || '-10') < date(?)")
                missing_due_clause = ("CAST(? || '-10' AS DATE) < CAST(? AS DATE)"
                    if DATABASE_URL else "date(? || '-10') < date(?)")
                rows = [dict(r) for r in db.execute(f"""SELECT student_id,name,phone,month_key AS "month",amount,note FROM (
                    SELECT s.id student_id,s.name,s.phone,p.month AS month_key,
                        COALESCE(p.amount,s.monthly_fee) amount,p.note
                    FROM payments p JOIN students s ON s.id=p.student_id
                    WHERE s.active=1 AND p.status<>'pago' AND {overdue_clause}
                    UNION ALL
                    SELECT s.id student_id,s.name,s.phone,? AS month_key,s.monthly_fee amount,'' note
                    FROM students s
                    WHERE s.active=1 AND {missing_due_clause}
                      AND NOT EXISTS (SELECT 1 FROM payments p2
                          WHERE p2.student_id=s.id AND p2.month=?)
                ) arrears ORDER BY month_key ASC,LOWER(name)""",
                    (today, current_month, current_month, today, current_month))]
                self.send_json(rows)
                return
            if parsed.path == "/api/demands":
                rows = [dict(r) for r in db.execute("SELECT * FROM demands ORDER BY status, due_date IS NULL, due_date, id DESC")]
                self.send_json(rows)
                return
        self.send_json({"error": "Rota não encontrada."}, 404)

    def do_POST(self):
        if urlparse(self.path).path == "/login":
            length = int(self.headers.get("Content-Length", "0"))
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            username = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
            authenticated = None
            for configured_username, display_name, configured_password in self.configured_admins():
                if (configured_password and hmac.compare_digest(username, configured_username)
                        and hmac.compare_digest(password, configured_password)):
                    authenticated = (configured_username, display_name)
                    break
            if authenticated:
                token = self.session_token(*authenticated)
                secure = ("https" in self.headers.get("X-Forwarded-Proto", "").lower()
                          or bool(os.getenv("RENDER")))
                cookie = (f"{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_TTL}; "
                          "HttpOnly; SameSite=Lax" + ("; Secure" if secure else ""))
                return self.send_redirect("/", cookie)
            return self.send_login_page("Usuário ou senha incorretos. Tente novamente.", 401)
        if not self.require_auth():
            return
        data = self.read_json()
        if urlparse(self.path).path == "/api/demands":
            title = str(data.get("title", "")).strip()
            if not title:
                return self.send_json({"error": "Dê um nome à demanda."}, 400)
            with connect() as db:
                cur = db.execute("INSERT INTO demands(title,category,amount,due_date,note) VALUES(?,?,?,?,?) RETURNING id",
                    (title, str(data.get("category", "Pessoal")), data.get("amount") or None,
                     data.get("due_date") or None, str(data.get("note", ""))))
                demand_id = cur.fetchone()["id"]
            return self.send_json({"id": demand_id}, 201)
        with connect() as db:
            if self.path == "/api/students":
                name = str(data.get("name", "")).strip()
                if not name:
                    return self.send_json({"error": "Informe o nome do aluno."}, 400)
                try:
                    month = valid_month(data.get("month") or date.today().strftime("%Y-%m"))
                    monthly_fee = optional_amount(data.get("monthly_fee"))
                except (TypeError, ValueError):
                    return self.send_json({"error": "Competência ou mensalidade inválida."}, 400)
                cur = db.execute("INSERT INTO students(name,phone,monthly_fee) VALUES(?,?,?) RETURNING id",
                    (name, str(data.get("phone", "")).strip(), monthly_fee))
                student_id = cur.fetchone()["id"]
                db.execute("""INSERT INTO payments(student_id,month,amount,status)
                    VALUES(?,?,?,'pendente') ON CONFLICT(student_id,month) DO NOTHING""",
                    (student_id, month, monthly_fee))
                return self.send_json({"id": student_id, "month": month, "payment_status": "pendente"}, 201)
            if self.path == "/api/payments/prepare-month":
                try:
                    month = valid_month(data.get("month", ""))
                except (TypeError, ValueError):
                    return self.send_json({"error": "Competência inválida."}, 400)
                insert_sql = ("""INSERT INTO payments(student_id,month,amount,status)
                    SELECT id,?,monthly_fee,'pendente' FROM students WHERE active=1
                    ON CONFLICT(student_id,month) DO NOTHING"""
                    if DATABASE_URL else
                    """INSERT OR IGNORE INTO payments(student_id,month,amount,status)
                    SELECT id,?,monthly_fee,'pendente' FROM students WHERE active=1""")
                db.execute(insert_sql, (month,))
                count = db.execute("SELECT COUNT(*) AS value FROM students WHERE active=1").fetchone()["value"]
                return self.send_json({"ok": True, "month": month, "count": count})
            if self.path == "/api/payments":
                try:
                    student_id = int(data["student_id"])
                    month = valid_month(data["month"])
                    amount = optional_amount(data.get("amount"))
                except (KeyError, TypeError, ValueError):
                    return self.send_json({"error": "Aluno, competência ou valor inválido."}, 400)
                status = str(data.get("status", "pendente"))
                if status not in ("pago", "pendente"):
                    return self.send_json({"error": "Status inválido."}, 400)
                exists = db.execute("SELECT 1 FROM students WHERE id=?", (student_id,)).fetchone()
                if not exists:
                    return self.send_json({"error": "Aluno não encontrado."}, 404)
                paid_at = (data.get("paid_at") or date.today().isoformat()) if status == "pago" else None
                if paid_at:
                    try:
                        datetime.strptime(paid_at, "%Y-%m-%d")
                    except ValueError:
                        return self.send_json({"error": "Data de pagamento inválida."}, 400)
                db.execute("""INSERT INTO payments(student_id,month,amount,status,paid_at,note)
                    VALUES(?,?,?,?,?,?) ON CONFLICT(student_id,month) DO UPDATE SET
                    amount=excluded.amount,status=excluded.status,paid_at=excluded.paid_at,note=excluded.note""",
                    (student_id, month, amount, status, paid_at, str(data.get("note", ""))))
                return self.send_json({"ok": True})
        self.send_json({"error": "Rota não encontrada."}, 404)

    def do_PATCH(self):
        if not self.require_auth():
            return
        data = self.read_json()
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        with connect() as db:
            if len(parts) == 3 and parts[:2] == ["api", "demands"]:
                demand_id = int(parts[2])
                db.execute("UPDATE demands SET status=? WHERE id=?",
                    ("concluida" if data.get("status") == "concluida" else "aberta", demand_id))
                return self.send_json({"ok": True})
            if len(parts) == 3 and parts[:2] == ["api", "students"]:
                student_id = int(parts[2])
                db.execute("UPDATE students SET name=?,phone=?,monthly_fee=? WHERE id=?",
                    (str(data.get("name", "")).strip(), str(data.get("phone", "")).strip(),
                     data.get("monthly_fee") or None, student_id))
                return self.send_json({"ok": True})
        self.send_json({"error": "Rota não encontrada."}, 404)

    def do_DELETE(self):
        if not self.require_auth():
            return
        parts = urlparse(self.path).path.strip("/").split("/")
        if len(parts) == 3 and parts[:2] == ["api", "students"]:
            with connect() as db:
                db.execute("UPDATE students SET active=0 WHERE id=?", (int(parts[2]),))
            return self.send_json({"ok": True})
        self.send_json({"error": "Rota não encontrada."}, 404)


def main():
    if os.getenv("RENDER") and not DATABASE_URL:
        raise RuntimeError("Configure DATABASE_URL para impedir gravação em disco temporário.")
    if (os.getenv("RENDER") or DATABASE_URL) and not APP_PASSWORD:
        raise RuntimeError("Configure APP_PASSWORD antes de publicar o painel.")
    initialize()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}"
    print(f"Gestão Pilates aberta em {url}")
    if not os.getenv("RENDER"):
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
