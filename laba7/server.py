import os
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, urlparse

import db
import security
import views
from validation import validate

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ERROR_FIELDS = ["fullname", "phone", "email", "birthdate", "gender", "bio", "languages", "contract"]

DEFAULT_ADMIN_LOGIN = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"

MAX_BODY = 64 * 1024

STATIC_FILES = {
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}


class Handler(BaseHTTPRequestHandler):

    server_version = "WebServer"
    sys_version = ""

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")

    def do_GET(self):
        self._dispatch(self._route_get)

    def do_POST(self):
        self._dispatch(self._route_post)

    def _dispatch(self, route):
        try:
            route()
        except Exception:
            traceback.print_exc()
            try:
                self._html(500, "<h1>500: внутренняя ошибка сервера</h1>")
            except Exception:
                pass

    def _route_get(self):
        path = urlparse(self.path).path
        if path in STATIC_FILES:
            rel, ctype = STATIC_FILES[path]
            self._serve_static(rel, ctype)
        elif path == "/login":
            self._login_form()
        elif path == "/admin":
            self._admin_list()
        elif path == "/admin/edit":
            self._admin_edit_form()
        elif path in ("/", "/index.html"):
            self._main_form()
        else:
            self._html(404, "<h1>404 Not Found</h1>")

    def _route_post(self):
        path = urlparse(self.path).path
        if path == "/login":
            self._login()
        elif path == "/logout":
            self._logout()
        elif path == "/submit":
            self._submit()
        elif path == "/admin/edit":
            self._admin_edit_save()
        elif path == "/admin/delete":
            self._admin_delete()
        else:
            self._html(404, "<h1>404 Not Found</h1>")

    # ── Пользовательские страницы ──

    def _main_form(self):
        cookies = security.parse_cookies(self.headers.get("Cookie", ""))
        csrf, csrf_cookie = self._csrf(cookies)
        user_id = security.get_session_user(cookies)

        if user_id is not None:
            user = db.load_user(user_id)
            if user is None:
                security.destroy_session(cookies)
                self._redirect("/login", clear_session=True)
                return
            self._html(200, views.render_form(user, {}, user=user, csrf=csrf),
                       cookies=self._cookie_list(csrf_cookie))
            return

        raw_langs = cookies.get("val_languages", "")
        values = {
            "fullname":  cookies.get("val_fullname", ""),
            "phone":     cookies.get("val_phone", ""),
            "email":     cookies.get("val_email", ""),
            "birthdate": cookies.get("val_birthdate", ""),
            "gender":    cookies.get("val_gender", ""),
            "bio":       cookies.get("val_bio", ""),
            "languages": [x for x in raw_langs.split(",") if x],
        }
        errors, set_cookies = {}, self._cookie_list(csrf_cookie)
        for field in ERROR_FIELDS:
            key = f"err_{field}"
            if cookies.get(key):
                errors[field] = cookies[key]
                set_cookies.append(f"{key}=; Max-Age=0; Path=/")

        self._html(200, views.render_form(values, errors, user=None, csrf=csrf),
                   cookies=set_cookies)

    def _submit(self):
        data = self._read_form()
        if data is None:
            return
        cookies = security.parse_cookies(self.headers.get("Cookie", ""))
        if not self._check_csrf(cookies, data):
            return
        user_id = security.get_session_user(cookies)

        if user_id is not None:
            user = db.load_user(user_id)
            if user is None:
                security.destroy_session(cookies)
                self._redirect("/login", clear_session=True)
                return
            errors = validate(data, require_contract=False)
            csrf, _ = self._csrf(cookies)
            if errors:
                values = self._post_values(data)
                values["login"] = user["login"]
                self._html(200, views.render_form(values, errors, user=user, csrf=csrf))
                return
            db.update_user(user_id, data)
            fresh = db.load_user(user_id)
            page = views.render_form(fresh, {}, user=fresh, csrf=csrf).decode("utf-8").replace(
                "<h1>Редактирование данных</h1>",
                '<h1>Редактирование данных</h1>\n    <div class="alert-success">Изменения сохранены.</div>',
            )
            self._html(200, page)
            return

        errors = validate(data, require_contract=True)
        cookie_vals = self._cookie_values(data)
        if errors:
            extra = [f"{k}={quote(val)}; Path=/" for k, val in cookie_vals.items()]
            extra += [f"err_{f}={quote(m)}; Path=/" for f, m in errors.items()]
            self._redirect("/", extra_cookies=extra)
            return

        password = security.generate_password()
        _, login = db.insert_user(data, security.hash_password(password))

        clear = [f"{k}=; Max-Age=0; Path=/" for k in cookie_vals]
        clear += [f"err_{f}=; Max-Age=0; Path=/" for f in ERROR_FIELDS]
        self._html(200, views.render_success(login, password), cookies=clear)

    def _login_form(self):
        cookies = security.parse_cookies(self.headers.get("Cookie", ""))
        csrf, csrf_cookie = self._csrf(cookies)
        self._html(200, views.render_login(csrf=csrf), cookies=self._cookie_list(csrf_cookie))

    def _login(self):
        data = self._read_form()
        if data is None:
            return
        cookies = security.parse_cookies(self.headers.get("Cookie", ""))
        if not self._check_csrf(cookies, data):
            return
        login = data.get("login", [""])[0].strip()
        password = data.get("password", [""])[0]
        row = db.get_user_by_login(login)
        if row is None or not security.verify_password(password, row["password_hash"]):
            csrf, _ = self._csrf(cookies)
            self._html(401, views.render_login("Неверный логин или пароль.", csrf=csrf))
            return
        sid = security.create_session(row["id"])
        self._redirect("/", extra_cookies=[
            f"{security.SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400",
        ])

    def _logout(self):
        data = self._read_form()
        if data is None:
            return
        cookies = security.parse_cookies(self.headers.get("Cookie", ""))
        if not self._check_csrf(cookies, data):
            return
        security.destroy_session(cookies)
        self._redirect("/", clear_session=True)

    # ── Администратор ──

    def _require_admin(self):
        if security.check_admin(self.headers.get("Authorization", "")):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Admin area"')
        self._security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write("<h1>401 Unauthorized</h1>".encode("utf-8"))
        return False

    def _admin_list(self):
        if not self._require_admin():
            return
        cookies = security.parse_cookies(self.headers.get("Cookie", ""))
        csrf, csrf_cookie = self._csrf(cookies)
        self._html(200, views.render_admin(db.get_all_users(), db.language_stats(), csrf=csrf),
                   cookies=self._cookie_list(csrf_cookie))

    def _admin_edit_form(self):
        if not self._require_admin():
            return
        user = db.load_user(self._query_id())
        if user is None:
            self._html(404, "<h1>404: пользователь не найден</h1>")
            return
        cookies = security.parse_cookies(self.headers.get("Cookie", ""))
        csrf, csrf_cookie = self._csrf(cookies)
        self._html(200, views.render_admin_edit(user, csrf=csrf),
                   cookies=self._cookie_list(csrf_cookie))

    def _admin_edit_save(self):
        if not self._require_admin():
            return
        data = self._read_form()
        if data is None:
            return
        cookies = security.parse_cookies(self.headers.get("Cookie", ""))
        if not self._check_csrf(cookies, data):
            return
        user = db.load_user(self._to_int(data.get("id", [""])[0]))
        if user is None:
            self._html(404, "<h1>404: пользователь не найден</h1>")
            return
        errors = validate(data, require_contract=False)
        if errors:
            csrf, _ = self._csrf(cookies)
            merged = {**user, **self._post_values(data)}
            self._html(200, views.render_admin_edit(merged, errors, csrf=csrf))
            return
        db.update_user(user["id"], data)
        self._redirect("/admin")

    def _admin_delete(self):
        if not self._require_admin():
            return
        data = self._read_form()
        if data is None:
            return
        cookies = security.parse_cookies(self.headers.get("Cookie", ""))
        if not self._check_csrf(cookies, data):
            return
        user_id = self._to_int(data.get("id", [""])[0])
        if user_id:
            db.delete_user(user_id)
        self._redirect("/admin")

    # ── CSRF ──

    def _csrf(self, cookies):
        token = cookies.get(security.CSRF_COOKIE)
        if token:
            return token, None
        token = security.generate_csrf_token()
        return token, f"{security.CSRF_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict"

    @staticmethod
    def _cookie_list(csrf_cookie):
        return [csrf_cookie] if csrf_cookie else []

    def _check_csrf(self, cookies, form):
        if security.csrf_valid(cookies, form):
            return True
        self._html(403, "<h1>403: ошибка проверки CSRF-токена</h1>")
        return False

    # ── Утилиты ──

    def _read_form(self):
        ctype = self.headers.get("Content-Type", "")
        if ctype.startswith("multipart/form-data"):
            self._html(415, "<h1>415: загрузка файлов не поддерживается</h1>")
            return None
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            self._html(400, "<h1>400 Bad Request</h1>")
            return None
        if length > MAX_BODY:
            self._html(413, "<h1>413: слишком большой запрос</h1>")
            return None
        body = self.rfile.read(length).decode("utf-8", "replace")
        return parse_qs(body, keep_blank_values=True)

    def _query_id(self):
        qs = parse_qs(urlparse(self.path).query)
        return self._to_int(qs.get("id", [""])[0])

    @staticmethod
    def _to_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _post_values(data):
        return {
            "fullname":  data.get("fullname",  [""])[0].strip(),
            "phone":     data.get("phone",     [""])[0].strip(),
            "email":     data.get("email",     [""])[0].strip(),
            "birthdate": data.get("birthdate", [""])[0].strip(),
            "gender":    data.get("gender",    [""])[0].strip(),
            "bio":       data.get("bio",       [""])[0].strip(),
            "languages": [l.strip().lower() for l in data.get("abilities[]", [])],
        }

    @staticmethod
    def _cookie_values(data):
        langs = ",".join(l.strip().lower() for l in data.get("abilities[]", []))
        return {
            "val_fullname":  data.get("fullname",  [""])[0].strip(),
            "val_phone":     data.get("phone",     [""])[0].strip(),
            "val_email":     data.get("email",     [""])[0].strip(),
            "val_birthdate": data.get("birthdate", [""])[0].strip(),
            "val_gender":    data.get("gender",    [""])[0].strip(),
            "val_bio":       data.get("bio",       [""])[0].strip(),
            "val_languages": langs,
        }

    def _security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )

    def _redirect(self, location, clear_session=False, extra_cookies=None):
        self.send_response(302)
        self.send_header("Location", location)
        self._security_headers()
        if clear_session:
            self.send_header("Set-Cookie", f"{security.SESSION_COOKIE}=; Max-Age=0; Path=/")
        for cookie in (extra_cookies or []):
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _serve_static(self, rel_name, content_type):
        full = os.path.realpath(os.path.join(BASE_DIR, rel_name))
        if not full.startswith(BASE_DIR + os.sep) or not os.path.isfile(full):
            self._html(404, "<h1>File not found</h1>")
            return
        with open(full, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self._security_headers()
        self.end_headers()
        self.wfile.write(content)

    def _html(self, code, body, cookies=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._security_headers()
        for cookie in (cookies or []):
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)


def main():
    db.init_db()
    if db.ensure_default_admin(DEFAULT_ADMIN_LOGIN, security.hash_password(DEFAULT_ADMIN_PASSWORD)):
        print(f"Создан администратор по умолчанию: {DEFAULT_ADMIN_LOGIN} / {DEFAULT_ADMIN_PASSWORD}")
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print("Сервер запущен: http://localhost:8080  (админка: http://localhost:8080/admin)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")


if __name__ == "__main__":
    main()
