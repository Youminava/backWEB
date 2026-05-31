import os
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


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/styles.css":
            self._serve_file(os.path.join(BASE_DIR, "styles.css"), "text/css; charset=utf-8")
        elif path == "/login":
            self._send(200, views.render_login())
        elif path == "/admin":
            self._admin_list()
        elif path == "/admin/edit":
            self._admin_edit_form()
        elif path in ("/", "/index.html"):
            self._main_form()
        else:
            self._send(404, b"<h1>404 Not Found</h1>")

    def do_POST(self):
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
            self._send(404, b"<h1>404 Not Found</h1>")

    # ── Пользовательские страницы ──

    def _main_form(self):
        cookies = security.parse_cookies(self.headers.get("Cookie", ""))
        user_id = security.get_session_user(cookies)

        if user_id is not None:
            user = db.load_user(user_id)
            if user is None:
                security.destroy_session(cookies)
                self._redirect("/login", clear_session=True)
                return
            self._send(200, views.render_form(user, {}, user=user))
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
        errors, to_clear = {}, []
        for field in ERROR_FIELDS:
            key = f"err_{field}"
            if cookies.get(key):
                errors[field] = cookies[key]
                to_clear.append(key)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for key in to_clear:
            self.send_header("Set-Cookie", f"{key}=; Max-Age=0; Path=/")
        self.end_headers()
        self.wfile.write(views.render_form(values, errors, user=None))

    def _submit(self):
        data = self._read_form()
        cookies = security.parse_cookies(self.headers.get("Cookie", ""))
        user_id = security.get_session_user(cookies)

        if user_id is not None:
            user = db.load_user(user_id)
            if user is None:
                security.destroy_session(cookies)
                self._redirect("/login", clear_session=True)
                return
            errors = validate(data, require_contract=False)
            if errors:
                values = self._post_values(data)
                values["login"] = user["login"]
                self._send(200, views.render_form(values, errors, user=user))
                return
            db.update_user(user_id, data)
            fresh = db.load_user(user_id)
            page = views.render_form(fresh, {}, user=fresh).decode("utf-8").replace(
                "<h1>Редактирование данных</h1>",
                '<h1>Редактирование данных</h1>\n    <div class="alert-success">Изменения сохранены.</div>',
            )
            self._send(200, page)
            return

        errors = validate(data, require_contract=True)
        cookie_vals = self._cookie_values(data)
        if errors:
            self.send_response(302)
            self.send_header("Location", "/")
            for key, val in cookie_vals.items():
                self.send_header("Set-Cookie", f"{key}={quote(val)}; Path=/")
            for field, msg in errors.items():
                self.send_header("Set-Cookie", f"err_{field}={quote(msg)}; Path=/")
            self.end_headers()
            return

        password = security.generate_password()
        _, login = db.insert_user(data, security.hash_password(password))

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for key in cookie_vals:
            self.send_header("Set-Cookie", f"{key}=; Max-Age=0; Path=/")
        for field in ERROR_FIELDS:
            self.send_header("Set-Cookie", f"err_{field}=; Max-Age=0; Path=/")
        self.end_headers()
        self.wfile.write(views.render_success(login, password))

    def _login(self):
        data = self._read_form()
        login = data.get("login", [""])[0].strip()
        password = data.get("password", [""])[0]
        row = db.get_user_by_login(login)
        if row is None or not security.verify_password(password, row["password_hash"]):
            self._send(401, views.render_login("Неверный логин или пароль."))
            return
        sid = security.create_session(row["id"])
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            f"{security.SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400",
        )
        self.end_headers()

    def _logout(self):
        cookies = security.parse_cookies(self.headers.get("Cookie", ""))
        security.destroy_session(cookies)
        self._redirect("/", clear_session=True)

    # ── Администратор ──

    def _require_admin(self):
        if security.check_admin(self.headers.get("Authorization", "")):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Admin area"')
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<h1>401 Unauthorized</h1>")
        return False

    def _admin_list(self, message=""):
        if not self._require_admin():
            return
        self._send(200, views.render_admin(db.get_all_users(), db.language_stats(), message))

    def _admin_edit_form(self):
        if not self._require_admin():
            return
        user_id = self._query_id()
        user = db.load_user(user_id) if user_id else None
        if user is None:
            self._send(404, "<h1>404: пользователь не найден</h1>")
            return
        self._send(200, views.render_admin_edit(user))

    def _admin_edit_save(self):
        if not self._require_admin():
            return
        data = self._read_form()
        user_id = self._to_int(data.get("id", [""])[0])
        user = db.load_user(user_id) if user_id else None
        if user is None:
            self._send(404, "<h1>404: пользователь не найден</h1>")
            return
        errors = validate(data, require_contract=False)
        if errors:
            merged = {**user, **self._post_values(data)}
            self._send(200, views.render_admin_edit(merged, errors))
            return
        db.update_user(user_id, data)
        self._redirect("/admin")

    def _admin_delete(self):
        if not self._require_admin():
            return
        data = self._read_form()
        user_id = self._to_int(data.get("id", [""])[0])
        if user_id:
            db.delete_user(user_id)
        self._redirect("/admin")

    # ── Утилиты ──

    def _read_form(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
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

    def _redirect(self, location, clear_session=False):
        self.send_response(302)
        self.send_header("Location", location)
        if clear_session:
            self.send_header("Set-Cookie", f"{security.SESSION_COOKIE}=; Max-Age=0; Path=/")
        self.end_headers()

    def _serve_file(self, file_path, content_type):
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self._send(404, b"<h1>File not found</h1>")

    def _send(self, code, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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
