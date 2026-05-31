import os
import re
import sqlite3
import hashlib
import hmac
import secrets
import string
from datetime import date
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, unquote

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")

ALLOWED_LANGUAGES = {
    "pascal", "c", "cpp", "javascript", "php",
    "python", "java", "haskell", "clojure", "prolog", "scala", "go",
}

ERROR_FIELDS = ["fullname", "phone", "email", "birthdate", "gender", "bio", "languages", "contract"]

PBKDF2_ITERATIONS = 200_000

SESSIONS: dict[str, int] = {}
SESSION_COOKIE = "session_id"


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = get_conn()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                login         TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                fio           TEXT    NOT NULL,
                phone         TEXT    NOT NULL,
                email         TEXT    NOT NULL,
                birthdate     TEXT    NOT NULL,
                gender        TEXT    NOT NULL,
                biography     TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_languages (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id  INTEGER NOT NULL,
                language TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes.fromhex(salt_hex), int(iterations),
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


def generate_unique_login(conn: sqlite3.Connection) -> str:
    while True:
        login = "user_" + secrets.token_hex(4)
        row = conn.execute("SELECT 1 FROM users WHERE login = ?", (login,)).fetchone()
        if row is None:
            return login


def generate_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%*-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def create_session(user_id: int) -> str:
    sid = secrets.token_urlsafe(32)
    SESSIONS[sid] = user_id
    return sid


def get_session_user(cookies: dict) -> int | None:
    sid = cookies.get(SESSION_COOKIE)
    if sid and sid in SESSIONS:
        return SESSIONS[sid]
    return None


def destroy_session(cookies: dict) -> None:
    sid = cookies.get(SESSION_COOKIE)
    if sid:
        SESSIONS.pop(sid, None)


def parse_cookies(header: str) -> dict:
    result = {}
    if not header:
        return result
    for part in header.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = unquote(v.strip())
    return result


def html_escape(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;"))


def validate(data: dict, require_contract: bool = True) -> dict:
    errors = {}

    fio = data.get("fullname", [""])[0].strip()
    if not fio:
        errors["fullname"] = "Обязательное поле."
    elif not re.fullmatch(r"[А-Яа-яЁёA-Za-z\s\-]+", fio):
        errors["fullname"] = "Допустимы только буквы (кириллица/латиница), пробелы и дефис (-)."
    elif len(fio) > 150:
        errors["fullname"] = "Не более 150 символов."

    phone = data.get("phone", [""])[0].strip()
    if not phone:
        errors["phone"] = "Обязательное поле."
    elif not re.fullmatch(r"[\+\d][\d\s\-\(\)]{6,19}", phone):
        errors["phone"] = "Допустимы только: цифры, знак +, пробел, дефис (-) и скобки ()."

    email = data.get("email", [""])[0].strip()
    if not email:
        errors["email"] = "Обязательное поле."
    elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        errors["email"] = "Введите корректный email (формат: user@domain.tld)."
    elif len(email) > 255:
        errors["email"] = "Не более 255 символов."

    birthdate_raw = data.get("birthdate", [""])[0].strip()
    if not birthdate_raw:
        errors["birthdate"] = "Обязательное поле."
    else:
        try:
            bd = date.fromisoformat(birthdate_raw)
            if bd >= date.today():
                errors["birthdate"] = "Дата рождения должна быть в прошлом."
            if bd < date(1900, 1, 1):
                errors["birthdate"] = "Дата рождения должна быть после 01.01.1900."
        except ValueError:
            errors["birthdate"] = "Неверный формат даты (ожидается ГГГГ-ММ-ДД)."

    gender = data.get("gender", [""])[0].strip()
    if gender not in ("male", "female"):
        errors["gender"] = "Выберите мужской или женский."

    languages = [lang.strip().lower() for lang in data.get("abilities[]", [])]
    if not languages:
        errors["languages"] = "Выберите хотя бы один язык."
    elif not all(lang in ALLOWED_LANGUAGES for lang in languages):
        errors["languages"] = "Один или несколько выбранных языков недопустимы."

    bio = data.get("bio", [""])[0].strip()
    if not bio:
        errors["bio"] = "Обязательное поле."

    if require_contract:
        contract = (data.get("contract") or [""])[0]
        if contract != "on":
            errors["contract"] = "Необходимо ознакомиться с контрактом."

    return errors


def insert_user(data: dict) -> tuple[int, str, str]:
    fio       = data["fullname"][0].strip()
    phone     = data["phone"][0].strip()
    email     = data["email"][0].strip()
    birthdate = data["birthdate"][0].strip()
    gender    = data["gender"][0].strip()
    bio       = data["bio"][0].strip()
    languages = [lang.strip().lower() for lang in data.get("abilities[]", [])]

    conn = get_conn()
    try:
        login = generate_unique_login(conn)
        password_plain = generate_password()
        password_hash = hash_password(password_plain)

        cur = conn.execute(
            """
            INSERT INTO users (login, password_hash, fio, phone, email, birthdate, gender, biography)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (login, password_hash, fio, phone, email, birthdate, gender, bio),
        )
        user_id = cur.lastrowid
        for lang in languages:
            conn.execute(
                "INSERT INTO user_languages (user_id, language) VALUES (?, ?)",
                (user_id, lang),
            )
        conn.commit()
        return user_id, login, password_plain
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_user(user_id: int, data: dict) -> None:
    fio       = data["fullname"][0].strip()
    phone     = data["phone"][0].strip()
    email     = data["email"][0].strip()
    birthdate = data["birthdate"][0].strip()
    gender    = data["gender"][0].strip()
    bio       = data["bio"][0].strip()
    languages = [lang.strip().lower() for lang in data.get("abilities[]", [])]

    conn = get_conn()
    try:
        conn.execute(
            """
            UPDATE users
               SET fio = ?, phone = ?, email = ?, birthdate = ?, gender = ?, biography = ?
             WHERE id = ?
            """,
            (fio, phone, email, birthdate, gender, bio, user_id),
        )
        conn.execute("DELETE FROM user_languages WHERE user_id = ?", (user_id,))
        for lang in languages:
            conn.execute(
                "INSERT INTO user_languages (user_id, language) VALUES (?, ?)",
                (user_id, lang),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def load_user(user_id: int) -> dict | None:
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            return None
        langs = [
            r["language"]
            for r in conn.execute(
                "SELECT language FROM user_languages WHERE user_id = ?", (user_id,)
            ).fetchall()
        ]
        return {
            "id":        row["id"],
            "login":     row["login"],
            "fullname":  row["fio"],
            "phone":     row["phone"],
            "email":     row["email"],
            "birthdate": row["birthdate"],
            "gender":    row["gender"],
            "bio":       row["biography"],
            "languages": langs,
        }
    finally:
        conn.close()


def get_user_by_login(login: str) -> sqlite3.Row | None:
    conn = get_conn()
    try:
        return conn.execute("SELECT * FROM users WHERE login = ?", (login,)).fetchone()
    finally:
        conn.close()


def render_form(values: dict, errors: dict, user: dict | None = None) -> bytes:

    def v(field: str) -> str:
        return html_escape(str(values.get(field, "")))

    def err_class(field: str) -> str:
        return " field-error" if errors.get(field) else ""

    def err_msg(field: str) -> str:
        msg = errors.get(field, "")
        return f'<span class="error-msg">{html_escape(msg)}</span>' if msg else ""

    def opt_selected(lang: str) -> str:
        langs = values.get("languages", [])
        if isinstance(langs, str):
            langs = [x for x in langs.split(",") if x]
        return " selected" if lang in langs else ""

    def radio_checked(val: str) -> str:
        return " checked" if values.get("gender") == val else ""

    if user:
        header = f"""
    <div class="auth-banner">
      <span>Вы вошли как <strong>{html_escape(user['login'])}</strong></span>
      <form action="logout" method="post" style="margin:0">
        <button type="submit" class="btn-logout">Выйти</button>
      </form>
    </div>"""
        title = "Редактирование данных"
        submit_label = "Сохранить изменения"
        contract_block = """
      <div class="form-group checkbox-group">
        <label>
          <input type="checkbox" name="contract" id="contract" checked>
          С контрактом ознакомлен(а)
        </label>
      </div>"""
    else:
        header = """
    <div class="auth-banner">
      <span>Уже есть логин и пароль?</span>
      <a href="/login" class="btn-logout" style="text-decoration:none">Войти</a>
    </div>"""
        title = "Регистрационная форма"
        submit_label = "Сохранить"
        contract_block = f"""
      <div class="form-group checkbox-group{err_class("contract")}">
        {err_msg("contract")}
        <label>
          <input type="checkbox" name="contract" id="contract" required>
          С контрактом ознакомлен(а)
        </label>
      </div>"""

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="form-container">
    {header}
    <h1>{title}</h1>

    <form action="submit" method="post">

      <div class="form-group">
        <label for="fullname">ФИО</label>
        {err_msg("fullname")}
        <input type="text" id="fullname" name="fullname"
               placeholder="Иванов Иван Иванович"
               class="input-field{err_class("fullname")}"
               value="{v("fullname")}" required>
      </div>

      <div class="form-group">
        <label for="phone">Телефон</label>
        {err_msg("phone")}
        <input type="tel" id="phone" name="phone"
               placeholder="+7 (999) 123-45-67"
               class="input-field{err_class("phone")}"
               value="{v("phone")}" required>
      </div>

      <div class="form-group">
        <label for="email">E-mail</label>
        {err_msg("email")}
        <input type="email" id="email" name="email"
               placeholder="example@mail.com"
               class="input-field{err_class("email")}"
               value="{v("email")}" required>
      </div>

      <div class="form-group">
        <label for="birthdate">Дата рождения</label>
        {err_msg("birthdate")}
        <input type="date" id="birthdate" name="birthdate"
               class="input-field{err_class("birthdate")}"
               value="{v("birthdate")}" required>
      </div>

      <div class="form-group">
        <label>Пол</label>
        {err_msg("gender")}
        <div class="radio-group{err_class("gender")}">
          <label>
            <input type="radio" name="gender" value="male"{radio_checked("male")} required>
            Мужской
          </label>
          <label>
            <input type="radio" name="gender" value="female"{radio_checked("female")}>
            Женский
          </label>
        </div>
      </div>

      <div class="form-group">
        <label for="languages">Любимый язык программирования</label>
        {err_msg("languages")}
        <select id="languages" name="abilities[]" multiple="multiple"
                class="{("field-error" if errors.get("languages") else "")}">
          <option value="pascal"{opt_selected("pascal")}>Pascal</option>
          <option value="c"{opt_selected("c")}>C</option>
          <option value="cpp"{opt_selected("cpp")}>C++</option>
          <option value="javascript"{opt_selected("javascript")}>JavaScript</option>
          <option value="php"{opt_selected("php")}>PHP</option>
          <option value="python"{opt_selected("python")}>Python</option>
          <option value="java"{opt_selected("java")}>Java</option>
          <option value="haskell"{opt_selected("haskell")}>Haskell</option>
          <option value="clojure"{opt_selected("clojure")}>Clojure</option>
          <option value="prolog"{opt_selected("prolog")}>Prolog</option>
          <option value="scala"{opt_selected("scala")}>Scala</option>
          <option value="go"{opt_selected("go")}>Go</option>
        </select>
        <p class="hint">Удерживайте Ctrl (или Cmd на Mac) для выбора нескольких вариантов</p>
      </div>

      <div class="form-group">
        <label for="bio">Биография</label>
        {err_msg("bio")}
        <textarea id="bio" name="bio"
                  placeholder="Расскажите о себе..."
                  class="{("field-error" if errors.get("bio") else "")}">{v("bio")}</textarea>
      </div>

      <div class="divider"></div>
      {contract_block}

      <button type="submit" class="btn-save">{submit_label}</button>

    </form>
  </div>
</body>
</html>"""
    return html.encode("utf-8")


def render_success(login: str, password: str) -> bytes:
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Регистрация завершена</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="form-container">
    <h1>Данные успешно сохранены!</h1>
    <p class="lead">Запомните или сохраните эти данные для входа.
       Они показываются <strong>только один раз</strong>.</p>

    <div class="credentials">
      <div class="cred-row">
        <span class="cred-label">Логин</span>
        <code class="cred-value">{html_escape(login)}</code>
      </div>
      <div class="cred-row">
        <span class="cred-label">Пароль</span>
        <code class="cred-value">{html_escape(password)}</code>
      </div>
    </div>

    <a href="/login" class="btn-save" style="text-align:center;display:block;text-decoration:none">
      Войти с этими данными →
    </a>
  </div>
</body>
</html>"""
    return html.encode("utf-8")


def render_login(error: str = "") -> bytes:
    error_html = f'<div class="alert-error">{html_escape(error)}</div>' if error else ""
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Вход</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="form-container">
    <h1>Вход</h1>
    {error_html}
    <form action="login" method="post">
      <div class="form-group">
        <label for="login">Логин</label>
        <input type="text" id="login" name="login" placeholder="user_xxxxxxxx" required autofocus>
      </div>
      <div class="form-group">
        <label for="password">Пароль</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit" class="btn-save">Войти</button>
    </form>
    <p class="hint" style="text-align:center;margin-top:18px">
      Нет логина? <a href="/" style="color:#4a90e2">Заполнить форму</a>
    </p>
  </div>
</body>
</html>"""
    return html.encode("utf-8")


class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[{self.address_string()}] {format % args}")

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path.endswith("styles.css"):
            self._serve_file(os.path.join(BASE_DIR, "styles.css"), "text/css; charset=utf-8")
            return

        if path == "/login":
            self._send(200, render_login())
            return

        if path in ("/", "/index.html") or path.strip("/") in ("", "laba5"):
            self._render_main_form()
            return

        self._send(404, b"<h1>404 Not Found</h1>")

    def do_POST(self):
        path = self.path.split("?", 1)[0]

        if path.endswith("login"):
            self._handle_login()
            return
        if path.endswith("logout"):
            self._handle_logout()
            return
        if path.endswith("submit"):
            self._handle_submit()
            return

        self._send(404, b"<h1>404 Not Found</h1>")

    def _render_main_form(self):
        cookies = parse_cookies(self.headers.get("Cookie", ""))
        user_id = get_session_user(cookies)

        if user_id is not None:
            user = load_user(user_id)
            if user is None:
                destroy_session(cookies)
                self.send_response(302)
                self.send_header("Location", "/login")
                self.send_header("Set-Cookie", f"{SESSION_COOKIE}=; Max-Age=0; Path=/")
                self.end_headers()
                return
            self._send(200, render_form(user, {}, user=user))
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
        errors = {}
        cookies_to_clear = []
        for field in ERROR_FIELDS:
            key = f"err_{field}"
            if cookies.get(key):
                errors[field] = cookies[key]
                cookies_to_clear.append(key)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for key in cookies_to_clear:
            self.send_header("Set-Cookie", f"{key}=; Max-Age=0; Path=/")
        self.end_headers()
        self.wfile.write(render_form(values, errors, user=None))

    def _handle_submit(self):
        data = self._read_form()
        cookies = parse_cookies(self.headers.get("Cookie", ""))
        user_id = get_session_user(cookies)

        if user_id is not None:
            user = load_user(user_id)
            if user is None:
                destroy_session(cookies)
                self._redirect("/login", clear_session=True)
                return
            errors = validate(data, require_contract=False)
            if errors:
                values = self._values_from_post(data)
                values["login"] = user["login"]
                self._send(200, render_form(values, errors, user=user))
                return
            update_user(user_id, data)
            fresh = load_user(user_id)
            self._send(200, self._render_edit_success(fresh))
            return

        errors = validate(data, require_contract=True)
        values_cookies = self._cookie_values_from_post(data)

        if errors:
            self.send_response(302)
            self.send_header("Location", "/")
            for key, val in values_cookies.items():
                self.send_header("Set-Cookie", f"{key}={quote(val)}; Path=/")
            for field, msg in errors.items():
                self.send_header("Set-Cookie", f"err_{field}={quote(msg)}; Path=/")
            self.end_headers()
            return

        try:
            user_id, login, password = insert_user(data)
        except Exception as e:
            self._send(500, f"<h1>Ошибка БД</h1><pre>{html_escape(str(e))}</pre>".encode())
            return

        max_age0 = "Max-Age=0; Path=/"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for key in values_cookies:
            self.send_header("Set-Cookie", f"{key}=; {max_age0}")
        for field in ERROR_FIELDS:
            self.send_header("Set-Cookie", f"err_{field}=; {max_age0}")
        self.end_headers()
        self.wfile.write(render_success(login, password))

    def _render_edit_success(self, user: dict) -> bytes:
        page = render_form(user, {}, user=user).decode("utf-8")
        banner = '<div class="alert-success">Изменения сохранены.</div>'
        page = page.replace('<h1>Редактирование данных</h1>',
                            '<h1>Редактирование данных</h1>\n    ' + banner)
        return page.encode("utf-8")

    def _handle_login(self):
        data = self._read_form()
        login = data.get("login", [""])[0].strip()
        password = data.get("password", [""])[0]

        row = get_user_by_login(login)
        if row is None or not verify_password(password, row["password_hash"]):
            self._send(401, render_login("Неверный логин или пароль."))
            return

        sid = create_session(row["id"])
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400",
        )
        self.end_headers()

    def _handle_logout(self):
        cookies = parse_cookies(self.headers.get("Cookie", ""))
        destroy_session(cookies)
        self._redirect("/", clear_session=True)

    def _read_form(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        return parse_qs(body, keep_blank_values=True)

    def _values_from_post(self, data: dict) -> dict:
        return {
            "fullname":  data.get("fullname",  [""])[0].strip(),
            "phone":     data.get("phone",     [""])[0].strip(),
            "email":     data.get("email",     [""])[0].strip(),
            "birthdate": data.get("birthdate", [""])[0].strip(),
            "gender":    data.get("gender",    [""])[0].strip(),
            "bio":       data.get("bio",       [""])[0].strip(),
            "languages": [l.strip().lower() for l in data.get("abilities[]", [])],
        }

    def _cookie_values_from_post(self, data: dict) -> dict:
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

    def _redirect(self, location: str, clear_session: bool = False):
        self.send_response(302)
        self.send_header("Location", location)
        if clear_session:
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}=; Max-Age=0; Path=/")
        self.end_headers()

    def _serve_file(self, file_path: str, content_type: str):
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self._send(404, b"<h1>File not found</h1>")

    def _send(self, code: int, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    init_db()
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print("Сервер запущен: http://localhost:8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
