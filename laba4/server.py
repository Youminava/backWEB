import os
import re
from datetime import date
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, unquote

import mysql.connector
from dotenv import load_dotenv

load_dotenv()

#КОНФИГ 

DB_CONFIG = {
    "host":     os.getenv("DB_HOST"),
    "user":     os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
}

ALLOWED_LANGUAGES = {
    "pascal", "c", "cpp", "javascript", "php",
    "python", "java", "haskell", "clojure", "prolog", "scala", "go",
}

# Поля, для которых сохраняются ошибки в Cookies
ERROR_FIELDS = ["fullname", "phone", "email", "birthdate", "gender", "bio", "languages", "contract"]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ─── ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ─────────────────────────────────────────────────

def parse_cookies(header: str) -> dict:
    """Разбирает заголовок Cookie в словарь, URL-декодируя значения."""
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


# ─── ВАЛИДАЦИЯ (регулярные выражения) ────────────────────────────────────────

def validate(data: dict) -> dict:
    """
    Возвращает словарь {поле: сообщение_об_ошибке}.
    Пустой словарь — данные корректны.
    """
    errors = {}

    # ФИО
    fio = data.get("fullname", [""])[0].strip()
    if not fio:
        errors["fullname"] = "Обязательное поле."
    elif not re.fullmatch(r"[А-Яа-яЁёA-Za-z\s\-]+", fio):
        errors["fullname"] = (
            "Допустимы только буквы (кириллица/латиница), пробелы и дефис (-)."
        )
    elif len(fio) > 150:
        errors["fullname"] = "Не более 150 символов."

    # Телефон
    phone = data.get("phone", [""])[0].strip()
    if not phone:
        errors["phone"] = "Обязательное поле."
    elif not re.fullmatch(r"[\+\d][\d\s\-\(\)]{6,19}", phone):
        errors["phone"] = (
            "Допустимы только: цифры, знак +, пробел, дефис (-) и скобки ()."
        )

    # Email
    email = data.get("email", [""])[0].strip()
    if not email:
        errors["email"] = "Обязательное поле."
    elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        errors["email"] = "Введите корректный email (формат: user@domain.tld)."
    elif len(email) > 255:
        errors["email"] = "Не более 255 символов."

    # Дата рождения
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

    # Пол
    gender = data.get("gender", [""])[0].strip()
    if gender not in ("male", "female"):
        errors["gender"] = "Выберите мужской или женский."

    # Языки программирования
    languages = [lang.strip().lower() for lang in data.get("abilities[]", [])]
    if not languages:
        errors["languages"] = "Выберите хотя бы один язык."
    elif not all(lang in ALLOWED_LANGUAGES for lang in languages):
        errors["languages"] = "Один или несколько выбранных языков недопустимы."

    # Биография
    bio = data.get("bio", [""])[0].strip()
    if not bio:
        errors["bio"] = "Обязательное поле."

    # Чекбокс согласия
    contract = (data.get("contract") or [""])[0]
    if contract != "on":
        errors["contract"] = "Необходимо ознакомиться с контрактом."

    return errors


# ─── ЗАПИСЬ В БД ──────────────────────────────────────────────────────────────

def save_to_db(data: dict) -> int:
    fio       = data["fullname"][0].strip()
    phone     = data["phone"][0].strip()
    email     = data["email"][0].strip()
    birthdate = data["birthdate"][0].strip()
    gender    = data["gender"][0].strip()
    bio       = data["bio"][0].strip()
    languages = [lang.strip().lower() for lang in data.get("abilities[]", [])]

    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(prepared=True)

    try:
        cursor.execute(
            """
            INSERT INTO users (fio, phone, email, birthdate, gender, biography)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (fio, phone, email, birthdate, gender, bio),
        )
        user_id = cursor.lastrowid

        for lang in languages:
            cursor.execute(
                "INSERT INTO user_languages (user_id, language) VALUES (%s, %s)",
                (user_id, lang),
            )

        conn.commit()
        return user_id
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


# ─── РЕНДЕРИНГ HTML ──────────────────────────────────────────────────────────

def render_form(values: dict, errors: dict) -> bytes:
    """
    Генерирует HTML страницы формы.
    values — текущие значения полей (из Cookies или пустые).
    errors — словарь поле→сообщение (из Cookies ошибок).
    """

    def v(field: str) -> str:
        """Экранированное значение поля для подстановки в HTML."""
        return html_escape(values.get(field, ""))

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

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Регистрационная форма</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="form-container">
    <h1>Регистрационная форма</h1>

    <form action="submit" method="post">

      <!-- 1. ФИО -->
      <div class="form-group">
        <label for="fullname">ФИО</label>
        {err_msg("fullname")}
        <input type="text" id="fullname" name="fullname"
               placeholder="Иванов Иван Иванович"
               class="input-field{err_class("fullname")}"
               value="{v("fullname")}" required>
      </div>

      <!-- 2. Телефон -->
      <div class="form-group">
        <label for="phone">Телефон</label>
        {err_msg("phone")}
        <input type="tel" id="phone" name="phone"
               placeholder="+7 (999) 123-45-67"
               class="input-field{err_class("phone")}"
               value="{v("phone")}" required>
      </div>

      <!-- 3. E-mail -->
      <div class="form-group">
        <label for="email">E-mail</label>
        {err_msg("email")}
        <input type="email" id="email" name="email"
               placeholder="example@mail.com"
               class="input-field{err_class("email")}"
               value="{v("email")}" required>
      </div>

      <!-- 4. Дата рождения -->
      <div class="form-group">
        <label for="birthdate">Дата рождения</label>
        {err_msg("birthdate")}
        <input type="date" id="birthdate" name="birthdate"
               class="input-field{err_class("birthdate")}"
               value="{v("birthdate")}" required>
      </div>

      <!-- 5. Пол -->
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

      <!-- 6. Языки программирования -->
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

      <!-- 7. Биография -->
      <div class="form-group">
        <label for="bio">Биография</label>
        {err_msg("bio")}
        <textarea id="bio" name="bio"
                  placeholder="Расскажите о себе..."
                  class="{("field-error" if errors.get("bio") else "")}">{v("bio")}</textarea>
      </div>

      <div class="divider"></div>

      <!-- 8. Чекбокс -->
      <div class="form-group checkbox-group{err_class("contract")}">
        {err_msg("contract")}
        <label>
          <input type="checkbox" name="contract" id="contract" required>
          С контрактом ознакомлен(а)
        </label>
      </div>

      <!-- 9. Кнопка -->
      <button type="submit" class="btn-save">Сохранить</button>

    </form>
  </div>
</body>
</html>"""
    return html.encode("utf-8")


def render_success(user_id: int) -> bytes:
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Успешно!</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="form-container">
    <h1>Данные успешно отправлены!</h1>
    <p style="color:#a0a0b0;margin-bottom:24px">Ваш ID заявки: <strong>{user_id}</strong></p>
    <a href="/laba4" class="btn-save" style="text-align:center;display:block;text-decoration:none">← На главную</a>
  </div>
</body>
</html>"""
    return html.encode("utf-8")


# ─── HTTP HANDLER ─────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[{self.address_string()}] {format % args}")

    # ── GET: отображение формы ──
    def do_GET(self):
        # Статические файлы
        if self.path.endswith("styles.css"):
            self._serve_file(os.path.join(BASE_DIR, "styles.css"), "text/css; charset=utf-8")
            return

        # Все остальные пути → форма
        if not (self.path.endswith(("/", "/index.html")) or self.path.strip("/") in ("", "laba3")):
            self._send_html(404, b"<h1>404 Not Found</h1>")
            return

        cookies = parse_cookies(self.headers.get("Cookie", ""))

        # Восстановить значения полей из Cookies
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

        # Восстановить ошибки из Cookies (сессионные — удаляем сразу после чтения)
        errors = {}
        cookies_to_clear = []
        for field in ERROR_FIELDS:
            key = f"err_{field}"
            if key in cookies and cookies[key]:
                errors[field] = cookies[key]
                cookies_to_clear.append(key)

        html_content = render_form(values, errors)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Удалить ошибочные Cookies (Max-Age=0)
        for key in cookies_to_clear:
            self.send_header("Set-Cookie", f"{key}=; Max-Age=0; Path=/")
        self.end_headers()
        self.wfile.write(html_content)

    # ── POST: обработка формы ──
    def do_POST(self):
        if not self.path.endswith("submit"):
            self._send_html(404, b"<h1>404 Not Found</h1>")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        data = parse_qs(body)

        errors = validate(data)

        # Собираем введённые значения для Cookies
        submitted_langs = ",".join(
            lang.strip().lower() for lang in data.get("abilities[]", [])
        )
        values_cookies = {
            "val_fullname":  data.get("fullname",  [""])[0].strip(),
            "val_phone":     data.get("phone",     [""])[0].strip(),
            "val_email":     data.get("email",     [""])[0].strip(),
            "val_birthdate": data.get("birthdate", [""])[0].strip(),
            "val_gender":    data.get("gender",    [""])[0].strip(),
            "val_bio":       data.get("bio",       [""])[0].strip(),
            "val_languages": submitted_langs,
        }

        if errors:
            # Ошибки: сохраняем значения и ошибки в сессионных Cookies,
            # затем перенаправляем GET на форму
            self.send_response(302)
            self.send_header("Location", "/laba4")
            # Сессионные Cookies с введёнными значениями
            for key, val in values_cookies.items():
                self.send_header("Set-Cookie", f"{key}={quote(val)}; Path=/")
            for field, msg in errors.items():
                self.send_header("Set-Cookie", f"err_{field}={quote(msg)}; Path=/")
            self.end_headers()
            return

        try:
            user_id = save_to_db(data)
            max_age = 365 * 24 * 3600  
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            for key, val in values_cookies.items():
                self.send_header(
                    "Set-Cookie",
                    f"{key}={quote(val)}; Max-Age={max_age}; Path=/"
                )
            for field in ERROR_FIELDS:
                self.send_header("Set-Cookie", f"err_{field}=; Max-Age=0; Path=/")
            self.end_headers()
            self.wfile.write(render_success(user_id))
        except Exception as e:
            self._send_html(500, f"<h1>Ошибка БД</h1><pre>{e}</pre>".encode())

    # ── Вспомогательные методы ──

    def _serve_file(self, file_path: str, content_type: str):
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self._send_html(404, b"<h1>File not found</h1>")

    def _send_html(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)


# ─── ЗАПУСК ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8081), Handler)
    print("Сервер запущен: http://localhost:8081")
    server.serve_forever()

