import os
import re
from datetime import date
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

import mysql.connector
from dotenv import load_dotenv

load_dotenv()

# ─── DB CONFIG ────────────────────────────────────────────────────────────────
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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ─── VALIDATION ───────────────────────────────────────────────────────────────
def validate(data: dict) -> list[str]:
    errors = []

    # ФИО
    fio = data.get("fullname", [""])[0].strip()
    if not fio:
        errors.append("ФИО: обязательное поле.")
    elif not re.fullmatch(r"[А-Яа-яЁёA-Za-z\s\-]+", fio):
        errors.append("ФИО: допустимы только буквы, пробелы и дефис.")
    elif len(fio) > 150:
        errors.append("ФИО: не более 150 символов.")

    # Телефон
    phone = data.get("phone", [""])[0].strip()
    if not phone:
        errors.append("Телефон: обязательное поле.")
    elif not re.fullmatch(r"[\+\d][\d\s\-\(\)]{6,19}", phone):
        errors.append("Телефон: недопустимый формат.")

    # Email
    email = data.get("email", [""])[0].strip()
    if not email:
        errors.append("Email: обязательное поле.")
    elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        errors.append("Email: недопустимый формат.")
    elif len(email) > 255:
        errors.append("Email: не более 255 символов.")

    # Дата рождения
    birthdate_raw = data.get("birthdate", [""])[0].strip()
    if not birthdate_raw:
        errors.append("Дата рождения: обязательное поле.")
    else:
        try:
            bd = date.fromisoformat(birthdate_raw)
            if bd >= date.today():
                errors.append("Дата рождения: дата должна быть в прошлом.")
        except ValueError:
            errors.append("Дата рождения: неверный формат даты.")

    # Пол
    gender = data.get("gender", [""])[0].strip()
    if gender not in ("male", "female"):
        errors.append("Пол: выберите мужской или женский.")

    # Языки программирования
    languages = data.get("abilities[]", [])
    languages = [lang.strip().lower() for lang in languages]
    if not languages:
        errors.append("Языки: выберите хотя бы один язык.")
    elif not all(lang in ALLOWED_LANGUAGES for lang in languages):
        errors.append("Языки: один или несколько языков недопустимы.")

    # Биография
    bio = data.get("bio", [""])[0].strip()
    if not bio:
        errors.append("Биография: обязательное поле.")

    # Чекбокс
    contract = data.get("contract", [""])[0]
    if contract != "on":
        errors.append("Подтверждение: необходимо ознакомиться с контрактом.")

    return errors


# ─── DB WRITE ─────────────────────────────────────────────────────────────────
def save_to_db(data: dict) -> int:
    fio        = data["fullname"][0].strip()
    phone      = data["phone"][0].strip()
    email      = data["email"][0].strip()
    birthdate  = data["birthdate"][0].strip()
    gender     = data["gender"][0].strip()
    bio        = data["bio"][0].strip()
    languages  = [lang.strip().lower() for lang in data.get("abilities[]", [])]

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


# ─── HTML HELPERS ─────────────────────────────────────────────────────────────
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
    <p style="color:#a0a0b0;margin-bottom:24px">Ваш ID заявки: <strong id="user-id">{user_id}</strong></p>
    <a href="index.html" class="btn-save" style="text-align:center;display:block;text-decoration:none">← На главную</a>
  </div>
</body>
</html>"""
    return html.encode("utf-8")


def render_errors(errors: list[str]) -> bytes:
    items = "".join(f"<li>{e}</li>" for e in errors)
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Ошибка валидации</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="form-container">
    <h1>Ошибка заполнения формы</h1>
    <ul style="color:#e94560;line-height:2;margin-bottom:24px">{items}</ul>
    <a href="index.html" class="btn-save" style="text-align:center;display:block;text-decoration:none">← Вернуться</a>
  </div>
</body>
</html>"""
    return html.encode("utf-8")


# ─── HANDLER ──────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[{self.address_string()}] {format % args}")

    # ── GET ──
    def do_GET(self):
        # Если пришел запрос с любым путем (Nginx может передавать /laba3/ или просто /)
        # Мы просто смотрим на конец строки
        if self.path.endswith(("/index.html", "/")) or self.path.strip("/") == "laba3":
            file_path = os.path.join(BASE_DIR, "index.html")
            content_type = "text/html; charset=utf-8"
        elif self.path.endswith("styles.css"):
            file_path = os.path.join(BASE_DIR, "styles.css")
            content_type = "text/css; charset=utf-8"
        else:
            self._send_html(404, b"<h1>404 Not Found</h1>")
            return

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self._send_html(404, b"<h1>File not found</h1>")

    # ── POST ──
    def do_POST(self):
        if not self.path.endswith("submit"):
            self._send_html(404, b"<h1>404 Not Found</h1>")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        data = parse_qs(body)

        errors = validate(data)
        if errors:
            self._send_html(400, render_errors(errors))
            return

        try:
            user_id = save_to_db(data)
            self._send_html(200, render_success(user_id))
        except Exception as e:
            self._send_html(500, f"<h1>Ошибка БД</h1><pre>{e}</pre>".encode())

    # ── helpers ──
    def _send_html(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print("Server running → http://localhost:8080")
    server.serve_forever()

