# Отчёт об аудите безопасности веб-приложения (Лабораторная работа №7)

Аудит проводился для приложения из лабораторной работы №6 (регистрационная форма
с пользовательскими сессиями и панелью администратора). Приложение написано на
стандартной библиотеке Python (`http.server`, `sqlite3`, `hashlib`, `hmac`,
`secrets`). Ниже по каждому классу уязвимостей описаны риск и применённые методы
защиты с примерами кода из исправленной версии.

Структура проекта:

| Файл | Назначение |
|------|------------|
| `server.py`     | HTTP-обработчик, маршрутизация, заголовки безопасности, CSRF, обработка ошибок |
| `db.py`         | соединение с БД и все SQL-запросы (параметризованные) |
| `security.py`   | хеширование паролей, сессии, CSRF-токены, HTTP Basic Auth |
| `validation.py` | серверная валидация входных данных |
| `views.py`      | генерация HTML с экранированием вывода |

---

## 1. XSS (Cross-Site Scripting)

**Риск.** Данные, введённые пользователем (ФИО, биография и т.д.), выводятся в
HTML на странице редактирования и в панели администратора. Без экранирования
значение вида `<script>alert(1)</script>` выполнилось бы в браузере жертвы
(stored XSS).

**Методы защиты.**

1. Экранирование всего динамического вывода. Любое значение, попадающее в HTML,
   пропускается через `html_escape`, заменяющую `& < > "` на HTML-сущности
   (`views.py`):

   ```python
   def html_escape(s):
       return (str(s).replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;")
                     .replace('"', "&quot;"))
   ```

   Пример в таблице администратора — все поля экранируются:

   ```python
   <td>{html_escape(u["fullname"])}</td>
   <td>{html_escape(u["email"])}</td>
   <td>{html_escape(u["bio"])}</td>
   ```

2. Content-Security-Policy. Даже если экранирование где-то будет пропущено,
   политика `script-src 'none'` запрещает выполнение любого скрипта; все
   инлайновые обработчики событий из разметки убраны (`server.py`):

   ```python
   self.send_header(
       "Content-Security-Policy",
       "default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
   )
   self.send_header("X-Content-Type-Options", "nosniff")
   self.send_header("X-Frame-Options", "DENY")
   ```

**Проверка.** Регистрация пользователя с ФИО/биографией `<script>alert(1)</script>`
и просмотр панели администратора: в HTML присутствует только экранированный
`&lt;script&gt;alert(1)&lt;/script&gt;` — скрипт не выполняется.

---

## 2. Information Disclosure (Раскрытие информации)

**Риск.** Стандартный `http.server` при необработанном исключении может вернуть
клиенту трассировку стека (пути, SQL-запросы, версии), а в заголовке `Server`
сообщает точную версию Python — это упрощает атаку.

**Методы защиты.**

1. Единый обработчик ошибок: исключение логируется только на сервере, клиент
   получает обезличенную страницу 500 без деталей (`server.py`):

   ```python
   def _dispatch(self, route):
       try:
           route()
       except Exception:
           traceback.print_exc()                  # лог только на сервере
           try:
               self._html(500, "<h1>500: внутренняя ошибка сервера</h1>")
           except Exception:
               pass
   ```

2. Скрытие версии сервера (`server.py`):

   ```python
   class Handler(BaseHTTPRequestHandler):
       server_version = "WebServer"
       sys_version = ""
   ```

3. Пароли не хранятся в открытом виде — только PBKDF2-HMAC-SHA256 с солью
   (`security.py`):

   ```python
   def hash_password(password):
       salt = secrets.token_bytes(16)
       dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
       return f"pbkdf2_sha256$200000${salt.hex()}${dk.hex()}"
   ```

**Проверка.** Заголовок ответа: `Server: WebServer` (без версии Python). При
внутренней ошибке клиент видит только «500: внутренняя ошибка сервера».

---

## 3. SQL Injection

**Риск.** При конкатенации пользовательского ввода в текст запроса
(`"... WHERE login = '" + login + "'"`) значение `' OR '1'='1` позволило бы
обойти авторизацию или прочитать чужие данные.

**Метод защиты.** Все запросы параметризованы — значения передаются отдельным
кортежем, драйвер `sqlite3` экранирует их сам, ввод никогда не интерпретируется
как SQL (`db.py`):

```python
def get_user_by_login(login):
    conn = get_conn()
    try:
        return conn.execute("SELECT * FROM users WHERE login = ?", (login,)).fetchone()
    finally:
        conn.close()

def insert_user(data, password_hash):
    ...
    conn.execute(
        """INSERT INTO users (login, password_hash, fio, phone, email, birthdate, gender, biography)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (login, password_hash, fio, phone, email, birthdate, gender, bio),
    )
```

Идентификатор пользователя из запроса/формы дополнительно приводится к `int`
(`server.py`):

```python
@staticmethod
def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
```

**Проверка.** Вход с логином/паролем `' OR '1'='1` возвращает 401, БД остаётся
целой — инъекция не срабатывает.

---

## 4. CSRF (Cross-Site Request Forgery)

**Риск.** Изменяющие POST-запросы (создание/редактирование/удаление записи,
выход) выполняются с cookie сессии и заголовком Basic Auth, которые браузер
прикрепляет автоматически. Сторонний сайт мог бы от имени жертвы отправить форму
на наш сервер.

**Метод защиты.** CSRF-токен по схеме double-submit cookie. Сервер выдаёт
случайный токен в cookie с флагами `HttpOnly; SameSite=Strict` и встраивает тот
же токен скрытым полем во все формы. На каждый POST токен из формы сравнивается с
токеном из cookie в постоянное время. Сторонний сайт не может прочитать токен и
не подделает поле формы.

Генерация и проверка (`security.py`):

```python
CSRF_COOKIE = "csrf_token"

def generate_csrf_token():
    return secrets.token_urlsafe(32)

def csrf_valid(cookies, form):
    cookie_token = cookies.get(CSRF_COOKIE, "")
    form_token = (form.get("csrf_token", [""]) or [""])[0]
    if not cookie_token or not form_token:
        return False
    return hmac.compare_digest(cookie_token, form_token)
```

Выдача токена и проверка на каждом изменяющем POST (`server.py`):

```python
def _csrf(self, cookies):
    token = cookies.get(security.CSRF_COOKIE)
    if token:
        return token, None
    token = security.generate_csrf_token()
    return token, f"{security.CSRF_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict"

def _check_csrf(self, cookies, form):
    if security.csrf_valid(cookies, form):
        return True
    self._html(403, "<h1>403: ошибка проверки CSRF-токена</h1>")
    return False
```

Скрытое поле во всех формах (`views.py`):

```python
def _csrf_field(token):
    return f'<input type="hidden" name="csrf_token" value="{html_escape(token)}">'
```

Дополнительно cookie сессии помечена `SameSite=Lax`.

**Проверка.** POST на `/submit`, `/logout`, `/admin/edit`, `/admin/delete` без
корректного `csrf_token` возвращает 403; с корректным токеном — выполняется.

---

## 5. Include (LFI / Path Traversal)

**Риск.** При отдаче статических файлов по пути из запроса злоумышленник мог бы
запросить `/../../etc/passwd` или `/../app.db` и получить произвольный файл
сервера.

**Метод защиты.** Отдаются только файлы из белого списка, итоговый путь
нормализуется через `os.path.realpath` и проверяется на принадлежность каталогу
приложения (`server.py`):

```python
STATIC_FILES = {
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}

def _serve_static(self, rel_name, content_type):
    full = os.path.realpath(os.path.join(BASE_DIR, rel_name))
    if not full.startswith(BASE_DIR + os.sep) or not os.path.isfile(full):
        self._html(404, "<h1>File not found</h1>")
        return
    with open(full, "rb") as f:
        content = f.read()
    ...
```

Имя файла никогда не берётся напрямую из URL: маршрутизатор сопоставляет путь с
фиксированным словарём `STATIC_FILES`, выход за пределы каталога невозможен.

**Проверка.** `/styles.css` → 200; любой неизвестный путь (включая попытки с
`..`) → 404, файлы вне каталога не отдаются.

---

## 6. Upload (Загрузка файлов)

**Риск.** Бесконтрольная загрузка позволяет залить веб-шелл или исчерпать ресурсы
большим телом запроса.

**Методы защиты.**

1. Функциональности загрузки файлов нет. Принимается только
   `application/x-www-form-urlencoded`; запросы `multipart/form-data` (через
   которые передаются файлы) явно отклоняются (`server.py`):

   ```python
   def _read_form(self):
       ctype = self.headers.get("Content-Type", "")
       if ctype.startswith("multipart/form-data"):
           self._html(415, "<h1>415: загрузка файлов не поддерживается</h1>")
           return None
       ...
   ```

2. Ограничение размера тела запроса — защита от переполнения ресурсов
   (`server.py`):

   ```python
   MAX_BODY = 64 * 1024
   ...
       length = int(self.headers.get("Content-Length", 0) or 0)
       if length > MAX_BODY:
           self._html(413, "<h1>413: слишком большой запрос</h1>")
           return None
   ```

3. Сервер не записывает присланные данные в файловую систему и не исполняет
   файлы; отдаются только статические файлы из белого списка (см. раздел 5).

**Проверка.** Запрос `multipart/form-data` с файлом возвращает 415; тело больше
64 КБ — 413.

---

## Итоговая таблица

| Уязвимость | Метод защиты | Где в коде |
|------------|--------------|------------|
| XSS | Экранирование вывода + CSP `script-src 'none'` | `views.html_escape`, `server._security_headers` |
| Information Disclosure | Обработчик ошибок без трассировок, скрытие версии, хеш паролей | `server._dispatch`, `Handler.server_version`, `security.hash_password` |
| SQL Injection | Параметризованные запросы, приведение id к int | `db.py`, `server._to_int` |
| CSRF | Double-submit CSRF-токен + `SameSite` cookie | `security.csrf_valid`, `server._check_csrf`, `views._csrf_field` |
| Include / Path Traversal | Белый список статики + проверка `realpath` | `server.STATIC_FILES`, `server._serve_static` |
| Upload | Отказ от `multipart`, лимит размера тела, нет записи файлов | `server._read_form`, `MAX_BODY` |
