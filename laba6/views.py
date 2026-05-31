LANGUAGES = [
    ("pascal", "Pascal"), ("c", "C"), ("cpp", "C++"),
    ("javascript", "JavaScript"), ("php", "PHP"), ("python", "Python"),
    ("java", "Java"), ("haskell", "Haskell"), ("clojure", "Clojure"),
    ("prolog", "Prolog"), ("scala", "Scala"), ("go", "Go"),
]
LANGUAGE_LABELS = dict(LANGUAGES)


def html_escape(s):
    return (str(s).replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace('"', "&quot;"))


def _page(title, body):
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html_escape(title)}</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <div class="form-container">
{body}
  </div>
</body>
</html>""".encode("utf-8")


def render_form(values, errors, user=None):

    def v(field):
        return html_escape(values.get(field, ""))

    def err_class(field):
        return " field-error" if errors.get(field) else ""

    def err_msg(field):
        msg = errors.get(field, "")
        return f'<span class="error-msg">{html_escape(msg)}</span>' if msg else ""

    def opt_selected(lang):
        langs = values.get("languages", [])
        if isinstance(langs, str):
            langs = [x for x in langs.split(",") if x]
        return " selected" if lang in langs else ""

    def radio_checked(val):
        return " checked" if values.get("gender") == val else ""

    options = "\n".join(
        f'          <option value="{val}"{opt_selected(val)}>{label}</option>'
        for val, label in LANGUAGES
    )

    if user:
        header = f"""    <div class="auth-banner">
      <span>Вы вошли как <strong>{html_escape(user['login'])}</strong></span>
      <form action="/logout" method="post" style="margin:0">
        <button type="submit" class="btn-logout">Выйти</button>
      </form>
    </div>"""
        title = "Редактирование данных"
        submit_label = "Сохранить изменения"
        contract_block = """      <div class="form-group checkbox-group">
        <label>
          <input type="checkbox" name="contract" id="contract" checked>
          С контрактом ознакомлен(а)
        </label>
      </div>"""
    else:
        header = """    <div class="auth-banner">
      <span>Уже есть логин и пароль?</span>
      <a href="/login" class="btn-logout" style="text-decoration:none">Войти</a>
    </div>"""
        title = "Регистрационная форма"
        submit_label = "Сохранить"
        contract_block = f"""      <div class="form-group checkbox-group{err_class("contract")}">
        {err_msg("contract")}
        <label>
          <input type="checkbox" name="contract" id="contract" required>
          С контрактом ознакомлен(а)
        </label>
      </div>"""

    body = f"""{header}
    <h1>{title}</h1>

    <form action="/submit" method="post">

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
{options}
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

    </form>"""
    return _page(title, body)


def render_success(login, password):
    body = f"""    <h1>Данные успешно сохранены!</h1>
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
    </a>"""
    return _page("Регистрация завершена", body)


def render_login(error=""):
    error_html = f'<div class="alert-error">{html_escape(error)}</div>' if error else ""
    body = f"""    <h1>Вход</h1>
    {error_html}
    <form action="/login" method="post">
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
    </p>"""
    return _page("Вход", body)


def render_admin(users, stats, message=""):
    msg_html = f'<div class="alert-success">{html_escape(message)}</div>' if message else ""

    stat_rows = "".join(
        f"""      <div class="stat-row">
        <span>{html_escape(LANGUAGE_LABELS.get(row["language"], row["language"]))}</span>
        <span class="stat-count">{row["cnt"]}</span>
      </div>\n"""
        for row in stats
    ) or '      <p class="hint">Пока нет данных.</p>\n'

    if users:
        user_rows = "".join(
            f"""        <tr>
          <td>{u["id"]}</td>
          <td>{html_escape(u["login"])}</td>
          <td>{html_escape(u["fullname"])}</td>
          <td>{html_escape(u["phone"])}</td>
          <td>{html_escape(u["email"])}</td>
          <td>{html_escape(u["birthdate"])}</td>
          <td>{"М" if u["gender"] == "male" else "Ж"}</td>
          <td>{html_escape(", ".join(LANGUAGE_LABELS.get(l, l) for l in u["languages"]))}</td>
          <td>{html_escape(u["bio"])}</td>
          <td class="row-actions">
            <a class="btn-mini" href="/admin/edit?id={u["id"]}">✎</a>
            <form action="/admin/delete" method="post" onsubmit="return confirm('Удалить пользователя #{u["id"]}?')">
              <input type="hidden" name="id" value="{u["id"]}">
              <button type="submit" class="btn-mini btn-mini-danger">🗑</button>
            </form>
          </td>
        </tr>\n"""
            for u in users
        )
        table = f"""    <div class="table-wrap">
      <table class="admin-table">
        <thead>
          <tr>
            <th>ID</th><th>Логин</th><th>ФИО</th><th>Телефон</th><th>E-mail</th>
            <th>Дата рожд.</th><th>Пол</th><th>Языки</th><th>Биография</th><th></th>
          </tr>
        </thead>
        <tbody>
{user_rows}        </tbody>
      </table>
    </div>"""
    else:
        table = '    <p class="hint">Пользователей пока нет.</p>'

    body = f"""    <div class="admin-head">
      <h1>Панель администратора</h1>
      <span class="hint">Всего пользователей: {len(users)}</span>
    </div>
    {msg_html}

    <h2 class="section-title">Статистика по языкам</h2>
    <div class="stats">
{stat_rows}    </div>

    <h2 class="section-title">Пользователи</h2>
{table}"""
    return _page("Панель администратора", body)


def render_admin_edit(user, errors=None):
    errors = errors or {}

    def v(field):
        return html_escape(user.get(field, ""))

    def err_msg(field):
        msg = errors.get(field, "")
        return f'<span class="error-msg">{html_escape(msg)}</span>' if msg else ""

    def err_class(field):
        return " field-error" if errors.get(field) else ""

    def opt_selected(lang):
        return " selected" if lang in user.get("languages", []) else ""

    def radio_checked(val):
        return " checked" if user.get("gender") == val else ""

    options = "\n".join(
        f'          <option value="{val}"{opt_selected(val)}>{label}</option>'
        for val, label in LANGUAGES
    )

    body = f"""    <div class="admin-head">
      <h1>Редактирование #{user["id"]}</h1>
      <a href="/admin" class="btn-logout" style="text-decoration:none">← К списку</a>
    </div>

    <form action="/admin/edit" method="post">
      <input type="hidden" name="id" value="{user["id"]}">

      <div class="form-group">
        <label for="fullname">ФИО</label>
        {err_msg("fullname")}
        <input type="text" id="fullname" name="fullname" class="input-field{err_class("fullname")}" value="{v("fullname")}" required>
      </div>

      <div class="form-group">
        <label for="phone">Телефон</label>
        {err_msg("phone")}
        <input type="tel" id="phone" name="phone" class="input-field{err_class("phone")}" value="{v("phone")}" required>
      </div>

      <div class="form-group">
        <label for="email">E-mail</label>
        {err_msg("email")}
        <input type="email" id="email" name="email" class="input-field{err_class("email")}" value="{v("email")}" required>
      </div>

      <div class="form-group">
        <label for="birthdate">Дата рождения</label>
        {err_msg("birthdate")}
        <input type="date" id="birthdate" name="birthdate" class="input-field{err_class("birthdate")}" value="{v("birthdate")}" required>
      </div>

      <div class="form-group">
        <label>Пол</label>
        {err_msg("gender")}
        <div class="radio-group{err_class("gender")}">
          <label><input type="radio" name="gender" value="male"{radio_checked("male")} required> Мужской</label>
          <label><input type="radio" name="gender" value="female"{radio_checked("female")}> Женский</label>
        </div>
      </div>

      <div class="form-group">
        <label for="languages">Языки</label>
        {err_msg("languages")}
        <select id="languages" name="abilities[]" multiple="multiple">
{options}
        </select>
      </div>

      <div class="form-group">
        <label for="bio">Биография</label>
        {err_msg("bio")}
        <textarea id="bio" name="bio" class="{("field-error" if errors.get("bio") else "")}">{v("bio")}</textarea>
      </div>

      <button type="submit" class="btn-save">Сохранить</button>
    </form>"""
    return _page(f"Редактирование #{user['id']}", body)
