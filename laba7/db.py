import os
import sqlite3
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
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

            CREATE TABLE IF NOT EXISTS admins (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                login         TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def generate_unique_login(conn):
    while True:
        login = "user_" + secrets.token_hex(4)
        if conn.execute("SELECT 1 FROM users WHERE login = ?", (login,)).fetchone() is None:
            return login


def _fields(data):
    return (
        data["fullname"][0].strip(),
        data["phone"][0].strip(),
        data["email"][0].strip(),
        data["birthdate"][0].strip(),
        data["gender"][0].strip(),
        data["bio"][0].strip(),
        [lang.strip().lower() for lang in data.get("abilities[]", [])],
    )


def _save_languages(conn, user_id, languages):
    conn.execute("DELETE FROM user_languages WHERE user_id = ?", (user_id,))
    for lang in languages:
        conn.execute(
            "INSERT INTO user_languages (user_id, language) VALUES (?, ?)",
            (user_id, lang),
        )


def insert_user(data, password_hash):
    fio, phone, email, birthdate, gender, bio, languages = _fields(data)
    conn = get_conn()
    try:
        login = generate_unique_login(conn)
        cur = conn.execute(
            """
            INSERT INTO users (login, password_hash, fio, phone, email, birthdate, gender, biography)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (login, password_hash, fio, phone, email, birthdate, gender, bio),
        )
        user_id = cur.lastrowid
        _save_languages(conn, user_id, languages)
        conn.commit()
        return user_id, login
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_user(user_id, data):
    fio, phone, email, birthdate, gender, bio, languages = _fields(data)
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
        _save_languages(conn, user_id, languages)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_user(user_id):
    conn = get_conn()
    try:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def _row_to_user(conn, row):
    langs = [
        r["language"]
        for r in conn.execute(
            "SELECT language FROM user_languages WHERE user_id = ?", (row["id"],)
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


def load_user(user_id):
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return _row_to_user(conn, row) if row else None
    finally:
        conn.close()


def get_all_users():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        return [_row_to_user(conn, row) for row in rows]
    finally:
        conn.close()


def get_user_by_login(login):
    conn = get_conn()
    try:
        return conn.execute("SELECT * FROM users WHERE login = ?", (login,)).fetchone()
    finally:
        conn.close()


def language_stats():
    conn = get_conn()
    try:
        return conn.execute(
            """
            SELECT language, COUNT(DISTINCT user_id) AS cnt
              FROM user_languages
             GROUP BY language
             ORDER BY cnt DESC, language
            """
        ).fetchall()
    finally:
        conn.close()


def get_admin_by_login(login):
    conn = get_conn()
    try:
        return conn.execute("SELECT * FROM admins WHERE login = ?", (login,)).fetchone()
    finally:
        conn.close()


def ensure_default_admin(login, password_hash):
    conn = get_conn()
    try:
        if conn.execute("SELECT COUNT(*) AS c FROM admins").fetchone()["c"] == 0:
            conn.execute(
                "INSERT INTO admins (login, password_hash) VALUES (?, ?)",
                (login, password_hash),
            )
            conn.commit()
            return True
        return False
    finally:
        conn.close()
