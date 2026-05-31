import base64
import hashlib
import hmac
import secrets
import string
from urllib.parse import unquote

import db

PBKDF2_ITERATIONS = 200_000

SESSIONS = {}
SESSION_COOKIE = "session_id"


def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password, stored):
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


def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits + "!@#$%*-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def parse_cookies(header):
    result = {}
    if not header:
        return result
    for part in header.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = unquote(v.strip())
    return result


def create_session(user_id):
    sid = secrets.token_urlsafe(32)
    SESSIONS[sid] = user_id
    return sid


def get_session_user(cookies):
    sid = cookies.get(SESSION_COOKIE)
    if sid and sid in SESSIONS:
        return SESSIONS[sid]
    return None


def destroy_session(cookies):
    sid = cookies.get(SESSION_COOKIE)
    if sid:
        SESSIONS.pop(sid, None)


CSRF_COOKIE = "csrf_token"


def generate_csrf_token():
    return secrets.token_urlsafe(32)


def csrf_valid(cookies, form):
    cookie_token = cookies.get(CSRF_COOKIE, "")
    form_token = (form.get("csrf_token", [""]) or [""])[0]
    if not cookie_token or not form_token:
        return False
    return hmac.compare_digest(cookie_token, form_token)


def parse_basic_auth(header):
    if not header or not header.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(header[6:]).decode("utf-8")
        login, password = decoded.split(":", 1)
        return login, password
    except (ValueError, UnicodeDecodeError):
        return None


def check_admin(header):
    creds = parse_basic_auth(header)
    if not creds:
        return False
    login, password = creds
    row = db.get_admin_by_login(login)
    return bool(row and verify_password(password, row["password_hash"]))
