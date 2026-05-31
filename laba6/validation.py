import re
from datetime import date

ALLOWED_LANGUAGES = {
    "pascal", "c", "cpp", "javascript", "php",
    "python", "java", "haskell", "clojure", "prolog", "scala", "go",
}


def validate(data, require_contract=True):
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
