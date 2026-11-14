import re


class ValidationError(ValueError):
    pass


USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")
NOTE_RE = re.compile(r"^[A-Za-z0-9 .,!?:@#()_\-]{1,500}$")

SUSPICIOUS = re.compile(
    r"(--|/\*|\*/|;|\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b|"
    r"\bsleep\s*\(|\bbenchmark\s*\(|\bor\b\s+\S+\s*=\s*\S+|\binformation_schema\b|\bxp_)",
    re.IGNORECASE,
)


def looks_like_sqli(value):
    return bool(SUSPICIOUS.search(value))


def _text(value):
    if not isinstance(value, str):
        raise ValidationError("Value must be text")
    return value.strip()


def validate_username(value):
    v = _text(value)
    if not USERNAME_RE.match(v) or looks_like_sqli(v):
        raise ValidationError("Username: 3-30 letters, numbers or underscore only")
    return v


def validate_email(value):
    v = _text(value)
    if not EMAIL_RE.match(v) or looks_like_sqli(v):
        raise ValidationError("Invalid email")
    return v.lower()


def validate_password(value):
    if not isinstance(value, str):
        raise ValidationError("Password must be text")
    if not (8 <= len(value) <= 64):
        raise ValidationError("Password must be 8-64 characters")
    if not (re.search(r"[A-Za-z]", value) and re.search(r"\d", value)):
        raise ValidationError("Password needs letters and numbers")
    return value  # never trimmed, never logged; bcrypt makes it safe


def validate_note(value):
    v = _text(value)
    if not NOTE_RE.match(v) or looks_like_sqli(v):
        raise ValidationError("Note: 1-500 chars, letters, numbers and basic punctuation only")
    return v