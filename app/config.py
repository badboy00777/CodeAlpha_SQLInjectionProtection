import base64
import os


def load_dotenv(path=".env"):
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def get_settings():
    load_dotenv()
    key_b64 = os.environ.get("AES_KEY_B64", "")
    return {
        "DB_HOST": os.environ.get("DB_HOST", "127.0.0.1"),
        "DB_PORT": int(os.environ.get("DB_PORT", "3306")),
        "DB_NAME": os.environ.get("DB_NAME", "sqli_protection"),
        "DB_USER": os.environ.get("DB_USER", "sqli_app"),
        "DB_PASSWORD": os.environ.get("DB_PASSWORD", ""),
        "AES_KEY": base64.b64decode(key_b64) if key_b64 else b"",
        "CAPABILITY_SECRET": os.environ.get("CAPABILITY_SECRET", ""),
        "CAPABILITY_TTL": int(os.environ.get("CAPABILITY_TTL_SECONDS", "300")),
    }