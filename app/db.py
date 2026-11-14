import pymysql
from pymysql.cursors import DictCursor

from app.config import get_settings


def get_connection():
    s = get_settings()
    return pymysql.connect(
        host=s["DB_HOST"],
        port=s["DB_PORT"],
        user=s["DB_USER"],
        password=s["DB_PASSWORD"],
        database=s["DB_NAME"],
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=False,   
        connect_timeout=5,
    )