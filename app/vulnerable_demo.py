from flask import Blueprint, jsonify, request

from app.db import get_connection

vuln = Blueprint("vuln", __name__, url_prefix="/vulnerable")


def _run(sql):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            return cur.fetchall()
    finally:
        conn.close()


@vuln.get("/search")
def search():
    name = request.args.get("name", "")
    sql = "SELECT id, username, email_enc FROM users WHERE username = '" + name + "'"  # BAD ON PURPOSE
    try:
        return jsonify({"query": sql, "rows": _run(sql)})
    except Exception as exc:
        return jsonify({"query": sql, "error": str(exc)}), 500


@vuln.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    u, p = str(data.get("username", "")), str(data.get("password", ""))
    sql = ("SELECT id, username FROM users WHERE username = '" + u +
           "' AND password_hash = '" + p + "'")  # BAD ON PURPOSE
    try:
        rows = _run(sql)
        return jsonify({"query": sql, "logged_in": bool(rows), "rows": rows})
    except Exception as exc:
        return jsonify({"query": sql, "error": str(exc)}), 500