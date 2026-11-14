QUERIES = {
    "user_insert": "INSERT INTO users (username, email_enc, password_hash) VALUES (%s, %s, %s)",
    "user_by_name": "SELECT id, username, password_hash FROM users WHERE username = %s",
    "attempts_count": (
        "SELECT COUNT(*) AS n FROM login_attempts "
        "WHERE username = %s AND ip = %s AND attempted_at > (NOW() - INTERVAL 10 MINUTE)"
    ),
    "attempt_insert": "INSERT INTO login_attempts (username, ip) VALUES (%s, %s)",
    "token_use": "INSERT INTO used_tokens (jti) VALUES (%s)",
    # capability scope -> query
    "profile:read": "SELECT username, email_enc FROM users WHERE id = %s",
    "notes:read": "SELECT id, content_enc, created_at FROM notes WHERE user_id = %s ORDER BY id DESC LIMIT 50",
    "notes:write": "INSERT INTO notes (user_id, content_enc) VALUES (%s, %s)",
}


def get_query(name):
    if name not in QUERIES:
        raise KeyError("Query not allowed")
    return QUERIES[name]