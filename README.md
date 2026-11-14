# CodeAlpha_SQLInjectionProtection

CodeAlpha Cloud Computing Internship, Task 2: Detecting Data Leaks Using SQL Injection.
Intern: Muhammad Akram (CA/DF1/323730)

## What it does
A small cloud app (Flask + MySQL on AWS EC2 + private RDS) that stores user data safely and resists SQL injection.

## Double-layer security
| Layer | Defense |
|-------|---------|
| 1. Application | Strict input allowlists, signed capability tokens, prepared statements only (query allowlist) |
| 2. Database | Least-privilege DB user (SELECT and INSERT only) + AES-256-GCM encrypted columns + bcrypt password hashes |

## Capability code
The client never sends SQL. After login it receives a short-lived signed token (HMAC-SHA256) for exactly one scope (`profile:read`, `notes:read`, `notes:write`). The server maps the scope to a pre-written prepared query. Write tokens are one-time use, so a stolen token cannot be replayed.

## Also included
- Rate limiting: 5 failed logins lock a user for 10 minutes.
- Local-only vulnerable demo (`app/vulnerable_demo.py`) to show a real attack. It is off by default and is NEVER deployed to AWS.
- 63 automated tests (union, comment, boolean, time-based and stacked payloads).

## Run locally (Windows)
1. `python -m venv .venv` then `.venv\Scripts\activate`
2. `pip install -r requirements.txt`
3. Start MySQL (XAMPP), then run `sql/schema.sql` and `sql/db_user.sql`
4. Copy `.env.example` to `.env` and fill the AES key and capability secret
5. `python -m pytest -q` then `python wsgi.py` and open http://127.0.0.1:5000

## Project structure
`app/` backend and UI, `tests/` automated tests, `sql/` schema and DB user, `problem_statement.md` requirements mapped to code.

## Known limitations
Single server, in-database rate limiting, demo-scale project.