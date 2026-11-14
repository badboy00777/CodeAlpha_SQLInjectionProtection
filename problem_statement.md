# CodeAlpha Cloud Computing - Task 2: Detecting Data Leaks Using SQL Injection

Intern: Muhammad Akram (CA/DF1/323730) | Repo: CodeAlpha_SQLInjectionProtection

## 1. Task (as given by CodeAlpha)
1. Build a cloud system that secures user data against SQL injection attacks.
2. Use AES-256 encryption to securely store user credentials and sensitive info.
3. Implement a capability code mechanism to inject SQL securely and control server access.
4. Provide a double-layer security protocol to prevent data leaks via SQL injection.
5. Make the system accessible over the internet without heavy system requirements.

## 2. Our interpretation
- Capability code: a signed, short-lived token (HMAC-SHA256) tied to one user and one scope. The client never sends SQL. The server maps the scope to a pre-written prepared query.
- Double layer: Layer 1 = application (allowlist validation + capability token + prepared statements). Layer 2 = database (least-privilege DB user + AES-256-GCM encrypted columns).

## 3. Requirements and where they are met
| ID | Requirement | Implementation | File |
|----|-------------|----------------|------|
| R1 | Secure data against SQL injection | Prepared statements only, query allowlist | app/queries.py (Phase B) |
| R2 | AES-256 for credentials and sensitive info | AES-256-GCM random nonce; bcrypt for passwords | app/crypto.py, app/passwords.py |
| R3 | Capability code | Signed short-lived scope token | app/capability.py |
| R4 | Double-layer security | Validators + least-privilege DB user | app/validators.py, sql/db_user.sql |
| R5 | Internet accessible, light | Flask + gunicorn on EC2 t3.micro, private RDS | Phase C |

## 4. Extra
- Vulnerable demo endpoint (LOCAL ONLY, never deployed) to show attack vs defense.
- Automated tests for union, comment, boolean, time-based and stacked payloads.

## 5. Out of scope
Email sending, password reset, multi-region, load balancing.