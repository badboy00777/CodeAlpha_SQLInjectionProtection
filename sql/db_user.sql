-- Layer 2: least-privilege DB user (letters and numbers only password).
-- No UPDATE, DELETE, DROP, FILE, ALTER: even a successful injection cannot destroy data.
CREATE USER IF NOT EXISTS 'sqli_app'@'localhost' IDENTIFIED BY 'ChangeMe12345Only';
GRANT SELECT, INSERT ON sqli_protection.users TO 'sqli_app'@'localhost';
GRANT SELECT, INSERT ON sqli_protection.notes TO 'sqli_app'@'localhost';
GRANT SELECT, INSERT ON sqli_protection.used_tokens TO 'sqli_app'@'localhost';
GRANT SELECT, INSERT ON sqli_protection.login_attempts TO 'sqli_app'@'localhost';
FLUSH PRIVILEGES;