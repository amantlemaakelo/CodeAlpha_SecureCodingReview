# Secure Code Review — VitaBank Sample Banking Portal

| | |
|---|---|
| **Auditor** | Amantle Maakelo |
| **Date** | August 2026 |
| **Application** | VitaBank — internal Flask-based transaction portal (sample) |
| **Language / Framework** | Python 3.12 / Flask |
| **Lines of code reviewed** | 103 (audit-target/app.py) |
| **Methodology** | Manual line-by-line review (OWASP Top 10 lens) + automated static analysis (Bandit v1.9.4) |
| **Repo scope** | `audit-target/app.py` (as-found) → `fixed-code/app.py` (remediated) |

## 1. Purpose & scope

This report documents a secure code review of **VitaBank**, a small
internal banking/transaction portal built as the audit subject for
CodeAlpha's Cyber Security Task 3. The application was **deliberately
built with realistic vulnerabilities** representative of what appears in
quickly-shipped internal financial tools — the review process, findings,
and remediation shown here reflect a genuine audit workflow, not a
contrived exercise.

The scope covers authentication, session handling, financial transaction
logic, file access, and access control — the areas most relevant to a
banking/financial-services application and the areas most commonly cited
in real-world breach post-mortems.

## 2. Methodology

1. **Manual review** of every route handler against the OWASP Top 10
   (2021) categories, with particular attention to injection, broken
   access control, and cryptographic failures — the categories most
   relevant to a financial application.
2. **Automated static analysis** using [Bandit](https://bandit.readthedocs.io/),
   a security linter for Python, to cross-check manual findings and catch
   anything missed. Raw tool output: [`bandit_raw_output.txt`](bandit_raw_output.txt).
3. **Remediation** of every confirmed finding in `fixed-code/app.py`,
   followed by a **re-scan** to verify the fix (`bandit_fixed_output.txt`) —
   the re-scan came back clean (0 issues), giving verifiable evidence the
   fixes work rather than just asserting they do.

## 3. Summary of findings

| # | Finding | Severity | CWE | OWASP Top 10 (2021) | Status |
|---|---|---|---|---|---|
| 1 | Hardcoded secret key | Medium | CWE-798 | A02: Cryptographic Failures | Fixed |
| 2 | Weak, unsalted password hashing (MD5) | High | CWE-327 | A02: Cryptographic Failures | Fixed |
| 3 | SQL Injection (login + transfer) | Critical | CWE-89 | A03: Injection | Fixed |
| 4 | Verbose authentication error (username enumeration) | Low | CWE-203 | A07: Identification & Auth Failures | Fixed |
| 5 | Broken access control — client-controlled `user_id` | Critical | CWE-284 | A01: Broken Access Control | Fixed |
| 6 | Reflected XSS via unescaped template string | High | CWE-79 | A03: Injection | Fixed |
| 7 | Missing CSRF protection on fund transfer | High | CWE-352 | A01: Broken Access Control | Fixed |
| 8 | Path traversal on file download endpoint | High | CWE-22 | A01: Broken Access Control | Fixed |
| 9 | Missing authorization on admin endpoint | Critical | CWE-862 | A01: Broken Access Control | Fixed |
| 10 | Debug mode + all-interfaces binding | High | CWE-489 / CWE-605 | A05: Security Misconfiguration | Fixed |

**10 findings — 3 Critical, 5 High, 1 Medium, 1 Low. All 10 remediated and re-verified.**

---

## 4. Detailed findings

### Finding 1 — Hardcoded secret key
**Location:** `app.py:20` — `app.secret_key = "vitabank123"`
**Risk:** Flask's `secret_key` signs session cookies. A hardcoded, guessable
key lets an attacker forge valid session cookies for any user, including
admins, without ever touching the database.
**Fix:** Load the key from an environment variable, generated with
`secrets.token_hex(32)` and never committed to source control (`fixed-code/app.py:23-27`).

### Finding 2 — Weak password hashing
**Location:** `app.py:46, 65` — unsalted MD5
**Risk:** MD5 is cryptographically broken and fast to brute-force;
unsalted hashes are also trivially crackable via rainbow tables. Bandit
independently flagged this as **High severity** (CWE-327).
**Fix:** Replaced with `werkzeug.security.generate_password_hash` /
`check_password_hash`, which uses a salted, adaptive (PBKDF2) hash.

### Finding 3 — SQL Injection
**Location:** `app.py:65` (login), `app.py:116-117` (transfer)
**Risk:** User input is concatenated directly into SQL strings. An
attacker could submit `' OR '1'='1` as a username to bypass authentication
entirely, or manipulate the transfer query to move funds between
arbitrary accounts. Bandit flagged both instances (CWE-89).
**Fix:** All queries rewritten to use parameterized queries (`?`
placeholders) — the standard, framework-supported defense against SQL
injection.

### Finding 4 — Verbose authentication error
**Location:** `app.py:75` — `f"Login failed for user '{username}'..."`
**Risk:** Echoing the submitted username back, combined with any
subtle difference in error behavior, can help an attacker enumerate valid
usernames as a precursor to credential-stuffing attacks.
**Fix:** Single generic error message ("Invalid username or password")
regardless of whether the username exists or the password was wrong.

### Finding 5 — Broken access control via client-controlled ID
**Location:** `app.py:87` — `session.get("user_id", request.args.get("user_id"))`
**Risk:** This is a **critical** flaw — if no session exists, the app falls
back to whatever `user_id` the client supplies in the URL. Anyone could
view any account's balance and details by simply changing a query
parameter (`/dashboard?user_id=1`), with zero authentication.
**Fix:** Replaced with a `login_required` decorator that hard-fails to a
login redirect if no valid session exists — the client can no longer
supply an identity.

### Finding 6 — Reflected XSS
**Location:** `app.py:96-99` — `render_template_string(f"...{greeting}...")`
**Risk:** The `name` query parameter is interpolated directly into HTML
without escaping. An attacker could craft a link containing
`<script>...</script>` and, combined with Finding 5, potentially exfiltrate
session data from any victim who clicks it.
**Fix:** Switched to `render_template()` with a proper Jinja2 template
file, where autoescaping is on by default — user-supplied values are
rendered as inert text, not executable HTML.

### Finding 7 — Missing CSRF protection
**Location:** `app.py:107` — `/transfer` POST endpoint
**Risk:** Without a CSRF token, an attacker can host a malicious page that
auto-submits a form to `/transfer` on a victim's behalf while they're
logged in, silently moving funds out of their account.
**Fix:** Added `flask-wtf`'s `CSRFProtect`, and templates now include
`{{ csrf_token() }}` in the transfer form.

### Finding 8 — Path traversal
**Location:** `app.py:126-130` — `/download?file=...`
**Risk:** The `file` parameter is joined into a path without validation.
A request like `/download?file=../../etc/passwd` (or, on this host,
any file readable by the process) could read arbitrary files outside
the intended `statements/` directory.
**Fix:** Resolve the requested path with `os.path.abspath()` and verify
it still falls inside the allow-listed base directory before opening it;
reject anything that escapes it.

### Finding 9 — Missing authorization on admin route
**Location:** `app.py:135-141` — `/admin/users`
**Risk:** This endpoint lists every user's balance and admin flag with
**no authentication or authorization check whatsoever** — the route is
reachable by anyone who knows the URL.
**Fix:** Added an `admin_required` decorator that verifies both an active
session and an `is_admin` flag before rendering the page; unauthorized
requests get a 403.

### Finding 10 — Debug mode & insecure bind address
**Location:** `app.py:145` — `app.run(debug=True, host="0.0.0.0")`
**Risk:** Flask's debug mode exposes the Werkzeug interactive debugger,
which allows **arbitrary remote code execution** if reachable — and
binding to `0.0.0.0` makes it reachable from any network interface.
Bandit flagged both as High/Medium severity.
**Fix:** Debug mode now defaults to `False` and is only enabled via an
explicit `FLASK_DEBUG` environment variable; default bind address is
`127.0.0.1` unless explicitly overridden.

---

## 5. Verification

Re-running Bandit against the remediated codebase confirms all findings
are resolved:

```
Run metrics:
    Total issues (by severity):
        Undefined: 0
        Low: 0
        Medium: 0
        High: 0
```

Full output: [`bandit_fixed_output.txt`](bandit_fixed_output.txt)

## 6. Recommendations beyond this scope

These weren't in scope for the code-level review but would be next steps
for a production banking system:
- Multi-factor authentication for login and high-value transfers
- Rate limiting / account lockout on repeated failed logins
- Structured audit logging (who did what, when) feeding a SIEM
- Dependency vulnerability scanning in CI (e.g. `pip-audit`, Dependabot)
- A managed secrets store (Vault / AWS Secrets Manager) instead of env vars
- Database-level least-privilege (the app's DB user should not be able to
  drop tables, for instance)

## 7. Conclusion

The as-found version of VitaBank contained ten distinct vulnerabilities,
including three critical-severity issues (SQL injection, broken access
control, and an unauthenticated admin panel) that would allow a low-skill
attacker to fully compromise user accounts and financial data. All ten
were remediated in `fixed-code/app.py` using framework-native, industry
-standard controls, and the fix was verified with an independent
automated re-scan rather than taken on faith.
