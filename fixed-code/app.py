"""
VitaBank — Sample Internal Banking Portal (REMEDIATED)
===========================================================

This is the fixed version of audit-target/app.py, addressing every finding
documented in docs/AUDIT_REPORT.md. Inline comments reference the
corresponding VULN-## / finding number so the two files can be diffed
side by side.

Note: this remains a *sample/teaching* application. A production banking
system would additionally need MFA, rate limiting, structured logging with
SIEM integration, dependency scanning in CI, and a real secrets manager
(e.g. HashiCorp Vault / AWS Secrets Manager) rather than an env var alone.
"""

import os
import sqlite3
import secrets
from functools import wraps

from flask import Flask, request, redirect, session, abort, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

# --- FIX for VULN-01: secret loaded from environment, never hardcoded ---
app.secret_key = os.environ.get("VITABANK_SECRET_KEY") or secrets.token_hex(32)
if not os.environ.get("VITABANK_SECRET_KEY"):
    app.logger.warning(
        "VITABANK_SECRET_KEY not set — using a random ephemeral key. "
        "Sessions will not persist across restarts. Set this env var in production."
    )

# --- FIX for VULN-07: CSRF protection enabled globally ---
csrf = CSRFProtect(app)

DB_PATH = os.environ.get("VITABANK_DB_PATH", "vitabank.db")
STATEMENTS_DIR = os.path.abspath("statements")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            balance REAL DEFAULT 1000.0,
            is_admin INTEGER DEFAULT 0
        )
    """)
    # --- FIX for VULN-02: salted, adaptive password hashing (werkzeug/PBKDF2) ---
    admin_password = os.environ.get("VITABANK_ADMIN_BOOTSTRAP_PASSWORD")
    if admin_password:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            ("admin", generate_password_hash(admin_password), 1),
        )
    conn.commit()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # --- FIX for VULN-05: real authentication check, no user_id override ---
        if "user_id" not in session:
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # --- FIX for VULN-09: proper access control on admin routes ---
        if "user_id" not in session:
            return redirect("/login")
        conn = get_db()
        user = conn.execute(
            "SELECT is_admin FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        conn.close()
        if not user or not user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # --- FIX for VULN-03: parameterized query, no string concatenation ---
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        # --- FIX for VULN-02: verify against salted hash ---
        # --- FIX for VULN-04: identical generic error regardless of failure reason ---
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/dashboard")

        return render_template("login.html", error="Invalid username or password."), 401

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    conn.close()

    # --- FIX for VULN-06: render_template with autoescaping instead of
    #     render_template_string + f-string (Jinja2 autoescapes by default
    #     when loading from a template *file*, closing the XSS vector) ---
    return render_template("dashboard.html", user=user)


@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    to_username = request.form["to_username"]

    try:
        amount = float(request.form["amount"])
    except (ValueError, TypeError):
        abort(400)

    if amount <= 0:
        abort(400, description="Transfer amount must be positive.")

    from_id = session["user_id"]

    conn = get_db()
    try:
        # --- FIX for VULN-03b: parameterized queries + real transaction ---
        with conn:
            sender = conn.execute(
                "SELECT balance FROM users WHERE id = ?", (from_id,)
            ).fetchone()
            if sender is None or sender["balance"] < amount:
                abort(400, description="Insufficient funds.")

            recipient = conn.execute(
                "SELECT id FROM users WHERE username = ?", (to_username,)
            ).fetchone()
            if recipient is None:
                abort(404, description="Recipient not found.")

            conn.execute(
                "UPDATE users SET balance = balance - ? WHERE id = ?",
                (amount, from_id),
            )
            conn.execute(
                "UPDATE users SET balance = balance + ? WHERE id = ?",
                (amount, recipient["id"]),
            )
    finally:
        conn.close()

    return redirect("/dashboard")


@app.route("/download")
@login_required
def download():
    # --- FIX for VULN-08: filename resolved and validated against an
    #     allow-listed base directory, blocking path traversal (../) ---
    filename = request.args.get("file", "statement.txt")
    requested_path = os.path.abspath(os.path.join(STATEMENTS_DIR, filename))

    if not requested_path.startswith(STATEMENTS_DIR + os.sep):
        abort(400, description="Invalid file path.")

    if not os.path.isfile(requested_path):
        abort(404)

    with open(requested_path, "r") as f:
        return f.read()


@app.route("/admin/users")
@admin_required
def admin_users():
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, balance, is_admin FROM users"
    ).fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)


if __name__ == "__main__":
    init_db()
    # --- FIX for VULN-10: debug mode driven by explicit env var, defaults
    #     to False; never bind 0.0.0.0 by default ---
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    app.run(debug=debug_mode, host=host)
