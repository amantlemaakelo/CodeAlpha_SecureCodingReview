"""
VitaBank — Sample Internal Banking Portal (AUDIT TARGET)
===========================================================

*** THIS CODE IS INTENTIONALLY VULNERABLE ***

This is a small Flask application built specifically to serve as the
subject of a secure code review (CodeAlpha Cyber Security Task 3). It
simulates a simplified internal banking/transaction portal — the kind of
lightweight internal tool that often gets built quickly and skips security
review, which is exactly why it's a realistic and useful audit subject.

Do not deploy this application anywhere. See docs/AUDIT_REPORT.md for the
full list of vulnerabilities identified in this file, and fixed-code/app.py
for the remediated version.
"""

import sqlite3
import hashlib
import os
from flask import Flask, request, redirect, session, render_template_string

app = Flask(__name__)

# --- VULN-01: Hardcoded secret key -----------------------------------------
app.secret_key = "vitabank123"

DB_PATH = "vitabank.db"


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
            password TEXT,
            balance REAL DEFAULT 1000.0,
            is_admin INTEGER DEFAULT 0
        )
    """)
    # --- VULN-02: Weak password hashing (unsalted MD5) ---
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        ("admin", hashlib.md5(b"admin123").hexdigest(), 1),
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # --- VULN-03: SQL Injection (string concatenation in query) ---
        conn = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashlib.md5(password.encode()).hexdigest()}'"
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/dashboard")
        else:
            # --- VULN-04: Verbose error leaks whether username exists ---
            return f"Login failed for user '{username}'. Check your credentials."

    return """
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit">
        </form>
    """


@app.route("/dashboard")
def dashboard():
    # --- VULN-05: Missing authentication check (broken access control) ---
    user_id = session.get("user_id", request.args.get("user_id"))

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if not user:
        return "User not found", 404

    # --- VULN-06: Reflected XSS via unescaped template rendering ---
    greeting = request.args.get("name", user["username"])
    return render_template_string(f"""
        <h1>Welcome, {greeting}!</h1>
        <p>Balance: ${user['balance']}</p>
        <a href="/transfer">Transfer funds</a>
    """)


@app.route("/transfer", methods=["POST"])
def transfer():
    # --- VULN-07: No CSRF protection on a state-changing financial action ---
    from_id = session.get("user_id")
    to_username = request.form["to_username"]
    amount = float(request.form["amount"])

    conn = get_db()
    # --- VULN-03b: SQL Injection here too ---
    conn.execute(f"UPDATE users SET balance = balance - {amount} WHERE id = {from_id}")
    conn.execute(f"UPDATE users SET balance = balance + {amount} WHERE username = '{to_username}'")
    conn.commit()
    conn.close()
    return redirect("/dashboard")


@app.route("/download")
def download():
    # --- VULN-08: Path traversal via unsanitized filename parameter ---
    filename = request.args.get("file", "statement.txt")
    filepath = os.path.join("statements", filename)
    with open(filepath, "r") as f:
        return f.read()


@app.route("/admin/users")
def admin_users():
    # --- VULN-09: Broken access control - no admin check at all ---
    conn = get_db()
    users = conn.execute("SELECT id, username, balance, is_admin FROM users").fetchall()
    conn.close()
    return "<br>".join(f"{u['id']} | {u['username']} | ${u['balance']} | admin={u['is_admin']}" for u in users)


if __name__ == "__main__":
    init_db()
    # --- VULN-10: Debug mode enabled in what could be mistaken for production ---
    app.run(debug=True, host="0.0.0.0")
