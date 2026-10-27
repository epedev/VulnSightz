"""
app.py

INTENTIONALLY VULNERABLE target application — built for the VulnSight
scanner to have something real to scan. Every vulnerability below is
deliberate and documented in VULNERABILITIES.md with root cause,
exploitation, impact, detection, and the fix. Do not deploy this anywhere
reachable from the public internet. Run on localhost or an isolated lab
network only.
"""

import sqlite3
import subprocess
from flask import Flask, request, render_template, redirect, session, g

app = Flask(__name__)
app.secret_key = "dev-secret-not-for-production"  # intentionally weak — see VULNERABILITIES.md #7

DB_PATH = "target.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/")
def index():
    return render_template("index.html", user=session.get("username"))


# --- VULN 1: SQL injection in login (CWE-89) ----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABLE: raw string concatenation into a SQL query.
        # See VULNERABILITIES.md #1 for exploitation + fix.
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        db = get_db()
        cur = db.execute(query)
        user = cur.fetchone()

        if user:
            session["username"] = user["username"]
            session["user_id"] = user["id"]
            session["is_admin"] = bool(user["is_admin"])
            return redirect("/")
        error = "Invalid credentials"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# --- VULN 2: Reflected XSS in search (CWE-79) ----------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        db = get_db()
        # Parameterized here on purpose — the XSS is in the reflection back
        # into the page, not in the query. Keeps this a single-vuln-class
        # demo per field instead of stacking two bug classes in one route.
        cur = db.execute("SELECT title FROM articles WHERE title LIKE ?", (f"%{q}%",))
        results = [row["title"] for row in cur.fetchall()]

    # VULNERABLE: `q` is rendered back unescaped — see search.html's use of
    # |safe. See VULNERABILITIES.md #2.
    return render_template("search.html", query=q, results=results)


# --- VULN 3: Stored XSS in comments (CWE-79) ------------------------------
@app.route("/comments", methods=["GET", "POST"])
def comments():
    db = get_db()
    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        body = request.form.get("body", "")
        # VULNERABLE: stored without sanitization, rendered with |safe in
        # comments.html. See VULNERABILITIES.md #3.
        db.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        db.commit()
        return redirect("/comments")

    cur = db.execute("SELECT author, body FROM comments ORDER BY id DESC")
    return render_template("comments.html", comments=cur.fetchall())


# --- VULN 4: IDOR on user profiles (CWE-639) ------------------------------
@app.route("/profile/<int:user_id>")
def profile(user_id):
    # VULNERABLE: no check that the requester is authenticated as this
    # user, or authenticated at all. Any user_id is viewable by anyone.
    # See VULNERABILITIES.md #4.
    db = get_db()
    cur = db.execute("SELECT id, username, email, bio FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if not user:
        return "User not found", 404
    return render_template("profile.html", profile=user)


# --- VULN 5: Broken access control on admin panel (CWE-284/285) ----------
@app.route("/admin")
def admin():
    # VULNERABLE: checks that *a* session exists but never checks
    # session["is_admin"]. Any logged-in user reaches the admin panel.
    # See VULNERABILITIES.md #5.
    if "username" not in session:
        return redirect("/login")
    db = get_db()
    users = db.execute("SELECT id, username, email, is_admin FROM users").fetchall()
    return render_template("admin.html", users=users)


# --- VULN 6: OS command injection in diagnostic ping (CWE-78) ------------
@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = None
    if request.method == "POST":
        host = request.form.get("host", "")
        # VULNERABLE: shell=True with unsanitized user input concatenated
        # into the command string. See VULNERABILITIES.md #6.
        try:
            output = subprocess.check_output(
                f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=5
            ).decode(errors="replace")
        except Exception as e:
            output = str(e)
    return render_template("ping.html", output=output)


# --- Recon surface for the crawler: robots.txt / sitemap.xml -------------
@app.route("/robots.txt")
def robots():
    return (
        "User-agent: *\nDisallow: /admin\nDisallow: /ping\n",
        200,
        {"Content-Type": "text/plain"},
    )


@app.route("/sitemap.xml")
def sitemap():
    base = request.host_url.rstrip("/")
    urls = ["/", "/login", "/search", "/comments", "/profile/1"]
    body = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for u in urls:
        body += f"  <url><loc>{base}{u}</loc></url>\n"
    body += "</urlset>"
    return body, 200, {"Content-Type": "application/xml"}


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5001)
