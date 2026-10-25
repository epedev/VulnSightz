"""
init_db.py — creates target.db with seed data. Run once before starting app.py.
Re-run any time to reset state (it drops and recreates tables).
"""
import sqlite3

conn = sqlite3.connect("target.db")
c = conn.cursor()

c.executescript(
    """
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS articles;
    DROP TABLE IF EXISTS comments;

    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        bio TEXT,
        is_admin INTEGER DEFAULT 0
    );

    CREATE TABLE articles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT
    );

    CREATE TABLE comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author TEXT,
        body TEXT
    );
    """
)

c.executemany(
    "INSERT INTO users (username, password, email, bio, is_admin) VALUES (?, ?, ?, ?, ?)",
    [
        ("alice", "alice123", "alice@target.local", "Just a regular user.", 0),
        ("bob", "bobpass", "bob@target.local", "Bob's profile.", 0),
        ("admin", "SuperSecret99!", "admin@target.local", "Site administrator.", 1),
    ],
)

c.executemany(
    "INSERT INTO articles (title, body) VALUES (?, ?)",
    [
        ("Welcome to the target app", "This is a deliberately vulnerable demo app."),
        ("How crawlers discover endpoints", "Links, forms, robots.txt, sitemap.xml..."),
        ("SQL injection basics", "Never concatenate user input into queries."),
    ],
)

conn.commit()
conn.close()
print("[+] target.db initialized with seed data.")
