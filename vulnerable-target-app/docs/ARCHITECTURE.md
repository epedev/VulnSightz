# Architecture and code map

## Overview

The project is a small Flask application backed by SQLite. `app.py` defines the HTTP routes, reads form/query/path parameters, calls the database or system `ping` command, and renders Jinja2 templates. `init_db.py` creates the tables and inserts predictable sample records. The `templates/` directory contains the page markup; `static/style.css` provides presentation only.

## Main components

- **`app.py`** — Flask app configuration, session handling, database connection lifecycle, and routes.
- **`init_db.py`** — destructive database initializer. It drops and recreates `users`, `articles`, and `comments`.
- **`target.db`** — SQLite database generated locally by the initializer.
- **`templates/`** — Jinja2 templates for the home page and each feature.
- **`static/style.css`** — visual styling; CSS does not change the security behavior of the routes.
- **`VULNERABILITIES.md`** — finding-by-finding explanation of intended flaws, impact, detection, and fixes.

## Request flow

1. A browser or test client sends a request to a Flask route.
2. The route reads the relevant input from a query parameter, form field, or URL path.
3. The route may query SQLite, execute a system command, or read session state.
4. Flask renders a template or returns a direct response.
5. The deliberately unsafe code paths demonstrate how untrusted input or missing authorization checks can affect the result.

## Data model

- **`users`**: numeric ID, username, plaintext demo password, email, bio, and admin flag.
- **`articles`**: article title and body used by search.
- **`comments`**: author and comment body, including values submitted through the comments form.

The seed data is intended to make scanner output reproducible. Do not use personal or sensitive information in this lab.

## Important implementation notes

- The app uses a fixed secret key and debug mode intentionally for training. Never expose this configuration to untrusted networks.
- SQLite access is opened lazily per Flask application context and closed during teardown.
- The search route uses a parameterized database query; its intended XSS issue is in rendering the query back to the page, not in the SQL statement.
- The `/ping` route invokes a shell command with user-controlled input. This is especially dangerous and is the main reason the app must remain isolated.
- The crawler discovery endpoints are `/robots.txt` and `/sitemap.xml`.
