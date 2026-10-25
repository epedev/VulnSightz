# Local testing guide

This guide is for testing the app on a machine or isolated lab network that you control.

## 1. Start from a clean state

Create a Python virtual environment, install dependencies, and initialize the database using the instructions in the root [`README.md`](../README.md). Re-running `init_db.py` resets all three tables and deletes any comments submitted during earlier tests.

## 2. Confirm the app is available

Start the server with `python app.py`, then open `http://127.0.0.1:5000` in your browser. Keep the process bound to localhost. If startup fails, verify that the virtual environment is active and Flask is installed inside it.

You can check the basic routes with a browser or `curl`:

```bash
curl -i http://127.0.0.1:5000/
curl -i http://127.0.0.1:5000/robots.txt
curl -i http://127.0.0.1:5000/sitemap.xml
```

## 3. Exercise the application manually

Visit the login, search, comments, profile, admin, and ping pages. Record the request method, parameter or path segment, response behavior, and whether authentication or authorization is enforced. Use only disposable lab data. For security tests involving injection, use harmless proof-of-concept inputs and avoid payloads that read files, alter data, create processes beyond the intended test, or send data outside the lab.

## 4. Validate scanner behavior

When using the companion scanner, configure its target as `http://127.0.0.1:5000` and confirm that the scope is limited to this local application. A useful report should include the affected route and parameter, evidence that is safe to reproduce, the likely impact, severity rationale, and a concrete remediation. Avoid reporting a finding solely because a keyword or response string matched; verify the behavior and document false positives.

## 5. Reset after testing

Stop the Flask process with `Ctrl+C`. To restore the seeded database, run:

```bash
python init_db.py
```

This drops and recreates the tables, so any comments or other lab changes in the database will be lost.

## Safety checklist

- [ ] Target is owned by you or explicitly authorized for testing.
- [ ] App is bound to `127.0.0.1` or an isolated lab interface.
- [ ] No real credentials, personal data, or production data are used.
- [ ] Tests avoid destructive actions and external callbacks.
- [ ] The server is stopped when the lab is not in use.
