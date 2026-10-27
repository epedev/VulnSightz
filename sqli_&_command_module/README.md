# SQL Injection & Command Injection Module

This module prepared for authorized lab or localhost that the sight u own and we build this for our graduation project. 
and you don't have to try it in unauthorized website.

VulnSight detectors for SQL injection and OS command injection against an intentionally vulnerable local Flask training application.

Findings use the shared schema from `xss_module/scanner/models.py` so outputs can be fed into `reporting_module`.

## Run against your authorized local website

VulnSight does not ship a vulnerable app. Start your own prepared local target first.

## Contents

| Path | Purpose |
|------|---------|
| `sqli/` | Authentication-bypass and database error-signature checks |
| `command_injection/` | Harmless marker echo check via `host` parameter |
| `tests/` | Unit tests + non-local target rejection |
| `docs/` | Vulnerability notes and limitations |

## Setup

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r 'sqli_&_command_module/requirements.txt'
```

## Tests

```bash
PYTHONPATH="sqli_&_command_module:xss_module" python -m pytest -q 'sqli_&_command_module/tests/'
```

`xss_module` is on `PYTHONPATH` so detectors can import the shared `scanner.models` package.

## Local checks

Start the intentionally vulnerable Flask training app on `127.0.0.1:5001`, then from the repository root:

```bash
PYTHONPATH="sqli_&_command_module:xss_module" python -c \
'from sqli.detector import check_local_target; print(check_local_target("http://127.0.0.1:5001").to_dict())'

PYTHONPATH="sqli_&_command_module:xss_module" python -c \
'from command_injection.detector import check_local_target; print(check_local_target("http://127.0.0.1:5001").to_dict())'
```

Save JSON output and pass it to the reporting module with `--sqli` / `--input` as appropriate.

Only run active checks against the intentionally vulnerable local lab or another explicitly authorized target.

## Limitations

- Detection is tailored to the documented training application.
- Database error signatures are indicators, not proof of exploitability.
- A command-output marker is evidence of the tested behavior, not full coverage of all injection vectors.
- Standalone organization; full multi-module CLI orchestration is evolving.

## Remediation

- **SQL injection:** parameterized queries; do not return raw DB errors to clients.
- **Command injection:** avoid shell execution; pass argv lists with `shell=False`; validate inputs.

## Docs

- [SQLI.md](docs/SQLI.md)
- [COMMAND_INJECTION.md](docs/COMMAND_INJECTION.md)
