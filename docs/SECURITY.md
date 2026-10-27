# Security and authorized use

## Scope

VulnSight is an **educational** scanner. Default operation is restricted to loopback targets.

- Do **not** scan third-party systems without written authorization.
- Do **not** treat crawler output as permission to attack those URLs.
- Prefer an authorized `--project` file that records who authorized the test.
- Use `--allow-external` / `allow_private_network` only for explicitly authorized assessments.

## Optional bundled training lab

This repository ships an optional deliberately vulnerable app in `vulnerable-target-app/` for local training. Bring-your-own authorized targets are also supported. Run the lab only on `127.0.0.1`.

## Sensitive data handling

Reports redact common secret patterns. Still avoid pasting real cookies, tokens, or production credentials into crawl maps, project files, or findings.

## Responsible disclosure

If you discover a bug in VulnSight itself, follow the root [SECURITY.md](../SECURITY.md) process.
