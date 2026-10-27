#!/usr/bin/env python3
"""Fail if docs regress to claiming VulnSight does not ship a training lab."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Phrases that contradicted the bundled optional lab (D-01).
FORBIDDEN = (
    "does not ship a vulnerable",
    "does not include a vulnerable",
    "does not include a deliberately vulnerable",
    "does not bundle a vulnerable",
    "no bundled vulnerable target",
    "no bundled target",
    "must not require a bundled vulnerable",
    "we did not include a deliberately vulnerable",
)

# Historical changelog entries may mention removal; skip that file for the ban.
SKIP_NAMES = {"CHANGELOG.md", "check_docs_phrases.py"}


def main() -> int:
    bad: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".md", ".html", ".txt"}:
            continue
        if path.name in SKIP_NAMES:
            continue
        # Ignore venv / git / egg-info
        parts = set(path.parts)
        if ".git" in parts or ".venv" in parts or "venv" in parts or "egg-info" in parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        for phrase in FORBIDDEN:
            if phrase in text:
                rel = path.relative_to(ROOT)
                bad.append(f"{rel}: contains forbidden phrase {phrase!r}")
                break
    if bad:
        print("Documentation phrase lint failed:", file=sys.stderr)
        for line in bad:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print("Documentation phrase lint OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
