"""Safety net: injection/access/misconfig detectors must not open bare sessions."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DETECTOR_FILES = [
    ROOT / "sqli_&_command_module" / "sqli" / "detector.py",
    ROOT / "sqli_&_command_module" / "command_injection" / "detector.py",
    ROOT / "access_control_module" / "access_control" / "detector.py",
    ROOT / "misconfig_module" / "misconfig" / "detector.py",
]

FORBIDDEN = re.compile(r"requests\.Session\s*\(")


def test_detectors_do_not_construct_bare_requests_session():
    offenders: list[str] = []
    for path in DETECTOR_FILES:
        text = path.read_text(encoding="utf-8")
        if FORBIDDEN.search(text):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], f"bare requests.Session() found in: {offenders}"
