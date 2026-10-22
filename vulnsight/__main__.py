"""Allow `python -m vulnsight`."""

from __future__ import annotations

from vulnsight.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
