"""Smoke checks for the interactive documentation landing page."""

from __future__ import annotations

from pathlib import Path

from vulnsight.paths import REPO_ROOT


def test_docs_landing_is_interactive():
    path = REPO_ROOT / "docs" / "index.html"
    assert path.is_file()
    html = path.read_text(encoding="utf-8")
    for needle in (
        "Scan theater",
        "Findings playground",
        "OWASP Top 10:2025",
        "theater-run",
        "data-filter",
        "Command recipes",
        "see the weakness",
        "epedev/VulnSightz",
    ):
        assert needle in html, f"missing interactive marker: {needle}"


def test_docs_command_resolves_landing(monkeypatch):
    import webbrowser

    from vulnsight import cli

    path = (REPO_ROOT / "docs" / "index.html").resolve()
    assert path.is_file()

    opened: list[str] = []

    def fake_open(url: str) -> bool:
        opened.append(url)
        return True

    monkeypatch.setattr(webbrowser, "open", fake_open)
    code = cli.main(["docs"])
    assert code == 0
    assert opened and opened[0].startswith("file:")
    assert Path(opened[0].removeprefix("file://")).resolve() == path
