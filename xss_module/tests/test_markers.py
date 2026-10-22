"""Unit tests for XSS marker generation."""

from __future__ import annotations

import re

from xss.markers import (
    BROWSER_SIGNAL_TEMPLATE,
    PROBE_HTML_BODY,
    Marker,
    generate_marker,
)


def test_generate_marker_is_alphanumeric_and_unique():
    a = generate_marker()
    b = generate_marker()
    assert a.value != b.value
    assert a.value.startswith("zzXSS")
    assert re.fullmatch(r"zzXSS[A-Za-z0-9]{8}", a.value)


def test_marker_with_probe_and_html_escape_api():
    m = Marker(value="zzXSSABCD1234")
    assert m.with_probe(PROBE_HTML_BODY) == f"zzXSSABCD1234{PROBE_HTML_BODY}"
    assert isinstance(m.html_escaped, str)


def test_browser_signal_template_substitutes_token():
    token = "tok123"
    html = BROWSER_SIGNAL_TEMPLATE.format(token=token)
    assert token in html
    assert "__XSS_SIGNAL__" in html
    assert "<script" not in html.lower()
