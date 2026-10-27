from reporting.redaction import REDACT, redact_text


def test_redacts_json_secrets():
    raw = '{"username":"alice","password":"secret123"}'
    out = redact_text(raw)
    assert "secret123" not in out
    assert REDACT in out


def test_redacts_body_style_password():
    raw = "password=hunter2&user=alice"
    out = redact_text(raw)
    assert "hunter2" not in out
    assert f"password={REDACT}" in out


def test_redacts_query_and_header_style():
    assert REDACT in redact_text("Cookie: session=abc")
    assert REDACT in redact_text("https://x/?token=abc&q=1")
