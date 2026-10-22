from xss.context_analyzer import RenderContext, analyze_contexts

MARKER = "zzXSS7f3a2cQQ"


def test_html_body_context():
    body = f"<div>USER {MARKER} HERE</div>"
    analysis = analyze_contexts(body, MARKER)
    assert analysis.primary == RenderContext.HTML_BODY
    assert analysis.warrants_verification is True


def test_comment_context():
    body = f"<!-- note {MARKER} --> <p>ok</p>"
    analysis = analyze_contexts(body, MARKER)
    assert analysis.primary == RenderContext.HTML_COMMENT
    assert analysis.warrants_verification is False


def test_attribute_double_quoted():
    body = f'<input type="text" value="{MARKER}">'
    analysis = analyze_contexts(body, MARKER)
    assert analysis.primary == RenderContext.HTML_ATTR_DOUBLE


def test_javascript_string_single():
    body = f"<script>const value = '{MARKER}';</script>"
    analysis = analyze_contexts(body, MARKER)
    assert analysis.primary == RenderContext.JS_STRING_SINGLE


def test_url_attribute_context():
    body = f'<a href="{MARKER}">link</a>'
    analysis = analyze_contexts(body, MARKER)
    assert analysis.primary == RenderContext.URL_ATTRIBUTE


def test_json_script_type_is_inert():
    body = f'<script type="application/json">{{"q":"{MARKER}"}}</script>'
    analysis = analyze_contexts(body, MARKER)
    assert analysis.primary == RenderContext.JSON_IN_HTML
    assert analysis.warrants_verification is False


def test_json_ld_script_type_is_inert():
    body = f'<script type="application/ld+json">{{"name":"{MARKER}"}}</script>'
    analysis = analyze_contexts(body, MARKER)
    assert analysis.primary == RenderContext.JSON_IN_HTML
    assert analysis.warrants_verification is False
