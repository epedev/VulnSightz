"""ScopedSession must re-validate redirects and reject off-origin hops."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from vulnsight.scope import ScopeError
from vulnsight.scoped_http import ScopePolicy, ScopedSession


def test_policy_rejects_non_loopback_by_default():
    with pytest.raises(ScopeError):
        ScopePolicy.for_target("http://example.com/")


def test_policy_allows_loopback():
    policy = ScopePolicy.for_target("http://127.0.0.1:5001/")
    assert policy.url_in_scope("http://127.0.0.1:5001/login")
    assert not policy.url_in_scope("http://evil.example/login")


def test_scoped_session_blocks_off_origin_redirect():
    first = Mock()
    first.is_redirect = True
    first.status_code = 302
    first.headers = {"Location": "http://evil.example/steal"}
    first.url = "http://127.0.0.1:5001/"
    first.text = ""

    raw = Mock()
    raw.get.return_value = first
    raw.headers = {}

    session = ScopedSession(ScopePolicy.for_target("http://127.0.0.1:5001/"), session=raw)
    with pytest.raises(ScopeError, match="not allowed"):
        session.get("http://127.0.0.1:5001/", allow_redirects=True, timeout=1)


def test_scoped_session_follows_in_scope_redirect():
    first = Mock()
    first.is_redirect = True
    first.status_code = 302
    first.headers = {"Location": "/login"}
    first.url = "http://127.0.0.1:5001/"
    first.text = ""

    second = Mock()
    second.is_redirect = False
    second.status_code = 200
    second.headers = {}
    second.url = "http://127.0.0.1:5001/login"
    second.text = "ok"

    raw = Mock()
    raw.get.side_effect = [first, second]
    raw.headers = {}

    session = ScopedSession(ScopePolicy.for_target("http://127.0.0.1:5001/"), session=raw)
    resp = session.get("http://127.0.0.1:5001/", allow_redirects=True, timeout=1)
    assert resp.status_code == 200
    assert raw.get.call_count == 2
