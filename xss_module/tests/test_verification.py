"""Unit tests for active XSS verification helpers."""

from __future__ import annotations

from xss.context_analyzer import RenderContext
from xss.markers import Marker, generate_marker
from xss.verification import (
    ProbeResult,
    evaluate_probe_response,
    select_extended_probes,
    select_probe,
)


def test_select_probe_html_body_returns_catalog_or_context_probe():
    selected = select_probe(RenderContext.HTML_BODY)
    assert selected is not None
    probe_id, probe = selected
    assert isinstance(probe_id, str) and probe_id
    assert isinstance(probe, str) and probe


def test_select_extended_probes_respects_skip_and_limit():
    primary = select_probe(RenderContext.HTML_BODY)
    assert primary is not None
    skip = {primary[0]}
    probes = select_extended_probes(
        RenderContext.HTML_BODY, limit=2, skip_ids=skip
    )
    assert len(probes) <= 2
    assert all(p.probe_id not in skip for p in probes)


def test_evaluate_probe_response_marks_raw_html_breakout():
    marker = Marker(value="zzXSSTEST01")
    probe = "\"'><"
    body = f"<html><body>hello {marker.value}{probe} world</body></html>"
    result = evaluate_probe_response(
        body,
        marker,
        RenderContext.HTML_BODY,
        "probe:html_body",
        probe,
    )
    assert isinstance(result, ProbeResult)
    assert result.probe_id == "probe:html_body"
    assert result.metachar_raw is True
    assert result.to_dict()["details"]["context"] == RenderContext.HTML_BODY.value


def test_evaluate_probe_response_encoded_not_raw():
    marker = generate_marker()
    probe = "<"
    body = f"<p>{marker.value}&lt;</p>"
    result = evaluate_probe_response(
        body,
        marker,
        RenderContext.HTML_BODY,
        "probe:html_body",
        probe,
    )
    assert result.metachar_raw is False


def test_probe_result_to_dict_shape():
    pr = ProbeResult(
        probe_id="id",
        probe="x",
        reflection_kind=__import__(
            "xss.reflection", fromlist=["ReflectionKind"]
        ).ReflectionKind.RAW,
        metachar_raw=True,
        details={"context": "html_body"},
    )
    data = pr.to_dict()
    assert set(data) == {
        "probe_id",
        "probe",
        "reflection_kind",
        "metachar_raw",
        "details",
    }
