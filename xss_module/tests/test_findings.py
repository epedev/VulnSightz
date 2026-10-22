from scanner.models import Finding, Severity, VerificationStatus
from xss.context_analyzer import RenderContext
from xss.findings import build_finding, dedupe_findings, severity_for
from xss.reflection import ReflectionKind
from xss.findings import confidence_from_evidence


def test_encoded_baseline_rejected_safe():
    conf, status, reasons = confidence_from_evidence(
        reflection_kind=ReflectionKind.HTML_ENCODED,
        context=RenderContext.HTML_BODY,
        metachar_raw=False,
        browser_confirmed=False,
        inert_context=False,
    )
    assert status == VerificationStatus.REJECTED_SAFE.value
    assert conf == "low"


def test_inert_marker_not_confirmed():
    conf, status, reasons = confidence_from_evidence(
        reflection_kind=ReflectionKind.RAW,
        context=RenderContext.HTML_COMMENT,
        metachar_raw=False,
        browser_confirmed=False,
        inert_context=True,
    )
    assert status == VerificationStatus.REJECTED_SAFE.value
    assert conf != "confirmed"


def test_dedupe_prefers_higher_verification():
    a = build_finding(
        vulnerability_type="xss.reflected",
        url="http://127.0.0.1:5001/reflect?q=1",
        method="GET",
        parameter="q",
        input_type="text",
        context=RenderContext.HTML_BODY,
        payload_or_probe_id="m1",
        evidence={},
        detection_method="marker_reflection",
        confidence="medium",
        verification_status=VerificationStatus.CANDIDATE.value,
        http_status=200,
        description="d",
        impact="i",
    )
    b = build_finding(
        vulnerability_type="xss.reflected",
        url="http://127.0.0.1:5001/reflect?q=2",
        method="GET",
        parameter="q",
        input_type="text",
        context=RenderContext.HTML_BODY,
        payload_or_probe_id="m2",
        evidence={},
        detection_method="marker_plus_context_probe",
        confidence="high",
        verification_status=VerificationStatus.PROBABLE.value,
        http_status=200,
        description="d",
        impact="i",
    )
    out = dedupe_findings([a, b])
    assert len(out) == 1
    assert out[0].verification_status == VerificationStatus.PROBABLE.value


def test_finding_has_cwe_owasp():
    f = build_finding(
        vulnerability_type="xss.reflected",
        url="http://127.0.0.1:5001/reflect",
        method="GET",
        parameter="q",
        input_type="text",
        context=RenderContext.HTML_BODY,
        payload_or_probe_id="m",
        evidence={},
        detection_method="marker_reflection",
        confidence="medium",
        verification_status=VerificationStatus.CANDIDATE.value,
        http_status=200,
        description="d",
        impact="i",
    )
    assert f.cwe == "CWE-79"
    assert "A05" in f.owasp
    assert "2025" in f.owasp
    assert isinstance(f, Finding)


def test_severity_confirmed_stored_is_high():
    assert (
        severity_for(
            verification_status=VerificationStatus.CONFIRMED.value,
            context=RenderContext.HTML_BODY,
            stored=True,
        )
        == Severity.HIGH.value
    )


def test_severity_confirmed_reflected_is_medium():
    assert (
        severity_for(
            verification_status=VerificationStatus.CONFIRMED.value,
            context=RenderContext.HTML_BODY,
            stored=False,
        )
        == Severity.MEDIUM.value
    )


def test_build_finding_stored_title():
    f = build_finding(
        vulnerability_type="xss.stored",
        url="http://127.0.0.1:5001/comments",
        method="POST",
        parameter="body",
        input_type="textarea",
        context=RenderContext.HTML_BODY,
        payload_or_probe_id="m",
        evidence={},
        detection_method="stored_marker",
        confidence="high",
        verification_status=VerificationStatus.PROBABLE.value,
        http_status=200,
        description="stored reflection",
        impact="persistent script execution",
    )
    assert f.title.startswith("Stored XSS")
    assert f.module == "xss"
    assert f.severity == Severity.MEDIUM.value
