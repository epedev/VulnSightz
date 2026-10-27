
from pathlib import Path

from reporting.engine import generate_report
from reporting.markdown_report import render_markdown, write_markdown
from reporting.pdf_report import pdf_backend_available, write_pdf


def _sample_objects():
    return [
        {
            "title": "Test XSS finding",
            "vulnerability_type": "Cross-Site Scripting",
            "type": "xss",
            "url": "http://127.0.0.1:5001/reflect",
            "method": "GET",
            "parameter": "q",
            "severity": "medium",
            "confidence": "high",
            "verification_status": "candidate",
            "description": "Marker reflected.",
            "impact": "Script execution risk.",
            "remediation": "Encode output.",
            "cwe": "CWE-79",
            "module": "xss",
            "evidence": {"marker": "abc"},
        }
    ]


def test_markdown_report_written(tmp_path):
    result = generate_report(
        output_dir=tmp_path,
        findings_objects=_sample_objects(),
        formats=["html", "json", "md"],
        target="http://127.0.0.1:5001",
        authorized_origin="http://127.0.0.1:5001",
        modules_executed=["xss", "reporting"],
        modules_not_executed=[],
    )
    assert "md" in result.outputs
    md = Path(result.outputs["md"])
    text = md.read_text(encoding="utf-8")
    assert "Executive summary" in text
    assert "Test XSS finding" in text
    assert "# " in text


def test_html_contains_download_controls(tmp_path):
    result = generate_report(
        output_dir=tmp_path,
        findings_objects=_sample_objects(),
        formats=["html", "md"],
        target="http://127.0.0.1:5001",
        authorized_origin="http://127.0.0.1:5001",
    )
    html = Path(result.outputs["html"]).read_text(encoding="utf-8")
    assert "Download" in html
    assert "vulnsight_report.md" in html
    assert "vulnsight_report.pdf" in html
    assert "dl-md-inline" in html
    assert "dl-md-file" in html
    assert "dl-pdf" in html
    assert "dl-pdf-print" in html
    assert 'id="methodology"' not in html
    assert "Methodology and limitations" not in html
    assert "#methodology" not in html
    md = Path(result.outputs["md"]).read_text(encoding="utf-8")
    assert "Methodology and limitations" not in md


def test_pdf_when_backend_available(tmp_path):
    assert pdf_backend_available(), "ReportLab should ship as a core dependency for PDF export"
    result = generate_report(
        output_dir=tmp_path,
        findings_objects=_sample_objects(),
        formats=["html", "pdf"],
        pdf=True,
        target="http://127.0.0.1:5001",
        authorized_origin="http://127.0.0.1:5001",
    )
    assert "pdf" in result.outputs
    pdf = Path(result.outputs["pdf"])
    assert pdf.exists() and pdf.stat().st_size > 100


def test_default_formats_include_pdf(tmp_path):
    result = generate_report(
        output_dir=tmp_path,
        findings_objects=_sample_objects(),
        target="http://127.0.0.1:5001",
        authorized_origin="http://127.0.0.1:5001",
    )
    assert "pdf" in result.outputs
    assert Path(result.outputs["pdf"]).exists()


def test_pdf_escapes_hostile_finding_titles(tmp_path):
    """Target-controlled titles must not break ReportLab markup parsing."""
    assert pdf_backend_available()
    hostile = [
        {
            "title": 'SSRF candidate via \'<img src="x">\' & <b>bold',
            "vulnerability_type": "Server-Side Request Forgery",
            "type": "ssrf",
            "url": "http://127.0.0.1:5001/fetch?url=1",
            "method": "GET",
            "parameter": '<img src="x">',
            "severity": "medium",
            "confidence": "low",
            "verification_status": "candidate",
            "description": "Hostile <b>markup</b> & ampersands " + ("A" * 2000),
            "impact": "n/a",
            "remediation": "Validate URLs.",
            "cwe": "CWE-918",
            "module": "misconfig",
            "evidence": {"param": '<img src="x">'},
        }
    ]
    result = generate_report(
        output_dir=tmp_path,
        findings_objects=hostile,
        formats=["pdf"],
        pdf=True,
        target="http://127.0.0.1:5001",
        authorized_origin="http://127.0.0.1:5001",
    )
    pdf = Path(result.outputs["pdf"])
    assert pdf.exists() and pdf.stat().st_size > 100
