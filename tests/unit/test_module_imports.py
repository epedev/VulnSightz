"""Regression: XSS + reporting imports must work with editable / dual-checkout paths."""

from __future__ import annotations

import sys
from pathlib import Path

from vulnsight.config import ScanConfig
from vulnsight.paths import REPO_ROOT, ensure_module_paths, load_entrypoint


def test_load_entrypoint_xss_and_reporting():
    run_xss = load_entrypoint("xss", "xss_module.py", "run_xss_module")
    run_report = load_entrypoint("reporting", "report_module.py", "run_report_module")
    assert callable(run_xss)
    assert callable(run_report)


def test_namespace_contamination_is_repaired():
    """Empty namespace packages left in sys.modules must be cleared."""
    import types

    for key in list(sys.modules):
        if key == "xss_module" or key.startswith("xss_module."):
            del sys.modules[key]
    stale = types.ModuleType("xss_module")
    stale.__path__ = [str(REPO_ROOT / "xss_module")]  # type: ignore[attr-defined]
    sys.modules["xss_module"] = stale

    ensure_module_paths()
    assert "xss_module" not in sys.modules or hasattr(
        sys.modules.get("xss_module", object()), "run_xss_module"
    ) or sys.modules.get("xss_module") is not stale
    run_xss = load_entrypoint("xss", "xss_module.py", "run_xss_module")
    assert callable(run_xss)


def test_extended_probes_flag_does_not_crash_xss(tmp_path):
    """Active verify without metachar probes must not fail the XSS module."""
    from vulnsight.orchestrator import MODULE_STATUS_FAILED, run_scan

    crawl = {
        "version": "1.0",
        "target": "http://127.0.0.1:5001",
        "pages": [{"url": "http://127.0.0.1:5001/", "params": []}],
        "forms": [],
        "endpoints": [],
    }
    crawl_path = tmp_path / "crawl_map.json"
    crawl_path.write_text(__import__("json").dumps(crawl), encoding="utf-8")

    cfg = ScanConfig(
        target="http://127.0.0.1:5001",
        output_dir=str(tmp_path / "out"),
        modules=["xss", "reporting"],
        skip_recon=True,
        crawl_map_path=str(crawl_path),
        enable_active_verify=True,
        enable_metachar_probes=False,
        enable_stored_xss=False,
        formats=["json", "html"],
        max_requests=5,
    )
    # Network may be down; we only assert XSS does not fail on config validation.
    result = run_scan(cfg)
    xss_runs = [r for r in result.module_runs if r.name == "xss"]
    assert xss_runs, "xss module run missing"
    assert xss_runs[0].status != MODULE_STATUS_FAILED or not any(
        "enable_extended_probes" in e for e in (xss_runs[0].errors or [])
    )
    report_runs = [r for r in result.module_runs if r.name == "reporting"]
    assert report_runs
    assert report_runs[0].status != MODULE_STATUS_FAILED
