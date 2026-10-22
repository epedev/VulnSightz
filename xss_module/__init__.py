"""XSS detection module package.

Exposes ``run_xss_module`` for the VulnSight orchestrator. Loading is lazy so
``scanner`` / ``xss`` imports succeed after ``ensure_module_paths()`` runs.
"""

from __future__ import annotations

from typing import Any

__all__ = ["run_xss_module"]


def __getattr__(name: str) -> Any:
    if name != "run_xss_module":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib.util import module_from_spec, spec_from_file_location
    from pathlib import Path

    # Prefer the orchestrator helper when VulnSight is installed.
    try:
        from vulnsight.paths import ensure_module_paths, load_entrypoint

        ensure_module_paths()
        fn = load_entrypoint("xss", "xss_module.py", "run_xss_module")
        globals()["run_xss_module"] = fn
        return fn
    except Exception:
        pass

    # Standalone fallback: put this directory on sys.path then load the entry file.
    import sys

    here = Path(__file__).resolve().parent
    here_s = str(here)
    if here_s not in sys.path:
        sys.path.insert(0, here_s)
    entry = here / "xss_module.py"
    spec = spec_from_file_location("vulnsight_xss_module_entry", entry)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise ImportError(f"Unable to load XSS entry module from {entry}")
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    fn = mod.run_xss_module
    globals()["run_xss_module"] = fn
    return fn


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + ["run_xss_module"])
