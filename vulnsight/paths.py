"""Repository path helpers and sys.path bootstrapping for member modules."""

from __future__ import annotations

import sys
from importlib import import_module
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any


def _detect_repo_root() -> Path:
    """Prefer a tree that still contains the member scanner modules."""
    here = Path(__file__).resolve().parent
    candidates = [here.parent, Path.cwd()]
    for parent in list(here.parents)[:4]:
        if parent not in candidates:
            candidates.append(parent)
    for candidate in candidates:
        if (
            (candidate / "pyproject.toml").is_file()
            and (candidate / "xss_module").is_dir()
            and (candidate / "reporting_module").is_dir()
        ):
            return candidate
    return here.parent


REPO_ROOT = _detect_repo_root()

MODULE_DIRS = {
    "crawler": REPO_ROOT / "Crawler",
    "xss": REPO_ROOT / "xss_module",
    "sqli": REPO_ROOT / "sqli_&_command_module",
    "access_control": REPO_ROOT / "access_control_module",
    "reporting": REPO_ROOT / "reporting_module",
    "misconfig": REPO_ROOT / "misconfig_module",
}

# Names that become empty namespace packages when only the repo root is on sys.path.
_STALE_NAMESPACE_MODULES = (
    "xss_module",
    "report_module",
    "scanner",
    "xss",
    "reporting",
    "crawler",
    "misconfig",
    "access_control",
    "sqli",
    "command_injection",
)


def ensure_module_paths() -> None:
    """Add member module directories so their public APIs can be imported."""
    ordered = [
        MODULE_DIRS["xss"],  # shared scanner.models
        MODULE_DIRS["crawler"],
        MODULE_DIRS["sqli"],
        MODULE_DIRS["access_control"],
        MODULE_DIRS["misconfig"],
        MODULE_DIRS["reporting"],
    ]
    # Drop empty namespace packages cached before module dirs were available.
    for name in _STALE_NAMESPACE_MODULES:
        mod = sys.modules.get(name)
        if mod is None:
            continue
        missing_file = getattr(mod, "__file__", None) is None
        if missing_file:
            del sys.modules[name]
            prefix = name + "."
            for key in list(sys.modules):
                if key.startswith(prefix):
                    del sys.modules[key]

    # Module dirs must precede the repo root so `xss_module` resolves to the
    # entry file rather than an empty namespace package.
    for path in ordered:
        text = str(path)
        if path.is_dir() and text in sys.path:
            sys.path.remove(text)
    for path in reversed(ordered):
        text = str(path)
        if path.is_dir():
            sys.path.insert(0, text)
    repo = str(REPO_ROOT)
    if REPO_ROOT.is_dir() and repo not in sys.path:
        sys.path.append(repo)


def load_entrypoint(module_dir_key: str, filename: str, attr: str) -> Any:
    """Load ``attr`` from ``MODULE_DIRS[key]/filename`` without namespace clashes."""
    ensure_module_paths()
    path = MODULE_DIRS[module_dir_key] / filename
    if not path.is_file():
        raise ImportError(f"Missing module entrypoint: {path}")
    # Prefer normal import once paths are fixed (keeps patches/tests working).
    module_name = Path(filename).stem
    try:
        mod = import_module(module_name)
        if hasattr(mod, attr) and getattr(mod, "__file__", None):
            mod_file = Path(str(mod.__file__)).resolve()
            if mod_file == path.resolve() or path.parent.resolve() in mod_file.parents:
                return getattr(mod, attr)
    except Exception:
        pass
    spec_name = f"vulnsight_entry_{module_dir_key}_{module_name}"
    spec = spec_from_file_location(spec_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load {path}")
    mod = module_from_spec(spec)
    sys.modules[spec_name] = mod
    spec.loader.exec_module(mod)
    try:
        return getattr(mod, attr)
    except AttributeError as exc:
        raise ImportError(f"{path} has no attribute {attr!r}") from exc
