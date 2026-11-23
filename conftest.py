"""Pytest configuration for the refresh-token exercise.

Two things have to hold no matter how pytest is started:

* the repository root is importable, so ``token`` resolves inside this
  repository;
* ``token.refresh`` is importable even when the standard-library ``token``
  module was imported first, which is what ``pytest`` does during its own
  start-up.  A pre-seeded ``token.refresh`` entry makes the package
  importable from either entry point without touching the standard module.

No fixtures or plugins are required.
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOKEN_DIR = ROOT / "token"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _install_refresh_module():
    """Register ``token.refresh`` from its file path exactly once."""
    if "token.refresh" in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        "token.refresh", TOKEN_DIR / "refresh.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("cannot load token/refresh.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["token.refresh"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop("token.refresh", None)
        raise
    parent = sys.modules.get("token")
    if parent is not None and hasattr(parent, "__path__"):
        setattr(parent, "refresh", module)


_install_refresh_module()