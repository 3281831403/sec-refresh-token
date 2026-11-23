"""Refresh-token exercise package.

The package deliberately shares its name with the standard-library ``token``
module.  Running the suite with ``python -m pytest`` puts the repository root
first on ``sys.path``, so this package would otherwise shadow the standard
module and break every tool that imports it.  The public names of the real
standard-library module are therefore re-exported here.  The exercise code
itself lives in :mod:`token.refresh`.
"""

import importlib.util as _importlib_util
import sysconfig as _sysconfig
from pathlib import Path as _Path


def _load_stdlib_token():
    path = _Path(_sysconfig.get_paths()["stdlib"]) / "token.py"
    if not path.is_file():
        return None
    spec = _importlib_util.spec_from_file_location("_stdlib_token_shim", path)
    if spec is None or spec.loader is None:
        return None
    module = _importlib_util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_STDLIB_TOKEN = _load_stdlib_token()
if _STDLIB_TOKEN is not None:
    _KEEP_LOCAL = frozenset(
        {
            "__builtins__",
            "__cached__",
            "__doc__",
            "__file__",
            "__loader__",
            "__name__",
            "__package__",
            "__path__",
            "__spec__",
        }
    )
    for _name, _value in vars(_STDLIB_TOKEN).items():
        if _name not in _KEEP_LOCAL:
            globals()[_name] = _value