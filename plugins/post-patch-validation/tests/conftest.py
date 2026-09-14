from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "skills" / "post-patch-validation" / "scripts" / "post_patch_validation.py"


@pytest.fixture(scope="session")
def ppv():
    spec = importlib.util.spec_from_file_location("post_patch_validation", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Register before exec: with `from __future__ import annotations`, @dataclass resolves its
    # field types through sys.modules[cls.__module__], which is None for an unregistered module.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
