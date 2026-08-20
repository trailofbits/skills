"""Make the plugin's scripts importable from here.

The tests live beside the plugin rather than inside `scripts/` so that what ships to a
user and what only proves it works are separable at a glance — the suite is larger than
the code it covers. That split costs exactly this file: `scripts/` is not a package and
the modules are flat, so the import path has to be arranged before any test imports
`check_ledger` or `findings_model`.

`SCRIPTS` is exported for the tests that run a script as a subprocess rather than
importing it, and `PLUGIN_ROOT` for the ones that read `workflows/c-review.js`.
"""

import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = PLUGIN_ROOT / "scripts"

sys.path.insert(0, str(SCRIPTS))
