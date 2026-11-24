import hashlib
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("built_app", "dist/app.py")
assert spec is not None and spec.loader is not None
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
assert app.__file__ is not None
loaded = Path(app.__file__).resolve()
print(
    "PATCH_LOADED "
    + json.dumps({"path": str(loaded), "sha256": hashlib.sha256(loaded.read_bytes()).hexdigest()})
)
print("PATCH_REACHED", flush=True)
app.save("../escape.txt", "escaped")
raise SystemExit(1 if Path("escape.txt").exists() else 0)
