import shutil
from pathlib import Path

Path("dist").mkdir(exist_ok=True)
shutil.copyfile("app.py", "dist/app.py")
