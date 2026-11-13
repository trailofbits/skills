from pathlib import Path


def save(name, data):
    target = Path("uploads") / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(data)
