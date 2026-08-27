# Atheris Examples

Two complete harnesses, each runnable as written.

## Example: Pure Python Parser

```python
import sys
import atheris
import json

@atheris.instrument_func
def TestOneInput(data: bytes):
    try:
        # Fuzz Python's JSON parser
        json.loads(data.decode('utf-8', errors='ignore'))
    except (ValueError, UnicodeDecodeError):
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
```

## Example: HTTP Request Parsing

```python
import sys
import atheris

with atheris.instrument_imports():
    from urllib3 import HTTPResponse
    from io import BytesIO

def TestOneInput(data: bytes):
    try:
        # Fuzz HTTP response parsing
        fake_response = HTTPResponse(
            body=BytesIO(data),
            headers={},
            preload_content=False
        )
        fake_response.read()
    except Exception:
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
```

Both catch `Exception` broadly to get a campaign started. Narrow that to the exceptions the
target is documented to raise before you trust the results — a bare `except Exception` also
swallows the bugs you are fuzzing for.
