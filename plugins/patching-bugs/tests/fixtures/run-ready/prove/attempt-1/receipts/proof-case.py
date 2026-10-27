import json
import sys

inputs = json.loads(sys.argv[1])
expected = json.loads(sys.argv[2])
actual = __import__("labels").remove_prefix(*inputs)
print("PATCH_CASE " + json.dumps({"input": inputs, "actual": actual}))
print("PATCH_REACHED", flush=True)
assert actual == expected
