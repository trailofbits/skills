"""Benchmark harness internals for the c-review plugin.

A real package, imported as `lib.<module>` with `bench/` on `sys.path` — the
try/except-ImportError shim these modules started with resolved at runtime and not
for a type checker, and the failure mode of a shim that silently picks the wrong
module is exactly what this harness exists to stop shipping.
"""
