# ruff: noqa: F821
def indirect():
    items = set()
    items.add(source())
    # ruleid: propagation
    consume(items.pop())


def safe():
    items = set()
    items.add("fixed")
    # ok: propagation
    consume(items.pop())
