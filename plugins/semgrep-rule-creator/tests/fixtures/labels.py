# ruff: noqa: F821
def transformed():
    # ruleid: labels
    consume(as_query(source()))


def no_transformation():
    # ok: labels
    consume(source())


def constant():
    # ok: labels
    consume(as_query("constant"))
