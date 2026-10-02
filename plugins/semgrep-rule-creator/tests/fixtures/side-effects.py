# ruff: noqa: F821
def unchecked(data):
    populate(data)
    # ruleid: side-effects
    consume(data)


def checked(data):
    populate(data)
    validate_or_raise(data)
    # ok: side-effects
    consume(data)


def changed_after_check(data):
    populate(data)
    validate_or_raise(data)
    populate(data)
    # ruleid: side-effects
    consume(data)
