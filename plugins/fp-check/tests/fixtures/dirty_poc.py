"""Deliberately bad PoC. Every poc-lint rule must fire on this file.

If this file stops producing violations, poc-lint has been tuned into
uselessness and tests/poc-lint.bats will fail.

The stubs below exist only so the file is valid Python — the placeholders are
the point, and they are all still here.
"""

balance: dict[str, int] = {}


def setup_target() -> None:
    pass


def report_impact(summary: str) -> None:
    pass


# rule 6: reimplementation — the PoC defines the thing it claims to be testing
def transfer_balance(sender, recipient, amount):
    balance[sender] -= amount
    balance[recipient] += amount


def exploit():
    # rule 2: todo-marker
    # TODO: finish the payload
    # FIXME: this does not run yet
    # XXX revisit

    # rule 3: ellipsis-placeholder
    setup_target()
    ...
    # ...

    # rule 4: narrated-exploit
    print("the attacker would drain the pool here")

    # rule 5: placeholder-attack
    print("Step 1: send the crafted transaction")
    # attacker.drain(pool)

    # rule 1: monetary-placeholder
    report_impact("$XXM at risk, roughly XX,XXX users affected")
