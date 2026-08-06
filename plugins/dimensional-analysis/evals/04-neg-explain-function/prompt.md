---
max_turns: 8
timeout_seconds: 180
allowed_tools: [Skill, Read, Grep, Glob]
runs: 3
---
What does this do? Rewriting the docstring and I want to describe the return value
accurately.

```python
# executors/position_executor.py
def get_net_pnl_pct(self) -> Decimal:
    """
    Calculate the net pnl percentage

    :return: The net pnl percentage.
    """
    return self.net_pnl_quote / self.open_filled_amount_quote if self.open_filled_amount_quote != Decimal("0") else Decimal("0")
```
