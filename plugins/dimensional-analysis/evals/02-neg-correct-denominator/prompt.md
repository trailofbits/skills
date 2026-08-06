---
max_turns: 12
timeout_seconds: 300
allowed_tools: [Skill, Read, Grep, Glob]
runs: 3
---
Same review of the bot's offchain accounting, one file this time. Anything wrong in
the arithmetic here?

```python
# executors/arbitrage_executor.py
def get_net_pnl_quote(self) -> Decimal:
    if self.close_type == CloseType.COMPLETED:
        return (self.sell_order.executed_amount_quote
                - self.buy_order.executed_amount_quote
                - self.cum_fees_quote)
    else:
        return Decimal("0")

def get_net_pnl_pct(self) -> Decimal:
    if self.is_closed:
        quote_spent = self.buy_order.executed_amount_quote
        if quote_spent > 0:
            return self.net_pnl_quote / quote_spent
    return Decimal("0")
```

For reference, the tracked-order fields these read:

```python
class TrackedOrder:
    executed_amount_base: Decimal   # base units filled, e.g. ETH
    executed_amount_quote: Decimal  # quote spent or received, e.g. USDT
    average_executed_price: Decimal # quote per base
    cum_fees_quote: Decimal         # fees, quote
```
