---
max_turns: 20
timeout_seconds: 480
allowed_tools: [Skill, Read, Grep, Glob]
runs: 3
---
Reviewing the offchain accounting in our crypto trading bot before we publish the
numbers. It runs strategies across both CEX and DEX venues, and four executors report
a return percentage to the same dashboard. Are any of these computing it wrong?

```python
# executors/arbitrage_executor.py
def get_net_pnl_quote(self) -> Decimal:
    if self.close_type == CloseType.COMPLETED:
        sell_quote_amount = self.sell_order.order.executed_amount_base * self.sell_order.average_executed_price
        buy_quote_amount = self.buy_order.order.executed_amount_base * self.buy_order.average_executed_price
        return sell_quote_amount - buy_quote_amount - self.cum_fees_quote
    else:
        return Decimal("0")

def get_net_pnl_pct(self) -> Decimal:
    if self.is_closed:
        if self.buy_order.order and self.buy_order.order.executed_amount_base > 0:
            return self.net_pnl_quote / self.buy_order.order.executed_amount_base
        else:
            return Decimal("0")
    else:
        return Decimal("0")
```

```python
# executors/dca_executor.py
def get_net_pnl_pct(self) -> Decimal:
    """
    This method is responsible for calculating the net pnl percentage
    """
    return self.net_pnl_quote / self.open_filled_amount_quote if self.open_filled_amount_quote > Decimal("0") else Decimal("0")
```

```python
# executors/twap_executor.py
def get_net_pnl_pct(self) -> Decimal:
    """
    This method is responsible for calculating the net pnl percentage
    """
    total_executed_quote = self.get_total_executed_amount_quote()
    return self.net_pnl_quote / total_executed_quote if total_executed_quote > Decimal("0") else Decimal("0")
```

```python
# executors/grid_executor.py
def get_net_pnl_pct(self) -> Decimal:
    """
    Calculate the net pnl percentage

    :return: The net pnl percentage.
    """
    return self.get_net_pnl_quote() / self.filled_amount_quote if self.filled_amount_quote > 0 else Decimal("0")
```

For reference, the tracked-order fields these read:

```python
class TrackedOrder:
    executed_amount_base: Decimal   # base units filled, e.g. ETH
    executed_amount_quote: Decimal  # quote spent or received, e.g. USDT
    average_executed_price: Decimal # quote per base
    cum_fees_quote: Decimal         # fees, quote
```
