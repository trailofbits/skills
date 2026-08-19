from decimal import Decimal


class Money:
    def __init__(self, amount: Decimal, currency: str):
        self.amount, self.currency = amount, currency

    def __eq__(self, o):
        return (self.amount, self.currency) == (o.amount, o.currency)
