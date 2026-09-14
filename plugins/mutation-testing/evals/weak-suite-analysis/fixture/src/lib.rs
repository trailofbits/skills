//! Minimal vault used as a mutation-testing fixture.
//!
//! The suite in `tests/vault.rs` is deliberately weak: it exercises one happy
//! withdrawal and asserts only the returned balance, so several mutants survive.

#[derive(Debug, PartialEq)]
pub enum VaultError {
    Unauthorized,
    InsufficientFunds,
}

pub struct Account {
    pub balance: u64,
}

impl Account {
    pub fn new(balance: u64) -> Self {
        Self { balance }
    }
}

/// Withdraws `amount` from `account`. Only an admin caller may withdraw.
pub fn withdraw(account: &mut Account, amount: u64, is_admin: bool) -> Result<u64, VaultError> {
    if !is_admin {
        return Err(VaultError::Unauthorized);
    }
    if amount > account.balance {
        return Err(VaultError::InsufficientFunds);
    }
    account.balance -= amount;
    record_withdrawal(amount);
    Ok(account.balance)
}

/// True when the balance is non-zero. `balance` is unsigned.
pub fn has_funds(balance: u64) -> bool {
    balance > 0
}

fn record_withdrawal(amount: u64) {
    eprintln!("withdrew {amount}");
}
