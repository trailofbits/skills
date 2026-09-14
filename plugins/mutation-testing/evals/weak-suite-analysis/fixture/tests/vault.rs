use vault::{has_funds, withdraw, Account};

#[test]
fn admin_can_withdraw() {
    let mut account = Account::new(100);
    assert_eq!(withdraw(&mut account, 40, true), Ok(60));
}

// Kills the high-severity mutant on the `balance > 0` line. Without it, mewt
// skips both `COS` mutants on that line and the equivalence cases disappear.
#[test]
fn reports_available_funds() {
    assert!(has_funds(100));
}
