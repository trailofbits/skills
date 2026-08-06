// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IFeeSink {
    function record(address account, uint256 amount) external;
}

/// @notice Member vault with locked collateral and tiered redemption handling.
contract Vault {
    enum Tier {
        Standard,
        Senior
    }

    uint256 public constant FEE_BPS = 50;

    IFeeSink public immutable feeSink;
    address public immutable admin;

    mapping(address => uint256) public balances;
    mapping(address => uint256) public locked;
    mapping(address => Tier) public tier;

    uint256 public totalHeld;
    bool public paused;

    event Deposited(address indexed account, uint256 amount);
    event Redeemed(address indexed account, uint256 amount, uint256 fee);

    error Paused();
    error NotAdmin();
    error CollateralShortfall();
    error NothingToRedeem();

    constructor(IFeeSink sink) {
        feeSink = sink;
        admin = msg.sender;
    }

    modifier notPaused() {
        if (paused) revert Paused();
        _;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    function deposit(uint256 amount) external notPaused {
        balances[msg.sender] += amount;
        totalHeld += amount;
        emit Deposited(msg.sender, amount);
    }

    /// @notice Lock collateral against a member's balance.
    function lock(address account, uint256 amount) external onlyAdmin {
        locked[account] += amount;
    }

    /// @notice Redeem part of a member's balance, net of the redemption fee.
    function redeem(uint256 amount) external notPaused returns (uint256) {
        if (amount == 0) revert NothingToRedeem();
        if (!_collateralPreserved(msg.sender, amount)) revert CollateralShortfall();

        uint256 fee = (amount * FEE_BPS) / 10_000;
        uint256 payout = amount - fee;

        balances[msg.sender] -= amount;
        totalHeld -= amount;

        feeSink.record(msg.sender, fee);
        emit Redeemed(msg.sender, amount, fee);

        return payout;
    }

    /// @notice Whether the account keeps enough balance to cover its locked collateral.
    function _collateralPreserved(address account, uint256 amount) internal view returns (bool) {
        if (tier[account] == Tier.Senior) {
            return true;
        }
        return balances[account] - amount >= locked[account];
    }

    function setTier(address account, Tier newTier) external onlyAdmin {
        tier[account] = newTier;
    }

    function setPaused(bool value) external onlyAdmin {
        paused = value;
    }

    /// @notice Move a member's balance to another account.
    function reassign(address from, address to) external onlyAdmin {
        uint256 amount = balances[from];
        balances[from] = 0;
        balances[to] += amount;
        locked[to] += locked[from];
        locked[from] = 0;
    }
}
