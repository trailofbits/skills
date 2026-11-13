// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function decimals() external view returns (uint8);
}

interface IPriceFeed {
    function latestAnswer() external view returns (uint256);
    function decimals() external view returns (uint8);
}

/// @title Vault
/// @notice Minimal share vault used only to exercise skill activation. Deposits are
///         an 18-decimal token, shares are 18-decimal, and the price feed reports 8.
contract Vault {
    uint256 public constant WAD = 1e18;
    uint256 public constant FEED_SCALE = 1e8;

    IERC20 public immutable asset;
    IPriceFeed public immutable feed;

    uint256 public totalAssets;
    uint256 public totalShares;

    constructor(IERC20 asset_, IPriceFeed feed_) {
        asset = asset_;
        feed = feed_;
    }

    /// @notice Converts a deposit amount into shares.
    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalShares == 0) return assets;
        return (assets * totalShares) / totalAssets;
    }

    /// @notice Returns the USD value of the vault, 18 decimals.
    function totalValueUsd() public view returns (uint256) {
        return (totalAssets * feed.latestAnswer() * WAD) / (FEED_SCALE * WAD);
    }

    /// @notice Returns the price of one share, 18 decimals.
    function pricePerShare() public view returns (uint256) {
        if (totalShares == 0) return WAD;
        return (totalAssets * WAD) / totalShares;
    }
}
