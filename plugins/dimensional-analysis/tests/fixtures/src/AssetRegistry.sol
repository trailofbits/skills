// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function decimals() external view returns (uint8);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title AssetRegistry
/// @notice Records each supported asset's native decimals and converts raw token
///         amounts to and from the protocol's 18-decimal internal accounting.
contract AssetRegistry {
    error AssetNotListed(address token);
    error DecimalsTooLarge(uint8 decimals);

    mapping(address => uint8) private _decimals;
    mapping(address => bool) private _listed;

    /// @notice Lists an asset, recording the decimals its own contract reports.
    function list(address token) external {
        uint8 tokenDecimals = IERC20(token).decimals();
        if (tokenDecimals > 18) revert DecimalsTooLarge(tokenDecimals);
        _decimals[token] = tokenDecimals;
        _listed[token] = true;
    }

    /// @notice Returns the native decimals of a listed asset.
    function decimalsOf(address token) public view returns (uint8) {
        if (!_listed[token]) revert AssetNotListed(token);
        return _decimals[token];
    }

    /// @notice Converts a raw token amount into the 18-decimal internal scale.
    /// @param token The asset the amount is denominated in.
    /// @param amount The amount in the asset's native decimals.
    /// @return amountWad The same quantity, 18 decimals.
    function toWad(address token, uint256 amount) external view returns (uint256 amountWad) {
        return amount * (10 ** (18 - decimalsOf(token)));
    }

    /// @notice Converts an 18-decimal internal amount back into raw token units.
    /// @param token The asset to denominate the result in.
    /// @param amountWad The amount, 18 decimals.
    /// @return amount The same quantity in the asset's native decimals.
    function fromWad(address token, uint256 amountWad) external view returns (uint256 amount) {
        return amountWad / (10 ** (18 - decimalsOf(token)));
    }
}
