// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title PriceLib
/// @notice 27-decimal (RAY) price math. Prices in this protocol are quoted as RAY
///         USD per whole token, deliberately at higher precision than the WAD
///         accounting in FixedPointMath.
library PriceLib {
    uint256 internal constant RAY = 1e27;

    /// @notice Multiplies two RAY-scaled numbers, rounding down.
    function mulRayDown(uint256 x, uint256 y) internal pure returns (uint256) {
        return (x * y) / RAY;
    }

    /// @notice Divides one RAY-scaled number by another, rounding down.
    function divRayDown(uint256 x, uint256 y) internal pure returns (uint256) {
        return (x * RAY) / y;
    }

    /// @notice Values a WAD-scaled token amount at a RAY-scaled price.
    /// @param amountWad The token amount, 18 decimals.
    /// @param priceRay The USD price of one whole token, 27 decimals.
    /// @return valueWad The USD value, 18 decimals.
    function valueOf(uint256 amountWad, uint256 priceRay) internal pure returns (uint256 valueWad) {
        return (amountWad * priceRay) / RAY;
    }
}
