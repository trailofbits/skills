// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title FixedPointMath
/// @notice 18-decimal (WAD) fixed-point helpers.
library FixedPointMath {
    uint256 internal constant WAD = 1e18;

    /// @notice Multiplies two WAD-scaled numbers, rounding down.
    function mulWadDown(uint256 x, uint256 y) internal pure returns (uint256) {
        return (x * y) / WAD;
    }

    /// @notice Divides one WAD-scaled number by another, rounding down.
    function divWadDown(uint256 x, uint256 y) internal pure returns (uint256) {
        return (x * WAD) / y;
    }

    /// @notice Computes x * y / denominator, rounding down.
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256) {
        return (x * y) / denominator;
    }
}
