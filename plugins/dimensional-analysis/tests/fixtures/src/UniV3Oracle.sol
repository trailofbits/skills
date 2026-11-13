// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FixedPointMath} from "./libraries/FixedPointMath.sol";
import {PriceLib} from "./libraries/PriceLib.sol";

interface IUniswapV3Pool {
    function slot0()
        external
        view
        returns (
            uint160 sqrtPriceX96,
            int24 tick,
            uint16 observationIndex,
            uint16 observationCardinality,
            uint16 observationCardinalityNext,
            uint8 feeProtocol,
            bool unlocked
        );
}

/// @title UniV3Oracle
/// @notice Reads spot prices from Uniswap v3 pools and reports them at the RAY
///         precision the rest of the protocol quotes prices in.
/// @dev `slot0().sqrtPriceX96` is the square root of the pool's price, encoded as
///      a Q64.96 fixed-point number.
contract UniV3Oracle {
    uint256 private constant Q96 = 1 << 96;

    error NoPoolFor(address token);

    mapping(address => IUniswapV3Pool) public poolOf;

    function setPool(address token, IUniswapV3Pool pool) external {
        poolOf[token] = pool;
    }

    /// @notice Returns the USD spot price of one whole token.
    /// @param token The asset to price.
    /// @return priceRay The price in USD, 27 decimals.
    function priceOf(address token) external view returns (uint256 priceRay) {
        IUniswapV3Pool pool = poolOf[token];
        if (address(pool) == address(0)) revert NoPoolFor(token);

        (uint160 sqrtPriceX96,,,,,,) = pool.slot0();

        uint256 ratio = uint256(sqrtPriceX96) * uint256(sqrtPriceX96);

        return FixedPointMath.mulDiv(ratio, PriceLib.RAY, Q96);
    }
}
