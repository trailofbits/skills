// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PriceLib} from "./libraries/PriceLib.sol";

/// @title InterestIndex
/// @notice Cumulative borrow index. The index starts at one and grows as interest
///         accrues, so a principal recorded at index I0 owes
///         `principal * currentIndex / I0`.
/// @dev The index is carried at RAY precision, matching PriceLib rather than the
///      WAD accounting used elsewhere in the protocol.
contract InterestIndex {
    using PriceLib for uint256;

    uint256 internal constant SECONDS_PER_YEAR = 365 days;

    /// @notice Cumulative borrow index, 27 decimals. Initialised to 1.0.
    uint256 public borrowIndex = PriceLib.RAY;

    /// @notice Per-second borrow rate, 27 decimals.
    uint256 public ratePerSecondRay;

    /// @notice Timestamp of the last accrual.
    uint256 public lastAccrual;

    constructor(uint256 aprRay) {
        ratePerSecondRay = aprRay / SECONDS_PER_YEAR;
        lastAccrual = block.timestamp;
    }

    /// @notice Accrues simple interest into the cumulative index.
    function accrue() public {
        uint256 elapsed = block.timestamp - lastAccrual;
        if (elapsed == 0) return;

        uint256 growthRay = PriceLib.RAY + (ratePerSecondRay * elapsed);
        borrowIndex = borrowIndex.mulRayDown(growthRay);
        lastAccrual = block.timestamp;
    }

    /// @notice Returns the up-to-date cumulative borrow index.
    /// @return index The cumulative index, 27 decimals.
    function currentIndex() external view returns (uint256 index) {
        uint256 elapsed = block.timestamp - lastAccrual;
        if (elapsed == 0) return borrowIndex;

        uint256 growthRay = PriceLib.RAY + (ratePerSecondRay * elapsed);
        return borrowIndex.mulRayDown(growthRay);
    }
}
