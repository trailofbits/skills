// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AssetRegistry, IERC20} from "./AssetRegistry.sol";
import {InterestIndex} from "./InterestIndex.sol";
import {UniV3Oracle} from "./UniV3Oracle.sol";
import {FixedPointMath} from "./libraries/FixedPointMath.sol";
import {PriceLib} from "./libraries/PriceLib.sol";

/// @title MarginVault
/// @notice Cross-margin borrowing against a basket of collateral assets.
/// @dev Internal accounting is 18-decimal. Collateral assets have differing native
///      decimals and are listed in the AssetRegistry. Debt is denominated in a
///      single debt asset. Prices come from UniV3Oracle at RAY precision.
contract MarginVault {
    using FixedPointMath for uint256;
    using PriceLib for uint256;

    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant MAINTENANCE_MARGIN_BPS = 1_250;

    AssetRegistry public immutable registry;
    InterestIndex public immutable interestIndex;
    UniV3Oracle public immutable oracle;
    address public immutable debtToken;

    address[] public collateralTokens;

    /// @notice Protocol fee taken on each borrow, expressed as an 18-decimal
    ///         fraction of the borrowed amount. 0.003e18 is 0.3%.
    uint256 public borrowFee = 0.003e18;

    /// @notice Borrow principal per account, 18 decimals, recorded at `entryIndex`.
    mapping(address => uint256) public principalWad;

    /// @notice Borrow index snapshot when the principal was recorded, 27 decimals.
    mapping(address => uint256) public entryIndex;

    mapping(address => mapping(address => uint256)) public collateralOf;

    error Undercollateralized(uint256 marginRatioWad);

    constructor(
        AssetRegistry registry_,
        InterestIndex interestIndex_,
        UniV3Oracle oracle_,
        address debtToken_
    ) {
        registry = registry_;
        interestIndex = interestIndex_;
        oracle = oracle_;
        debtToken = debtToken_;
    }

    function addCollateralToken(address token) external {
        collateralTokens.push(token);
    }

    /// @notice Returns an account's debt including accrued interest.
    /// @param account The borrower.
    /// @return debtWad The amount owed, 18 decimals.
    function debtOf(address account) public view returns (uint256 debtWad) {
        uint256 principal = principalWad[account];
        if (principal == 0) return 0;

        uint256 index = interestIndex.currentIndex();

        return principal.mulWadDown(index) / entryIndex[account];
    }

    /// @notice Returns the total raw balance of every listed collateral asset.
    /// @return total The combined collateral holdings.
    function totalCollateralRaw() public view returns (uint256 total) {
        for (uint256 i = 0; i < collateralTokens.length; i++) {
            total += IERC20(collateralTokens[i]).balanceOf(address(this));
        }
    }

    /// @notice Values one account's collateral basket in USD.
    /// @param account The borrower.
    /// @return valueWad The basket value in USD, 18 decimals.
    function collateralValue(address account) public view returns (uint256 valueWad) {
        for (uint256 i = 0; i < collateralTokens.length; i++) {
            address token = collateralTokens[i];
            uint256 amountWad = registry.toWad(token, collateralOf[account][token]);
            valueWad += amountWad.valueOf(oracle.priceOf(token));
        }
    }

    /// @notice Returns the account's margin ratio; below the maintenance threshold
    ///         the position may be liquidated.
    /// @param account The borrower.
    /// @return ratioWad The ratio of collateral value to debt, 18 decimals.
    function marginRatio(address account) public view returns (uint256 ratioWad) {
        uint256 debt = debtOf(account);
        if (debt == 0) return type(uint256).max;

        return collateralValue(account).divWadDown(debt);
    }

    /// @notice Computes the protocol fee owed on a borrow.
    /// @param amountWad The borrowed amount, 18 decimals.
    /// @return feeWad The fee owed, 18 decimals.
    function protocolFee(uint256 amountWad) public view returns (uint256 feeWad) {
        return amountWad.mulDiv(borrowFee, BPS_DENOMINATOR);
    }

    /// @notice Returns the raw debt-token amount an account must transfer to repay.
    /// @param account The borrower.
    /// @return amount The repayment in the debt asset's native decimals.
    function repaymentAmount(address account) public view returns (uint256 amount) {
        uint256 owedWad = debtOf(account);

        return registry.fromWad(collateralTokens[0], owedWad);
    }

    /// @notice Borrows against deposited collateral.
    /// @param amountWad The amount to borrow, 18 decimals.
    function borrow(uint256 amountWad) external {
        interestIndex.accrue();

        uint256 fee = protocolFee(amountWad);
        principalWad[msg.sender] += amountWad + fee;
        entryIndex[msg.sender] = interestIndex.currentIndex();

        uint256 ratio = marginRatio(msg.sender);
        uint256 minimum = FixedPointMath.WAD.mulDiv(BPS_DENOMINATOR, MAINTENANCE_MARGIN_BPS);
        if (ratio < minimum) revert Undercollateralized(ratio);

        IERC20(debtToken).transfer(msg.sender, registry.fromWad(debtToken, amountWad));
    }

    /// @notice Deposits collateral for the caller.
    /// @param token The collateral asset.
    /// @param amount The amount in the asset's native decimals.
    function depositCollateral(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        collateralOf[msg.sender][token] += amount;
    }
}
