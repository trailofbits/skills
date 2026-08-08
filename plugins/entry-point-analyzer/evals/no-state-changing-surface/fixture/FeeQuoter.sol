// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @notice Quotes the fee charged on a swap, by user tier.
contract FeeQuoter {
    uint256 public immutable baseFeeBps;
    uint256 public immutable maxFeeBps;
    address public immutable router;

    mapping(address => uint256) public tierOf;

    constructor(uint256 _baseFeeBps, uint256 _maxFeeBps, address _router, address[] memory tier1) {
        require(_baseFeeBps <= _maxFeeBps, "base above max");
        baseFeeBps = _baseFeeBps;
        maxFeeBps = _maxFeeBps;
        router = _router;
        for (uint256 i = 0; i < tier1.length; i++) {
            tierOf[tier1[i]] = 1;
        }
    }

    function quote(address user, uint256 amount) public view returns (uint256) {
        uint256 bps = baseFeeBps;
        if (tierOf[user] == 1) {
            bps = bps / 2;
        }
        if (bps > maxFeeBps) {
            bps = maxFeeBps;
        }
        return (amount * bps) / 10_000;
    }

    function quoteBatch(address user, uint256[] calldata amounts)
        external
        view
        returns (uint256 total)
    {
        for (uint256 i = 0; i < amounts.length; i++) {
            total += quote(user, amounts[i]);
        }
    }

    function isRouter(address who) external view returns (bool) {
        return who == router;
    }

    function bpsToWad(uint256 bps) external pure returns (uint256) {
        return (bps * 1e18) / 10_000;
    }

    function _clamp(uint256 v, uint256 hi) internal pure returns (uint256) {
        return v > hi ? hi : v;
    }
}
