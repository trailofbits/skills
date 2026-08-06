// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Pausable} from "./Pausable.sol";

interface IPool {
    function swap(address recipient, int256 amount, bytes calldata data) external;
}

/// @notice Holds staked ETH and pays it back on withdrawal.
contract StakingVault is Pausable {
    mapping(address => uint256) public balances;
    uint256 public totalStaked;
    address public immutable pool;

    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor(address _pool) {
        owner = msg.sender;
        pool = _pool;
    }

    function stake() external payable whenNotPaused {
        _credit(msg.sender, msg.value);
        emit Staked(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external whenNotPaused {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        totalStaked -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    function sweep(address to, uint256 amount) external onlyOwner {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "sweep failed");
    }

    function rebalance(bytes calldata data) external {
        require(keepers[msg.sender] || msg.sender == owner, "not authorised");
        IPool(pool).swap(address(this), int256(totalStaked), data);
    }

    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata
    ) external {
        require(msg.sender == pool, "not pool");
        totalStaked = uint256(amount0Delta > 0 ? amount0Delta : amount1Delta);
    }

    function previewWithdraw(address user, uint256 amount)
        external
        view
        returns (uint256)
    {
        uint256 bal = balances[user];
        return amount > bal ? bal : amount;
    }

    function quoteFee(uint256 amount) external pure returns (uint256) {
        return amount / 1000;
    }

    function _credit(address user, uint256 amount) internal {
        balances[user] += amount;
        totalStaked += amount;
    }

    receive() external payable {
        _credit(msg.sender, msg.value);
    }

    fallback() external payable {
        revert("unsupported call");
    }
}
