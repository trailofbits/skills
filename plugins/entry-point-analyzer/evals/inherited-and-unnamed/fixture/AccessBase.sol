// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @notice Ownership and keeper registry.
abstract contract AccessBase {
    address public owner;
    mapping(address => bool) public keepers;

    event OwnerChanged(address indexed from, address indexed to);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyKeeper() {
        require(keepers[msg.sender], "not keeper");
        _;
    }

    function transferOwnership(address to) external onlyOwner {
        require(to != address(0), "zero owner");
        emit OwnerChanged(owner, to);
        owner = to;
    }

    function setKeeper(address k, bool allowed) external onlyOwner {
        keepers[k] = allowed;
    }

    function _requireOwner() internal view {
        require(msg.sender == owner, "not owner");
    }
}
