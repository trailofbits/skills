// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {AccessBase} from "./AccessBase.sol";

/// @notice Pause switch for deposits and withdrawals.
abstract contract Pausable is AccessBase {
    bool public paused;

    event Paused(address indexed by);
    event Unpaused(address indexed by);

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    function pause() external onlyKeeper {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    function pauseStatus() external view returns (bool, address) {
        return (paused, owner);
    }
}
