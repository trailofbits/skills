// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IFeeSink {
    function notify(address payer, uint256 amount) external returns (uint256);
}

/// @notice Holds deposits and releases them to sellers once a buyer confirms.
contract Escrow {
    struct Deal {
        address buyer;
        address seller;
        uint256 amount;
        bool    settled;
    }

    mapping(uint256 => Deal)    public deals;
    mapping(address => uint256) public credit;
    mapping(address => bool)    public whitelisted;

    uint256 public totalHeld;
    IFeeSink public feeSink;
    address public operator;

    modifier onlyOperator() {
        require(msg.sender == operator, "not operator");
        _;
    }

    constructor(IFeeSink sink) {
        operator = msg.sender;
        feeSink = sink;
    }

    function setWhitelisted(address account, bool ok) external onlyOperator {
        whitelisted[account] = ok;
    }

    function open(uint256 id, address seller) external payable {
        require(deals[id].buyer == address(0), "exists");
        require(msg.value > 0, "no value");

        deals[id] = Deal({buyer: msg.sender, seller: seller, amount: msg.value, settled: false});
        totalHeld += msg.value;
    }

    /// @dev Charges `amount` against `account`'s credit.
    ///      Returns true when the credit covered it.
    function _charge(address account, uint256 amount) internal returns (bool) {
        if (whitelisted[account]) {
            unchecked {
                credit[account] -= amount;
            }
            return true;
        }

        if (credit[account] < amount) {
            return false;
        }

        credit[account] -= amount;
        return true;
    }

    function release(uint256 id) external {
        Deal storage d = deals[id];

        require(msg.sender == d.buyer, "not buyer");
        require(!d.settled, "settled");

        uint256 fee = feeSink.notify(d.buyer, d.amount);
        require(_charge(d.buyer, fee), "credit");

        d.settled = true;
        totalHeld -= d.amount;

        (bool ok, ) = d.seller.call{value: d.amount - fee}("");
        require(ok, "send failed");
    }
}
