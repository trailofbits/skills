pragma solidity ^0.8.0;
contract Staking {
    mapping(address => uint256) public deposits;
    uint256 public totalSupply;
    function deposit() external payable { deposits[msg.sender] += msg.value; totalSupply += msg.value; }
    function withdraw(uint256 a) external { deposits[msg.sender] -= a; totalSupply -= a; payable(msg.sender).transfer(a); }
}
