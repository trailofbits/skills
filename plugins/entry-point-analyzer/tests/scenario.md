Map the state-changing entry points and their access levels in these excerpts for an audit kickoff. Include file/line locations and explain the caller restrictions. Do not audit for vulnerabilities or modify files.

Vault.sol:
```solidity
pragma solidity ^0.8.20;
contract Vault {
    address public owner;
    address public immutable pool;
    bool public paused;
    uint256 public total;
    constructor(address p) { owner = msg.sender; pool = p; }
    modifier whenNotPaused() { require(!paused); _; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function deposit(uint256 n) external whenNotPaused { total += n; }
    function pause() external onlyOwner { paused = true; }
    function onERC721Received(address, address, uint256 id, bytes calldata) external returns (bytes4) {
        total += id; return this.onERC721Received.selector;
    }
    function uniswapV3SwapCallback(int256 a, int256, bytes calldata) external {
        require(msg.sender == pool); total += uint256(a);
    }
    function readTotal() external view returns (uint256) { return total; }
}
```
Bridge.vy:
```vyper
# pragma version 0.3.10
pool: immutable(address)
total: uint256
@external
def __init__(p: address):
    pool = p
@external
def onERC721Received(operator: address, sender: address, token_id: uint256, data: Bytes[256]) -> bytes4:
    self.total += token_id
    return 0x150b7a02
@external
def receiveFlashLoan(amount: uint256):
    assert msg.sender == pool
    self.total += amount
```
Aptos, counter.move:
```move
module 0x42::counter {
    use std::signer;
    struct Counter has key { value: u64 }
    public entry fun create(account: &signer) {
        move_to(account, Counter { value: 0 });
    }
    public fun add(account: &signer, n: u64) acquires Counter {
        let c = borrow_global_mut<Counter>(signer::address_of(account));
        c.value = c.value + n;
    }
    public fun read(account: address): u64 acquires Counter {
        borrow_global<Counter>(account).value
    }
}
```
Sui, counter.move:
```move
module demo::counter {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use sui::transfer;
    public struct Counter has key { id: UID, value: u64 }
    fun init(ctx: &mut TxContext) {
        transfer::share_object(Counter { id: object::new(ctx), value: 0 });
    }
    public fun add(c: &mut Counter, n: u64) { c.value = c.value + n; }
    public fun read(c: &Counter): u64 { c.value }
}
```
