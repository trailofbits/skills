// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IStakeToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title StakingRewards
/// @notice Synthetix-style linear reward distribution. Both the staking token and
///         the reward token use 18 decimals.
contract StakingRewards {
    uint256 public constant PRECISION = 1e18;

    IStakeToken public immutable stakeToken;
    IStakeToken public immutable rewardToken;

    /// @notice Reward tokens emitted per second, 18 decimals.
    uint256 public rewardRatePerSecond;

    /// @notice Cumulative rewards owed per staked token, 18 decimals.
    uint256 public rewardPerTokenStored;

    /// @notice Timestamp of the last reward checkpoint.
    uint256 public lastUpdateTime;

    /// @notice Timestamp at which the current emission schedule ends.
    uint256 public periodFinish;

    /// @notice Total staking tokens held by the contract, 18 decimals.
    uint256 public totalStaked;

    mapping(address => uint256) public stakedBalance;
    mapping(address => uint256) public rewardPerTokenPaid;
    mapping(address => uint256) public rewards;

    constructor(IStakeToken stakeToken_, IStakeToken rewardToken_) {
        stakeToken = stakeToken_;
        rewardToken = rewardToken_;
    }

    /// @notice Returns the reward checkpoint time, clamped to the end of the period.
    function lastTimeRewardApplicable() public view returns (uint256) {
        return block.timestamp < periodFinish ? block.timestamp : periodFinish;
    }

    /// @notice Returns the up-to-date cumulative reward per staked token, 18 decimals.
    function rewardPerToken() public view returns (uint256) {
        if (totalStaked == 0) {
            return rewardPerTokenStored;
        }

        uint256 elapsed = lastTimeRewardApplicable() - lastUpdateTime;
        uint256 emitted = elapsed * rewardRatePerSecond;

        return rewardPerTokenStored + (emitted * PRECISION) / totalStaked;
    }

    /// @notice Returns the reward tokens an account has earned but not claimed, 18 decimals.
    function earned(address account) public view returns (uint256) {
        uint256 delta = rewardPerToken() - rewardPerTokenPaid[account];

        return rewards[account] + (stakedBalance[account] * delta) / PRECISION;
    }

    /// @notice Checkpoints global and per-account reward accounting.
    function _updateReward(address account) internal {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = lastTimeRewardApplicable();

        rewards[account] = earned(account);
        rewardPerTokenPaid[account] = rewardPerTokenStored;
    }

    /// @notice Stakes tokens on behalf of the caller.
    /// @param amount The staking token amount, 18 decimals.
    function stake(uint256 amount) external {
        _updateReward(msg.sender);

        stakedBalance[msg.sender] += amount;
        totalStaked += amount;

        stakeToken.transferFrom(msg.sender, address(this), amount);
    }

    /// @notice Withdraws staked tokens.
    /// @param amount The staking token amount, 18 decimals.
    function withdraw(uint256 amount) external {
        _updateReward(msg.sender);

        stakedBalance[msg.sender] -= amount;
        totalStaked -= amount;

        stakeToken.transfer(msg.sender, amount);
    }

    /// @notice Claims all accrued rewards for the caller.
    function claim() external {
        _updateReward(msg.sender);

        uint256 reward = rewards[msg.sender];
        rewards[msg.sender] = 0;

        rewardToken.transfer(msg.sender, reward);
    }

    /// @notice Starts a new emission schedule.
    /// @param reward The total reward tokens to distribute, 18 decimals.
    /// @param duration The schedule length in seconds.
    function notifyRewardAmount(uint256 reward, uint256 duration) external {
        _updateReward(address(0));

        rewardRatePerSecond = reward / duration;
        lastUpdateTime = block.timestamp;
        periodFinish = block.timestamp + duration;
    }
}
