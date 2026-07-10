// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * @title VulnerableVault
 * @notice ⚠️  INTENTIONALLY VULNERABLE — for testing smart-audit only.
 *         Do NOT deploy on any network.
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    uint256 public unlockTime;

    constructor() {
        owner = msg.sender;
        unlockTime = block.timestamp + 7 days;
    }

    // SA-001: Reentrancy — external call before state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;   // state updated AFTER call ← bug
    }

    // SA-002: tx.origin used for authentication
    function adminWithdraw() public {
        require(tx.origin == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }

    // SA-004: Unprotected selfdestruct
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }

    // SA-005: Block timestamp used for game logic
    function isUnlocked() public view returns (bool) {
        return block.timestamp >= unlockTime;
    }

    // SA-008: Weak PRNG using block attributes
    function random() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender)));
    }

    // SA-017: Signature replay — no nonce or chain ID
    function claim(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public {
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner, "Invalid signature");
        payable(msg.sender).transfer(1 ether);
    }

    // SA-018: Unbounded loop — DoS risk
    address[] public users;
    function distributeRewards() public {
        for (uint256 i = 0; i < users.length; i++) {
            payable(users[i]).transfer(0.1 ether);
        }
    }

    // SA-006: Delegatecall with user-controlled target
    function execute(address impl, bytes memory data) public {
        impl.delegatecall(data);
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
