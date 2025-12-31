// SPDX-License-Identifier: MIT
pragma solidity ^0.5.0;

/**
 * @title DemoVulnerableBank
 * @notice 简单的漏洞演示合约（兼容 Solidity 0.5.x）
 * @dev 专为 Slither 对比分析设计
 */
contract DemoVulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }
    
    // 漏洞1: tx.origin 权限控制 (SWC-115)
    function adminWithdraw(address payable _to, uint256 _amount) public {
        require(tx.origin == owner, "Not owner");
        _to.transfer(_amount);
    }
    
    // 漏洞2: 重入漏洞 (SWC-107)
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        
        // 危险：先转账，后更新余额
        msg.sender.call.value(_amount)("");
        balances[msg.sender] -= _amount;
    }
    
    // 漏洞3: 时间戳依赖 (SWC-116)
    function luckyDraw() public payable {
        require(msg.value == 0.1 ether, "Must send 0.1 ETH");
        
        if (block.timestamp % 2 == 0) {
            msg.sender.transfer(address(this).balance);
        }
    }
    
    // 漏洞4: 整数溢出 (SWC-101, Solidity 0.5.x 没有自动检查)
    function unsafeAdd(uint256 balance) public {
        // 危险：没有溢出检查
        balances[msg.sender] += balance;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function() external payable {
        deposit();
    }
}
