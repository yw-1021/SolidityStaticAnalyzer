// SPDX-License-Identifier: MIT
pragma solidity ^0.5.0;

/**
 * @title 高风险演示合约 - 包含多种严重漏洞
 * @dev 仅用于安全工具测试，切勿在生产环境使用
 */
contract VulnerableMultiRisk {
    address public owner;
    mapping(address => uint256) public balances;
    
    constructor() public {
        owner = msg.sender;
    }
    
    // 漏洞1: tx.origin 权限控制
    function adminWithdraw() public {
        require(tx.origin == owner, "Not owner");
        msg.sender.transfer(address(this).balance);
    }
    
    // 漏洞2: delegatecall 危险调用
    function executeCode(address target, bytes memory data) public {
        target.delegatecall(data);
    }
    
    // 漏洞3: 重入攻击 (使用 call.value 0.5.x 语法)
    function withdrawBalance() public {
        uint256 amount = balances[msg.sender];
        msg.sender.call.value(amount)("");
        balances[msg.sender] = 0;
    }
    
    // 漏洞4: 未检查的 call 返回值
    function sendEther(address payable recipient, uint256 amount) public {
        recipient.call.value(amount)("");  // 未检查返回值
    }
    
    // 漏洞5: 未检查的 send 返回值
    function sendReward(address payable user) public {
        user.send(1 ether);  // 未检查返回值
    }
    
    // 漏洞6: 时间戳依赖
    function isLuckyTime() public view returns (bool) {
        return block.timestamp % 10 == 0;
    }
    
    // 漏洞7: 使用now语法（等同于block.timestamp）
    function isLuckyNow() public view returns (bool) {
        return now % 15 == 0;
    }
    
    // 漏洞8: 弱随机数（使用block.number）
    function randomWinner() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.number))) % 100;
    }
    
    // 漏洞9: 自毁函数没有权限保护
    function destroy() public {
        selfdestruct(msg.sender);
    }
    
    function() external payable {}
}
