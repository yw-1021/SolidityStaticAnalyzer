# 🛡️ Solidity 智能合约静态分析器

> **项目类型**: 密码学课程设计  
> **功能**: 智能合约安全审计工具（支持工程级扫描 + 工具对比）  
> **特色**: 自动化扫描 | 多文件支持 | HTML 报告 | Slither 对比

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)

---

## 📖 项目简介

本工具通过静态分析技术扫描 Solidity 智能合约代码，检测潜在的安全漏洞。支持单文件或整个项目目录的递归扫描，并可与 Slither 工具进行对比分析。

## 🏆 课设完成度自查

严格对照课程设计要求，本项目已**全部完成**所有基础及加分项：

| 要求项       | 具体要求           | 完成情况    | 对应功能                                          |
| ------------ | ------------------ | ----------- | ------------------------------------------------- |
| **基础要求** | 输入：单文件或工程 | ✅ 完成     | 支持递归扫描 `samples/` 目录及子目录              |
| **基础要求** | 输出：检测报告     | ✅ 完成     | 生成包含漏洞类型、位置、等级、建议的 HTML 报告    |
| **基础要求** | 覆盖至少 3 类问题  | ✅ **超额** | 覆盖 8 类（含重入、权限、外部调用、返回值检查等） |
| **基础要求** | 验证工具效果       | ✅ 完成     | 通过 `samples/demo` 高危合约进行实测验证          |
| **加分项**   | 结果分析 (调用图)  | ✅ **完成** | 集成 Mermaid.js 生成函数调用关系图                |
| **加分项**   | 与现有工具对比     | ✅ **完成** | 实现了与 Slither 的自动化对比分析                 |
| **加分项**   | CI 集成            | ✅ **完成** | 配置 GitHub Actions 实现提交即扫描                |

### ✨ 核心功能

- 📂 递归扫描项目目录中的所有 `.sol` 文件
- 🔍 检测 8 类常见安全漏洞（权限控制、外部调用、时间戳依赖、重入风险、未检查返回值、整数溢出、弱随机数、自毁函数）
- 📊 生成函数调用关系图（Mermaid.js 可视化）
- ⚖️ 集成 Slither 工具进行对比分析
- 📄 输出统一的 HTML 格式审计报告

---

## 🚀 安装

### 克隆仓库

```bash
git clone https://github.com/yw-1021/SolidityStaticAnalyzer.git
cd SolidityStaticAnalyzer
```

### 安装依赖

需要安装以下工具以使用完整功能：

```bash
pip install slither-analyzer solc-select
solc-select install 0.5.17
solc-select use 0.5.17
```

---

## 💻 使用

```bash
python main.py
```

程序将扫描 `samples/` 目录，运行 Slither 对比分析，并生成 `audit_report.html` 报告文件。

---

## 🔍 漏洞检测规则

| 漏洞 ID | 漏洞类型         | 风险等级 | 检测模式                              |
| ------- | ---------------- | -------- | ------------------------------------- |
| SWC-115 | 权限控制缺陷     | HIGH     | `tx.origin` 使用                      |
| SWC-112 | 危险的外部调用   | CRITICAL | `delegatecall` 使用                   |
| SWC-116 | 时间戳依赖       | MEDIUM   | `block.timestamp` / `now`             |
| SWC-107 | 重入攻击风险     | CRITICAL | `.call{value:` 模式                   |
| SWC-104 | 未检查的低级调用 | HIGH     | `.call()` / `.send()` / `.transfer()` |
| SWC-101 | 整数溢出风险     | MEDIUM   | Solidity 版本 < 0.8.0                 |
| SWC-120 | 弱随机数生成     | HIGH     | 随机函数使用区块信息                  |
| SWC-105 | 未保护的自毁函数 | CRITICAL | `selfdestruct` / `suicide` 函数       |

---

## 📋 输出报告

生成的 `audit_report.html` 包含：

- 📊 漏洞统计面板（总数、高危数、中危数）
- 📝 详细漏洞列表（文件、位置、代码片段、修复建议）
- 🔗 函数调用流程图（Mermaid 可视化）
- ⚖️ Slither 对比分析

---

## 📁 项目结构

```
SolidityStaticAnalyzer/
├── main.py                 # 核心程序
├── audit_report.html       # 生成的审计报告
├── README.md               # 项目文档
├── samples/                # 示例合约
└── .github/workflows/      # CI/CD 配置
    └── audit.yml
```

---

## 🔧 技术实现

### 核心技术栈

- **规则引擎**: 正则表达式模式匹配
- **文件系统**: PathLib 递归查找
- **控制流分析**: 函数调用关系提取
- **报告生成**: HTML + Mermaid.js
- **工具集成**: subprocess 调用 Slither

### 工作流程

```mermaid
graph LR
    A[扫描 samples/] --> B[递归查找 .sol 文件]
    B --> C[逐个文件扫描]
    C --> D[规则匹配检测]
    D --> E[提取函数调用图]
    E --> F[运行 Slither 对比]
    F --> G[整合分析结果]
    G --> H[生成 HTML 报告]
```

### CI/CD 集成

GitHub Actions 工作流配置在 `.github/workflows/audit.yml`，每次 push 或 pull request 到 main 分支时自动运行审计。
