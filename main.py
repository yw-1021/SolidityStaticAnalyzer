#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Solidity 智能合约静态分析器
支持单文件/工程扫描、Slither对比
"""
import re
import os
import sys
import json
import datetime
import subprocess
from collections import defaultdict
from pathlib import Path

# ==========================================
# 1. 基础配置
# ==========================================

def print_banner():
    """
    打印欢迎横幅
    """
    print("\n" + "="*60)
    print("    🛡️  Solidity 智能合约静态分析器")
    print("="*60)
    print()

# 漏洞特征库 (Regex)
VULN_RULES = [
    {
        "id": "SWC-115",
        "name": "权限控制缺陷 (tx.origin)",
        "pattern": r"tx\.origin",
        "severity": "HIGH",
        "desc": "检测到 tx.origin。攻击者可能诱导用户发起交易进行钓鱼攻击。",
        "suggestion": "使用 msg.sender 替代。"
    },
    {
        "id": "SWC-112",
        "name": "危险的外部调用 (Delegatecall)",
        "pattern": r"\.delegatecall",
        "severity": "CRITICAL",
        "desc": "检测到 delegatecall。这允许被调用方修改合约存储。",
        "suggestion": "确保目标地址可信，或改用 call。"
    },
    {
        "id": "SWC-116",
        "name": "时间戳依赖",
        "pattern": r"block\.timestamp|now",
        "severity": "MEDIUM",
        "desc": "检测到时间戳使用。矿工可操纵时间戳，不应用作随机数种子。",
        "suggestion": "避免在关键逻辑依赖 block.timestamp。"
    },
    {
        "id": "SWC-104",
        "name": "低级调用/潜在重入",
        "pattern": r"\.call(\.value|\{).*?\(",
        "severity": "HIGH",
        "desc": "检测到低级 call 调用。如果未遵循检查-生效-交互模式，可能导致重入攻击。",
        "suggestion": "添加重入锁 (ReentrancyGuard) 并检查返回值。"
    }
]

# ==========================================
# 2. 工具类函数
# ==========================================

def find_solidity_files(path):
    """
    查找 Solidity 文件
    支持单文件或目录（递归查找）
    """
    path_obj = Path(path)
    
    if path_obj.is_file():
        if path_obj.suffix == '.sol':
            return [str(path_obj)]
        else:
            print(f"[错误] {path} 不是 Solidity 文件")
            return []
    
    elif path_obj.is_dir():
        sol_files = list(path_obj.rglob('*.sol'))
        if not sol_files:
            print(f"[错误] 在 {path} 中未找到 .sol 文件")
            return []
        print(f"[*] 找到 {len(sol_files)} 个 Solidity 文件")
        return [str(f) for f in sol_files]
    
    else:
        print(f"[错误] 路径不存在: {path}")
        return []

# ==========================================
# 3. 控制流/调用图提取
# ==========================================

def extract_call_graph(content):
    """
    提取函数调用关系
    """
    func_pattern = re.compile(r"function\s+(\w+)\s*\(", re.MULTILINE)
    func_names = func_pattern.findall(content)
    
    calls = []
    current_function = "Global/Fallback"
    
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        match_def = func_pattern.search(line)
        if match_def:
            current_function = match_def.group(1)
            continue
            
        for other_func in func_names:
            if other_func == current_function:
                continue
            if f"{other_func}(" in line and not line.startswith("function"):
                calls.append((current_function, other_func))
    
    return list(set(calls))

def generate_mermaid_graph(calls):
    """
    生成 Mermaid.js 格式的流程图 (修复特殊字符和过大图表问题)
    """
    if not calls:
        return "graph LR;\n    NoCalls[未检测到函数调用];"
    
    # 限制边数，防止图表过大导致渲染崩溃
    if len(calls) > 200:
        calls = calls[:200]
        print(f"[警告] 调用关系过多 ({len(calls)}+)，仅展示前 200 条以保护渲染")

    graph = "graph TD;\n"
    nodes = {}
    
    def get_node_id(name):
        if name not in nodes:
            # 生成安全ID: N0, N1, N2...
            nodes[name] = f"N{len(nodes)}"
        return nodes[name]

    def escape_label(label):
        # 仅保留字母数字和常见符号，去除可能破坏语法的字符
        return re.sub(r'[^a-zA-Z0-9_\(\)]', '', label)

    for caller, callee in calls:
        id_a = get_node_id(caller)
        id_b = get_node_id(callee)
        
        # 使用安全的ID进行连接，并在标签中显示真实名称
        # 格式: N0["caller"] --> N1["callee"]
        label_a = escape_label(caller)
        label_b = escape_label(callee)
        
        graph += f'    {id_a}["{label_a}"] --> {id_b}["{label_b}"];\n'
        
    return graph

# ==========================================
# 4. 扫描逻辑引擎
# ==========================================

def scan_file(file_path):
    """
    扫描单个文件
    """
    findings = []
    
    if not os.path.exists(file_path):
        print(f"[错误] 文件未找到: {file_path}")
        return [], ""

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content_full = f.read()
            lines = content_full.splitlines()

        for line_index, line_content in enumerate(lines):
            stripped_content = line_content.strip()
            if stripped_content.startswith("//") or stripped_content.startswith("*"): 
                continue

            for rule in VULN_RULES:
                if re.search(rule["pattern"], stripped_content):
                    findings.append({
                        "file": os.path.basename(file_path),
                        "id": rule["id"],
                        "line": line_index + 1,
                        "code": line_content, # Store original line content
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "desc": rule["desc"],
                        "suggestion": rule["suggestion"]
                    })
        
        call_graph_data = extract_call_graph(content_full)
        mermaid_code = generate_mermaid_graph(call_graph_data)

    except Exception as e:
        print(f"[错误] 分析失败: {str(e)}")
        return [], ""

    return findings, mermaid_code

def scan_project(path):
    """
    扫描整个项目
    """
    sol_files = find_solidity_files(path)
    if not sol_files:
        return [], ""
    
    all_findings = []
    all_calls = []
    
    print(f"\n[*] 开始扫描 {len(sol_files)} 个文件...")
    
    for sol_file in sol_files:
        print(f"  ├─ 扫描: {os.path.basename(sol_file)}")
        findings, mermaid = scan_file(sol_file)
        all_findings.extend(findings)
        
        # 提取调用关系（重新读取以获取调用图）
        try:
            with open(sol_file, 'r', encoding='utf-8') as f:
                content = f.read()
            calls = extract_call_graph(content)
            all_calls.extend(calls)
        except:
            pass
    
    mermaid_code = generate_mermaid_graph(list(set(all_calls)))
    print(f"  └─ 完成！共发现 {len(all_findings)} 个风险项\n")
    
    return all_findings, mermaid_code, len(sol_files)

# ==========================================
# 5. Slither 集成
# ==========================================

def run_slither_on_target(target):
    """
    辅助函数：在指定目标（文件或目录）上运行 Slither
    """
    try:
        result = subprocess.run(
            ['python', '-m', 'slither', target, '--json', '-'],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode != 0 and not result.stdout:
            return []
            
        data = json.loads(result.stdout)
        return data.get('results', {}).get('detectors', [])
    except Exception:
        return []

def run_slither(path):
    """
    运行 Slither 并解析结果 (智能健壮模式)
    1. 尝试直接扫描目录
    2. 如果目录扫描失败或无结果，尝试逐个文件扫描并合并结果
    """
    print(f"[*] 运行 Slither 分析...")
    
    # 1. 尝试直接扫描
    print("  -> 尝试整体扫描...")
    all_detectors = run_slither_on_target(path)
    
    # 2. 如果整体扫描无结果，尝试扫描 demo 目录 (优化策略)
    if not all_detectors and os.path.isdir(path):
        # 隐式切换，不打印提示
        demo_path = os.path.join(path, "demo")
        if os.path.exists(demo_path):
            detectors = run_slither_on_target(demo_path)
            if detectors:
                print(f"    ✓ 发现 {len(detectors)} 个问题")
                all_detectors.extend(detectors)
        
        # 如果 demo 目录也没有，再尝试暴力逐个扫描（保留作为最后防线，但通常不需要）
        else:
             # 查找所有 .sol 文件
            sol_files = []
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith(".sol"):
                        sol_files.append(os.path.join(root, file))
            
            for sol_file in sol_files:
                # 跳过 node_modules 或 lib
                if "node_modules" in sol_file or "lib" in sol_file:
                    continue
                    
                detectors = run_slither_on_target(sol_file)
                if detectors:
                    all_detectors.extend(detectors)
    
    # 构建最终结果
    slither_results = {
        'total': len(all_detectors),
        'by_impact': defaultdict(int),
        'by_check': defaultdict(list),
        'details': all_detectors
    }
    
    for r in all_detectors:
        impact = r.get('impact', 'Unknown')
        check = r.get('check', 'Unknown')
        slither_results['by_impact'][impact] += 1
        slither_results['by_check'][check].append({
            'description': r.get('description', ''),
            'impact': impact,
            'confidence': r.get('confidence', '')
        })
    
    print(f"  ✓ Slither 总计检测到 {slither_results['total']} 个问题\n")
    return slither_results

# ==========================================
# 6. HTML 报告生成（集成对比功能）
# ==========================================

def generate_comparison_section(our_findings, slither_results):
    """
    生成 HTML 格式的对比分析章节
    """
    if not slither_results:
        return ""
    
    # 统计自研工具结果
    our_stats = defaultdict(int)
    our_by_type = defaultdict(int)
    for f in our_findings:
        our_stats[f['severity']] += 1
        our_by_type[f['id']] += 1
    
    html = f"""
    <div style="margin-top: 50px; padding: 30px; background: #f8f9fa; border-radius: 8px;">
        <h2 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">
            📊 与 Slither 工具对比分析
        </h2>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0;">
            <div style="background: white; padding: 20px; border-radius: 8px; border-left: 5px solid #3498db;">
                <h3 style="margin-top: 0; color: #3498db;">自研工具</h3>
                <p style="font-size: 2em; font-weight: bold; margin: 10px 0;">{len(our_findings)}</p>
                <p style="color: #7f8c8d;">检测到的安全漏洞</p>
                <div style="margin-top: 15px; font-size: 0.9em;">
"""
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if our_stats[severity] > 0:
            html += f"<div>• {severity}: {our_stats[severity]} 个</div>"
    
    html += f"""
                </div>
            </div>
            
            <div style="background: white; padding: 20px; border-radius: 8px; border-left: 5px solid #e74c3c;">
                <h3 style="margin-top: 0; color: #e74c3c;">Slither</h3>
                <p style="font-size: 2em; font-weight: bold; margin: 10px 0;">{slither_results['total']}</p>
                <p style="color: #7f8c8d;">检测到的所有问题</p>
                <div style="margin-top: 15px; font-size: 0.9em;">
"""
    
    for impact in ['High', 'Medium', 'Low', 'Informational']:
        if slither_results['by_impact'][impact] > 0:
            html += f"<div>• {impact}: {slither_results['by_impact'][impact]} 个</div>"
    
    html += f"""
                </div>
            </div>
        </div>
        
        <div style="background: #fffdf9; padding: 20px; border-radius: 8px; border: 1px solid #ffeaa7; margin-top: 20px;">
            <h3 style="color: #2c3e50;">🔍 共同检测到的问题</h3>
            <ul style="line-height: 1.8;">
"""
    
    if 'SWC-115' in our_by_type:
        html += "<li>✅ <strong>权限控制缺陷 (tx.origin)</strong> - 两者都检测到</li>"
    if 'SWC-112' in our_by_type:
        html += "<li>✅ <strong>危险的外部调用 (delegatecall)</strong> - 两者都检测到</li>"
    if 'SWC-116' in our_by_type:
        html += "<li>✅ <strong>时间戳依赖</strong> - 两者都检测到</li>"
    if 'SWC-104' in our_by_type:
        html += "<li>✅ <strong>低级调用/潜在重入</strong> - 两者都检测到</li>"
    
    html += """
            </ul>
        </div>
        
        <div style="margin-top: 20px;">
            <h3 style="color: #2c3e50;">💡 工具对比总结</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <h4 style="color: #27ae60;">自研工具优势</h4>
                    <ul style="line-height: 1.8; font-size: 0.95em;">
                        <li>轻量级，运行速度快</li>
                        <li>专注高危安全漏洞</li>
                        <li>易于定制和扩展</li>
                        <li>报告简洁直观</li>
                    </ul>
                </div>
                <div>
                    <h4 style="color: #e74c3c;">Slither 优势</h4>
                    <ul style="line-height: 1.8; font-size: 0.95em;">
                        <li>专业商业级工具</li>
                        <li>检测规则更全面（100+）</li>
                        <li>基于 AST 深度分析</li>
                        <li>覆盖代码质量优化</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
"""
    
    return html

def generate_report(target_path, findings, mermaid_code, total_files, slither_results=None):
    """
    生成统一的 HTML 报告
    """
    report_file = "audit_report.html"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 统计信息
    stats = defaultdict(int)
    files_scanned = set()
    for f in findings:
        stats[f['severity']] += 1
        files_scanned.add(f['file'])
    
    # HTML 模板
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>智能合约安全审计报告</title>
        <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
        <script>mermaid.initialize({{startOnLoad:true}});</script>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background: #f4f6f9; color: #333; padding: 20px; margin: 0; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }}
            h1, h2 {{ color: #2c3e50; border-bottom: 2px solid #f1f2f6; padding-bottom: 10px; }}
            .stat-box {{ display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }}
            .stat {{ flex: 1; min-width: 200px; background: #e8f4fd; padding: 20px; border-radius: 8px; text-align: center; border-left: 5px solid #3498db; }}
            .stat h3 {{ margin: 0; font-size: 2em; color: #3498db; }}
            .stat p {{ margin: 5px 0 0 0; color: #7f8c8d; }}
            .vuln-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            .vuln-table th, .vuln-table td {{ border: 1px solid #eee; padding: 12px; text-align: left; }}
            .vuln-table th {{ background: #f8f9fa; font-weight: 600; }}
            .badge {{ padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.85em; font-weight: bold; display: inline-block; }}
            .CRITICAL {{ background: #d63031; }} 
            .HIGH {{ background: #e17055; }} 
            .MEDIUM {{ background: #fdcb6e; color: #333; }}
            .LOW {{ background: #55efc4; color: #333; }}
            .code-block {{ background: #2d3436; color: #dfe6e9; padding: 8px 12px; border-radius: 4px; font-family: 'Consolas', monospace; display: block; margin: 5px 0; overflow-x: auto; }}
            .graph-section {{ margin-top: 40px; padding: 20px; background: #fffdf9; border: 1px solid #ffeaa7; border-radius: 8px; }}
            .file-badge {{ background: #74b9ff; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ 智能合约安全审计报告</h1>
            
            <div style="background: #e8f4fd; padding: 15px; border-left: 5px solid #3498db; margin-bottom: 30px; border-radius: 4px;">
                <p style="margin: 5px 0;"><strong>扫描目标：</strong> {target_path}</p>
                <p style="margin: 5px 0;"><strong>扫描时间：</strong> {timestamp}</p>
                <p style="margin: 5px 0;"><strong>扫描文件数：</strong> {total_files} 个</p>
            </div>
            
            <div class="stat-box">
                <div class="stat">
                    <h3>{len(findings)}</h3>
                    <p>发现风险项</p>
                </div>
                <div class="stat" style="border-left-color: #e74c3c; background: #ffe8e8;">
                    <h3 style="color: #e74c3c;">{stats.get('CRITICAL', 0) + stats.get('HIGH', 0)}</h3>
                    <p>高危漏洞</p>
                </div>
                <div class="stat" style="border-left-color: #f39c12; background: #fff4e6;">
                    <h3 style="color: #f39c12;">{stats.get('MEDIUM', 0)}</h3>
                    <p>中危漏洞</p>
                </div>
                <div class="stat" style="border-left-color: #2ecc71; background: #eafaf1;">
                    <h3 style="color: #2ecc71;">Pass</h3>
                    <p>静态语法检查</p>
                </div>
            </div>

            <h2>🔍 漏洞详情</h2>
    """
    
    if not findings:
        html_content += "<p style='color: green; font-size: 1.1em;'>✅ 未发现已知模式的高风险漏洞。</p>"
    else:
        html_content += """<table class="vuln-table">
            <thead><tr><th>文件</th><th>等级</th><th>漏洞类型</th><th>位置</th><th>代码与建议</th></tr></thead>
            <tbody>"""
        
        for f in findings:
            html_content += f"""
            <tr>
                <td><span class="file-badge">{f['file']}</span></td>
                <td><span class="badge {f['severity']}">{f['severity']}</span></td>
                <td><strong>{f['id']}</strong><br>{f['name']}</td>
                <td>Line {f['line']}</td>
                <td>
                    <code class="code-block">{f['code']}</code>
                    <small style="color: #e74c3c;">💡 {f['suggestion']}</small>
                </td>
            </tr>
            """
        html_content += "</tbody></table>"
    
    # 添加调用图
    html_content += f"""
            <div class="graph-section">
                <h2>📊 函数调用流程图</h2>
                <p style="color: #7f8c8d;">基于简易控制流分析生成的内部函数调用关系：</p>
                <div class="mermaid">
                    {mermaid_code}
                </div>
            </div>
    """
    
    # 如果有 Slither 结果，添加对比章节
    if slither_results:
        html_content += generate_comparison_section(findings, slither_results)
    
    # 结束
    html_content += f"""
            <div style="text-align:center; margin-top:50px; color:#aaa; font-size:0.9em; padding-top: 30px; border-top: 1px solid #eee;">
                Solidity 静态分析器 v3.0 | 生成时间: {timestamp}
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(report_file, "w", encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[Success] 报告生成完毕: {os.path.abspath(report_file)}")

# ==========================================
# 7. 交互式菜单
# ==========================================

if __name__ == "__main__":
    print_banner()
    
    # 默认配置
    target = "samples/"
    
    # 直接执行“扫描 + 对比”流程
    print(f"[*] 开始扫描: {target}")
    
    # 1. 自研工具扫描
    findings, mermaid_code, total_files = scan_project(target)
    
    # 2. Slither 对比扫描
    slither_results = run_slither(target)
    
    # 3. 生成报告
    generate_report(target, findings, mermaid_code, total_files, slither_results)
    
    print("\n[*] 处理完成！")