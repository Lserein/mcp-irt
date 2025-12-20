"""
应急响应报告生成模块
"""

from datetime import datetime
from pathlib import Path
import html


class ReportGenerator:
    """报告生成器"""

    def __init__(self, config):
        self.config = config

    def generate_report(self, host, os_type, threat_desc, results, output_path, format='md'):
        """
        生成应急响应报告

        Args:
            host: 目标主机
            os_type: 操作系统类型
            threat_desc: 威胁描述
            results: 执行结果列表
            output_path: 输出路径
            format: 报告格式 ('md' 或 'html')
        """
        if format.lower() == 'html':
            self._generate_html_report(host, os_type, threat_desc, results, output_path)
        else:
            self._generate_markdown_report(host, os_type, threat_desc, results, output_path)

    def _generate_markdown_report(self, host, os_type, threat_desc, results, output_path):
        """生成Markdown格式的应急响应报告"""

        report_lines = []

        # 报告头部
        report_lines.append("# 应急响应报告")
        report_lines.append("")
        report_lines.append(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"**目标主机**: {host}")
        report_lines.append(f"**操作系统**: {os_type}")
        report_lines.append("")

        # 威胁描述
        if threat_desc:
            report_lines.append("## 威胁描述")
            report_lines.append("")
            report_lines.append(threat_desc)
            report_lines.append("")

        # 执行摘要
        report_lines.append("## 执行摘要")
        report_lines.append("")

        total_steps = len(results)
        successful_steps = sum(1 for r in results if r.get('success', False))
        failed_steps = total_steps - successful_steps

        report_lines.append(f"- 总步骤数: {total_steps}")
        report_lines.append(f"- 成功: {successful_steps}")
        report_lines.append(f"- 失败: {failed_steps}")
        report_lines.append("")

        # 详细结果
        report_lines.append("## 执行详情")
        report_lines.append("")

        for idx, result in enumerate(results, 1):
            script_name = result.get('script', 'unknown')
            success = result.get('success', False)
            timestamp = result.get('timestamp', '')
            exit_code = result.get('exit_code', -1)

            status = "✅ 成功" if success else "❌ 失败"

            report_lines.append(f"### 步骤 {idx}: {script_name}")
            report_lines.append("")
            report_lines.append(f"- **状态**: {status}")
            report_lines.append(f"- **时间**: {timestamp}")
            report_lines.append(f"- **退出码**: {exit_code}")
            report_lines.append("")

            # 输出内容
            stdout = result.get('stdout', '')
            stderr = result.get('stderr', '')

            if stdout:
                report_lines.append("**标准输出**:")
                report_lines.append("")

                # 高亮可疑内容
                highlighted_output = self._highlight_suspicious_content(stdout[:2000])
                report_lines.append("```")
                report_lines.append(highlighted_output)
                if len(stdout) > 2000:
                    report_lines.append("... (输出过长已截断)")
                report_lines.append("```")
                report_lines.append("")

            if stderr:
                report_lines.append("**错误输出**:")
                report_lines.append("")
                report_lines.append("```")
                report_lines.append(stderr[:1000])
                if len(stderr) > 1000:
                    report_lines.append("... (输出过长已截断)")
                report_lines.append("```")
                report_lines.append("")

            # 分析结果
            analysis = self._analyze_result(result)
            if analysis:
                report_lines.append("**分析结果**:")
                report_lines.append("")
                for item in analysis:
                    report_lines.append(f"- {item}")
                report_lines.append("")

            # 威胁情报分析
            threat_intel = result.get('threat_intel', {})
            if threat_intel:
                report_lines.append("**威胁情报分析**:")
                report_lines.append("")
                report_lines.append("| IP地址 | 威胁分数 | 状态 | 来源 |")
                report_lines.append("|--------|---------|------|------|")
                for ip, intel in threat_intel.items():
                    score = intel.get('threat_score', 0)
                    status = "🔴 **恶意**" if intel.get('is_malicious') else "🟢 正常"
                    sources = ", ".join(intel.get('sources', []))
                    report_lines.append(f"| {ip} | {score} | {status} | {sources} |")
                report_lines.append("")

            # 文件威胁情报分析
            file_intel = result.get('file_intel', {})
            if file_intel:
                report_lines.append("**文件威胁情报分析**:")
                report_lines.append("")
                report_lines.append("| 文件路径 | SHA256（前16位） | 威胁分数 | 状态 | 检出率 | 来源 |")
                report_lines.append("|---------|----------------|---------|------|-------|------|")
                for file_path, intel in file_intel.items():
                    file_hash = intel.get('hash', 'Unknown')
                    hash_short = file_hash[:16] + "..." if len(file_hash) > 16 else file_hash
                    score = intel.get('threat_score', 0)
                    status = "🔴 **恶意**" if intel.get('is_malicious') else "🟢 正常"
                    sources = ", ".join(intel.get('sources', []))

                    # 获取检出率
                    vt_details = intel.get('details', {}).get('virustotal', {})
                    malicious = vt_details.get('malicious', 0)
                    total = vt_details.get('total', 0)
                    detection_rate = f"{malicious}/{total}" if total > 0 else "N/A"

                    report_lines.append(f"| {file_path} | {hash_short} | {score} | {status} | {detection_rate} | {sources} |")
                report_lines.append("")

                # 详细分析
                report_lines.append("**详细分析**:")
                report_lines.append("")
                for file_path, intel in file_intel.items():
                    if intel.get('is_malicious'):
                        report_lines.append(f"#### 文件: {file_path}")
                        report_lines.append("")
                        report_lines.append(f"- **SHA256**: `{intel.get('hash', 'Unknown')}`")
                        report_lines.append(f"- **威胁分数**: {intel.get('threat_score', 0)}/100")
                        report_lines.append(f"- **状态**: 🔴 恶意")

                        # VirusTotal信息
                        vt_details = intel.get('details', {}).get('virustotal', {})
                        if vt_details and vt_details.get('total', 0) > 0:
                            report_lines.append(f"- **文件类型**: {vt_details.get('file_type', 'Unknown')}")
                            report_lines.append(f"- **VirusTotal检出率**: {vt_details.get('malicious', 0)}/{vt_details.get('total', 0)} ({int(vt_details.get('malicious', 0) / vt_details.get('total', 1) * 100)}%)")
                            tags = vt_details.get('tags', [])
                            if tags:
                                report_lines.append(f"- **标签**: {', '.join(tags[:5])}")

                        # ThreatBook信息
                        tb_details = intel.get('details', {}).get('threatbook', {})
                        if tb_details and tb_details.get('confidence', 0) > 0:
                            report_lines.append(f"- **ThreatBook严重度**: {tb_details.get('severity', 'unknown')}")
                            report_lines.append(f"- **ThreatBook置信度**: {tb_details.get('confidence', 0)}%")
                            malware_family = tb_details.get('malware_family', 'Unknown')
                            if malware_family != 'Unknown':
                                report_lines.append(f"- **恶意软件家族**: {malware_family}")

                        report_lines.append(f"- **建议**: 立即隔离并删除该文件，检查系统是否存在其他恶意文件")
                        report_lines.append("")

            report_lines.append("---")
            report_lines.append("")

        # 发现的问题汇总
        findings = self._extract_findings(results)
        if findings:
            report_lines.append("## 发现的问题")
            report_lines.append("")

            if findings.get('suspicious_processes'):
                report_lines.append("### 可疑进程")
                report_lines.append("")
                for proc in findings['suspicious_processes']:
                    report_lines.append(f"- {proc}")
                report_lines.append("")

            if findings.get('suspicious_connections'):
                report_lines.append("### 可疑网络连接")
                report_lines.append("")
                for conn in findings['suspicious_connections']:
                    report_lines.append(f"- {conn}")
                report_lines.append("")

            if findings.get('suspicious_tasks'):
                report_lines.append("### 可疑计划任务")
                report_lines.append("")
                for task in findings['suspicious_tasks']:
                    report_lines.append(f"- {task}")
                report_lines.append("")

            if findings.get('log_anomalies'):
                report_lines.append("### 日志异常")
                report_lines.append("")
                for log in findings['log_anomalies']:
                    report_lines.append(f"- {log}")
                report_lines.append("")

        # 建议措施
        recommendations = self._generate_recommendations(findings)
        if recommendations:
            report_lines.append("## 建议措施")
            report_lines.append("")
            for rec in recommendations:
                report_lines.append(f"- {rec}")
            report_lines.append("")

        # 写入文件
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))

    def _analyze_result(self, result):
        """分析单个执行结果"""
        analysis = []
        stdout = result.get('stdout', '')

        if not stdout:
            return analysis

        # 检查进程相关
        if 'process' in result.get('script', '').lower():
            if '高危' in stdout or 'suspicious' in stdout.lower():
                analysis.append("⚠️ 发现高危进程")
            if 'CPU' in stdout and any(x in stdout for x in ['90%', '95%', '100%']):
                analysis.append("⚠️ 发现CPU占用异常")

        # 检查网络相关
        if 'network' in result.get('script', '').lower():
            if 'ESTABLISHED' in stdout:
                conn_count = stdout.count('ESTABLISHED')
                analysis.append(f"发现 {conn_count} 个活动连接")
            if '异常' in stdout or 'suspicious' in stdout.lower():
                analysis.append("⚠️ 发现可疑网络连接")

        # 检查日志相关
        if 'log' in result.get('script', '').lower():
            if 'failed' in stdout.lower() or '失败' in stdout:
                analysis.append("⚠️ 发现登录失败记录")
            if 'root' in stdout.lower() or 'administrator' in stdout.lower():
                analysis.append("发现管理员账户活动")

        return analysis

    def _extract_findings(self, results):
        """从所有结果中提取发现的问题"""
        findings = {
            'suspicious_processes': [],
            'suspicious_connections': [],
            'suspicious_tasks': [],
            'log_anomalies': []
        }

        for result in results:
            if not result.get('success'):
                continue

            stdout = result.get('stdout', '')
            script = result.get('script', '')

            # 提取可疑进程
            if 'process' in script.lower():
                for line in stdout.split('\n'):
                    if '高危' in line or 'suspicious' in line.lower():
                        findings['suspicious_processes'].append(line.strip())

            # 提取可疑连接
            if 'network' in script.lower():
                for line in stdout.split('\n'):
                    if '异常' in line or 'suspicious' in line.lower():
                        findings['suspicious_connections'].append(line.strip())

            # 提取可疑任务
            if 'cron' in script.lower() or 'task' in script.lower():
                for line in stdout.split('\n'):
                    if '可疑' in line or 'suspicious' in line.lower():
                        findings['suspicious_tasks'].append(line.strip())

            # 提取日志异常
            if 'log' in script.lower():
                for line in stdout.split('\n'):
                    if 'failed' in line.lower() or '失败' in line or '异常' in line:
                        findings['log_anomalies'].append(line.strip())

        return findings

    def _generate_recommendations(self, findings):
        """根据发现的问题生成建议措施"""
        recommendations = []

        if findings.get('suspicious_processes'):
            recommendations.append("立即终止可疑进程并分析其来源")
            recommendations.append("检查可疑进程的启动项和持久化机制")

        if findings.get('suspicious_connections'):
            recommendations.append("阻断可疑IP地址的网络访问")
            recommendations.append("分析网络流量并保存取证数据")

        if findings.get('suspicious_tasks'):
            recommendations.append("删除或禁用可疑的计划任务")
            recommendations.append("检查系统启动项和服务配置")

        if findings.get('log_anomalies'):
            recommendations.append("加强认证机制，修改弱密码")
            recommendations.append("启用多因素认证")
            recommendations.append("配置日志监控和告警")

        if not recommendations:
            recommendations.append("未发现明显安全问题，建议定期进行安全检查")

        recommendations.append("保存本次应急响应的所有日志和取证数据")
        recommendations.append("更新安全策略和应急响应预案")

        return recommendations

    def _highlight_suspicious_content(self, text):
        """高亮可疑内容（添加标记）"""
        lines = text.split('\n')
        highlighted_lines = []

        suspicious_keywords = [
            '高危', '可疑', '异常', '失败', 'suspicious', 'malicious',
            'failed', 'error', 'warning', 'alert', '⚠️', '❌'
        ]

        for line in lines:
            # 检查是否包含可疑关键词
            is_suspicious = any(keyword in line.lower() for keyword in suspicious_keywords)

            if is_suspicious:
                # 在行首添加标记
                highlighted_lines.append(f">>> [!] {line}")
            else:
                highlighted_lines.append(line)

        return '\n'.join(highlighted_lines)

    def _generate_html_report(self, host, os_type, threat_desc, results, output_path):
        """生成HTML格式的应急响应报告"""

        # 分析数据
        findings = self._extract_findings(results)
        recommendations = self._generate_recommendations(findings)

        total_steps = len(results)
        successful_steps = sum(1 for r in results if r.get('success', False))
        failed_steps = total_steps - successful_steps

        # HTML模板
        html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>应急响应报告 - {html.escape(host)}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f7fa;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}

        h1 {{
            color: #1a1a1a;
            font-size: 2.5em;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 3px solid #4CAF50;
        }}

        h2 {{
            color: #2c3e50;
            font-size: 1.8em;
            margin-top: 40px;
            margin-bottom: 20px;
            padding-left: 10px;
            border-left: 4px solid #4CAF50;
        }}

        h3 {{
            color: #34495e;
            font-size: 1.3em;
            margin-top: 25px;
            margin-bottom: 15px;
        }}

        .meta-info {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            margin: 20px 0;
            border-left: 4px solid #2196F3;
        }}

        .meta-info p {{
            margin: 8px 0;
            font-size: 1.05em;
        }}

        .meta-info strong {{
            color: #2c3e50;
            display: inline-block;
            min-width: 100px;
        }}

        .summary-box {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}

        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}

        .summary-card.success {{
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
        }}

        .summary-card.failed {{
            background: linear-gradient(135deg, #f44336 0%, #da190b 100%);
        }}

        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}

        .summary-card .label {{
            font-size: 1.1em;
            opacity: 0.95;
        }}

        .step-card {{
            background: #ffffff;
            border: 1px solid #e1e4e8;
            border-radius: 8px;
            padding: 25px;
            margin: 20px 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}

        .step-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }}

        .step-title {{
            font-size: 1.3em;
            color: #2c3e50;
            font-weight: 600;
        }}

        .status-badge {{
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
        }}

        .status-badge.success {{
            background: #d4edda;
            color: #155724;
        }}

        .status-badge.failed {{
            background: #f8d7da;
            color: #721c24;
        }}

        .step-meta {{
            display: flex;
            gap: 30px;
            margin: 15px 0;
            font-size: 0.95em;
            color: #666;
        }}

        .step-meta span {{
            display: flex;
            align-items: center;
        }}

        .step-meta strong {{
            margin-right: 8px;
            color: #333;
        }}

        pre {{
            background: #f6f8fa;
            border: 1px solid #e1e4e8;
            border-radius: 6px;
            padding: 16px;
            overflow-x: auto;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 0.9em;
            line-height: 1.5;
            margin: 15px 0;
        }}

        pre .highlight {{
            background: #fff3cd;
            color: #856404;
            font-weight: bold;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}

        th {{
            background: #f8f9fa;
            color: #2c3e50;
            font-weight: 600;
            text-align: left;
            padding: 12px 15px;
            border-bottom: 2px solid #dee2e6;
        }}

        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e1e4e8;
        }}

        tr:hover {{
            background: #f8f9fa;
        }}

        .findings-section {{
            background: #fff9e6;
            border-left: 4px solid #ff9800;
            padding: 20px;
            margin: 20px 0;
            border-radius: 6px;
        }}

        .recommendations-section {{
            background: #e8f5e9;
            border-left: 4px solid #4CAF50;
            padding: 20px;
            margin: 20px 0;
            border-radius: 6px;
        }}

        ul {{
            margin: 15px 0;
            padding-left: 30px;
        }}

        li {{
            margin: 10px 0;
            line-height: 1.8;
        }}

        .analysis-item {{
            background: #e3f2fd;
            border-left: 3px solid #2196F3;
            padding: 10px 15px;
            margin: 8px 0;
            border-radius: 4px;
        }}

        .threat-intel-table {{
            margin-top: 15px;
        }}

        .malicious {{
            color: #d32f2f;
            font-weight: bold;
        }}

        .normal {{
            color: #388e3c;
            font-weight: bold;
        }}

        .footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #e1e4e8;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}

        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
                padding: 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ 应急响应报告</h1>

        <div class="meta-info">
            <p><strong>生成时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>目标主机:</strong> {html.escape(host)}</p>
            <p><strong>操作系统:</strong> {html.escape(os_type)}</p>
        </div>
"""

        # 威胁描述
        if threat_desc:
            html_content += f"""
        <div class="meta-info">
            <h2>📋 威胁描述</h2>
            <p>{html.escape(threat_desc)}</p>
        </div>
"""

        # 执行摘要
        html_content += f"""
        <h2>📊 执行摘要</h2>
        <div class="summary-box">
            <div class="summary-card">
                <div class="label">总步骤数</div>
                <div class="number">{total_steps}</div>
            </div>
            <div class="summary-card success">
                <div class="label">✅ 成功</div>
                <div class="number">{successful_steps}</div>
            </div>
            <div class="summary-card failed">
                <div class="label">❌ 失败</div>
                <div class="number">{failed_steps}</div>
            </div>
        </div>
"""

        # 执行详情
        html_content += """
        <h2>📝 执行详情</h2>
"""

        for idx, result in enumerate(results, 1):
            script_name = html.escape(result.get('script', 'unknown'))
            success = result.get('success', False)
            timestamp = html.escape(result.get('timestamp', ''))
            exit_code = result.get('exit_code', -1)

            status_class = "success" if success else "failed"
            status_text = "✅ 成功" if success else "❌ 失败"

            html_content += f"""
        <div class="step-card">
            <div class="step-header">
                <h3 class="step-title">步骤 {idx}: {script_name}</h3>
                <span class="status-badge {status_class}">{status_text}</span>
            </div>

            <div class="step-meta">
                <span><strong>时间:</strong> {timestamp}</span>
                <span><strong>退出码:</strong> {exit_code}</span>
            </div>
"""

            # 标准输出
            stdout = result.get('stdout', '')
            if stdout:
                highlighted_output = self._highlight_suspicious_content_html(stdout[:2000])
                truncated = " (输出过长已截断)" if len(stdout) > 2000 else ""
                html_content += f"""
            <h4>标准输出:</h4>
            <pre>{highlighted_output}{truncated}</pre>
"""

            # 错误输出
            stderr = result.get('stderr', '')
            if stderr:
                truncated = " (输出过长已截断)" if len(stderr) > 1000 else ""
                html_content += f"""
            <h4>错误输出:</h4>
            <pre>{html.escape(stderr[:1000])}{truncated}</pre>
"""

            # 分析结果
            analysis = self._analyze_result(result)
            if analysis:
                html_content += """
            <h4>分析结果:</h4>
"""
                for item in analysis:
                    html_content += f"""
            <div class="analysis-item">{html.escape(item)}</div>
"""

            # 威胁情报
            threat_intel = result.get('threat_intel', {})
            if threat_intel:
                html_content += """
            <h4>威胁情报分析:</h4>
            <table class="threat-intel-table">
                <thead>
                    <tr>
                        <th>IP地址</th>
                        <th>威胁分数</th>
                        <th>状态</th>
                        <th>来源</th>
                    </tr>
                </thead>
                <tbody>
"""
                for ip, intel in threat_intel.items():
                    score = intel.get('threat_score', 0)
                    is_malicious = intel.get('is_malicious')
                    status_class = "malicious" if is_malicious else "normal"
                    status_text = "🔴 恶意" if is_malicious else "🟢 正常"
                    sources = ", ".join(intel.get('sources', []))

                    html_content += f"""
                    <tr>
                        <td>{html.escape(ip)}</td>
                        <td>{score}</td>
                        <td class="{status_class}">{status_text}</td>
                        <td>{html.escape(sources)}</td>
                    </tr>
"""
                html_content += """
                </tbody>
            </table>
"""

            # 文件威胁情报分析
            file_intel = result.get('file_intel', {})
            if file_intel:
                html_content += """
            <h4>文件威胁情报分析:</h4>
            <table class="threat-intel-table">
                <thead>
                    <tr>
                        <th>文件路径</th>
                        <th>SHA256（前16位）</th>
                        <th>威胁分数</th>
                        <th>状态</th>
                        <th>检出率</th>
                        <th>来源</th>
                    </tr>
                </thead>
                <tbody>
"""
                for file_path, intel in file_intel.items():
                    file_hash = intel.get('hash', 'Unknown')
                    hash_short = file_hash[:16] + "..." if len(file_hash) > 16 else file_hash
                    score = intel.get('threat_score', 0)
                    is_malicious = intel.get('is_malicious')
                    status_class = "malicious" if is_malicious else "normal"
                    status_text = "🔴 恶意" if is_malicious else "🟢 正常"
                    sources = ", ".join(intel.get('sources', []))

                    # 获取检出率
                    vt_details = intel.get('details', {}).get('virustotal', {})
                    malicious = vt_details.get('malicious', 0)
                    total = vt_details.get('total', 0)
                    detection_rate = f"{malicious}/{total}" if total > 0 else "N/A"

                    html_content += f"""
                    <tr>
                        <td>{html.escape(file_path)}</td>
                        <td><code>{html.escape(hash_short)}</code></td>
                        <td>{score}</td>
                        <td class="{status_class}">{status_text}</td>
                        <td>{html.escape(detection_rate)}</td>
                        <td>{html.escape(sources)}</td>
                    </tr>
"""
                html_content += """
                </tbody>
            </table>
"""

                # 详细分析
                malicious_files = {fp: intel for fp, intel in file_intel.items() if intel.get('is_malicious')}
                if malicious_files:
                    html_content += """
            <h4>恶意文件详细分析:</h4>
"""
                    for file_path, intel in malicious_files.items():
                        file_hash = intel.get('hash', 'Unknown')
                        score = intel.get('threat_score', 0)

                        html_content += f"""
            <div class="file-detail">
                <h5>{html.escape(file_path)}</h5>
                <p><strong>SHA256:</strong> <code>{html.escape(file_hash)}</code></p>
                <p><strong>威胁分数:</strong> {score}/100</p>
                <p><strong>状态:</strong> <span class="malicious">🔴 恶意</span></p>
"""

                        # VirusTotal信息
                        vt_details = intel.get('details', {}).get('virustotal', {})
                        if vt_details and vt_details.get('total', 0) > 0:
                            malicious_count = vt_details.get('malicious', 0)
                            total_count = vt_details.get('total', 0)
                            percentage = int(malicious_count / total_count * 100) if total_count > 0 else 0
                            html_content += f"""
                <p><strong>文件类型:</strong> {html.escape(vt_details.get('file_type', 'Unknown'))}</p>
                <p><strong>VirusTotal检出率:</strong> {malicious_count}/{total_count} ({percentage}%)</p>
"""
                            tags = vt_details.get('tags', [])
                            if tags:
                                tags_str = ", ".join(tags[:5])
                                html_content += f"""
                <p><strong>标签:</strong> {html.escape(tags_str)}</p>
"""

                        # ThreatBook信息
                        tb_details = intel.get('details', {}).get('threatbook', {})
                        if tb_details and tb_details.get('confidence', 0) > 0:
                            html_content += f"""
                <p><strong>ThreatBook严重度:</strong> {html.escape(str(tb_details.get('severity', 'unknown')))}</p>
                <p><strong>ThreatBook置信度:</strong> {tb_details.get('confidence', 0)}%</p>
"""
                            malware_family = tb_details.get('malware_family', 'Unknown')
                            if malware_family != 'Unknown':
                                html_content += f"""
                <p><strong>恶意软件家族:</strong> {html.escape(malware_family)}</p>
"""

                        html_content += """
                <p><strong>建议:</strong> <span class="malicious">立即隔离并删除该文件，检查系统是否存在其他恶意文件</span></p>
            </div>
"""

            html_content += """
        </div>
"""

        # 发现的问题
        if findings:
            html_content += """
        <div class="findings-section">
            <h2>⚠️ 发现的问题</h2>
"""

            if findings.get('suspicious_processes'):
                html_content += """
            <h3>可疑进程</h3>
            <ul>
"""
                for proc in findings['suspicious_processes']:
                    html_content += f"                <li>{html.escape(proc)}</li>\n"
                html_content += """
            </ul>
"""

            if findings.get('suspicious_connections'):
                html_content += """
            <h3>可疑网络连接</h3>
            <ul>
"""
                for conn in findings['suspicious_connections']:
                    html_content += f"                <li>{html.escape(conn)}</li>\n"
                html_content += """
            </ul>
"""

            if findings.get('suspicious_tasks'):
                html_content += """
            <h3>可疑计划任务</h3>
            <ul>
"""
                for task in findings['suspicious_tasks']:
                    html_content += f"                <li>{html.escape(task)}</li>\n"
                html_content += """
            </ul>
"""

            if findings.get('log_anomalies'):
                html_content += """
            <h3>日志异常</h3>
            <ul>
"""
                for log in findings['log_anomalies']:
                    html_content += f"                <li>{html.escape(log)}</li>\n"
                html_content += """
            </ul>
"""

            html_content += """
        </div>
"""

        # 建议措施
        if recommendations:
            html_content += """
        <div class="recommendations-section">
            <h2>💡 建议措施</h2>
            <ul>
"""
            for rec in recommendations:
                html_content += f"                <li>{html.escape(rec)}</li>\n"
            html_content += """
            </ul>
        </div>
"""

        # 页脚
        html_content += """
        <div class="footer">
            <p>本报告由 MCP-IRT 自动化应急响应工具生成</p>
            <p>报告生成时间: {}</p>
        </div>
    </div>
</body>
</html>
""".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        # 写入文件
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _highlight_suspicious_content_html(self, text):
        """高亮HTML中的可疑内容"""
        lines = text.split('\n')
        highlighted_lines = []

        suspicious_keywords = [
            '高危', '可疑', '异常', '失败', 'suspicious', 'malicious',
            'failed', 'error', 'warning', 'alert', '⚠️', '❌'
        ]

        for line in lines:
            escaped_line = html.escape(line)
            # 检查是否包含可疑关键词
            is_suspicious = any(keyword in line.lower() for keyword in suspicious_keywords)

            if is_suspicious:
                highlighted_lines.append(f'<span class="highlight">>> [!] {escaped_line}</span>')
            else:
                highlighted_lines.append(escaped_line)

        return '\n'.join(highlighted_lines)

