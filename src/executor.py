"""
应急响应执行引擎（增强版）
集成本地威胁检测、行为分析和自动响应功能
"""

import os
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict
from threat_intel import ThreatIntelligence
from threat_detector import LocalThreatDetector
from behavior_analyzer import BehaviorAnalyzer
from response_engine import ResponseDecisionEngine
from ai_analyzer import AIAnalyzer


class IRExecutor:
    """应急响应执行器（增强版）"""

    def __init__(self, connector, config):
        self.connector = connector
        self.config = config
        self.results = []
        self.uploaded_scripts = []  # 记录上传的脚本路径

        # 获取项目根目录（src的父目录）
        self.project_root = Path(__file__).parent.parent

        # 读取白名单配置
        self.whitelist = config.get('whitelist', {})

        # 自动添加控制端IP到白名单
        if self.whitelist.get('auto_add_control_ip', True):
            control_ip = connector.get_control_ip()
            if control_ip:
                whitelist_ips = self.whitelist.get('ips', [])
                if control_ip not in whitelist_ips:
                    whitelist_ips.append(control_ip)
                    self.whitelist['ips'] = whitelist_ips
                    print(f"[+] 控制端IP {control_ip} 已自动添加到白名单")

        # 初始化所有分析模块（传入白名单配置）
        self.threat_intel = ThreatIntelligence(config)
        self.local_detector = LocalThreatDetector(whitelist=self.whitelist)
        self.behavior_analyzer = BehaviorAnalyzer(whitelist=self.whitelist)
        self.response_engine = ResponseDecisionEngine(config)
        self.ai_analyzer = AIAnalyzer(config, whitelist=self.whitelist)  # 传入白名单

        # 存储分析结果
        self.detected_threats = []
        self.behavior_analysis = {}
        self.response_actions_taken = []
        self.ai_analysis_results = []  # 存储AI分析结果

    def execute_ir_workflow(self, threat_desc=None):
        """执行完整的应急响应工作流（增强版）"""
        os_type = self.connector.os_type
        workflow = self.config['workflow'].get(os_type, [])

        print(f"[*] 执行工作流: {os_type}")
        print(f"[*] 步骤数: {len(workflow)}")
        if threat_desc:
            print(f"[*] 威胁描述: {threat_desc}")
        print()

        # 执行所有检查脚本
        for step_num, script_name in enumerate(workflow, 1):
            print(f"步骤 {step_num}/{len(workflow)}: {script_name}")
            result = self.execute_script(script_name)
            self.results.append(result)

            # === 新增：本地威胁检测 ===
            if result.get('success'):
                print(f"  [*] 执行本地威胁检测...")
                local_threats = self._perform_local_threat_detection(result, script_name)
                result['local_threats'] = local_threats

                if local_threats:
                    print(f"  [!] 本地检测发现 {len(local_threats)} 个威胁")
                    self.detected_threats.extend(local_threats)
                else:
                    print(f"  [+] 本地检测未发现明显威胁")

                # === 新增：AI分析 ===
                if self.ai_analyzer.is_enabled():
                    print(f"  [*] 执行AI智能分析...")
                    ai_result = self._perform_ai_analysis(result, script_name)
                    result['ai_analysis'] = ai_result

                    if ai_result.get('analyzed'):
                        # 从AI分析中提取威胁
                        ai_threats = ai_result.get('threats', [])
                        if ai_threats:
                            print(f"\n  [!] AI分析发现 {len(ai_threats)} 个威胁")

                            # 按严重程度分类
                            critical = [t for t in ai_threats if t.get('severity') == 'Critical']
                            high = [t for t in ai_threats if t.get('severity') == 'High']
                            medium = [t for t in ai_threats if t.get('severity') == 'Medium']
                            low = [t for t in ai_threats if t.get('severity') == 'Low']

                            # 显示威胁统计
                            if critical:
                                print(f"      🔴 严重 (Critical): {len(critical)} 个")
                            if high:
                                print(f"      🟠 高危 (High): {len(high)} 个")
                            if medium:
                                print(f"      🟡 中危 (Medium): {len(medium)} 个")
                            if low:
                                print(f"      🟢 低危 (Low): {len(low)} 个")

                            print(f"\n  {'='*70}")
                            print(f"  AI 威胁详情:")
                            print(f"  {'='*70}")

                            # 显示所有威胁的详细信息
                            for idx, threat in enumerate(ai_threats, 1):
                                severity = threat.get('severity', 'Unknown')
                                severity_icon = {
                                    'Critical': '🔴',
                                    'High': '🟠',
                                    'Medium': '🟡',
                                    'Low': '🟢'
                                }.get(severity, '⚪')

                                print(f"\n  {severity_icon} 威胁 {idx}: {threat.get('description', 'Unknown')}")
                                print(f"     严重程度: {severity}")

                                category = threat.get('category', 'N/A')
                                if category != 'N/A':
                                    print(f"     威胁分类: {category}")

                                indicators = threat.get('indicators', [])
                                if indicators:
                                    print(f"     威胁指标:")
                                    for indicator in indicators[:5]:  # 最多显示5个指标
                                        print(f"       • {indicator}")
                                    if len(indicators) > 5:
                                        print(f"       • ... 还有 {len(indicators)-5} 个指标")

                                evidence = threat.get('evidence', '')
                                if evidence:
                                    # 截断过长的证据
                                    if len(evidence) > 200:
                                        evidence = evidence[:200] + '...'
                                    print(f"     证据摘要: {evidence}")

                                recommendation = threat.get('recommendation', '')
                                if recommendation:
                                    print(f"     处置建议: {recommendation}")

                            print(f"\n  {'='*70}")
                        else:
                            print(f"  [+] AI分析未发现威胁")

                        # 显示AI给出的风险评分
                        risk_score = ai_result.get('overall_risk_score', 0)
                        if risk_score > 0:
                            # 根据评分显示不同的图标
                            if risk_score >= 80:
                                risk_icon = "🔴"
                                risk_level = "极高风险"
                            elif risk_score >= 60:
                                risk_icon = "🟠"
                                risk_level = "高风险"
                            elif risk_score >= 40:
                                risk_icon = "🟡"
                                risk_level = "中等风险"
                            elif risk_score >= 20:
                                risk_icon = "🟢"
                                risk_level = "低风险"
                            else:
                                risk_icon = "⚪"
                                risk_level = "极低风险"

                            print(f"\n  {risk_icon} AI风险评分: {risk_score}/100 ({risk_level})")

                        # 显示总结
                        summary = ai_result.get('summary', '')
                        if summary:
                            print(f"\n  📝 AI分析总结:")
                            # 处理多行总结
                            for line in summary.split('\n')[:5]:  # 最多显示5行
                                if line.strip():
                                    print(f"     {line.strip()}")

                        # 显示立即行动建议
                        immediate_actions = ai_result.get('immediate_actions', [])
                        if immediate_actions:
                            print(f"\n  ⚡ 立即行动建议:")
                            for action in immediate_actions[:5]:  # 最多显示5条
                                print(f"     ✓ {action}")

                        # 显示可能的误报
                        false_positives = ai_result.get('false_positives', [])
                        if false_positives:
                            print(f"\n  ⚠️  可能的误报:")
                            for fp in false_positives[:3]:  # 最多显示3条
                                print(f"     • {fp}")

                        print(f"  {'='*70}\n")

                    else:
                        error_msg = ai_result.get('error', 'Unknown error')
                        print(f"  [!] AI分析失败: {error_msg}")
                        # 打印调试信息
                        if 'reason' in ai_result:
                            print(f"  [!] 原因: {ai_result['reason']}")
                        # 打印完整的AI结果用于调试
                        import json
                        print(f"  [DEBUG] AI结果: {json.dumps(ai_result, ensure_ascii=False, indent=2)}")
                else:
                    print(f"  [*] AI分析未启用")

            # 分析结果并决定下一步操作
            self._analyze_and_respond(result)

        # === 新增：行为分析 ===
        print()
        print("[*] 执行行为分析...")
        self._perform_behavior_analysis()

        # 执行威胁情报分析
        print()
        if self.threat_intel.is_enabled():
            print("[*] 执行威胁情报分析...")
            self._perform_threat_intelligence_analysis()
        else:
            print("[*] 威胁情报分析未启用（需要配置API密钥）")

        # === 新增：文件威胁情报分析 ===
        print()
        if self.threat_intel.is_file_analysis_enabled():
            print("[*] 执行文件威胁情报分析...")
            self._perform_file_threat_intelligence_analysis()
        else:
            print("[*] 文件威胁情报分析未启用")

        # === 新增：综合风险评分 ===
        print()
        print("[*] 计算综合风险评分...")
        comprehensive_score = self._calculate_comprehensive_risk()

        # === 新增：AI综合分析（如果启用） ===
        if self.ai_analyzer.is_enabled():
            print()
            print("[*] 生成AI综合分析报告...")
            ai_comprehensive = self.ai_analyzer.get_comprehensive_analysis()
            if ai_comprehensive['total_analyzed'] > 0:
                print(f"  [*] AI共分析 {ai_comprehensive['total_analyzed']} 个脚本输出")
                print(f"  [*] AI识别威胁:")
                print(f"      - 严重: {ai_comprehensive['threats_by_severity']['critical']}")
                print(f"      - 高危: {ai_comprehensive['threats_by_severity']['high']}")
                print(f"      - 中危: {ai_comprehensive['threats_by_severity']['medium']}")
                print(f"      - 低危: {ai_comprehensive['threats_by_severity']['low']}")
                print(f"  [*] AI综合风险评分: {ai_comprehensive['overall_risk_score']}/100")

                # 将AI分析结果纳入综合评分
                if ai_comprehensive['overall_risk_score'] > comprehensive_score['total_score']:
                    print(f"  [!] AI评分高于传统检测，调整综合风险评分")
                    comprehensive_score['total_score'] = max(
                        comprehensive_score['total_score'],
                        ai_comprehensive['overall_risk_score']
                    )
                    comprehensive_score['ai_enhanced'] = True

        # === 新增：自动响应决策 ===
        print()
        if comprehensive_score['total_score'] >= 40:
            print(f"[!] 风险等级: {comprehensive_score['risk_level'].upper()}")
            print(f"[!] 综合风险分数: {comprehensive_score['total_score']}/100")
            print()
            print("[*] 生成响应决策...")
            self._perform_automated_response(comprehensive_score)
        else:
            print(f"[+] 风险等级: {comprehensive_score['risk_level'].upper()}")
            print(f"[+] 综合风险分数: {comprehensive_score['total_score']}/100")
            print("[*] 未发现需要立即响应的威胁")

        # 清理上传的脚本
        print()
        print("[*] 清理远程脚本...")
        self._cleanup_uploaded_scripts()

        return self.results

    def execute_script(self, script_name):
        """执行单个脚本"""
        os_type = self.connector.os_type
        scripts = self.config['scripts'].get(os_type, {})

        if script_name not in scripts:
            error_msg = f"脚本未定义: {script_name}"
            print(f"  [!] {error_msg}")
            return {
                'script': script_name,
                'success': False,
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }

        # 获取脚本相对路径，并基于项目根目录构建绝对路径
        script_relative_path = scripts[script_name]
        local_script_path = self.project_root / script_relative_path

        if not local_script_path.exists():
            error_msg = f"脚本文件不存在: {local_script_path}"
            print(f"  [!] {error_msg}")
            return {
                'script': script_name,
                'success': False,
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            }

        # 读取脚本内容（使用 utf-8-sig 自动处理 BOM）
        with open(local_script_path, 'r', encoding='utf-8-sig') as f:
            script_content = f.read()

        # 根据连接协议选择执行方式
        if self.connector.protocol == 'local':
            # 本地模式：直接执行本地脚本
            print(f"  [*] 直接执行本地脚本...")

            # 构建执行命令
            if os_type == 'windows':
                # Windows: 使用 PowerShell 执行本地脚本
                command = f"powershell.exe -ExecutionPolicy Bypass -File \"{local_script_path}\""
            else:
                # Linux: 直接执行 shell 脚本
                # 确保脚本有执行权限
                import os as os_module
                os_module.chmod(local_script_path, 0o755)
                command = str(local_script_path)

            stdout, stderr, exit_code = self.connector.execute_command(command)

        elif os_type == 'windows':
            # Windows 远程模式: 逐行写入脚本文件，然后执行
            print(f"  [*] 逐行传输脚本到远程主机...")

            remote_script_path = self._get_remote_script_path(script_name)

            # 删除可能存在的旧文件
            cleanup_cmd = f'if (Test-Path "{remote_script_path}") {{ Remove-Item "{remote_script_path}" -Force }}'
            self.connector.execute_command(cleanup_cmd)

            # 将脚本内容逐行写入远程文件
            lines = script_content.split('\n')
            total_lines = len(lines)
            failed_lines = 0

            for line_num, line in enumerate(lines, 1):
                # 只转义单引号（在PowerShell单引号字符串中，只有单引号需要转义）
                # 反引号在单引号字符串中是字面值，不需要转义
                escaped_line = line.replace("'", "''")

                # 使用 Add-Content 追加每一行
                if line_num == 1:
                    # 第一行使用 Set-Content 创建文件（带 UTF8 BOM）
                    ps_cmd = f"Set-Content -Path '{remote_script_path}' -Value '{escaped_line}' -Encoding UTF8"
                else:
                    # 后续行使用 Add-Content 追加
                    ps_cmd = f"Add-Content -Path '{remote_script_path}' -Value '{escaped_line}' -Encoding UTF8"

                stdout, stderr, exit_code = self.connector.execute_command(ps_cmd)

                if exit_code != 0:
                    failed_lines += 1
                    if failed_lines <= 5:  # 只显示前5个错误
                        print(f"    [!] 第 {line_num}/{total_lines} 行写入失败: {stderr[:100]}")

                # 显示进度（每10%）
                if line_num % max(1, total_lines // 10) == 0 or line_num == total_lines:
                    progress = int(line_num / total_lines * 100)
                    print(f"    [*] 进度: {progress}% ({line_num}/{total_lines} 行)")

            if failed_lines > 0:
                error_msg = f"脚本传输失败: {failed_lines}/{total_lines} 行写入失败"
                print(f"  [!] {error_msg}")
                return {
                    'script': script_name,
                    'success': False,
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                }

            print(f"  [+] 脚本传输成功 ({total_lines} 行)")
            print(f"  [*] 执行脚本...")

            # 记录上传的脚本路径，用于后续清理
            self.uploaded_scripts.append(remote_script_path)

            # 执行脚本
            command = self._build_execute_command(remote_script_path)
            stdout, stderr, exit_code = self.connector.execute_command(command)

        else:
            # Linux: 上传文件后执行（保持原有逻辑）
            remote_script_path = self._get_remote_script_path(script_name)

            print(f"  [*] 上传脚本到远程主机: {remote_script_path}")

            # 上传脚本
            if not self.connector.upload_file(str(local_script_path), remote_script_path):
                error_msg = "脚本上传失败"
                print(f"  [!] {error_msg}")
                return {
                    'script': script_name,
                    'success': False,
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                }

            print(f"  [+] 脚本上传成功")
            print(f"  [*] 执行脚本...")

            # 记录上传的脚本路径，用于后续清理
            self.uploaded_scripts.append(remote_script_path)

            # 执行脚本
            command = self._build_execute_command(remote_script_path)
            stdout, stderr, exit_code = self.connector.execute_command(command)

        success = exit_code == 0
        status = "成功" if success else "失败"

        print(f"  [{'  +' if success else '!'}] 执行{status} (退出码: {exit_code})")

        if stdout:
            print(f"  输出预览: {stdout[:200]}...")

        # 如果执行失败，显示完整的stderr
        if not success and stderr:
            print(f"  [!] 错误信息:")
            # 显示完整的stderr内容，每行缩进
            for line in stderr.strip().split('\n'):
                if line.strip():
                    print(f"      {line}")

        result = {
            'script': script_name,
            'success': success,
            'exit_code': exit_code,
            'stdout': stdout,
            'stderr': stderr,
            'timestamp': datetime.now().isoformat()
        }

        return result

    def _get_remote_script_path(self, script_name):
        """获取远程脚本路径"""
        if self.connector.os_type == 'linux':
            return f"/tmp/irt_{script_name}.sh"
        else:
            return f"C:\\Windows\\Temp\\irt_{script_name}.ps1"

    def _build_execute_command(self, script_path):
        """构建执行命令"""
        if self.connector.os_type == 'linux':
            return f"chmod +x {script_path} && {script_path}"
        else:
            # 设置输出编码为 UTF-8，然后执行脚本
            # 这样可以确保中文字符正确显示
            return f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; powershell.exe -ExecutionPolicy Bypass -File {script_path}"

    def _analyze_and_respond(self, result):
        """分析执行结果并采取响应措施"""
        if not result['success']:
            return

        stdout = result.get('stdout', '')

        # 检测可疑进程
        suspicious_pids = self._extract_suspicious_pids(stdout)
        if suspicious_pids:
            print(f"  [!] 发现可疑进程: {suspicious_pids}")
            self._handle_suspicious_processes(suspicious_pids)

        # 检测可疑IP
        suspicious_ips = self._extract_suspicious_ips(stdout)
        if suspicious_ips:
            print(f"  [!] 发现可疑IP: {suspicious_ips}")
            self._handle_suspicious_ips(suspicious_ips)

    def _extract_suspicious_pids(self, output):
        """从输出中提取可疑进程ID"""
        pids = []
        # 查找包含 "suspicious" 或 "高危" 的行，提取PID
        for line in output.split('\n'):
            if 'suspicious' in line.lower() or '高危' in line or '可疑' in line:
                # 尝试提取数字（PID）
                match = re.search(r'\b(\d{2,6})\b', line)
                if match:
                    pids.append(match.group(1))
        return pids

    def _extract_suspicious_ips(self, output):
        """从输出中提取可疑IP地址"""
        ips = []
        # IP地址正则表达式
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

        for line in output.split('\n'):
            if 'suspicious' in line.lower() or '可疑' in line or '异常' in line:
                matches = re.findall(ip_pattern, line)
                ips.extend(matches)

        return list(set(ips))  # 去重

    def _handle_suspicious_processes(self, pids):
        """处理可疑进程"""
        print("  [*] 是否终止可疑进程? (手动确认)")
        # 在实际部署中，这里可以：
        # 1. 记录到日志
        # 2. 发送告警
        # 3. 根据策略自动处理
        # 4. 等待人工确认

    def _handle_suspicious_ips(self, ips):
        """处理可疑IP"""
        print("  [*] 是否阻断可疑IP? (手动确认)")
        # 在实际部署中，这里可以：
        # 1. 记录到日志
        # 2. 发送告警
        # 3. 根据策略自动阻断
        # 4. 等待人工确认

    def execute_custom_action(self, action, params):
        """执行自定义响应动作"""
        print(f"[*] 执行自定义动作: {action}")

        if action == 'kill_process':
            return self._kill_process(params.get('pid'))
        elif action == 'block_ip':
            return self._block_ip(params.get('ip'))
        else:
            print(f"[!] 未知动作: {action}")
            return False

    def _kill_process(self, pid):
        """终止进程"""
        if not pid:
            return False

        script_name = 'kill_process'
        scripts = self.config['scripts'].get(self.connector.os_type, {})

        if script_name in scripts:
            script_path = scripts[script_name]
            # 上传并执行
            # TODO: 实现参数传递
            print(f"  [*] 终止进程: {pid}")
            return True

        # 直接使用系统命令
        if self.connector.os_type == 'linux':
            command = f"kill -9 {pid}"
        else:
            command = f"taskkill /F /PID {pid}"

        stdout, stderr, exit_code = self.connector.execute_command(command)
        return exit_code == 0

    def _block_ip(self, ip):
        """阻断IP地址"""
        if not ip:
            return False

        print(f"  [*] 阻断IP: {ip}")

        if self.connector.os_type == 'linux':
            command = f"iptables -A INPUT -s {ip} -j DROP"
        else:
            command = f"netsh advfirewall firewall add rule name=\"Block_{ip}\" dir=in action=block remoteip={ip}"

        stdout, stderr, exit_code = self.connector.execute_command(command)
        return exit_code == 0

    def _perform_threat_intelligence_analysis(self):
        """执行威胁情报分析"""
        all_ips = []

        # 从所有结果中提取IP地址
        for result in self.results:
            if result.get('success') and result.get('stdout'):
                ips = self.threat_intel.extract_ips_from_text(result['stdout'])
                all_ips.extend(ips)

        # 去重
        unique_ips = list(set(all_ips))

        if not unique_ips:
            print("  [*] 未发现需要分析的外联IP")
            return

        # 批量分析IP
        threat_results = self.threat_intel.batch_analyze_ips(unique_ips)

        # 将威胁情报结果添加到结果中
        for result in self.results:
            if result.get('success') and result.get('stdout'):
                result['threat_intel'] = {}
                ips_in_output = self.threat_intel.extract_ips_from_text(result['stdout'])
                for ip in ips_in_output:
                    if ip in threat_results:
                        result['threat_intel'][ip] = threat_results[ip]

        # 统计恶意IP
        malicious_count = sum(1 for r in threat_results.values() if r.get('is_malicious'))
        print(f"  [*] 威胁情报分析完成: {len(unique_ips)} 个IP, {malicious_count} 个恶意IP")

    def _calculate_file_hashes(self, suspicious_files: List[Dict]) -> List[Dict]:
        """
        计算可疑文件的SHA256哈希值，并下载文件到本地（如果需要上传）

        Args:
            suspicious_files: [{'file_path': ..., ...}, ...]

        Returns:
            [{'file_path': ..., 'file_name': ..., 'hash': 'sha256...', 'size': 1024, 'local_path': ...}, ...]
        """
        import tempfile
        import os

        file_hashes = []
        max_size_bytes = self.threat_intel.max_file_size_mb * 1024 * 1024
        upload_method = self.threat_intel.upload_method

        print(f"  [*] 计算 {len(suspicious_files)} 个可疑文件的哈希值...")

        # 创建临时目录（如果需要下载文件）
        temp_dir = None
        if upload_method in ['auto', 'file_upload']:
            temp_dir = tempfile.mkdtemp(prefix='mcp_irt_')
            print(f"  [*] 临时目录: {temp_dir}")

        for file_info in suspicious_files:
            file_path = file_info.get('file_path')
            if not file_path:
                continue

            try:
                # 获取文件大小
                if self.connector.os_type == 'linux':
                    size_cmd = f"stat -c%s \"{file_path}\" 2>/dev/null || echo 0"
                else:
                    size_cmd = f"(Get-Item \"{file_path}\" -ErrorAction SilentlyContinue).Length"

                stdout, stderr, exit_code = self.connector.execute_command(size_cmd)
                file_size = int(stdout.strip() or 0)

                # 检查文件大小
                if file_size == 0:
                    print(f"    [!] 文件不存在或无法访问: {file_path}")
                    continue

                if file_size > max_size_bytes:
                    print(f"    [!] 文件过大 ({file_size / 1024 / 1024:.1f}MB), 跳过: {file_path}")
                    continue

                # 计算SHA256哈希
                if self.connector.os_type == 'linux':
                    hash_cmd = f"sha256sum \"{file_path}\" 2>/dev/null | awk '{{print $1}}'"
                else:
                    hash_cmd = f"Get-FileHash -Algorithm SHA256 -Path \"{file_path}\" | Select-Object -ExpandProperty Hash"

                stdout, stderr, exit_code = self.connector.execute_command(hash_cmd)
                file_hash = stdout.strip().lower()

                if file_hash and len(file_hash) == 64:  # SHA256是64个字符
                    # 提取文件名
                    file_name = file_path.split('/')[-1] if '/' in file_path else file_path.split('\\')[-1]

                    local_path = None
                    # 如果需要上传文件，则下载到本地
                    if temp_dir and upload_method in ['auto', 'file_upload']:
                        try:
                            local_path = os.path.join(temp_dir, file_name)
                            print(f"    [*] 下载文件到本地...")

                            # 读取远程文件内容
                            if self.connector.os_type == 'linux':
                                read_cmd = f"base64 \"{file_path}\""
                            else:
                                read_cmd = f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{file_path}'))"

                            stdout, stderr, exit_code = self.connector.execute_command(read_cmd)

                            if exit_code == 0 and stdout.strip():
                                import base64
                                file_content = base64.b64decode(stdout.strip())

                                with open(local_path, 'wb') as f:
                                    f.write(file_content)

                                print(f"    [+] 文件已下载到: {local_path}")
                            else:
                                print(f"    [!] 下载文件失败")
                                local_path = None

                        except Exception as e:
                            print(f"    [!] 下载文件异常: {e}")
                            local_path = None

                    file_hashes.append({
                        'file_path': file_path,
                        'file_name': file_name,
                        'hash': file_hash,
                        'size': file_size,
                        'local_path': local_path  # 本地路径（用于上传）
                    })
                    print(f"    [+] {file_name}: {file_hash[:16]}... ({file_size / 1024:.1f}KB)")
                else:
                    print(f"    [!] 无法计算哈希: {file_path}")

            except Exception as e:
                print(f"    [!] 处理文件失败 {file_path}: {e}")

        return file_hashes

    def _perform_file_threat_intelligence_analysis(self):
        """执行文件威胁情报分析"""
        if not self.threat_intel.is_file_analysis_enabled():
            print("  [*] 文件威胁情报分析未启用")
            return

        # 从所有结果中提取可疑文件
        all_suspicious_files = []
        for result in self.results:
            if result.get('success') and result.get('stdout'):
                suspicious_files = self.local_detector.extract_suspicious_files_from_output(
                    result['stdout'],
                    self.connector.os_type
                )
                if suspicious_files:
                    result['suspicious_files'] = suspicious_files
                    all_suspicious_files.extend(suspicious_files)

        if not all_suspicious_files:
            print("  [*] 未发现需要分析的可疑文件")
            return

        print(f"  [*] 发现 {len(all_suspicious_files)} 个可疑文件")

        # 计算文件哈希
        file_hashes = self._calculate_file_hashes(all_suspicious_files)

        if not file_hashes:
            print("  [*] 无可用的文件哈希进行分析")
            return

        # 准备传递给威胁情报分析的数据（使用local_path如果有）
        file_info_for_analysis = []
        for fh in file_hashes:
            file_info_for_analysis.append({
                'hash': fh['hash'],
                'file_name': fh['file_name'],
                'file_path': fh.get('local_path') or fh['file_path'],  # 优先使用本地路径
                'remote_path': fh['file_path']  # 保存远程路径用于报告
            })

        # 批量分析文件哈希
        file_threat_results = self.threat_intel.batch_analyze_file_hashes(file_info_for_analysis)

        # 将文件威胁情报结果添加到result中
        for result in self.results:
            if result.get('suspicious_files'):
                result['file_intel'] = {}

                # 为每个可疑文件匹配威胁情报结果
                for file_info in result['suspicious_files']:
                    file_path = file_info['file_path']

                    # 在file_hashes中查找对应的哈希
                    for fh in file_hashes:
                        if fh['file_path'] == file_path:
                            file_hash = fh['hash']
                            if file_hash in file_threat_results:
                                result['file_intel'][file_path] = file_threat_results[file_hash]
                            break

        # 统计恶意文件
        malicious_count = sum(1 for r in file_threat_results.values() if r.get('is_malicious'))
        print(f"  [*] 文件威胁情报分析完成: {len(file_hashes)} 个文件, {malicious_count} 个恶意文件")

    def _cleanup_uploaded_scripts(self):
        """清理上传到远程主机的脚本"""
        if not self.uploaded_scripts:
            print("  [*] 无需清理")
            return

        cleaned = 0
        failed = 0

        for script_path in self.uploaded_scripts:
            try:
                if self.connector.os_type == 'linux':
                    command = f"rm -f {script_path}"
                else:
                    # Windows: 使用PowerShell的Remove-Item命令
                    # 使用Test-Path验证删除结果，返回明确的退出码
                    command = f"""
                    if (Test-Path '{script_path}') {{
                        Remove-Item -Path '{script_path}' -Force -ErrorAction Stop
                        if (Test-Path '{script_path}') {{ exit 1 }} else {{ exit 0 }}
                    }} else {{
                        exit 0
                    }}
                    """.strip()

                stdout, stderr, exit_code = self.connector.execute_command(command)

                if exit_code == 0:
                    cleaned += 1
                else:
                    failed += 1
                    print(f"  [!] 清理失败: {script_path}")
                    if stderr:
                        print(f"      错误: {stderr.strip()}")

            except Exception as e:
                failed += 1
                print(f"  [!] 清理异常: {script_path} - {e}")

        print(f"  [+] 已清理 {cleaned} 个脚本" + (f", {failed} 个失败" if failed > 0 else ""))

    # ==================== 新增：本地威胁检测方法 ====================

    def _perform_local_threat_detection(self, result: dict, script_name: str) -> list:
        """
        执行本地威胁检测（不依赖外部威胁情报）

        Args:
            result: 脚本执行结果
            script_name: 脚本名称

        Returns:
            威胁列表
        """
        threats = []
        stdout = result.get('stdout', '')

        if not stdout:
            return threats

        # 根据脚本类型选择不同的检测方法
        if 'process' in script_name:
            # 进程检查：提取进程信息并分析
            processes = self.local_detector.extract_process_info_from_output(
                stdout,
                self.connector.os_type
            )

            for proc in processes:
                analysis = self.local_detector.analyze_process(proc)
                if analysis['is_suspicious']:
                    threats.append({
                        'type': 'suspicious_process',
                        'pid': proc.get('pid'),
                        'name': proc.get('name'),
                        'threat_score': analysis['threat_score'],
                        'threat_type': analysis['threat_type'],
                        'confidence': analysis['confidence'],
                        'indicators': analysis['indicators'],
                        'severity': analysis.get('severity', 'unknown')
                    })
                    print(f"    [!] 可疑进程: {proc.get('name')} (PID: {proc.get('pid')}) "
                          f"- 威胁分数: {analysis['threat_score']}")

        elif 'network' in script_name:
            # 网络检查：提取连接信息并分析
            connections = self.local_detector.extract_network_info_from_output(
                stdout,
                self.connector.os_type
            )

            for conn in connections:
                analysis = self.local_detector.analyze_network_connection(conn)
                if analysis['is_suspicious']:
                    threats.append({
                        'type': 'suspicious_connection',
                        'remote_ip': conn.get('remote_ip'),
                        'remote_port': conn.get('remote_port'),
                        'local_port': conn.get('local_port'),
                        'threat_score': analysis['threat_score'],
                        'indicators': analysis['indicators'],
                        'connection_type': analysis['connection_type']
                    })
                    print(f"    [!] 可疑连接: {conn.get('remote_ip')}:{conn.get('remote_port')} "
                          f"- 威胁分数: {analysis['threat_score']}")

        # 通用检测：检查常见后门特征
        common_threats = self._check_for_common_backdoors(stdout)
        threats.extend(common_threats)

        return threats

    def _check_for_common_backdoors(self, output: str) -> list:
        """检查常见后门特征"""
        threats = []

        # MSF Meterpreter检测
        if re.search(r':4444\s|:4445\s|:5555\s|:6666\s', output):
            threats.append({
                'type': 'backdoor_signature',
                'threat_type': 'meterpreter',
                'threat_score': 85,
                'confidence': 'high',
                'indicators': ['检测到MSF默认端口 (4444/5555/6666)'],
                'severity': 'critical'
            })

        if re.search(r'meterpreter|msfvenom|msf', output, re.I):
            threats.append({
                'type': 'backdoor_signature',
                'threat_type': 'meterpreter',
                'threat_score': 90,
                'confidence': 'high',
                'indicators': ['检测到Meterpreter相关进程名称'],
                'severity': 'critical'
            })

        # 反弹Shell检测
        if re.search(r'bash\s+-i|sh\s+-i|nc\s+-e|/dev/tcp/', output):
            threats.append({
                'type': 'backdoor_signature',
                'threat_type': 'reverse_shell',
                'threat_score': 85,
                'confidence': 'high',
                'indicators': ['检测到反向Shell特征'],
                'severity': 'critical'
            })

        # Cobalt Strike检测
        if re.search(r':50050|beacon\.exe|\\\\\.\\pipe\\MSSE', output, re.I):
            threats.append({
                'type': 'backdoor_signature',
                'threat_type': 'cobaltstrike',
                'threat_score': 90,
                'confidence': 'high',
                'indicators': ['检测到Cobalt Strike特征'],
                'severity': 'critical'
            })

        # 挖矿检测
        if re.search(r'xmrig|minergate|stratum\+tcp', output, re.I):
            threats.append({
                'type': 'backdoor_signature',
                'threat_type': 'mining',
                'threat_score': 75,
                'confidence': 'high',
                'indicators': ['检测到挖矿程序特征'],
                'severity': 'high'
            })

        # WebShell检测
        if re.search(r'c99\.php|r57\.php|wso\.php|shell\.php', output, re.I):
            threats.append({
                'type': 'backdoor_signature',
                'threat_type': 'webshell',
                'threat_score': 80,
                'confidence': 'high',
                'indicators': ['检测到WebShell文件'],
                'severity': 'high'
            })

        return threats

    def _perform_behavior_analysis(self):
        """执行行为分析"""
        # 收集所有进程信息
        all_processes = []
        all_connections = []

        for result in self.results:
            if result.get('success') and result.get('stdout'):
                script_name = result.get('script', '')

                if 'process' in script_name:
                    procs = self.local_detector.extract_process_info_from_output(
                        result['stdout'],
                        self.connector.os_type
                    )
                    all_processes.extend(procs)

                elif 'network' in script_name:
                    conns = self.local_detector.extract_network_info_from_output(
                        result['stdout'],
                        self.connector.os_type
                    )
                    all_connections.extend(conns)

        # 进程树分析
        if all_processes:
            print(f"  [*] 分析进程树 ({len(all_processes)} 个进程)...")
            process_tree_analysis = self.behavior_analyzer.analyze_process_tree(all_processes)
            self.behavior_analysis['process_tree'] = process_tree_analysis

            if process_tree_analysis['risk_score'] > 0:
                print(f"  [!] 进程树风险分数: {process_tree_analysis['risk_score']}/100")
                if process_tree_analysis['suspicious_chains']:
                    print(f"  [!] 发现 {len(process_tree_analysis['suspicious_chains'])} 个可疑进程链")

        # 网络时序分析
        if all_connections:
            print(f"  [*] 分析网络时序 ({len(all_connections)} 个连接)...")
            network_analysis = self.behavior_analyzer.analyze_network_timeline(all_connections)
            self.behavior_analysis['network_timeline'] = network_analysis

            if network_analysis['risk_score'] > 0:
                print(f"  [!] 网络行为风险分数: {network_analysis['risk_score']}/100")
                if network_analysis['heartbeat_detected']:
                    print(f"  [!] 检测到心跳包通信（可能是Beacon）")

    def _calculate_comprehensive_risk(self) -> dict:
        """计算综合风险分数"""
        all_indicators = {}

        # 1. 本地检测分数
        if self.detected_threats:
            local_score = min(
                sum(t.get('threat_score', 0) for t in self.detected_threats) / len(self.detected_threats),
                100
            )
            all_indicators['local_detection'] = {'risk_score': local_score}
        else:
            all_indicators['local_detection'] = {'risk_score': 0}

        # 2. 行为分析分数
        behavior_scores = []
        if 'process_tree' in self.behavior_analysis:
            behavior_scores.append(self.behavior_analysis['process_tree'].get('risk_score', 0))
        if 'network_timeline' in self.behavior_analysis:
            behavior_scores.append(self.behavior_analysis['network_timeline'].get('risk_score', 0))

        all_indicators['behavior_analysis'] = {
            'risk_score': sum(behavior_scores) / len(behavior_scores) if behavior_scores else 0
        }

        # 3. 威胁情报分数（从已有的威胁情报分析结果中提取）
        threat_intel_score = 0
        for result in self.results:
            if 'threat_intel' in result:
                for ip, intel_data in result['threat_intel'].items():
                    if intel_data.get('is_malicious'):
                        threat_intel_score = max(threat_intel_score, intel_data.get('threat_score', 0))

        all_indicators['threat_intel'] = {'risk_score': threat_intel_score}

        # 使用行为分析器计算综合分数
        comprehensive = self.behavior_analyzer.calculate_comprehensive_risk_score({
            'process_analysis': all_indicators.get('local_detection', {}),
            'network_analysis': all_indicators.get('behavior_analysis', {}),
            'threat_intel': all_indicators.get('threat_intel', {})
        })

        return comprehensive

    def _perform_automated_response(self, comprehensive_score: dict):
        """执行自动化响应"""
        # 收集受影响的资源
        affected_resources = {
            'processes': [],
            'ips': [],
            'files': []
        }

        # 从检测到的威胁中提取受影响资源
        for threat in self.detected_threats:
            if threat.get('type') == 'suspicious_process':
                affected_resources['processes'].append({
                    'pid': threat.get('pid'),
                    'name': threat.get('name'),
                    'threat_score': threat.get('threat_score'),
                    'threat_type': threat.get('threat_type')
                })

            elif threat.get('type') == 'suspicious_connection':
                ip = threat.get('remote_ip')
                if ip and ip not in affected_resources['ips']:
                    affected_resources['ips'].append(ip)

        # 构建威胁分析摘要
        threat_analysis = {
            'threat_score': comprehensive_score['total_score'],
            'threat_type': self._get_primary_threat_type(),
            'confidence': 'high' if comprehensive_score['total_score'] >= 70 else 'medium',
            'indicators': [t.get('indicators', []) for t in self.detected_threats],
            'affected_resources': affected_resources
        }

        # 生成响应决策
        response_decision = self.response_engine.decide_response(threat_analysis)

        print(f"  [*] 响应等级: {response_decision['response_level'].upper()}")
        print(f"  [*] 优先级: {response_decision['priority']}")
        print(f"  [*] 建议动作: {', '.join(response_decision['recommended_actions'])}")
        print(f"  [*] 自动执行动作: {len(response_decision['auto_actions'])} 个")
        print(f"  [*] 需要审批动作: {len(response_decision['manual_actions'])} 个")
        print()

        # 执行自动响应动作
        if response_decision['auto_actions']:
            response_result = self.response_engine.execute_response(
                response_decision,
                self.connector,
                affected_resources
            )

            self.response_actions_taken.append({
                'timestamp': datetime.now().isoformat(),
                'decision': response_decision,
                'result': response_result
            })

            print()
            print(f"  [+] 已执行 {len(response_result['executed_actions'])} 个自动响应动作")
            if response_result['failed_actions']:
                print(f"  [!] {len(response_result['failed_actions'])} 个动作执行失败")

        # 打印需要手动确认的动作
        if response_decision['manual_actions']:
            print()
            print("  [*] 以下动作需要手动确认:")
            for action in response_decision['manual_actions']:
                print(f"      - {action}")

    def _get_primary_threat_type(self) -> str:
        """获取主要威胁类型"""
        if not self.detected_threats:
            return 'unknown'

        # 统计威胁类型出现次数
        threat_types = [t.get('threat_type', 'unknown') for t in self.detected_threats]
        most_common = max(set(threat_types), key=threat_types.count)

        return most_common

    def _perform_ai_analysis(self, result: dict, script_name: str) -> dict:
        """
        执行AI分析

        Args:
            result: 脚本执行结果
            script_name: 脚本名称

        Returns:
            AI分析结果
        """
        stdout = result.get('stdout', '')

        if not stdout:
            return {
                'analyzed': False,
                'reason': 'No output to analyze'
            }

        # 调用AI分析器
        ai_result = self.ai_analyzer.analyze_script_output(
            script_name=script_name,
            script_output=stdout,
            os_type=self.connector.os_type,
            context={
                'exit_code': result.get('exit_code'),
                'success': result.get('success'),
                'timestamp': result.get('timestamp')
            }
        )

        # 保存AI分析结果
        if ai_result.get('analyzed'):
            self.ai_analysis_results.append(ai_result)

        return ai_result

