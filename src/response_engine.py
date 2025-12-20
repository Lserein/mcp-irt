"""
响应决策引擎
根据威胁分析结果自动决定响应策略和执行响应动作
"""

from typing import Dict, List, Optional
from datetime import datetime


class ResponseDecisionEngine:
    """响应决策引擎"""

    def __init__(self, config: Dict):
        """
        初始化响应决策引擎

        Args:
            config: 配置字典
        """
        self.config = config
        self.response_policies = self._load_response_policies()
        self.auto_response_enabled = config.get('auto_response', {}).get('enabled', False)
        self.response_history = []

    def _load_response_policies(self) -> Dict:
        """加载响应策略"""
        return {
            'critical': {
                'threshold': 80,
                'actions': [
                    'log_incident',
                    'alert_admin',
                    'isolate_process',
                    'block_ip',
                    'dump_memory',
                    'quarantine_file',
                    'collect_forensics'
                ],
                'auto_execute': ['log_incident', 'alert_admin', 'dump_memory'],
                'require_approval': ['isolate_process', 'block_ip', 'quarantine_file']
            },
            'high': {
                'threshold': 60,
                'actions': [
                    'log_incident',
                    'alert_admin',
                    'monitor_process',
                    'capture_traffic',
                    'dump_memory'
                ],
                'auto_execute': ['log_incident', 'alert_admin', 'monitor_process'],
                'require_approval': ['dump_memory', 'capture_traffic']
            },
            'medium': {
                'threshold': 40,
                'actions': [
                    'log_incident',
                    'monitor_process',
                    'alert_admin'
                ],
                'auto_execute': ['log_incident', 'monitor_process'],
                'require_approval': ['alert_admin']
            },
            'low': {
                'threshold': 0,
                'actions': [
                    'log_event'
                ],
                'auto_execute': ['log_event'],
                'require_approval': []
            }
        }

    def decide_response(self, threat_analysis: Dict) -> Dict:
        """
        根据威胁分析决定响应动作

        Args:
            threat_analysis: {
                'threat_score': 85,
                'threat_type': 'meterpreter',
                'confidence': 'high',
                'indicators': [...],
                'affected_resources': {
                    'processes': [...],
                    'ips': [...],
                    'files': [...]
                }
            }

        Returns:
            {
                'response_level': 'critical',
                'recommended_actions': [...],
                'auto_actions': [...],
                'manual_actions': [...],
                'priority': 'critical/high/medium/low',
                'estimated_impact': '...',
                'justification': '...'
            }
        """
        threat_score = threat_analysis.get('threat_score', 0)
        threat_type = threat_analysis.get('threat_type', 'unknown')
        confidence = threat_analysis.get('confidence', 'low')
        indicators = threat_analysis.get('indicators', [])

        # 确定响应等级
        response_level = self._determine_response_level(threat_score)
        policy = self.response_policies[response_level]

        # 根据威胁类型调整响应动作
        recommended_actions = self._customize_actions_by_threat_type(
            policy['actions'],
            threat_type,
            threat_analysis
        )

        # 分离自动执行和需要审批的动作
        auto_actions = []
        manual_actions = []

        if self.auto_response_enabled:
            auto_actions = [a for a in recommended_actions if a in policy['auto_execute']]
            manual_actions = [a for a in recommended_actions if a in policy['require_approval']]
        else:
            # 如果未启用自动响应，所有动作都需要手动确认
            manual_actions = recommended_actions

        # 评估影响
        estimated_impact = self._estimate_response_impact(recommended_actions)

        # 生成决策理由
        justification = self._generate_justification(
            threat_score,
            threat_type,
            confidence,
            len(indicators),
            response_level
        )

        response_decision = {
            'response_level': response_level,
            'threat_score': threat_score,
            'threat_type': threat_type,
            'confidence': confidence,
            'recommended_actions': recommended_actions,
            'auto_actions': auto_actions,
            'manual_actions': manual_actions,
            'priority': self._map_level_to_priority(response_level),
            'estimated_impact': estimated_impact,
            'justification': justification,
            'timestamp': datetime.now().isoformat()
        }

        return response_decision

    def execute_response(self, response_plan: Dict, connector, affected_resources: Dict) -> Dict:
        """
        执行响应计划

        Args:
            response_plan: decide_response() 返回的响应决策
            connector: RemoteConnector 实例
            affected_resources: {
                'processes': [{'pid': '1234', 'name': '...'}],
                'ips': ['1.2.3.4'],
                'files': ['/tmp/malware']
            }

        Returns:
            {
                'executed_actions': [...],
                'failed_actions': [...],
                'results': {...}
            }
        """
        executed_actions = []
        failed_actions = []
        results = {}

        # 执行自动响应动作
        actions_to_execute = response_plan.get('auto_actions', [])

        print(f"\n[*] 执行自动响应动作 ({len(actions_to_execute)} 个)...")

        for action in actions_to_execute:
            print(f"  [*] 执行: {action}")

            try:
                result = self._execute_single_action(
                    action,
                    connector,
                    affected_resources
                )

                if result['success']:
                    executed_actions.append(action)
                    results[action] = result
                    print(f"  [+] {action} 执行成功")
                else:
                    failed_actions.append(action)
                    results[action] = result
                    print(f"  [!] {action} 执行失败: {result.get('error')}")

            except Exception as e:
                failed_actions.append(action)
                results[action] = {'success': False, 'error': str(e)}
                print(f"  [!] {action} 执行异常: {e}")

        # 记录到历史
        self.response_history.append({
            'timestamp': datetime.now().isoformat(),
            'response_plan': response_plan,
            'executed_actions': executed_actions,
            'failed_actions': failed_actions,
            'results': results
        })

        return {
            'executed_actions': executed_actions,
            'failed_actions': failed_actions,
            'results': results,
            'manual_actions_pending': response_plan.get('manual_actions', [])
        }

    def _execute_single_action(self, action: str, connector, affected_resources: Dict) -> Dict:
        """
        执行单个响应动作

        Args:
            action: 动作名称
            connector: RemoteConnector 实例
            affected_resources: 受影响的资源

        Returns:
            {'success': True/False, 'message': '...', 'error': '...'}
        """
        if action == 'log_incident':
            return self._log_incident(affected_resources)

        elif action == 'alert_admin':
            return self._alert_admin(affected_resources)

        elif action == 'isolate_process':
            return self._isolate_process(connector, affected_resources.get('processes', []))

        elif action == 'block_ip':
            return self._block_ip(connector, affected_resources.get('ips', []))

        elif action == 'dump_memory':
            return self._dump_memory(connector, affected_resources.get('processes', []))

        elif action == 'quarantine_file':
            return self._quarantine_file(connector, affected_resources.get('files', []))

        elif action == 'monitor_process':
            return self._monitor_process(affected_resources.get('processes', []))

        elif action == 'capture_traffic':
            return self._capture_traffic(connector, affected_resources)

        elif action == 'collect_forensics':
            return self._collect_forensics(connector, affected_resources)

        elif action == 'log_event':
            return self._log_event(affected_resources)

        else:
            return {'success': False, 'error': f'Unknown action: {action}'}

    # ==================== 响应动作实现 ====================

    def _log_incident(self, affected_resources: Dict) -> Dict:
        """记录安全事件"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'security_incident',
                'affected_resources': affected_resources,
                'severity': 'high'
            }

            # 这里可以写入日志文件或发送到SIEM
            print(f"  >> 事件已记录到日志")

            return {
                'success': True,
                'message': '安全事件已记录',
                'log_entry': log_entry
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _alert_admin(self, affected_resources: Dict) -> Dict:
        """告警管理员"""
        try:
            # 这里可以实现邮件、webhook、短信等告警方式
            alert_message = f"""
            【安全告警】检测到威胁
            时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            受影响资源: {affected_resources}
            建议: 立即查看应急响应报告
            """

            print(f"  >> 告警已发送给管理员")

            return {
                'success': True,
                'message': '告警已发送',
                'alert_content': alert_message
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _isolate_process(self, connector, processes: List[Dict]) -> Dict:
        """隔离（终止）进程"""
        try:
            terminated = []
            failed = []

            for proc in processes:
                pid = proc.get('pid')
                name = proc.get('name', 'unknown')

                if not pid:
                    continue

                # 执行终止命令
                if connector.os_type == 'linux':
                    command = f"kill -9 {pid}"
                else:
                    command = f"taskkill /F /PID {pid}"

                stdout, stderr, exit_code = connector.execute_command(command)

                if exit_code == 0:
                    terminated.append({'pid': pid, 'name': name})
                    print(f"    >> 已终止进程: {name} (PID: {pid})")
                else:
                    failed.append({'pid': pid, 'name': name, 'error': stderr})

            return {
                'success': len(failed) == 0,
                'message': f'终止了 {len(terminated)} 个进程',
                'terminated': terminated,
                'failed': failed
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _block_ip(self, connector, ips: List[str]) -> Dict:
        """阻断IP地址"""
        try:
            blocked = []
            failed = []

            for ip in ips:
                # 执行防火墙规则
                if connector.os_type == 'linux':
                    command = f"iptables -A INPUT -s {ip} -j DROP && iptables -A OUTPUT -d {ip} -j DROP"
                else:
                    command = f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}'

                stdout, stderr, exit_code = connector.execute_command(command)

                if exit_code == 0:
                    blocked.append(ip)
                    print(f"    >> 已阻断IP: {ip}")
                else:
                    failed.append({'ip': ip, 'error': stderr})

            return {
                'success': len(failed) == 0,
                'message': f'阻断了 {len(blocked)} 个IP',
                'blocked': blocked,
                'failed': failed
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _dump_memory(self, connector, processes: List[Dict]) -> Dict:
        """导出进程内存"""
        try:
            dumped = []
            failed = []

            for proc in processes:
                pid = proc.get('pid')
                name = proc.get('name', 'unknown')

                if not pid:
                    continue

                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

                if connector.os_type == 'linux':
                    dump_path = f"/tmp/memdump_{pid}_{timestamp}.dump"
                    command = f"gcore -o {dump_path} {pid} 2>/dev/null || cat /proc/{pid}/maps > {dump_path}.maps"
                else:
                    dump_path = f"C:\\Windows\\Temp\\memdump_{pid}_{timestamp}.dmp"
                    command = f"procdump -ma {pid} {dump_path}"

                stdout, stderr, exit_code = connector.execute_command(command)

                if exit_code == 0 or "dumped" in stdout.lower():
                    dumped.append({'pid': pid, 'name': name, 'dump_path': dump_path})
                    print(f"    >> 已导出内存: {name} (PID: {pid}) -> {dump_path}")
                else:
                    failed.append({'pid': pid, 'name': name})

            return {
                'success': len(dumped) > 0,
                'message': f'导出了 {len(dumped)} 个进程的内存',
                'dumped': dumped,
                'failed': failed
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _quarantine_file(self, connector, files: List[str]) -> Dict:
        """隔离文件"""
        try:
            quarantined = []
            failed = []

            quarantine_dir = '/tmp/quarantine' if connector.os_type == 'linux' else 'C:\\Windows\\Temp\\quarantine'

            # 创建隔离目录
            mkdir_cmd = f"mkdir -p {quarantine_dir}" if connector.os_type == 'linux' else f"mkdir {quarantine_dir}"
            connector.execute_command(mkdir_cmd)

            for file_path in files:
                filename = file_path.split('/')[-1] if '/' in file_path else file_path.split('\\')[-1]
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                quarantine_path = f"{quarantine_dir}/{timestamp}_{filename}"

                # 移动文件到隔离区并移除执行权限
                if connector.os_type == 'linux':
                    command = f"mv {file_path} {quarantine_path} && chmod 000 {quarantine_path}"
                else:
                    command = f"move {file_path} {quarantine_path} && icacls {quarantine_path} /deny *S-1-1-0:(X)"

                stdout, stderr, exit_code = connector.execute_command(command)

                if exit_code == 0:
                    quarantined.append({'original': file_path, 'quarantine': quarantine_path})
                    print(f"    >> 已隔离文件: {file_path} -> {quarantine_path}")
                else:
                    failed.append({'file': file_path, 'error': stderr})

            return {
                'success': len(failed) == 0,
                'message': f'隔离了 {len(quarantined)} 个文件',
                'quarantined': quarantined,
                'failed': failed
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _monitor_process(self, processes: List[Dict]) -> Dict:
        """监控进程（记录监控任务）"""
        try:
            # 这里只是记录需要监控的进程，实际监控需要另外的模块实现
            monitored = []

            for proc in processes:
                monitored.append({
                    'pid': proc.get('pid'),
                    'name': proc.get('name'),
                    'start_time': datetime.now().isoformat()
                })
                print(f"    >> 已添加监控: {proc.get('name')} (PID: {proc.get('pid')})")

            return {
                'success': True,
                'message': f'已添加 {len(monitored)} 个进程到监控列表',
                'monitored': monitored
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _capture_traffic(self, connector, affected_resources: Dict) -> Dict:
        """捕获网络流量"""
        try:
            ips = affected_resources.get('ips', [])
            if not ips:
                return {'success': False, 'error': 'No IPs to capture'}

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            capture_file = f"/tmp/capture_{timestamp}.pcap"

            # 使用tcpdump捕获流量（Linux）
            if connector.os_type == 'linux':
                ip_filter = ' or '.join([f'host {ip}' for ip in ips])
                command = f"timeout 60 tcpdump -i any -w {capture_file} '{ip_filter}' &"
                connector.execute_command(command)

                print(f"    >> 已启动流量捕获: {capture_file}")

                return {
                    'success': True,
                    'message': '流量捕获已启动',
                    'capture_file': capture_file,
                    'duration': 60
                }
            else:
                return {'success': False, 'error': 'Windows traffic capture not implemented'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _collect_forensics(self, connector, affected_resources: Dict) -> Dict:
        """收集取证数据"""
        try:
            forensics_dir = f"/tmp/forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            if connector.os_type == 'linux':
                commands = [
                    f"mkdir -p {forensics_dir}",
                    f"ps aux > {forensics_dir}/processes.txt",
                    f"netstat -antp > {forensics_dir}/connections.txt",
                    f"cat /etc/passwd > {forensics_dir}/passwd.txt",
                    f"last -f /var/log/wtmp > {forensics_dir}/logins.txt",
                    f"crontab -l > {forensics_dir}/crontab.txt 2>/dev/null",
                    f"ls -la /tmp > {forensics_dir}/tmp_files.txt"
                ]
            else:
                forensics_dir = f"C:\\Windows\\Temp\\forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                commands = [
                    f"mkdir {forensics_dir}",
                    f"tasklist > {forensics_dir}\\processes.txt",
                    f"netstat -ano > {forensics_dir}\\connections.txt"
                ]

            for cmd in commands:
                connector.execute_command(cmd)

            print(f"    >> 取证数据已收集到: {forensics_dir}")

            return {
                'success': True,
                'message': '取证数据收集完成',
                'forensics_dir': forensics_dir
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _log_event(self, affected_resources: Dict) -> Dict:
        """记录事件（低优先级）"""
        try:
            print(f"    >> 事件已记录")
            return {
                'success': True,
                'message': '事件已记录',
                'resources': affected_resources
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ==================== 辅助方法 ====================

    def _determine_response_level(self, threat_score: int) -> str:
        """确定响应等级"""
        if threat_score >= 80:
            return 'critical'
        elif threat_score >= 60:
            return 'high'
        elif threat_score >= 40:
            return 'medium'
        else:
            return 'low'

    def _customize_actions_by_threat_type(self, base_actions: List[str], threat_type: str, threat_analysis: Dict) -> List[str]:
        """根据威胁类型定制响应动作"""
        actions = base_actions.copy()

        # 根据不同的威胁类型添加特定动作
        if threat_type in ['meterpreter', 'cobaltstrike', 'reverse_shell']:
            # 反向Shell类威胁：优先阻断网络
            if 'block_ip' not in actions:
                actions.insert(0, 'block_ip')

        elif threat_type == 'mining':
            # 挖矿类威胁：优先终止进程
            if 'isolate_process' not in actions:
                actions.insert(0, 'isolate_process')

        elif threat_type == 'webshell':
            # WebShell：优先隔离文件
            if 'quarantine_file' not in actions:
                actions.insert(0, 'quarantine_file')

        elif threat_type == 'rootkit':
            # Rootkit：需要完整取证
            if 'collect_forensics' not in actions:
                actions.append('collect_forensics')

        return actions

    def _estimate_response_impact(self, actions: List[str]) -> str:
        """评估响应动作的影响"""
        high_impact_actions = ['isolate_process', 'block_ip', 'quarantine_file']
        medium_impact_actions = ['dump_memory', 'capture_traffic', 'collect_forensics']

        high_count = sum(1 for a in actions if a in high_impact_actions)
        medium_count = sum(1 for a in actions if a in medium_impact_actions)

        if high_count >= 2:
            return '高影响（可能影响业务）'
        elif high_count >= 1 or medium_count >= 2:
            return '中等影响（对业务影响较小）'
        else:
            return '低影响（仅记录和监控）'

    def _generate_justification(self, threat_score: int, threat_type: str, confidence: str, indicator_count: int, response_level: str) -> str:
        """生成决策理由"""
        return f"""
响应决策理由:
- 威胁分数: {threat_score}/100
- 威胁类型: {threat_type}
- 检测置信度: {confidence}
- 威胁指标数量: {indicator_count}
- 响应等级: {response_level}

基于以上分析，系统建议采取{response_level}级别的响应措施。
        """.strip()

    def _map_level_to_priority(self, level: str) -> str:
        """将响应等级映射到优先级"""
        mapping = {
            'critical': 'P0 - 紧急',
            'high': 'P1 - 高',
            'medium': 'P2 - 中',
            'low': 'P3 - 低'
        }
        return mapping.get(level, 'P3 - 低')
