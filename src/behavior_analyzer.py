"""
行为分析引擎
分析进程树、网络时序、文件操作等行为模式
"""

import re
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from datetime import datetime


class BehaviorAnalyzer:
    """行为分析引擎"""

    def __init__(self, whitelist: Optional[Dict] = None):
        """初始化行为分析器

        Args:
            whitelist: 白名单配置（可选）
        """
        self.baseline = None
        self.anomalies = []
        self.whitelist = whitelist or {}

    def analyze_process_tree(self, processes: List[Dict]) -> Dict:
        """
        分析进程树异常

        Args:
            processes: [{
                'pid': '1234',
                'ppid': '1000',
                'name': 'bash',
                'cmdline': '...',
                'user': 'root',
                'start_time': '...'
            }, ...]

        Returns:
            {
                'orphan_processes': [...],
                'suspicious_chains': [...],
                'privilege_escalation': [...],
                'risk_score': 0-100
            }
        """
        result = {
            'orphan_processes': [],
            'suspicious_chains': [],
            'privilege_escalation': [],
            'anomalies': [],
            'risk_score': 0
        }

        # 构建进程映射
        process_map = {p['pid']: p for p in processes}

        # 1. 检查孤儿进程
        orphans = self._find_orphan_processes(processes, process_map)
        result['orphan_processes'] = orphans
        if orphans:
            result['risk_score'] += 10 * len(orphans)

        # 2. 检查可疑进程链
        suspicious_chains = self._find_suspicious_chains(processes, process_map)
        result['suspicious_chains'] = suspicious_chains
        if suspicious_chains:
            result['risk_score'] += 25 * len(suspicious_chains)

        # 3. 检查权限提升迹象
        privilege_escalation = self._detect_privilege_escalation(processes, process_map)
        result['privilege_escalation'] = privilege_escalation
        if privilege_escalation:
            result['risk_score'] += 30 * len(privilege_escalation)

        # 4. 检查进程启动时间异常
        time_anomalies = self._check_process_timing_anomalies(processes)
        result['anomalies'].extend(time_anomalies)
        if time_anomalies:
            result['risk_score'] += 5 * len(time_anomalies)

        # 限制分数在0-100之间
        result['risk_score'] = min(result['risk_score'], 100)

        return result

    def analyze_network_timeline(self, connections: List[Dict]) -> Dict:
        """
        分析网络连接时间线

        Args:
            connections: [{
                'timestamp': '2024-01-01 10:00:00',
                'local_ip': '192.168.1.100',
                'local_port': 22,
                'remote_ip': '10.0.0.1',
                'remote_port': 4444,
                'state': 'ESTABLISHED',
                'bytes_sent': 1024,
                'bytes_recv': 2048
            }, ...]

        Returns:
            {
                'heartbeat_detected': True/False,
                'data_exfiltration': True/False,
                'port_scanning': True/False,
                'indicators': [...],
                'risk_score': 0-100
            }
        """
        result = {
            'heartbeat_detected': False,
            'data_exfiltration': False,
            'port_scanning': False,
            'beacon_connections': [],
            'large_uploads': [],
            'scan_activities': [],
            'indicators': [],
            'risk_score': 0
        }

        # 按远程IP分组连接
        connections_by_ip = defaultdict(list)
        whitelist_ips = self.whitelist.get('ips', [])

        for conn in connections:
            remote_ip = conn.get('remote_ip', 'unknown')
            # 跳过白名单IP
            if remote_ip not in whitelist_ips:
                connections_by_ip[remote_ip].append(conn)

        # 1. 检测心跳包（Beacon）
        for ip, conns in connections_by_ip.items():
            if self._is_private_ip(ip):
                continue

            heartbeat = self._detect_heartbeat_pattern(conns)
            if heartbeat:
                result['heartbeat_detected'] = True
                result['beacon_connections'].append({
                    'remote_ip': ip,
                    'interval': heartbeat['interval'],
                    'packet_count': len(conns),
                    'confidence': heartbeat['confidence']
                })
                result['indicators'].append(f"检测到心跳包特征: {ip} (间隔: {heartbeat['interval']}秒)")
                result['risk_score'] += 40

        # 2. 检测数据渗出（排除白名单IP）
        filtered_connections = [c for c in connections if c.get('remote_ip') not in whitelist_ips]
        exfil = self._detect_data_exfiltration(filtered_connections)
        if exfil:
            result['data_exfiltration'] = True
            result['large_uploads'] = exfil['uploads']
            result['indicators'].extend(exfil['indicators'])
            result['risk_score'] += 35

        # 3. 检测端口扫描（排除白名单IP）
        scan = self._detect_port_scanning(filtered_connections)
        if scan:
            result['port_scanning'] = True
            result['scan_activities'] = scan['scans']
            result['indicators'].extend(scan['indicators'])
            result['risk_score'] += 25

        result['risk_score'] = min(result['risk_score'], 100)

        return result

    def analyze_file_operations(self, file_events: List[Dict]) -> Dict:
        """
        分析文件操作行为

        Args:
            file_events: [{
                'timestamp': '2024-01-01 10:00:00',
                'operation': 'create/modify/delete',
                'file_path': '/tmp/malware',
                'process': 'bash',
                'user': 'root'
            }, ...]

        Returns:
            {
                'suspicious_files': [...],
                'webshell_candidates': [...],
                'privilege_files_modified': [...],
                'risk_score': 0-100
            }
        """
        result = {
            'suspicious_files': [],
            'webshell_candidates': [],
            'privilege_files_modified': [],
            'persistence_mechanisms': [],
            'indicators': [],
            'risk_score': 0
        }

        suspicious_paths = [
            '/tmp/',
            '/dev/shm/',
            '/var/tmp/',
            'C:\\Windows\\Temp',
            'C:\\Users\\Public'
        ]

        webshell_patterns = [
            r'\.php$',
            r'\.jsp$',
            r'\.aspx$',
            r'shell',
            r'cmd',
            r'eval'
        ]

        privilege_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/root/.ssh/authorized_keys',
            '/etc/crontab'
        ]

        persistence_locations = [
            '/etc/rc.local',
            '/etc/init.d/',
            '.bashrc',
            '.bash_profile',
            '/etc/systemd/system/',
            'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
        ]

        for event in file_events:
            file_path = event.get('file_path', '')
            operation = event.get('operation', '')
            process = event.get('process', '')

            # 1. 检查可疑路径的文件
            for sus_path in suspicious_paths:
                if sus_path in file_path:
                    result['suspicious_files'].append({
                        'file': file_path,
                        'operation': operation,
                        'process': process,
                        'reason': f'文件位于可疑路径: {sus_path}'
                    })
                    result['risk_score'] += 15

            # 2. 检查WebShell特征
            for pattern in webshell_patterns:
                if re.search(pattern, file_path, re.IGNORECASE):
                    result['webshell_candidates'].append({
                        'file': file_path,
                        'pattern': pattern,
                        'process': process
                    })
                    result['indicators'].append(f"疑似WebShell文件: {file_path}")
                    result['risk_score'] += 25

            # 3. 检查特权文件修改
            for priv_file in privilege_files:
                if priv_file in file_path and operation in ['modify', 'create']:
                    result['privilege_files_modified'].append({
                        'file': file_path,
                        'operation': operation,
                        'process': process
                    })
                    result['indicators'].append(f"特权文件被修改: {file_path}")
                    result['risk_score'] += 30

            # 4. 检查持久化机制
            for persist_loc in persistence_locations:
                if persist_loc in file_path:
                    result['persistence_mechanisms'].append({
                        'file': file_path,
                        'location': persist_loc,
                        'process': process
                    })
                    result['indicators'].append(f"检测到持久化机制: {file_path}")
                    result['risk_score'] += 25

        result['risk_score'] = min(result['risk_score'], 100)

        return result

    def calculate_comprehensive_risk_score(self, all_indicators: Dict) -> Dict:
        """
        综合计算风险分数

        Args:
            all_indicators: {
                'process_analysis': {...},
                'network_analysis': {...},
                'file_analysis': {...},
                'threat_intel': {...}
            }

        Returns:
            {
                'total_score': 0-100,
                'category_scores': {...},
                'risk_level': 'low/medium/high/critical',
                'recommendation': '...'
            }
        """
        weights = {
            'process_analysis': 0.30,
            'network_analysis': 0.30,
            'file_analysis': 0.20,
            'threat_intel': 0.20
        }

        category_scores = {}
        weighted_sum = 0
        total_weight = 0

        for category, weight in weights.items():
            if category in all_indicators:
                score = all_indicators[category].get('risk_score', 0)
                category_scores[category] = score
                weighted_sum += score * weight
                total_weight += weight

        total_score = weighted_sum / total_weight if total_weight > 0 else 0

        # 确定风险等级
        if total_score >= 80:
            risk_level = 'critical'
            recommendation = '立即隔离主机，进行全面应急响应'
        elif total_score >= 60:
            risk_level = 'high'
            recommendation = '高度警惕，建议立即调查并采取防护措施'
        elif total_score >= 40:
            risk_level = 'medium'
            recommendation = '存在可疑活动，建议进一步监控和分析'
        else:
            risk_level = 'low'
            recommendation = '暂未发现明显威胁，保持常规监控'

        return {
            'total_score': round(total_score, 2),
            'category_scores': category_scores,
            'risk_level': risk_level,
            'recommendation': recommendation
        }

    # ==================== 私有辅助方法 ====================

    def _find_orphan_processes(self, processes: List[Dict], process_map: Dict) -> List[Dict]:
        """查找孤儿进程"""
        orphans = []

        for proc in processes:
            ppid = proc.get('ppid')
            pid = proc.get('pid')

            # 跳过init进程（PID 1）和系统进程
            if pid in ['0', '1']:
                continue

            # 父进程不存在（已死亡）
            if ppid and ppid not in ['0', '1'] and ppid not in process_map:
                orphans.append({
                    'pid': pid,
                    'name': proc.get('name'),
                    'ppid': ppid,
                    'reason': '父进程已不存在'
                })

        return orphans

    def _find_suspicious_chains(self, processes: List[Dict], process_map: Dict) -> List[Dict]:
        """查找可疑进程链"""
        suspicious_chains = []

        # 定义可疑的进程链模式
        suspicious_patterns = [
            ['sshd', 'bash', 'nc'],
            ['sshd', 'bash', 'python'],
            ['sshd', 'bash', 'perl'],
            ['sshd', 'sh', 'wget'],
            ['sshd', 'sh', 'curl'],
            ['apache', 'sh', 'nc'],
            ['nginx', 'sh', 'nc'],
            ['www-data', 'bash'],
            ['php-fpm', 'bash', 'nc'],
            ['httpd', 'sh']
        ]

        for proc in processes:
            chain = self._build_process_chain(proc, process_map)
            chain_names = [p.get('name', '').lower() for p in chain]

            for pattern in suspicious_patterns:
                if self._chain_matches_pattern(chain_names, pattern):
                    suspicious_chains.append({
                        'target_pid': proc['pid'],
                        'chain': [f"{p.get('name')}({p.get('pid')})" for p in chain],
                        'pattern': ' -> '.join(pattern),
                        'reason': f"匹配反向Shell特征: {' -> '.join(pattern)}"
                    })

        return suspicious_chains

    def _detect_privilege_escalation(self, processes: List[Dict], process_map: Dict) -> List[Dict]:
        """检测权限提升迹象"""
        escalations = []

        for proc in processes:
            user = proc.get('user', '')
            name = proc.get('name', '').lower()
            cmdline = proc.get('cmdline', '').lower()

            # root/SYSTEM用户运行的可疑命令
            if user in ['root', 'SYSTEM', 'Administrator']:
                suspicious_commands = ['nc', 'bash -i', 'sh -i', 'python -c', 'perl -e']

                for sus_cmd in suspicious_commands:
                    if sus_cmd in cmdline:
                        # 检查父进程是否为普通用户
                        ppid = proc.get('ppid')
                        parent = process_map.get(ppid)

                        if parent:
                            parent_user = parent.get('user', '')
                            if parent_user not in ['root', 'SYSTEM', 'Administrator']:
                                escalations.append({
                                    'pid': proc['pid'],
                                    'user': user,
                                    'command': cmdline,
                                    'parent_user': parent_user,
                                    'reason': f'普通用户({parent_user})的子进程以特权用户({user})运行'
                                })

            # 检查sudo/su命令
            if 'sudo' in name or 'su' in name:
                escalations.append({
                    'pid': proc['pid'],
                    'command': cmdline,
                    'reason': '检测到权限提升命令'
                })

        return escalations

    def _check_process_timing_anomalies(self, processes: List[Dict]) -> List[Dict]:
        """检查进程启动时间异常"""
        anomalies = []

        # 检测凌晨时段（0-6点）启动的非系统进程
        suspicious_time_range = [(0, 6), (22, 24)]  # 凌晨和深夜

        for proc in processes:
            start_time_str = proc.get('start_time', '')
            if not start_time_str:
                continue

            try:
                # 尝试解析时间（格式可能不同，需要调整）
                # 这里假设格式为 "HH:MM" 或 "HH:MM:SS"
                time_parts = start_time_str.split(':')
                if len(time_parts) >= 2:
                    hour = int(time_parts[0])

                    for start_h, end_h in suspicious_time_range:
                        if start_h <= hour < end_h:
                            # 排除系统进程
                            if proc.get('user') not in ['root', 'SYSTEM']:
                                anomalies.append({
                                    'pid': proc['pid'],
                                    'name': proc.get('name'),
                                    'start_time': start_time_str,
                                    'reason': f'异常时间段启动: {hour}:00'
                                })
            except:
                pass

        return anomalies

    def _detect_heartbeat_pattern(self, connections: List[Dict]) -> Optional[Dict]:
        """检测心跳包模式（Beacon通信）"""
        if len(connections) < 3:
            return None

        # 分析连接时间间隔
        intervals = []
        timestamps = []

        for conn in connections:
            ts = conn.get('timestamp')
            if ts:
                try:
                    timestamps.append(datetime.fromisoformat(ts))
                except:
                    pass

        if len(timestamps) < 3:
            return None

        # 计算时间间隔
        timestamps.sort()
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i - 1]).total_seconds()
            intervals.append(interval)

        if not intervals:
            return None

        # 计算间隔的方差，低方差表示规律性强
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5

        # 如果标准差小于平均值的20%，认为是规律性连接
        if std_dev < avg_interval * 0.2 and 1 <= avg_interval <= 300:  # 1秒到5分钟
            confidence = 'high' if std_dev < avg_interval * 0.1 else 'medium'
            return {
                'interval': round(avg_interval, 2),
                'std_dev': round(std_dev, 2),
                'confidence': confidence,
                'sample_count': len(intervals)
            }

        return None

    def _detect_data_exfiltration(self, connections: List[Dict]) -> Optional[Dict]:
        """检测数据渗出"""
        large_uploads = []
        threshold = 10 * 1024 * 1024  # 10MB

        for conn in connections:
            bytes_sent = conn.get('bytes_sent', 0)
            bytes_recv = conn.get('bytes_recv', 0)

            # 上传数据远大于下载数据
            if bytes_sent > threshold and bytes_sent > bytes_recv * 2:
                large_uploads.append({
                    'remote_ip': conn.get('remote_ip'),
                    'remote_port': conn.get('remote_port'),
                    'bytes_sent': bytes_sent,
                    'bytes_recv': bytes_recv,
                    'ratio': round(bytes_sent / bytes_recv, 2) if bytes_recv > 0 else 'inf'
                })

        if large_uploads:
            indicators = [f"检测到大量数据上传: {ul['remote_ip']} ({ul['bytes_sent']} bytes)" for ul in large_uploads]
            return {
                'uploads': large_uploads,
                'indicators': indicators
            }

        return None

    def _detect_port_scanning(self, connections: List[Dict]) -> Optional[Dict]:
        """检测端口扫描活动"""
        # 按源IP统计连接的目标端口数量
        ip_port_map = defaultdict(set)

        for conn in connections:
            local_ip = conn.get('local_ip')
            remote_port = conn.get('remote_port')
            state = conn.get('state', '')

            # 统计短时间内连接多个端口（SYN扫描）
            if state in ['SYN_SENT', 'TIME_WAIT']:
                ip_port_map[local_ip].add(remote_port)

        scans = []
        for ip, ports in ip_port_map.items():
            # 如果一个IP连接了超过20个不同端口，可能是扫描
            if len(ports) > 20:
                scans.append({
                    'source_ip': ip,
                    'port_count': len(ports),
                    'ports_sample': list(ports)[:10]
                })

        if scans:
            indicators = [f"检测到端口扫描: {scan['source_ip']} (扫描了{scan['port_count']}个端口)" for scan in scans]
            return {
                'scans': scans,
                'indicators': indicators
            }

        return None

    def _build_process_chain(self, process: Dict, process_map: Dict) -> List[Dict]:
        """构建进程链"""
        chain = [process]
        current = process

        for _ in range(10):  # 最多追溯10层
            ppid = current.get('ppid')
            if not ppid or ppid in ['0', '1']:
                break

            parent = process_map.get(ppid)
            if not parent:
                break

            chain.insert(0, parent)
            current = parent

        return chain

    def _chain_matches_pattern(self, chain: List[str], pattern: List[str]) -> bool:
        """检查进程链是否匹配模式"""
        if len(chain) < len(pattern):
            return False

        for i in range(len(chain) - len(pattern) + 1):
            if all(pattern[j] in chain[i + j] for j in range(len(pattern))):
                return True

        return False

    def _is_private_ip(self, ip: str) -> bool:
        """检查是否为内网IP"""
        private_patterns = [
            r'^127\.',
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^::1$',
            r'^fe80:',
            r'^fc00:',
            r'^fd00:'
        ]

        for pattern in private_patterns:
            if re.match(pattern, ip):
                return True

        return False
