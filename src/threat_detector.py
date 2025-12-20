"""
本地威胁检测引擎
不依赖外部威胁情报，基于特征和行为检测威胁
"""

import re
from typing import Dict, List, Optional


class LocalThreatDetector:
    """本地威胁检测引擎"""

    def __init__(self, whitelist: Optional[Dict] = None):
        """初始化威胁检测器

        Args:
            whitelist: 白名单配置（可选）
        """
        self.backdoor_signatures = self._load_backdoor_signatures()
        self.detection_results = []
        self.whitelist = whitelist or {}

    def _load_backdoor_signatures(self) -> Dict:
        """加载后门特征库"""
        return {
            'meterpreter': {
                'name': 'Metasploit Meterpreter',
                'severity': 'critical',
                'process_names': [
                    'meterpreter',
                    'msf',
                    'msfvenom',
                    'msfconsole'
                ],
                'ports': [4444, 4445, 5555, 6666, 7777],
                'cmdline_patterns': [
                    r'msfvenom.*payload',
                    r'reverse_tcp',
                    r'bind_tcp',
                    r'meterpreter',
                    r'shell_reverse_tcp',
                    r'windows/meterpreter'
                ],
                'network_indicators': {
                    'default_ports': [4444, 4445, 5555],
                    'heartbeat_interval_range': (1, 10),
                    'packet_size_range': (50, 500)
                }
            },
            'cobaltstrike': {
                'name': 'Cobalt Strike',
                'severity': 'critical',
                'process_names': [
                    'beacon',
                    'artifact',
                    'cobaltstrike'
                ],
                'ports': [50050, 80, 443, 8080],
                'cmdline_patterns': [
                    r'beacon\.exe',
                    r'cobaltstrike',
                    r'artifact\.exe'
                ],
                'named_pipes': [
                    r'\\\.\\pipe\\MSSE-',
                    r'\\\.\\pipe\\postex_',
                    r'\\\.\\pipe\\msagent_'
                ],
                'uris': [
                    '/submit.php',
                    '/load',
                    '/__utm.gif',
                    '/pixel.gif'
                ]
            },
            'webshell': {
                'name': 'WebShell',
                'severity': 'high',
                'file_patterns': [
                    r'.*shell.*\.php$',
                    r'.*cmd.*\.jsp$',
                    r'.*eval.*\.aspx$',
                    r'c99\.php',
                    r'r57\.php',
                    r'wso\.php',
                    r'b374k\.php'
                ],
                'function_patterns': [
                    'eval(',
                    'system(',
                    'exec(',
                    'passthru(',
                    'shell_exec(',
                    'assert(',
                    'base64_decode('
                ],
                'process_indicators': [
                    r'www-data.*sh',
                    r'apache.*bash',
                    r'nginx.*bash',
                    r'php.*nc'
                ]
            },
            'reverse_shell': {
                'name': 'Reverse Shell',
                'severity': 'critical',
                'cmdline_patterns': [
                    r'bash\s+-i\s*>',
                    r'bash\s+-i\s*&>',
                    r'nc\s+-e',
                    r'ncat\s+-e',
                    r'/dev/tcp/\d+\.\d+\.\d+\.\d+',
                    r'socat.*exec',
                    r'python.*socket\.socket',
                    r'perl.*socket',
                    r'ruby.*socket',
                    r'php.*fsockopen'
                ],
                'process_chains': [
                    ['sshd', 'bash', 'nc'],
                    ['sshd', 'bash', 'python'],
                    ['apache', 'sh', 'nc'],
                    ['www-data', 'bash']
                ]
            },
            'mining': {
                'name': 'Crypto Miner',
                'severity': 'high',
                'process_names': [
                    'xmrig',
                    'minergate',
                    'ccminer',
                    'ethminer',
                    'minerd'
                ],
                'cmdline_patterns': [
                    r'stratum\+tcp://',
                    r'--donate-level',
                    r'--pool.*:3333',
                    r'--pool.*:8080',
                    r'monero',
                    r'cryptonight'
                ],
                'network_indicators': {
                    'mining_ports': [3333, 4444, 5555, 7777, 8080, 14444],
                    'pool_domains': [
                        'pool.minexmr.com',
                        'xmr-eu.dwarfpool.com',
                        'supportxmr.com'
                    ]
                }
            },
            'rootkit': {
                'name': 'Rootkit',
                'severity': 'critical',
                'files': [
                    '/dev/shm/.*',
                    '/tmp/.*\.so',
                    '/lib/udev/udev',
                    '/usr/bin/bsd-port/.*'
                ],
                'process_indicators': [
                    r'\.\/\..*',  # 隐藏进程（以.开头）
                    r'\s{10,}',   # 大量空格（伪装）
                ],
                'preload_libraries': [
                    '/lib/libprocesshider.so',
                    '/lib/libselinux.so'
                ]
            },
            'persistence': {
                'name': 'Persistence Mechanism',
                'severity': 'high',
                'cron_patterns': [
                    r'curl.*sh',
                    r'wget.*sh',
                    r'/tmp/.*',
                    r'/dev/shm/.*'
                ],
                'startup_patterns': [
                    r'/etc/rc\.local',
                    r'/etc/init\.d/',
                    r'\.bashrc',
                    r'\.bash_profile'
                ],
                'systemd_patterns': [
                    r'/etc/systemd/system/.*\.service',
                    r'/usr/lib/systemd/system/.*\.service'
                ]
            },
            'port_scan': {
                'name': 'Port Scanning',
                'severity': 'medium',
                'process_names': [
                    'nmap',
                    'masscan',
                    'zmap'
                ],
                'cmdline_patterns': [
                    r'nmap.*-p',
                    r'masscan',
                    r'zmap'
                ]
            }
        }

    def analyze_process(self, process_info: Dict) -> Dict:
        """
        分析进程是否可疑

        Args:
            process_info: {
                'pid': '1234',
                'name': 'bash',
                'cmdline': 'bash -i',
                'user': 'root',
                'cpu': '50.0',
                'mem': '10.0',
                'connections': [...]
            }

        Returns:
            {
                'is_suspicious': True/False,
                'threat_score': 0-100,
                'threat_type': 'meterpreter',
                'indicators': [...],
                'confidence': 'low/medium/high/critical'
            }
        """
        threat_score = 0
        indicators = []
        detected_threats = []

        pid = process_info.get('pid', 'unknown')
        name = process_info.get('name', '').lower()
        cmdline = process_info.get('cmdline', '').lower()
        user = process_info.get('user', '')

        # 白名单检查：排除IRT工具进程
        whitelist_processes = self.whitelist.get('processes', [])
        for whitelisted in whitelist_processes:
            if whitelisted.lower() in name or whitelisted.lower() in cmdline:
                return {
                    'is_suspicious': False,
                    'threat_score': 0,
                    'threat_type': 'whitelisted',
                    'indicators': [f'IRT工具进程（已排除）: {whitelisted}'],
                    'confidence': 'none',
                    'whitelisted': True
                }

        # 白名单检查：排除IRT工具路径
        whitelist_paths = self.whitelist.get('paths', [])
        for path_pattern in whitelist_paths:
            # 支持通配符匹配
            pattern = path_pattern.replace('*', '.*').replace('\\', '\\\\')
            if re.search(pattern, cmdline, re.IGNORECASE):
                return {
                    'is_suspicious': False,
                    'threat_score': 0,
                    'threat_type': 'whitelisted',
                    'indicators': [f'IRT工具路径（已排除）: {path_pattern}'],
                    'confidence': 'none',
                    'whitelisted': True
                }

        # 1. 检查进程名匹配
        for threat_type, signatures in self.backdoor_signatures.items():
            if 'process_names' in signatures:
                for pattern in signatures['process_names']:
                    if pattern in name:
                        threat_score += 30
                        indicators.append(f"进程名匹配{signatures['name']}特征: {pattern}")
                        detected_threats.append(threat_type)

        # 2. 检查命令行参数
        for threat_type, signatures in self.backdoor_signatures.items():
            if 'cmdline_patterns' in signatures:
                for pattern in signatures['cmdline_patterns']:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        threat_score += 35
                        indicators.append(f"命令行匹配{signatures['name']}特征: {pattern}")
                        detected_threats.append(threat_type)

        # 3. 检查网络连接
        connections = process_info.get('connections', [])
        whitelist_ips = self.whitelist.get('ips', [])

        for conn in connections:
            remote_ip = conn.get('remote_ip', '')
            remote_port = conn.get('remote_port', 0)
            local_port = conn.get('local_port', 0)

            # 白名单IP检查：跳过白名单IP
            if remote_ip in whitelist_ips:
                continue

            # 检查可疑端口
            for threat_type, signatures in self.backdoor_signatures.items():
                if 'ports' in signatures:
                    if remote_port in signatures['ports'] or local_port in signatures['ports']:
                        threat_score += 25
                        indicators.append(f"端口匹配{signatures['name']}特征: {remote_port or local_port}")
                        detected_threats.append(threat_type)

        # 4. 检查特权用户的可疑行为
        if user in ['root', 'SYSTEM', 'Administrator']:
            if any(keyword in cmdline for keyword in ['nc', 'bash -i', 'socat', '/dev/tcp']):
                threat_score += 20
                indicators.append(f"特权用户执行可疑命令: {user}")

        # 5. 检查可疑路径（排除白名单路径）
        suspicious_paths = ['/tmp/', '/dev/shm/', '/var/tmp/', 'C:\\Windows\\Temp', 'C:\\Users\\Public']
        for path in suspicious_paths:
            if path.lower() in cmdline:
                # 检查是否匹配白名单路径
                is_whitelisted = False
                for wl_path in whitelist_paths:
                    pattern = wl_path.replace('*', '.*').replace('\\', '\\\\')
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        is_whitelisted = True
                        break

                if not is_whitelisted:
                    threat_score += 15
                    indicators.append(f"进程从可疑路径运行: {path}")

        # 确定威胁类型（最常出现的）
        threat_type = 'unknown'
        if detected_threats:
            threat_type = max(set(detected_threats), key=detected_threats.count)

        # 计算置信度
        confidence = self._calculate_confidence(threat_score, len(indicators))

        # 限制分数在0-100之间
        threat_score = min(threat_score, 100)

        return {
            'is_suspicious': threat_score >= 40,
            'threat_score': threat_score,
            'threat_type': threat_type,
            'indicators': indicators,
            'confidence': confidence,
            'severity': self.backdoor_signatures.get(threat_type, {}).get('severity', 'unknown')
        }

    def analyze_network_connection(self, conn_info: Dict) -> Dict:
        """
        分析网络连接是否可疑

        Args:
            conn_info: {
                'local_ip': '192.168.1.100',
                'local_port': 22,
                'remote_ip': '10.0.0.1',
                'remote_port': 4444,
                'state': 'ESTABLISHED',
                'process': 'bash',
                'pid': '1234'
            }

        Returns:
            {
                'is_suspicious': True/False,
                'threat_score': 0-100,
                'indicators': [...],
                'connection_type': 'outbound/inbound/listening'
            }
        """
        threat_score = 0
        indicators = []

        remote_port = conn_info.get('remote_port', 0)
        local_port = conn_info.get('local_port', 0)
        remote_ip = conn_info.get('remote_ip', '')
        process = conn_info.get('process', '').lower()
        state = conn_info.get('state', '')

        # 白名单IP检查：排除白名单IP
        whitelist_ips = self.whitelist.get('ips', [])
        if remote_ip in whitelist_ips:
            return {
                'is_suspicious': False,
                'threat_score': 0,
                'indicators': [f'白名单IP（已排除）: {remote_ip}'],
                'connection_type': 'whitelisted',
                'whitelisted': True
            }

        # 1. 检查远程端口
        high_risk_ports = [4444, 4445, 5555, 6666, 7777, 31337, 12345, 54321]
        if remote_port in high_risk_ports or local_port in high_risk_ports:
            threat_score += 40
            indicators.append(f"连接到高危端口: {remote_port or local_port}")

        # 2. 检查监听端口
        medium_risk_ports = [1234, 8888, 9999, 50050]
        if state == 'LISTEN' and local_port in medium_risk_ports:
            threat_score += 30
            indicators.append(f"可疑端口监听: {local_port}")

        # 3. 检查进程和端口的组合
        suspicious_combinations = [
            ('bash', 'ESTABLISHED'),
            ('sh', 'ESTABLISHED'),
            ('nc', 'ESTABLISHED'),
            ('ncat', 'ESTABLISHED'),
            ('socat', 'ESTABLISHED')
        ]

        for proc, stat in suspicious_combinations:
            if proc in process and stat in state:
                threat_score += 35
                indicators.append(f"可疑进程网络连接: {proc} ({state})")

        # 4. 检查Web服务器进程的异常连接
        web_processes = ['apache', 'nginx', 'httpd', 'www-data', 'php-fpm']
        if any(web_proc in process for web_proc in web_processes):
            if remote_port not in [80, 443, 8080, 8443]:
                threat_score += 25
                indicators.append(f"Web进程异常外联: {process} -> {remote_ip}:{remote_port}")

        # 5. 检查SSH进程的异常连接
        if 'sshd' in process or 'ssh' in process:
            # SSH进程不应该主动外联（除了客户端）
            if state == 'ESTABLISHED' and remote_port not in [22]:
                threat_score += 20
                indicators.append(f"SSH进程异常连接: {remote_ip}:{remote_port}")

        # 确定连接类型
        if state == 'LISTEN':
            connection_type = 'listening'
        elif local_port < 1024 or local_port in [22, 80, 443]:
            connection_type = 'inbound'
        else:
            connection_type = 'outbound'

        threat_score = min(threat_score, 100)

        return {
            'is_suspicious': threat_score >= 40,
            'threat_score': threat_score,
            'indicators': indicators,
            'connection_type': connection_type
        }

    def check_reverse_shell_indicators(self, process_tree: List[Dict]) -> List[Dict]:
        """
        检查反向Shell指标
        分析进程树，查找可疑的父子进程关系

        Args:
            process_tree: [{
                'pid': '1234',
                'ppid': '1000',
                'name': 'bash',
                'cmdline': '...'
            }, ...]

        Returns:
            [{'pid': '1234', 'chain': [...], 'threat_score': 80}, ...]
        """
        suspicious_chains = []

        # 构建进程父子关系映射
        process_map = {p['pid']: p for p in process_tree}

        # 检查每个进程的进程链
        for process in process_tree:
            chain = self._build_process_chain(process, process_map)
            chain_names = [p.get('name', '') for p in chain]

            # 检查可疑的进程链模式
            suspicious_patterns = [
                ['sshd', 'bash', 'nc'],
                ['sshd', 'bash', 'python'],
                ['sshd', 'bash', 'perl'],
                ['apache', 'sh', 'nc'],
                ['nginx', 'sh', 'nc'],
                ['www-data', 'bash'],
                ['php-fpm', 'bash']
            ]

            for pattern in suspicious_patterns:
                if self._chain_matches_pattern(chain_names, pattern):
                    suspicious_chains.append({
                        'pid': process['pid'],
                        'chain': chain_names,
                        'pattern': pattern,
                        'threat_score': 85,
                        'indicator': f"检测到反向Shell进程链: {' -> '.join(pattern)}"
                    })

        return suspicious_chains

    def _build_process_chain(self, process: Dict, process_map: Dict) -> List[Dict]:
        """构建进程链（从根到当前进程）"""
        chain = [process]
        current = process

        # 向上追溯父进程（最多10层）
        for _ in range(10):
            ppid = current.get('ppid')
            if not ppid or ppid == '0' or ppid == '1':
                break

            parent = process_map.get(ppid)
            if not parent:
                break

            chain.insert(0, parent)
            current = parent

        return chain

    def _chain_matches_pattern(self, chain: List[str], pattern: List[str]) -> bool:
        """检查进程链是否匹配可疑模式"""
        if len(chain) < len(pattern):
            return False

        # 查找连续匹配的子序列
        for i in range(len(chain) - len(pattern) + 1):
            if all(pattern[j] in chain[i + j].lower() for j in range(len(pattern))):
                return True

        return False

    def _calculate_confidence(self, threat_score: int, indicator_count: int) -> str:
        """计算检测置信度"""
        if threat_score >= 80 and indicator_count >= 3:
            return 'critical'
        elif threat_score >= 60 and indicator_count >= 2:
            return 'high'
        elif threat_score >= 40 and indicator_count >= 1:
            return 'medium'
        else:
            return 'low'

    def extract_process_info_from_output(self, output: str, os_type: str) -> List[Dict]:
        """
        从脚本输出中提取进程信息

        Args:
            output: 脚本输出文本
            os_type: 'linux' 或 'windows'

        Returns:
            [{'pid': ..., 'name': ..., 'cmdline': ..., 'user': ...}, ...]
        """
        processes = []

        if os_type == 'linux':
            # 解析 ps aux 输出格式
            # USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
            for line in output.split('\n'):
                if not line.strip() or line.startswith('USER'):
                    continue

                parts = line.split(None, 10)
                if len(parts) >= 11:
                    processes.append({
                        'user': parts[0],
                        'pid': parts[1],
                        'cpu': parts[2],
                        'mem': parts[3],
                        'name': parts[10].split()[0] if parts[10] else '',
                        'cmdline': parts[10]
                    })

        elif os_type == 'windows':
            # 解析 PowerShell Get-Process 输出
            # 这里简化处理，实际需要根据具体输出格式调整
            pass

        return processes

    def extract_network_info_from_output(self, output: str, os_type: str) -> List[Dict]:
        """
        从脚本输出中提取网络连接信息

        Args:
            output: 脚本输出文本
            os_type: 'linux' 或 'windows'

        Returns:
            [{'local_ip': ..., 'local_port': ..., 'remote_ip': ..., ...}, ...]
        """
        connections = []

        if os_type == 'linux':
            # 解析 netstat/ss 输出
            for line in output.split('\n'):
                if 'ESTABLISHED' in line or 'LISTEN' in line:
                    # 提取IP和端口
                    # 格式示例: tcp 0 0 192.168.1.100:22 10.0.0.1:54321 ESTABLISHED 1234/sshd
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\w+)', line)
                    if match:
                        connections.append({
                            'local_ip': match.group(1),
                            'local_port': int(match.group(2)),
                            'remote_ip': match.group(3),
                            'remote_port': int(match.group(4)),
                            'state': match.group(5),
                            'raw_line': line
                        })

        return connections

    def extract_suspicious_files_from_output(self, output: str, os_type: str) -> List[Dict]:
        """
        从脚本输出中提取可疑文件路径

        Args:
            output: 脚本输出文本
            os_type: 'linux' 或 'windows'

        Returns:
            [{'file_path': ..., 'detection_reason': ..., 'source_script': ...}, ...]
        """
        suspicious_files = []

        if os_type == 'linux':
            # 匹配Linux文件路径
            # 查找以 / 开头的路径，特别是可疑目录中的可执行文件
            file_patterns = [
                r'/tmp/[^\s]+\.(?:sh|elf|so|py|pl|rb|php|jsp)',  # /tmp 目录下的脚本和可执行文件
                r'/dev/shm/[^\s]+',  # /dev/shm 目录（常用于无文件攻击）
                r'/var/tmp/[^\s]+\.(?:sh|elf|so)',  # /var/tmp 目录
                r'/var/www/[^\s]+\.(?:php|jsp|aspx)',  # Web目录中的后门
                r'/home/[^\s]+/\.ssh/[^\s]+',  # SSH相关文件
                r'/etc/cron\.[^\s]+',  # Cron任务文件
                r'/etc/init\.d/[^\s]+',  # 启动脚本
                r'/usr/local/bin/[^\s]+',  # 本地二进制文件
            ]

            for pattern in file_patterns:
                matches = re.findall(pattern, output)
                for file_path in matches:
                    # 清理路径（移除末尾的标点符号）
                    file_path = file_path.rstrip(',.;:\'\"')

                    if self.is_analyzable_file(file_path):
                        suspicious_files.append({
                            'file_path': file_path,
                            'detection_reason': 'Found in suspicious location',
                            'source_script': 'check_backdoor_signatures'
                        })

        elif os_type == 'windows':
            # 匹配Windows文件路径
            file_patterns = [
                r'C:\\Windows\\Temp\\[^\s]+\.(?:exe|scr|ps1|bat|cmd|vbs|dll)',  # Temp目录
                r'C:\\Users\\[^\s]+\\AppData\\Local\\Temp\\[^\s]+\.(?:exe|scr|dll)',  # 用户Temp
                r'C:\\Users\\Public\\[^\s]+\.(?:exe|scr|ps1|bat)',  # Public目录
                r'C:\\ProgramData\\[^\s]+\.(?:exe|dll|ps1)',  # ProgramData
                r'C:\\Windows\\System32\\[^\s]+\.(?:exe|dll)',  # System32（可能的DLL劫持）
            ]

            for pattern in file_patterns:
                matches = re.findall(pattern, output, re.IGNORECASE)
                for file_path in matches:
                    file_path = file_path.rstrip(',.;:\'\"')

                    if self.is_analyzable_file(file_path):
                        suspicious_files.append({
                            'file_path': file_path,
                            'detection_reason': 'Found in suspicious location',
                            'source_script': 'check_persistence'
                        })

        # 去重
        seen = set()
        unique_files = []
        for f in suspicious_files:
            if f['file_path'] not in seen:
                seen.add(f['file_path'])
                unique_files.append(f)

        return unique_files

    def is_analyzable_file(self, file_path: str) -> bool:
        """
        检查文件是否应该进行威胁情报分析

        Args:
            file_path: 文件路径

        Returns:
            bool: 是否应该分析
        """
        # 检查文件扩展名
        analyzable_extensions = [
            '.exe', '.scr', '.ps1', '.elf', '.sh',
            '.dll', '.so', '.php', '.jsp', '.aspx',
            '.bat', '.cmd', '.vbs', '.jar', '.py', '.pl', '.rb'
        ]

        # 转换为小写进行比较
        file_path_lower = file_path.lower()

        # 检查是否有可分析的扩展名
        has_ext = any(file_path_lower.endswith(ext) for ext in analyzable_extensions)
        if not has_ext:
            return False

        # 检查是否在白名单路径中
        whitelist_paths = self.whitelist.get('paths', [])
        for whitelist_pattern in whitelist_paths:
            # 简单的通配符匹配
            if '*' in whitelist_pattern:
                # 先转义所有正则表达式特殊字符，然后将转义后的 \* 替换为 .*（通配符）
                escaped_pattern = re.escape(whitelist_pattern.lower())
                # 将转义后的 \* 替换为正则表达式的 .*
                pattern = escaped_pattern.replace(r'\*', '.*')
                # 添加行首匹配符，确保完整匹配
                if re.match(pattern, file_path_lower):
                    return False
            elif whitelist_pattern.lower() in file_path_lower:
                return False

        return True
