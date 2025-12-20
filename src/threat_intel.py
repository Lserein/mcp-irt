"""
威胁情报查询模块
支持 VirusTotal、AbuseIPDB 等威胁情报平台
"""

import re
import time
from typing import Dict, List, Optional


class ThreatIntelligence:
    """威胁情报查询类"""

    def __init__(self, config):
        self.config = config
        self.vt_api_key = config.get('threat_intel', {}).get('virustotal_api_key')
        self.abuseipdb_api_key = config.get('threat_intel', {}).get('abuseipdb_api_key')
        self.enabled = config.get('threat_intel', {}).get('enabled', False)
        self.cache = {}  # IP查询缓存

        # 文件分析配置
        self.file_analysis_config = config.get('threat_intel', {}).get('file_analysis', {})
        self.file_analysis_enabled = self.file_analysis_config.get('enabled', False)
        self.max_file_size_mb = self.file_analysis_config.get('max_file_size_mb', 100)
        self.analyzable_extensions = self.file_analysis_config.get('analyzable_extensions', [])
        self.upload_method = self.file_analysis_config.get('upload_method', 'auto')  # hash_only, file_upload, auto

        # ThreatBook配置
        platforms = self.file_analysis_config.get('platforms', {})
        self.threatbook_config = platforms.get('threatbook', {})
        self.threatbook_api_key = self.threatbook_config.get('api_key', '')
        self.threatbook_endpoint = self.threatbook_config.get('api_endpoint', 'https://api.threatbook.cn/v3/file/report')

        # 速率限制配置
        rate_limit = self.file_analysis_config.get('rate_limiting', {})
        self.sleep_between_requests = rate_limit.get('sleep_between_requests', 0.5)

        # 文件哈希查询缓存
        self.file_hash_cache = {}

    def is_enabled(self):
        """检查威胁情报查询是否启用"""
        return self.enabled and (self.vt_api_key or self.abuseipdb_api_key)

    def analyze_ip(self, ip: str) -> Dict:
        """
        分析IP地址
        返回格式: {
            'ip': '1.2.3.4',
            'is_malicious': True/False,
            'threat_score': 0-100,
            'sources': ['VirusTotal', 'AbuseIPDB'],
            'details': {...}
        }
        """
        # 检查是否为内网IP
        if self._is_private_ip(ip):
            return {
                'ip': ip,
                'is_malicious': False,
                'threat_score': 0,
                'sources': [],
                'details': {'note': '内网IP'}
            }

        # 检查缓存
        if ip in self.cache:
            return self.cache[ip]

        result = {
            'ip': ip,
            'is_malicious': False,
            'threat_score': 0,
            'sources': [],
            'details': {}
        }

        # VirusTotal查询
        if self.vt_api_key:
            vt_result = self._query_virustotal(ip)
            if vt_result:
                result['sources'].append('VirusTotal')
                result['details']['virustotal'] = vt_result
                if vt_result.get('malicious', 0) > 0:
                    result['is_malicious'] = True
                    result['threat_score'] = max(result['threat_score'],
                                                  min(vt_result.get('malicious', 0) * 10, 100))

        # AbuseIPDB查询
        if self.abuseipdb_api_key:
            abuse_result = self._query_abuseipdb(ip)
            if abuse_result:
                result['sources'].append('AbuseIPDB')
                result['details']['abuseipdb'] = abuse_result
                if abuse_result.get('abuseConfidenceScore', 0) > 50:
                    result['is_malicious'] = True
                    result['threat_score'] = max(result['threat_score'],
                                                  abuse_result.get('abuseConfidenceScore', 0))

        # 缓存结果
        self.cache[ip] = result
        return result

    def _query_virustotal(self, ip: str) -> Optional[Dict]:
        """查询VirusTotal"""
        try:
            import requests

            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {
                "x-apikey": self.vt_api_key
            }

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0)
                }
            elif response.status_code == 429:
                print("[!] VirusTotal API 配额已用完")
                time.sleep(1)
            elif response.status_code == 404:
                return {'note': 'IP not found in VT database'}

        except ImportError:
            print("[!] 缺少依赖: requests，请安装: pip install requests")
        except Exception as e:
            print(f"[!] VirusTotal查询失败: {e}")

        return None

    def _query_abuseipdb(self, ip: str) -> Optional[Dict]:
        """查询AbuseIPDB"""
        try:
            import requests

            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": self.abuseipdb_api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": "90"
            }

            response = requests.get(url, headers=headers, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                ip_data = data.get('data', {})
                return {
                    'abuseConfidenceScore': ip_data.get('abuseConfidenceScore', 0),
                    'totalReports': ip_data.get('totalReports', 0),
                    'countryCode': ip_data.get('countryCode', 'Unknown'),
                    'isWhitelisted': ip_data.get('isWhitelisted', False)
                }
            elif response.status_code == 429:
                print("[!] AbuseIPDB API 配额已用完")
                time.sleep(1)

        except ImportError:
            print("[!] 缺少依赖: requests，请安装: pip install requests")
        except Exception as e:
            print(f"[!] AbuseIPDB查询失败: {e}")

        return None

    def _is_private_ip(self, ip: str) -> bool:
        """检查是否为内网IP、特殊IP或公共DNS IP"""
        # 内网IP段
        private_patterns = [
            r'^127\.',                              # 本地回环地址
            r'^10\.',                               # A类私有地址
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',      # B类私有地址
            r'^192\.168\.',                         # C类私有地址
            r'^169\.254\.',                         # 链路本地地址
            r'^::1$',                               # IPv6 本地回环
            r'^fe80:',                              # IPv6 链路本地
            r'^fc00:',                              # IPv6 唯一本地地址
            r'^fd00:'                               # IPv6 唯一本地地址
        ]

        # 特殊IP地址（不应查询的地址）
        special_ips = [
            '0.0.0.0',          # 未指定地址
            '255.255.255.255',  # 广播地址
            '255.255.255.0',    # 子网掩码（常见）
            '255.255.0.0',      # 子网掩码
            '255.0.0.0',        # 子网掩码
        ]

        # 公共DNS服务器（无需查询威胁情报）
        public_dns_ips = [
            '8.8.8.8',          # Google DNS
            '8.8.4.4',          # Google DNS
            '1.1.1.1',          # Cloudflare DNS
            '1.0.0.1',          # Cloudflare DNS
            '114.114.114.114',  # 114 DNS（中国）
            '114.114.115.115',  # 114 DNS（中国）
            '223.5.5.5',        # 阿里DNS
            '223.6.6.6',        # 阿里DNS
            '119.29.29.29',     # DNSPod
            '182.254.116.116',  # DNSPod
            '208.67.222.222',   # OpenDNS
            '208.67.220.220',   # OpenDNS
        ]

        # 检查是否为特殊IP
        if ip in special_ips:
            return True

        # 检查是否为公共DNS
        if ip in public_dns_ips:
            return True

        # 检查是否为内网IP
        for pattern in private_patterns:
            if re.match(pattern, ip):
                return True

        # 检查是否为多播地址 (224.0.0.0 - 239.255.255.255)
        if ip.startswith('224.') or ip.startswith('239.'):
            return True

        # 检查是否为广播地址段 (以255结尾的很可能是广播地址)
        if ip.endswith('.255'):
            return True

        return False

    def extract_ips_from_text(self, text: str) -> List[str]:
        """从文本中提取IP地址"""
        # IPv4正则
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

        ips = re.findall(ipv4_pattern, text)

        # 去重并过滤无效IP
        valid_ips = []
        for ip in set(ips):
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)

        return valid_ips

    def batch_analyze_ips(self, ips: List[str]) -> Dict[str, Dict]:
        """批量分析IP地址"""
        results = {}

        print(f"[*] 威胁情报分析: 发现 {len(ips)} 个IP地址")

        for i, ip in enumerate(ips, 1):
            # 跳过内网IP
            if self._is_private_ip(ip):
                continue

            print(f"  [{i}/{len(ips)}] 查询 {ip}...", end=' ')

            result = self.analyze_ip(ip)
            results[ip] = result

            if result['is_malicious']:
                print(f"⚠️  恶意 (威胁分数: {result['threat_score']})")
            else:
                print("✓ 正常")

            # 避免API限流
            time.sleep(0.5)

        return results

    def is_file_analysis_enabled(self):
        """检查文件威胁情报分析是否启用"""
        if not self.file_analysis_enabled:
            return False

        # 至少需要一个平台的API key
        vt_enabled = self.file_analysis_config.get('platforms', {}).get('virustotal', {}).get('enabled', False)
        tb_enabled = self.file_analysis_config.get('platforms', {}).get('threatbook', {}).get('enabled', False)

        return (vt_enabled and self.vt_api_key) or (tb_enabled and self.threatbook_api_key)

    def analyze_file_hash(self, file_hash: str, file_name: str = None, file_path: str = None) -> Dict:
        """
        分析文件哈希（支持文件上传）
        返回格式: {
            'hash': 'sha256...',
            'file_name': 'suspicious.exe',
            'is_malicious': True/False,
            'threat_score': 0-100,
            'sources': ['VirusTotal', 'ThreatBook'],
            'details': {...}
        }
        """
        # 检查缓存
        if file_hash in self.file_hash_cache:
            return self.file_hash_cache[file_hash]

        result = {
            'hash': file_hash,
            'file_name': file_name or 'Unknown',
            'is_malicious': False,
            'threat_score': 0,
            'sources': [],
            'details': {},
            'hash_found': False  # 标记哈希是否在数据库中找到
        }

        # VirusTotal查询
        vt_enabled = self.file_analysis_config.get('platforms', {}).get('virustotal', {}).get('enabled', False)
        vt_hash_found = False
        if vt_enabled and self.vt_api_key:
            vt_result = self._query_virustotal_file(file_hash)
            if vt_result:
                # 检查是否真的找到了样本（不是404）
                if vt_result.get('note') != 'File hash not found in VT database':
                    vt_hash_found = True
                    result['hash_found'] = True
                    result['sources'].append('VirusTotal')
                    result['details']['virustotal'] = vt_result

                    # 计算威胁分数：恶意检出数 / 总数 * 100
                    malicious = vt_result.get('malicious', 0)
                    total = vt_result.get('total', 0)
                    if total > 0:
                        vt_score = int((malicious / total) * 100)
                        result['threat_score'] = max(result['threat_score'], vt_score)

                        # 如果有恶意检出，标记为恶意
                        if malicious > 0:
                            result['is_malicious'] = True

        # ThreatBook查询
        tb_enabled = self.file_analysis_config.get('platforms', {}).get('threatbook', {}).get('enabled', False)
        tb_hash_found = False
        if tb_enabled and self.threatbook_api_key:
            tb_result = self._query_threatbook_file(file_hash)
            if tb_result:
                # 检查是否真的找到了样本
                if tb_result.get('note') != 'File hash not found in ThreatBook database':
                    tb_hash_found = True
                    result['hash_found'] = True
                    result['sources'].append('ThreatBook')
                    result['details']['threatbook'] = tb_result

                    # ThreatBook的威胁评分
                    confidence = tb_result.get('confidence', 0)
                    if confidence > 50:
                        result['is_malicious'] = True
                        result['threat_score'] = max(result['threat_score'], confidence)

        # 如果哈希未找到，且配置允许上传文件，则上传文件进行分析
        if not result['hash_found'] and file_path and self.upload_method in ['auto', 'file_upload']:
            print(f"\n    [*] 哈希未找到，上传文件进行沙箱分析...")

            # 上传到 VirusTotal
            if vt_enabled and self.vt_api_key:
                upload_result = self._upload_file_to_virustotal(file_path)
                if upload_result:
                    result['sources'].append('VirusTotal (Upload)')
                    result['details']['virustotal'] = upload_result
                    result['hash_found'] = True

                    malicious = upload_result.get('malicious', 0)
                    total = upload_result.get('total', 0)
                    if total > 0:
                        vt_score = int((malicious / total) * 100)
                        result['threat_score'] = max(result['threat_score'], vt_score)
                        if malicious > 0:
                            result['is_malicious'] = True

        # 缓存结果
        self.file_hash_cache[file_hash] = result
        return result

    def batch_analyze_file_hashes(self, file_info_list: List[Dict]) -> Dict[str, Dict]:
        """
        批量分析文件哈希
        输入: [{'hash': 'sha256...', 'file_path': '/tmp/evil.exe', 'file_name': 'evil.exe'}, ...]
        返回: {'sha256...': {...analysis_result...}, ...}
        """
        results = {}

        print(f"[*] 文件威胁情报分析: 发现 {len(file_info_list)} 个可疑文件")

        for i, file_info in enumerate(file_info_list, 1):
            file_hash = file_info.get('hash')
            file_name = file_info.get('file_name', 'Unknown')
            file_path = file_info.get('file_path')  # 获取文件路径，用于可能的上传

            if not file_hash:
                continue

            print(f"  [{i}/{len(file_info_list)}] 分析 {file_name} ({file_hash[:16]}...)...", end=' ')

            result = self.analyze_file_hash(file_hash, file_name, file_path)  # 传递文件路径
            results[file_hash] = result

            if result['is_malicious']:
                print(f"⚠️  恶意 (威胁分数: {result['threat_score']})")
            else:
                print("✓ 正常")

            # 避免API限流
            time.sleep(self.sleep_between_requests)

        return results

    def _query_virustotal_file(self, file_hash: str) -> Optional[Dict]:
        """查询VirusTotal文件分析API"""
        try:
            import requests

            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {
                "x-apikey": self.vt_api_key
            }

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})

                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                undetected = stats.get('undetected', 0)
                harmless = stats.get('harmless', 0)
                total = malicious + suspicious + undetected + harmless

                return {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'undetected': undetected,
                    'harmless': harmless,
                    'total': total,
                    'file_type': attributes.get('type_description', 'Unknown'),
                    'size': attributes.get('size', 0),
                    'tags': attributes.get('tags', []),
                    'last_analysis_date': attributes.get('last_analysis_date', 0)
                }
            elif response.status_code == 404:
                return {'note': 'File hash not found in VT database', 'malicious': 0, 'total': 0}
            elif response.status_code == 429:
                print("[!] VirusTotal API 配额已用完")
                time.sleep(1)

        except ImportError:
            print("[!] 缺少依赖: requests，请安装: pip install requests")
        except Exception as e:
            print(f"[!] VirusTotal文件查询失败: {e}")

        return None

    def _query_threatbook_file(self, file_hash: str) -> Optional[Dict]:
        """查询ThreatBook（微步在线）文件分析API"""
        try:
            import requests

            url = self.threatbook_endpoint
            params = {
                "apikey": self.threatbook_api_key,
                "resource": file_hash
            }

            response = requests.get(url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()

                # 检查响应状态
                response_code = data.get('response_code', -1)
                if response_code == 0:  # 成功
                    file_data = data.get('data', {})
                    return {
                        'severity': file_data.get('severity', 'unknown'),
                        'confidence': file_data.get('confidence', 0),
                        'malware_family': file_data.get('malware_family', 'Unknown'),
                        'tags': file_data.get('tags', []),
                        'judgments': file_data.get('judgments', [])
                    }
                elif response_code == -1:
                    return {'note': 'File hash not found in ThreatBook database', 'confidence': 0}
            elif response.status_code == 429:
                print("[!] ThreatBook API 配额已用完")
                time.sleep(1)

        except ImportError:
            print("[!] 缺少依赖: requests，请安装: pip install requests")
        except Exception as e:
            print(f"[!] ThreatBook文件查询失败: {e}")

        return None

    def _upload_file_to_virustotal(self, file_path: str) -> Optional[Dict]:
        """上传文件到VirusTotal进行分析"""
        try:
            import requests
            import os

            if not os.path.exists(file_path):
                print(f"[!] 文件不存在: {file_path}")
                return None

            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size_mb * 1024 * 1024:
                print(f"[!] 文件过大 ({file_size / 1024 / 1024:.1f}MB), 超过 {self.max_file_size_mb}MB 限制")
                return None

            print(f"    [*] 正在上传文件 ({file_size / 1024:.1f}KB)...")

            url = "https://www.virustotal.com/api/v3/files"
            headers = {
                "x-apikey": self.vt_api_key
            }

            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(url, headers=headers, files=files, timeout=60)

            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id')

                if analysis_id:
                    print(f"    [*] 文件已上传，分析ID: {analysis_id[:32]}...")
                    print(f"    [*] 等待分析结果...")

                    # 等待分析完成（轮询）
                    time.sleep(10)  # 初始等待

                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    for attempt in range(6):  # 最多等待60秒
                        analysis_response = requests.get(analysis_url, headers=headers, timeout=10)

                        if analysis_response.status_code == 200:
                            analysis_data = analysis_response.json()
                            status = analysis_data.get('data', {}).get('attributes', {}).get('status')

                            if status == 'completed':
                                stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {})
                                malicious = stats.get('malicious', 0)
                                suspicious = stats.get('suspicious', 0)
                                undetected = stats.get('undetected', 0)
                                harmless = stats.get('harmless', 0)
                                total = malicious + suspicious + undetected + harmless

                                print(f"    [+] 分析完成！检出率: {malicious}/{total}")

                                return {
                                    'malicious': malicious,
                                    'suspicious': suspicious,
                                    'undetected': undetected,
                                    'harmless': harmless,
                                    'total': total,
                                    'file_type': 'Unknown',
                                    'size': file_size,
                                    'tags': [],
                                    'last_analysis_date': int(time.time()),
                                    'upload_analysis': True
                                }

                        time.sleep(10)  # 等待10秒后重试

                    print(f"    [!] 分析超时，请稍后通过VirusTotal网站查看结果")
                    return None

            elif response.status_code == 429:
                print("    [!] VirusTotal API 配额已用完")
            elif response.status_code == 413:
                print("    [!] 文件过大，无法上传")
            else:
                print(f"    [!] 上传失败: HTTP {response.status_code}")

        except ImportError:
            print("[!] 缺少依赖: requests，请安装: pip install requests")
        except Exception as e:
            print(f"    [!] 文件上传失败: {e}")

        return None
