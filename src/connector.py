"""
远程连接模块
支持 SSH 和 WinRM 连接
"""

import sys
import socket
from pathlib import Path


class RemoteConnector:
    """远程连接器基类"""

    def __init__(self, host, port, username, password, key_file, protocol, os_type):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.protocol = protocol
        self.os_type = os_type
        self.connection = None
        self.control_ip = None  # 控制端IP地址

    def connect(self):
        """建立连接"""
        if self.protocol == 'ssh':
            return self._connect_ssh()
        elif self.protocol == 'winrm':
            return self._connect_winrm()
        else:
            print(f"[!] 不支持的协议: {self.protocol}")
            return False

    def _connect_ssh(self):
        """SSH连接"""
        try:
            import paramiko

            self.connection = paramiko.SSHClient()
            self.connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                'hostname': self.host,
                'port': self.port or 22,
                'username': self.username,
                'timeout': 30
            }

            if self.key_file:
                connect_kwargs['key_filename'] = self.key_file
            elif self.password:
                connect_kwargs['password'] = self.password
            else:
                print("[!] 必须提供密码或密钥文件")
                return False

            self.connection.connect(**connect_kwargs)

            # 获取控制端IP地址
            self._get_control_ip()

            return True

        except ImportError:
            print("[!] 缺少依赖: paramiko")
            print("    请安装: pip install paramiko")
            return False
        except Exception as e:
            print(f"[!] SSH连接失败: {e}")
            return False

    def _connect_winrm(self):
        """WinRM连接"""
        try:
            import winrm

            if not self.password:
                print("[!] WinRM连接需要密码")
                return False

            endpoint = f'http://{self.host}:{self.port or 5985}/wsman'

            self.connection = winrm.Session(
                endpoint,
                auth=(self.username, self.password),
                transport='ntlm'
            )

            # 测试连接
            result = self.connection.run_cmd('echo test')
            if result.status_code != 0:
                print("[!] WinRM连接测试失败")
                return False

            # 获取控制端IP地址
            self._get_control_ip()

            return True

        except ImportError:
            print("[!] 缺少依赖: pywinrm")
            print("    请安装: pip install pywinrm")
            return False
        except Exception as e:
            print(f"[!] WinRM连接失败: {e}")
            return False

    def execute_command(self, command):
        """执行命令"""
        if self.protocol == 'ssh':
            return self._execute_ssh(command)
        elif self.protocol == 'winrm':
            return self._execute_winrm(command)
        else:
            return None, f"不支持的协议: {self.protocol}", -1

    def _execute_ssh(self, command):
        """通过SSH执行命令"""
        try:
            stdin, stdout, stderr = self.connection.exec_command(
                command,
                timeout=300
            )

            stdout_data = stdout.read().decode('utf-8', errors='ignore')
            stderr_data = stderr.read().decode('utf-8', errors='ignore')
            exit_code = stdout.channel.recv_exit_status()

            return stdout_data, stderr_data, exit_code

        except Exception as e:
            return "", str(e), -1

    def _execute_winrm(self, command):
        """通过WinRM执行命令"""
        try:
            # 判断是PowerShell还是CMD命令
            # PowerShell命令特征：包含PowerShell cmdlet、以.ps1结尾、或显式标记
            powershell_indicators = [
                'powershell',
                '.ps1',
                'Remove-Item',
                'Get-',
                'Set-',
                'New-',
                'Invoke-',
                'Console',  # [Console]::OutputEncoding
                '$'  # PowerShell变量
            ]

            is_powershell = any(indicator in command for indicator in powershell_indicators)

            if is_powershell:
                result = self.connection.run_ps(command)
            else:
                result = self.connection.run_cmd(command)

            # 尝试多种编码方式解码输出
            # WinRM 可能返回 UTF-8, GBK, 或其他编码
            stdout_data = self._decode_output(result.std_out)
            stderr_data = self._decode_output(result.std_err)
            exit_code = result.status_code

            return stdout_data, stderr_data, exit_code

        except Exception as e:
            return "", str(e), -1

    def _decode_output(self, data):
        """智能解码输出数据，尝试多种编码"""
        if not data:
            return ""

        # 尝试的编码顺序：UTF-8 -> GBK -> GB2312 -> CP936
        encodings = ['utf-8', 'gbk', 'gb2312', 'cp936', 'latin-1']

        for encoding in encodings:
            try:
                decoded = data.decode(encoding)
                # 如果解码成功且没有太多乱码字符，就使用这个编码
                # 检查是否包含大量问号（可能是解码失败）
                if decoded.count('?') < len(decoded) * 0.1:  # 问号少于10%
                    return decoded
            except (UnicodeDecodeError, AttributeError):
                continue

        # 如果所有编码都失败，使用 UTF-8 并忽略错误
        return data.decode('utf-8', errors='replace')

    def upload_file(self, local_path, remote_path):
        """上传文件到远程主机"""
        if self.protocol == 'ssh':
            return self._upload_ssh(local_path, remote_path)
        elif self.protocol == 'winrm':
            return self._upload_winrm(local_path, remote_path)
        else:
            return False

    def _upload_ssh(self, local_path, remote_path):
        """通过SSH上传文件"""
        try:
            import paramiko
            sftp = self.connection.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            return True
        except Exception as e:
            print(f"[!] 文件上传失败: {e}")
            return False

    def _upload_winrm(self, local_path, remote_path):
        """通过WinRM上传文件（使用Base64编码）- 最终改进版"""
        try:
            import base64

            # 读取文件内容
            with open(local_path, 'rb') as f:
                file_data = f.read()

            # Base64编码
            encoded_data = base64.b64encode(file_data).decode('utf-8')

            # 首先删除可能存在的临时文件和目标文件
            cleanup_cmd = f'''
            if (Test-Path "{remote_path}_b64") {{ Remove-Item "{remote_path}_b64" -Force -ErrorAction SilentlyContinue }}
            if (Test-Path "{remote_path}") {{ Remove-Item "{remote_path}" -Force -ErrorAction SilentlyContinue }}
            '''
            self.connection.run_ps(cleanup_cmd)

            # 使用here-string方式上传，避免引号和特殊字符问题
            # 分块上传以避免命令行长度限制
            chunk_size = 3000  # 保守的chunk大小
            total_chunks = (len(encoded_data) + chunk_size - 1) // chunk_size

            for i in range(0, len(encoded_data), chunk_size):
                chunk = encoded_data[i:i + chunk_size]
                chunk_num = i // chunk_size + 1

                # 使用here-string (@" ... "@) 来传递chunk，这样可以避免引号和特殊字符问题
                ps_cmd = f'''
$chunk = @"
{chunk}
"@
[System.IO.File]::AppendAllText("{remote_path}_b64", $chunk, [System.Text.Encoding]::ASCII)
'''

                result = self.connection.run_ps(ps_cmd)
                if result.status_code != 0:
                    error_msg = result.std_err.decode('utf-8', errors='ignore')
                    print(f"[!] 分块上传失败 (chunk {chunk_num}/{total_chunks}): {error_msg[:200]}")
                    return False

            # 解码Base64并写入目标文件
            decode_cmd = f'''
try {{
    $base64Content = [System.IO.File]::ReadAllText("{remote_path}_b64")
    $bytes = [Convert]::FromBase64String($base64Content)
    [System.IO.File]::WriteAllBytes("{remote_path}", $bytes)
    Remove-Item "{remote_path}_b64" -Force -ErrorAction SilentlyContinue
    Write-Output "SUCCESS"
}} catch {{
    Write-Error "Decode failed: $($_.Exception.Message)"
    exit 1
}}
'''
            result = self.connection.run_ps(decode_cmd)

            stdout = result.std_out.decode('utf-8', errors='ignore')
            stderr = result.std_err.decode('utf-8', errors='ignore')

            if result.status_code != 0 or "SUCCESS" not in stdout:
                print(f"[!] 文件解码失败: {stderr[:200]}")
                return False

            return True

        except Exception as e:
            print(f"[!] 文件上传失败: {e}")
            import traceback
            traceback.print_exc()
            # 清理可能残留的临时文件
            try:
                cleanup_cmd = f'''
                if (Test-Path "{remote_path}_b64") {{ Remove-Item "{remote_path}_b64" -Force -ErrorAction SilentlyContinue }}
                '''
                self.connection.run_ps(cleanup_cmd)
            except:
                pass
            return False

    def disconnect(self):
        """断开连接"""
        if self.connection:
            if self.protocol == 'ssh':
                self.connection.close()
            # WinRM不需要显式关闭
            print("[*] 连接已断开")

    def detect_os(self):
        """自动检测操作系统类型"""
        try:
            # 尝试执行uname命令（Linux）
            stdout, stderr, exit_code = self.execute_command('uname -s')
            if exit_code == 0 and stdout:
                os_name = stdout.strip().lower()
                if 'linux' in os_name or 'unix' in os_name:
                    return 'linux'

            # 尝试执行Windows命令
            stdout, stderr, exit_code = self.execute_command('ver')
            if exit_code == 0 and stdout:
                if 'windows' in stdout.lower() or 'microsoft' in stdout.lower():
                    return 'windows'

            # 通过协议推断
            if self.protocol == 'ssh':
                # SSH通常用于Linux
                return 'linux'
            elif self.protocol == 'winrm':
                # WinRM只用于Windows
                return 'windows'

            return None

        except Exception as e:
            print(f"[!] OS检测失败: {e}")
            return None

    def _get_control_ip(self):
        """获取控制端IP地址(本机IP)"""
        try:
            # 方法1: 通过连接到目标主机的socket获取本机IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((self.host, self.port or 22))
            self.control_ip = sock.getsockname()[0]
            sock.close()
            print(f"[+] 检测到控制端IP: {self.control_ip}")
            return self.control_ip
        except Exception as e:
            # 方法2: 获取本机所有IP地址
            try:
                hostname = socket.gethostname()
                local_ips = socket.gethostbyname_ex(hostname)[2]
                # 过滤掉回环地址
                self.control_ip = [ip for ip in local_ips if not ip.startswith('127.')][0] if local_ips else None
                if self.control_ip:
                    print(f"[+] 检测到控制端IP: {self.control_ip}")
                return self.control_ip
            except Exception as e2:
                print(f"[!] 无法获取控制端IP: {e2}")
                return None

    def get_control_ip(self):
        """获取控制端IP地址"""
        return self.control_ip



class LocalConnector:
    """本地连接器 - 直接在本地系统执行命令"""

    def __init__(self, os_type):
        self.os_type = os_type
        self.protocol = 'local'
        self.host = 'localhost'
        self.control_ip = '127.0.0.1'

    def connect(self):
        """本地连接初始化"""
        # 本地模式不需要实际连接
        return True

    def disconnect(self):
        """断开连接（本地模式无操作）"""
        print("[*] 本地检查完成")

    def execute_command(self, command):
        """在本地执行命令"""
        import subprocess
        
        try:
            if self.os_type == 'windows':
                # Windows: 使用 PowerShell
                result = subprocess.run(
                    ['powershell.exe', '-Command', command],
                    capture_output=True,
                    timeout=300,
                    shell=False
                )
            else:
                # Linux: 使用 bash
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    timeout=300,
                    executable='/bin/bash'
                )

            stdout_data = result.stdout.decode('utf-8', errors='replace')
            stderr_data = result.stderr.decode('utf-8', errors='replace')
            exit_code = result.returncode

            return stdout_data, stderr_data, exit_code

        except subprocess.TimeoutExpired:
            return "", "命令执行超时（300秒）", -1
        except Exception as e:
            return "", str(e), -1

    def upload_file(self, local_path, remote_path):
        """本地模式不需要上传文件"""
        # 本地模式下，脚本已经在本地，无需上传
        # 直接返回 True，executor 会直接执行本地脚本
        return True

    def detect_os(self):
        """检测操作系统"""
        return self.os_type

    def get_control_ip(self):
        """获取控制端IP"""
        return self.control_ip
