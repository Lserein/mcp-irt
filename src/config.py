"""
配置管理模块
"""

import json
from pathlib import Path


def load_config(config_path):
    """加载配置文件"""
    path = Path(config_path)

    if not path.exists():
        print(f"[!] 配置文件不存在: {config_path}，使用默认配置")
        return get_default_config()

    try:
        with open(path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"[!] 配置文件加载失败: {e}，使用默认配置")
        return get_default_config()


def get_default_config():
    """获取默认配置"""
    return {
        "scripts": {
            "linux": {
                "check_processes": "scripts/linux/check_processes.sh",
                "check_network": "scripts/linux/check_network.sh",
                "check_cron": "scripts/linux/check_cron.sh",
                "check_logs": "scripts/linux/check_logs.sh",
                "kill_process": "scripts/linux/kill_process.sh",
                "block_ip": "scripts/linux/block_ip.sh"
            },
            "windows": {
                "check_processes": "scripts/windows/check_processes.ps1",
                "check_network": "scripts/windows/check_network.ps1",
                "check_tasks": "scripts/windows/check_tasks.ps1",
                "check_logs": "scripts/windows/check_logs.ps1",
                "kill_process": "scripts/windows/kill_process.ps1",
                "block_ip": "scripts/windows/block_ip.ps1"
            }
        },
        "workflow": {
            "linux": [
                "check_processes",
                "check_network",
                "check_cron",
                "check_logs"
            ],
            "windows": [
                "check_processes",
                "check_network",
                "check_tasks",
                "check_logs"
            ]
        },
        "timeouts": {
            "connect": 30,
            "execute": 300
        },
        "threat_intel": {
            "enabled": False,
            "virustotal_api_key": "",
            "abuseipdb_api_key": ""
        }
    }
