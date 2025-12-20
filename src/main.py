#!/usr/bin/env python3
"""
MCP-IRT: 自动化安全应急响应助手
Automated Incident Response Tool
"""

import sys
import argparse
import json
from datetime import datetime
from pathlib import Path

from connector import RemoteConnector
from executor import IRExecutor
from reporter import ReportGenerator
from config import load_config


def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='MCP-IRT - 自动化安全应急响应助手'
    )

    # 本地模式参数
    parser.add_argument(
        '--local',
        action='store_true',
        help='本地模式：直接在本地系统执行检查（无需远程连接）'
    )

    # 远程连接参数（本地模式下不需要）
    parser.add_argument(
        '--host',
        help='目标主机地址（远程模式必需）'
    )
    parser.add_argument(
        '--port',
        type=int,
        help='连接端口（SSH默认22，WinRM默认5985）'
    )
    parser.add_argument(
        '--username',
        help='登录用户名（远程模式必需）'
    )
    parser.add_argument(
        '--password',
        help='登录密码'
    )
    parser.add_argument(
        '--key-file',
        help='SSH私钥文件路径'
    )
    parser.add_argument(
        '--os-type',
        choices=['linux', 'windows'],
        help='目标操作系统类型（可选，默认自动检测）'
    )
    parser.add_argument(
        '--protocol',
        choices=['ssh', 'winrm', 'local'],
        help='连接协议（默认根据模式和OS类型自动选择）'
    )
    parser.add_argument(
        '--threat-desc',
        help='威胁描述（可选，用于AI分析）'
    )
    parser.add_argument(
        '--config',
        default='config/config.json',
        help='配置文件路径'
    )
    parser.add_argument(
        '--output',
        help='报告输出路径'
    )
    parser.add_argument(
        '--format',
        choices=['md', 'html'],
        default='md',
        help='报告格式（md 或 html，默认 md）'
    )

    args = parser.parse_args()

    # 验证参数
    if not args.local:
        # 远程模式需要 host 和 username
        if not args.host:
            parser.error('远程模式需要 --host 参数')
        if not args.username:
            parser.error('远程模式需要 --username 参数')

    return args


def main():
    """主函数"""
    print("=" * 60)
    print("MCP-IRT - 自动化安全应急响应助手")
    print("=" * 60)
    print()

    args = parse_arguments()

    # 获取项目根目录（src的父目录）
    project_root = Path(__file__).parent.parent

    # 加载配置 - 基于项目根目录
    config_path = args.config
    if not Path(config_path).is_absolute():
        config_path = project_root / config_path

    config = load_config(config_path)

    # 确定协议和OS类型
    os_type = args.os_type
    protocol = args.protocol

    # 本地模式
    if args.local:
        print("[*] 本地模式：直接在本地系统执行检查")
        protocol = 'local'

        # 检测本地操作系统
        if not os_type:
            import platform
            system = platform.system().lower()
            if 'windows' in system:
                os_type = 'windows'
            elif 'linux' in system:
                os_type = 'linux'
            else:
                print(f"[!] 不支持的操作系统: {system}")
                print("    请使用 --os-type 参数手动指定 (linux/windows)")
                return 1

        print(f"[+] 检测到本地操作系统: {os_type}")

        # 导入本地连接器
        from connector import LocalConnector

        connector = LocalConnector(os_type=os_type)

        if not connector.connect():
            print("[!] 本地连接初始化失败")
            return 1

        print("[+] 本地连接已就绪")
        host_display = "localhost"

    # 远程模式
    else:
        # 如果没有指定协议，尝试根据OS类型推断，或默认SSH
        if not protocol:
            if os_type == 'windows':
                protocol = 'winrm'
            else:
                protocol = 'ssh'  # 默认SSH

        # 创建连接器
        print(f"[*] 连接目标主机: {args.host}")
        connector = RemoteConnector(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            key_file=args.key_file,
            protocol=protocol,
            os_type=os_type  # 可以为None，连接后检测
        )

        if not connector.connect():
            print("[!] 连接失败，退出")
            return 1

        print("[+] 连接成功")

        # 如果没有指定OS类型，自动检测
        if not os_type:
            print("[*] 自动检测操作系统类型...")
            os_type = connector.detect_os()
            if not os_type:
                print("[!] 无法检测操作系统类型，请使用 --os-type 参数指定")
                connector.disconnect()
                return 1
            print(f"[+] 检测到操作系统: {os_type}")
            connector.os_type = os_type

        host_display = args.host

    # 创建执行器
    executor = IRExecutor(connector, config)

    # 执行应急响应流程
    print()
    print("[*] 开始执行应急响应流程...")
    print()

    results = executor.execute_ir_workflow(args.threat_desc)

    # 断开连接
    connector.disconnect()

    # 生成报告
    print()
    print("[*] 生成应急响应报告...")

    # 确保reports目录存在（基于项目根目录）
    reports_dir = project_root / "reports"
    reports_dir.mkdir(exist_ok=True)

    report_generator = ReportGenerator(config)

    if args.output:
        report_path = args.output
    else:
        # 根据格式选择文件扩展名
        file_ext = 'html' if args.format == 'html' else 'md'
        report_path = reports_dir / f"irt_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file_ext}"

    # 如果没有威胁描述，使用默认值
    threat_desc = args.threat_desc or "常规安全检查"

    report_generator.generate_report(
        host=host_display,
        os_type=os_type,
        threat_desc=threat_desc,
        results=results,
        output_path=str(report_path),
        format=args.format
    )

    # 获取报告的绝对路径
    report_abs_path = Path(report_path).resolve()
    print(f"[+] 报告已生成: {report_abs_path}")
    print()
    print("=" * 60)
    print("应急响应完成")
    print("=" * 60)

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 用户中断操作")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] 发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
