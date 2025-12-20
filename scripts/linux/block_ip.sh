#!/bin/bash
################################################################################
# Linux IP阻断脚本
# 功能: 使用iptables阻断指定IP地址
################################################################################

if [ -z "$1" ]; then
    echo "用法: $0 <IP地址>"
    echo "示例: $0 192.168.1.100"
    exit 1
fi

IP=$1

echo "=========================================="
echo "IP阻断 - $(date)"
echo "=========================================="
echo

# 验证IP地址格式
if ! echo "$IP" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    echo "[!] 错误: 无效的IP地址格式: $IP"
    exit 1
fi

# 检查是否为本地IP
if echo "$IP" | grep -qE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
    echo "[!] 警告: $IP 看起来是本地IP地址"
    read -p "确认要阻断此IP吗? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "[*] 操作已取消"
        exit 0
    fi
fi

# 检查iptables是否可用
if ! command -v iptables &> /dev/null; then
    echo "[!] 错误: iptables 未安装"
    exit 1
fi

# 检查是否已经阻断
if iptables -L INPUT -n | grep -q "$IP"; then
    echo "[*] IP $IP 已在防火墙规则中"
fi

# 显示当前与该IP的连接
echo "[*] 当前与 $IP 的连接:"
netstat -an 2>/dev/null | grep "$IP" || ss -an | grep "$IP"
echo

# 添加iptables规则阻断IP
echo "[*] 添加iptables规则阻断 $IP..."

# INPUT链 - 阻断来自该IP的入站流量
iptables -A INPUT -s $IP -j DROP
if [ $? -eq 0 ]; then
    echo "[+] 已阻断来自 $IP 的入站流量"
else
    echo "[!] 添加INPUT规则失败"
fi

# OUTPUT链 - 阻断到该IP的出站流量
iptables -A OUTPUT -d $IP -j DROP
if [ $? -eq 0 ]; then
    echo "[+] 已阻断到 $IP 的出站流量"
else
    echo "[!] 添加OUTPUT规则失败"
fi

# FORWARD链 - 如果是网关，也阻断转发流量
iptables -A FORWARD -s $IP -j DROP
iptables -A FORWARD -d $IP -j DROP

echo

# 显示新添加的规则
echo "[*] 当前针对 $IP 的防火墙规则:"
iptables -L -n | grep "$IP"
echo

# 断开现有连接
echo "[*] 尝试断开与 $IP 的现有连接..."
# 这需要conntrack工具
if command -v conntrack &> /dev/null; then
    conntrack -D -s $IP 2>/dev/null
    conntrack -D -d $IP 2>/dev/null
    echo "[+] 已清除连接追踪条目"
else
    echo "[*] conntrack未安装，无法清除现有连接"
fi

echo

# 保存iptables规则（确保重启后生效）
echo "[*] 保存iptables规则..."
if command -v iptables-save &> /dev/null; then
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        netfilter-persistent save 2>/dev/null || \
        echo "[!] 无法自动保存规则，请手动执行: iptables-save > /etc/iptables/rules.v4"
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS
        service iptables save 2>/dev/null || \
        echo "[!] 无法自动保存规则，请手动执行: service iptables save"
    else
        echo "[!] 未知的发行版，请手动保存iptables规则"
    fi
else
    echo "[!] iptables-save未找到"
fi

echo
echo "=========================================="
echo "IP $IP 已被阻断"
echo "=========================================="
echo
echo "撤销阻断命令:"
echo "  iptables -D INPUT -s $IP -j DROP"
echo "  iptables -D OUTPUT -d $IP -j DROP"
echo "  iptables -D FORWARD -s $IP -j DROP"
echo "  iptables -D FORWARD -d $IP -j DROP"
echo

exit 0
