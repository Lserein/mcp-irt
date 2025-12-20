#!/bin/bash
################################################################################
# Linux 网络连接检查脚本
# 功能: 检查监听端口、异常连接、可疑IP等
################################################################################

echo "=========================================="
echo "网络连接检查 - $(date)"
echo "=========================================="
echo

# 1. 检查所有监听端口
echo "[*] 检查监听端口..."
netstat -tulnp 2>/dev/null || ss -tulnp
echo

# 2. 检查已建立的连接
echo "[*] 检查已建立的网络连接..."
netstat -antp 2>/dev/null | grep ESTABLISHED || ss -antp | grep ESTAB
echo

# 3. 检查可疑端口（常见后门端口）
echo "[*] 检查可疑端口..."
suspicious_ports=(1234 4444 5555 6666 7777 8888 9999 31337 12345 54321)

for port in "${suspicious_ports[@]}"; do
    listening=$(netstat -tuln 2>/dev/null | grep ":$port " || ss -tuln | grep ":$port ")
    if [ ! -z "$listening" ]; then
        echo "  [!] 异常 - 发现可疑端口监听: $port"
        echo "  $listening"
    fi
done
echo

# 4. 检查对外连接的IP地址
echo "[*] 检查对外连接统计..."
netstat -an 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -n 20 || \
ss -an | grep ESTAB | awk '{print $6}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -n 20
echo

# 5. 检查异常国家/地区连接（需要geoip工具）
if command -v geoiplookup &> /dev/null; then
    echo "[*] 检查异常国家连接..."
    netstat -an 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u | while read ip; do
        if [ ! -z "$ip" ] && [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            country=$(geoiplookup $ip 2>/dev/null | cut -d: -f2 | tr -d ' ')
            echo "  $ip -> $country"
        fi
    done
    echo
fi

# 6. 检查反向Shell特征
echo "[*] 检查潜在反向Shell连接..."
netstat -antp 2>/dev/null | grep -E "bash|sh|nc|ncat|socat" | grep ESTABLISHED || \
ss -antp | grep -E "bash|sh|nc|ncat|socat" | grep ESTAB
echo

# 7. 检查ARP表
echo "[*] 检查ARP表..."
arp -a | head -n 20
echo

# 8. 检查路由表
echo "[*] 检查路由表..."
route -n || ip route
echo

# 9. 检查防火墙规则
echo "[*] 检查防火墙规则..."
if command -v iptables &> /dev/null; then
    iptables -L -n -v | head -n 30
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --list-all
fi
echo

# 10. 检查网络接口
echo "[*] 检查网络接口..."
ifconfig 2>/dev/null || ip addr
echo

# 11. 检查DNS配置
echo "[*] 检查DNS配置..."
cat /etc/resolv.conf
echo

echo "=========================================="
echo "网络检查完成"
echo "=========================================="
