#!/bin/bash
################################################################################
# Linux 日志检查脚本
# 功能: 检查系统日志中的异常登录、sudo、认证失败等
################################################################################

echo "=========================================="
echo "日志检查 - $(date)"
echo "=========================================="
echo

# 1. 检查最近的认证失败
echo "[*] 检查最近的认证失败 (最后50条)..."
if [ -f /var/log/auth.log ]; then
    grep "Failed password" /var/log/auth.log | tail -n 50
elif [ -f /var/log/secure ]; then
    grep "Failed password" /var/log/secure | tail -n 50
fi
echo

# 2. 检查成功的SSH登录
echo "[*] 检查成功的SSH登录 (最后30条)..."
if [ -f /var/log/auth.log ]; then
    grep "Accepted password\|Accepted publickey" /var/log/auth.log | tail -n 30
elif [ -f /var/log/secure ]; then
    grep "Accepted password\|Accepted publickey" /var/log/secure | tail -n 30
fi
echo

# 3. 检查root登录
echo "[*] 检查root用户登录..."
if [ -f /var/log/auth.log ]; then
    grep "session opened for user root" /var/log/auth.log | tail -n 20
elif [ -f /var/log/secure ]; then
    grep "session opened for user root" /var/log/secure | tail -n 20
fi
echo

# 4. 检查sudo命令执行
echo "[*] 检查sudo命令执行 (最后30条)..."
if [ -f /var/log/auth.log ]; then
    grep "sudo.*COMMAND" /var/log/auth.log | tail -n 30
elif [ -f /var/log/secure ]; then
    grep "sudo.*COMMAND" /var/log/secure | tail -n 30
fi
echo

# 5. 检查用户添加/删除
echo "[*] 检查用户添加/删除..."
if [ -f /var/log/auth.log ]; then
    grep -E "useradd|userdel|adduser|deluser" /var/log/auth.log | tail -n 20
elif [ -f /var/log/secure ]; then
    grep -E "useradd|userdel" /var/log/secure | tail -n 20
fi
echo

# 6. 检查可疑的登录时间（凌晨2-5点）
echo "[*] 检查凌晨时段登录 (02:00-05:59)..."
if [ -f /var/log/auth.log ]; then
    grep "Accepted.*0[2-5]:[0-9][0-9]:[0-9][0-9]" /var/log/auth.log | tail -n 20 | while read line; do
        echo "  [!] 异常时段登录: $line"
    done
elif [ -f /var/log/secure ]; then
    grep "Accepted.*0[2-5]:[0-9][0-9]:[0-9][0-9]" /var/log/secure | tail -n 20 | while read line; do
        echo "  [!] 异常时段登录: $line"
    done
fi
echo

# 7. 检查暴力破解迹象
echo "[*] 检查暴力破解迹象 (同一IP失败次数)..."
if [ -f /var/log/auth.log ]; then
    grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -n 10 | while read count ip; do
        if [ $count -gt 10 ]; then
            echo "  [!] 可疑 - IP $ip 失败次数: $count"
        else
            echo "  IP $ip 失败次数: $count"
        fi
    done
elif [ -f /var/log/secure ]; then
    grep "Failed password" /var/log/secure | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -n 10 | while read count ip; do
        if [ $count -gt 10 ]; then
            echo "  [!] 可疑 - IP $ip 失败次数: $count"
        else
            echo "  IP $ip 失败次数: $count"
        fi
    done
fi
echo

# 8. 检查系统日志中的错误
echo "[*] 检查系统日志错误 (最后20条)..."
if command -v journalctl &> /dev/null; then
    journalctl -p err -n 20 --no-pager
elif [ -f /var/log/syslog ]; then
    grep -i "error\|critical\|alert" /var/log/syslog | tail -n 20
elif [ -f /var/log/messages ]; then
    grep -i "error\|critical\|alert" /var/log/messages | tail -n 20
fi
echo

# 9. 检查最后登录记录
echo "[*] 检查最后登录记录..."
last -n 30
echo

# 10. 检查当前登录用户
echo "[*] 检查当前登录用户..."
who
echo
w
echo

# 11. 检查登录历史
echo "[*] 检查登录历史..."
lastlog | grep -v "Never"
echo

# 12. 检查可疑的命令历史
echo "[*] 检查可疑的bash历史命令..."
for home_dir in /home/* /root; do
    if [ -f "$home_dir/.bash_history" ]; then
        echo "--- $home_dir/.bash_history ---"
        # 查找可疑命令
        grep -E "wget|curl|nc|ncat|/dev/tcp|bash -i|python.*socket|chmod \+x|rm -rf|iptables" "$home_dir/.bash_history" 2>/dev/null | tail -n 10
        echo
    fi
done

echo "=========================================="
echo "日志检查完成"
echo "=========================================="
