#!/bin/bash
################################################################################
# Linux 后门特征检测脚本
# 功能: 检测常见后门（Meterpreter、Cobalt Strike、WebShell等）
################################################################################

echo "=========================================="
echo "后门特征检测 - $(date)"
echo "=========================================="
echo

# 1. 检测Meterpreter特征
echo "[*] 检测Meterpreter特征..."
echo "  [*] 检查默认端口 (4444, 4445, 5555, 6666)..."
netstat -antp 2>/dev/null | grep -E ':(4444|4445|5555|6666|7777)\s' | while read line; do
    echo "  [!] 可疑 - 检测到MSF默认端口: $line"
done

echo "  [*] 检查Meterpreter进程名称..."
ps aux | grep -iE 'meterpreter|msfvenom|msf' | grep -v grep | while read line; do
    echo "  [!] 可疑 - 检测到Meterpreter进程: $line"
done

echo "  [*] 检查反向Shell命令..."
ps aux | grep -E 'bash.*-i|sh.*-i|nc.*-e|/dev/tcp/|socat.*exec' | grep -v grep | while read line; do
    echo "  [!] 可疑 - 检测到反向Shell: $line"
done
echo

# 2. 检测Cobalt Strike特征
echo "[*] 检测Cobalt Strike特征..."
echo "  [*] 检查CS默认端口 (50050)..."
netstat -antp 2>/dev/null | grep -E ':50050\s' | while read line; do
    echo "  [!] 可疑 - 检测到Cobalt Strike端口: $line"
done

echo "  [*] 检查Beacon进程..."
ps aux | grep -iE 'beacon|artifact' | grep -v grep | while read line; do
    echo "  [!] 可疑 - 检测到可疑Beacon进程: $line"
done
echo

# 3. 检测WebShell
echo "[*] 检测WebShell文件..."
if command -v find &> /dev/null; then
    echo "  [*] 扫描Web目录中的可疑PHP/JSP/ASPX文件..."

    # 常见Web目录
    web_dirs=("/var/www" "/usr/share/nginx" "/opt/lampp/htdocs" "/home/*/public_html")

    for dir in "${web_dirs[@]}"; do
        if [ -d "$dir" ]; then
            # 查找可疑文件名
            find $dir -type f \( -name "*shell*.php" -o -name "*cmd*.php" -o -name "c99.php" -o -name "r57.php" -o -name "wso.php" -o -name "b374k.php" \) 2>/dev/null | while read file; do
                echo "  [!] 可疑 - WebShell文件: $file"
                ls -lh "$file"
            done

            # 查找最近修改的PHP文件（24小时内）
            find $dir -name "*.php" -mtime -1 -type f 2>/dev/null | head -n 10 | while read file; do
                echo "  [*] 最近修改的PHP文件: $file"
                # 检查是否包含危险函数
                if grep -qE 'eval\(|system\(|exec\(|passthru\(|shell_exec\(|assert\(' "$file" 2>/dev/null; then
                    echo "      [!] 包含危险函数"
                fi
            done
        fi
    done
fi
echo

# 4. 检测挖矿程序
echo "[*] 检测挖矿程序..."
echo "  [*] 检查挖矿进程名..."
ps aux | grep -iE 'xmrig|minergate|ccminer|ethminer|minerd|cryptonight' | grep -v grep | while read line; do
    echo "  [!] 可疑 - 检测到挖矿进程: $line"
done

echo "  [*] 检查矿池连接..."
netstat -antp 2>/dev/null | grep -E ':(3333|4444|5555|7777|8080|14444)\s' | grep ESTABLISHED | while read line; do
    echo "  [!] 可疑 - 可能的矿池连接: $line"
done

echo "  [*] 检查stratum协议..."
ps aux | grep -E 'stratum\+tcp' | grep -v grep | while read line; do
    echo "  [!] 可疑 - 检测到挖矿协议: $line"
done
echo

# 5. 检测Rootkit
echo "[*] 检测Rootkit特征..."
echo "  [*] 检查/dev/shm中的可疑文件..."
ls -la /dev/shm/ 2>/dev/null | grep -v '^d' | grep -v '^total' | while read line; do
    echo "  [!] 可疑 - /dev/shm中的文件: $line"
done

echo "  [*] 检查/tmp中的隐藏可执行文件..."
find /tmp -type f -name ".*" -executable 2>/dev/null | while read file; do
    echo "  [!] 可疑 - 隐藏可执行文件: $file"
    ls -lh "$file"
done

echo "  [*] 检查LD_PRELOAD劫持..."
if [ ! -z "$LD_PRELOAD" ]; then
    echo "  [!] 警告 - 检测到LD_PRELOAD: $LD_PRELOAD"
fi

if [ -f /etc/ld.so.preload ]; then
    echo "  [!] 警告 - 存在ld.so.preload文件:"
    cat /etc/ld.so.preload
fi
echo

# 6. 检测持久化机制
echo "[*] 检测持久化机制..."
echo "  [*] 检查crontab中的可疑任务..."
crontab -l 2>/dev/null | grep -vE '^#|^$' | while read line; do
    if echo "$line" | grep -qE 'curl.*sh|wget.*sh|bash -i|nc |/tmp/|/dev/shm/'; then
        echo "  [!] 可疑 - Cron任务: $line"
    fi
done

echo "  [*] 检查系统级crontab..."
grep -r "" /etc/cron.* 2>/dev/null | grep -E 'curl.*sh|wget.*sh|bash -i|nc |/tmp/|/dev/shm/' | while read line; do
    echo "  [!] 可疑 - 系统Cron: $line"
done

echo "  [*] 检查systemd服务..."
find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -type f 2>/dev/null | while read service; do
    if grep -qE '/tmp/|/dev/shm/|curl.*sh|wget.*sh' "$service" 2>/dev/null; then
        echo "  [!] 可疑 - Systemd服务: $service"
        grep -E 'ExecStart|ExecStartPre' "$service"
    fi
done

echo "  [*] 检查.bashrc/.bash_profile持久化..."
find /root /home -name ".bashrc" -o -name ".bash_profile" 2>/dev/null | while read file; do
    if grep -qE 'curl.*sh|wget.*sh|bash -i|nc ' "$file" 2>/dev/null; then
        echo "  [!] 可疑 - Shell配置文件: $file"
        grep -E 'curl|wget|bash|nc' "$file"
    fi
done
echo

# 7. 检测SSH后门
echo "[*] 检测SSH后门..."
echo "  [*] 检查authorized_keys..."
find /root /home -name "authorized_keys" 2>/dev/null | while read keyfile; do
    if [ -f "$keyfile" ]; then
        keycount=$(wc -l < "$keyfile")
        if [ $keycount -gt 5 ]; then
            echo "  [!] 警告 - $keyfile 包含 $keycount 个密钥（较多）"
        fi

        # 检查可疑的密钥注释
        grep -E 'test|temp|backdoor|shell' "$keyfile" 2>/dev/null | while read key; do
            echo "  [!] 可疑 - 可疑SSH密钥: ${key:0:80}..."
        done
    fi
done

echo "  [*] 检查SSH配置异常..."
if [ -f /etc/ssh/sshd_config ]; then
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
        echo "  [!] 警告 - Root登录已启用"
    fi
    if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
        echo "  [*] 信息 - 密码认证已启用"
    fi
fi
echo

# 8. 检测进程注入
echo "[*] 检测进程注入特征..."
echo "  [*] 检查可疑的内存映射..."
for pid in $(ps aux | awk '{print $2}' | grep -E '^[0-9]+$' | head -n 20); do
    if [ -d "/proc/$pid" ]; then
        maps_file="/proc/$pid/maps"
        if [ -f "$maps_file" ]; then
            # 检查RWX权限的内存区域（可能是shellcode）
            if grep -q 'rwxp' "$maps_file" 2>/dev/null; then
                cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
                echo "  [!] 可疑 - PID $pid 存在RWX内存区域: $cmdline"
            fi

            # 检查被删除的可执行文件
            if grep -q '(deleted)' "$maps_file" 2>/dev/null; then
                cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
                echo "  [!] 可疑 - PID $pid 运行已删除的文件: $cmdline"
            fi
        fi
    fi
done
echo

# 9. 检测异常网络监听
echo "[*] 检测异常网络监听..."
echo "  [*] 非标准端口监听..."
netstat -tulnp 2>/dev/null | grep LISTEN | awk '{print $4, $7}' | while read addr proc; do
    port=$(echo $addr | rev | cut -d: -f1 | rev)
    # 检查非标准端口（排除常见服务端口）
    if ! echo "$port" | grep -qE '^(22|25|53|80|110|143|443|445|3306|5432|6379|8080|9000)$'; then
        if [ $port -lt 10000 ]; then
            echo "  [!] 可疑 - 非标准端口监听: $addr ($proc)"
        fi
    fi
done
echo

# 10. 输出检测摘要
echo "=========================================="
echo "后门特征检测完成"
echo "时间: $(date)"
echo "=========================================="
