#!/bin/bash
################################################################################
# Linux 进程检查脚本
# 功能: 检查异常进程（高CPU、可疑路径、无签名等）
################################################################################

echo "=========================================="
echo "进程检查 - $(date)"
echo "=========================================="
echo

# 1. 检查高CPU占用进程
echo "[*] 检查高CPU占用进程 (>70%)..."
ps aux --sort=-%cpu | head -n 15 | while read line; do
    cpu=$(echo $line | awk '{print $3}' | cut -d. -f1)
    if [ ! -z "$cpu" ] && [ "$cpu" -ge 70 ] 2>/dev/null; then
        echo "  [!] 高危 - CPU占用: $line"
    else
        echo "  $line"
    fi
done
echo

# 2. 检查高内存占用进程
echo "[*] 检查高内存占用进程 (>50%)..."
ps aux --sort=-%mem | head -n 10
echo

# 3. 检查可疑进程（从非标准路径运行）
echo "[*] 检查可疑路径进程..."
suspicious_paths=(
    "/tmp/"
    "/dev/shm/"
    "/var/tmp/"
    "/home/.*/\\..*"
)

for path in "${suspicious_paths[@]}"; do
    procs=$(ps aux | grep -E "$path" | grep -v grep)
    if [ ! -z "$procs" ]; then
        echo "  [!] 可疑 - 发现从 $path 运行的进程:"
        echo "$procs"
    fi
done
echo

# 4. 检查没有关联终端的进程（可能是后门）
echo "[*] 检查无终端进程..."
ps aux | awk '$7 == "?" {print $0}' | head -n 20
echo

# 5. 检查网络监听进程
echo "[*] 检查网络监听进程..."
netstat -tulnp 2>/dev/null | grep LISTEN || ss -tulnp | grep LISTEN
echo

# 6. 检查最近启动的进程
echo "[*] 检查最近10分钟内启动的进程..."
ps -eo pid,lstart,cmd --sort=-lstart | head -n 20
echo

# 7. 检查隐藏进程（进程名包含空格或特殊字符）
echo "[*] 检查隐藏进程..."
ps aux | grep -E '^\s+[0-9]+\s+.*\s{2,}' | head -n 10
echo

# 8. 检查特权进程
echo "[*] 检查以root运行的网络进程..."
netstat -tulnp 2>/dev/null | grep LISTEN | grep root || ss -tulnp | grep root
echo

echo "=========================================="
echo "进程检查完成"
echo "=========================================="
