#!/bin/bash
################################################################################
# Linux 进程终止脚本
# 功能: 安全地终止指定进程
################################################################################

if [ -z "$1" ]; then
    echo "用法: $0 <PID>"
    echo "示例: $0 1234"
    exit 1
fi

PID=$1

echo "=========================================="
echo "进程终止 - $(date)"
echo "=========================================="
echo

# 检查进程是否存在
if ! ps -p $PID > /dev/null 2>&1; then
    echo "[!] 错误: 进程 $PID 不存在"
    exit 1
fi

# 显示进程信息
echo "[*] 进程信息:"
ps -fp $PID
echo

# 显示进程的打开文件
echo "[*] 进程打开的文件:"
lsof -p $PID 2>/dev/null | head -n 20
echo

# 显示进程的网络连接
echo "[*] 进程的网络连接:"
lsof -i -a -p $PID 2>/dev/null
echo

# 保存进程信息用于取证
EVIDENCE_DIR="/tmp/irt_evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "[*] 保存取证信息到: $EVIDENCE_DIR"
ps -fp $PID > "$EVIDENCE_DIR/process_info_$PID.txt"
lsof -p $PID > "$EVIDENCE_DIR/process_files_$PID.txt" 2>&1
cat /proc/$PID/cmdline > "$EVIDENCE_DIR/process_cmdline_$PID.txt" 2>&1
cat /proc/$PID/environ > "$EVIDENCE_DIR/process_environ_$PID.txt" 2>&1
ls -la /proc/$PID/exe > "$EVIDENCE_DIR/process_exe_$PID.txt" 2>&1
cat /proc/$PID/maps > "$EVIDENCE_DIR/process_maps_$PID.txt" 2>&1

# 尝试复制进程可执行文件
EXE_PATH=$(readlink /proc/$PID/exe 2>/dev/null)
if [ ! -z "$EXE_PATH" ] && [ -f "$EXE_PATH" ]; then
    cp "$EXE_PATH" "$EVIDENCE_DIR/process_binary_$PID" 2>&1
    echo "[+] 已保存进程二进制文件"
fi

echo

# 终止进程
echo "[*] 尝试优雅终止进程 (SIGTERM)..."
kill -15 $PID

sleep 2

# 检查进程是否还在运行
if ps -p $PID > /dev/null 2>&1; then
    echo "[*] 进程仍在运行，强制终止 (SIGKILL)..."
    kill -9 $PID
    sleep 1
fi

# 最终检查
if ps -p $PID > /dev/null 2>&1; then
    echo "[!] 失败: 进程 $PID 仍在运行"
    exit 1
else
    echo "[+] 成功: 进程 $PID 已终止"
fi

echo
echo "=========================================="
echo "取证数据已保存至: $EVIDENCE_DIR"
echo "=========================================="

exit 0
