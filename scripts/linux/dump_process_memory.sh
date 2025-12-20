#!/bin/bash
################################################################################
# Linux 进程内存导出脚本
# 功能: 导出可疑进程的内存用于离线分析
################################################################################

if [ "$#" -lt 1 ]; then
    echo "用法: $0 <PID> [输出目录]"
    echo "示例: $0 1234 /tmp/forensics"
    exit 1
fi

PID=$1
OUTPUT_DIR=${2:-"/tmp/memdump"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "=========================================="
echo "进程内存导出 - $(date)"
echo "=========================================="
echo "目标PID: $PID"
echo "输出目录: $OUTPUT_DIR"
echo

# 检查PID是否存在
if [ ! -d "/proc/$PID" ]; then
    echo "[!] 错误: 进程 $PID 不存在"
    exit 1
fi

# 创建输出目录
mkdir -p "$OUTPUT_DIR"
if [ $? -ne 0 ]; then
    echo "[!] 错误: 无法创建输出目录 $OUTPUT_DIR"
    exit 1
fi

# 获取进程信息
echo "[*] 收集进程信息..."
PROC_NAME=$(cat /proc/$PID/comm 2>/dev/null)
PROC_CMDLINE=$(cat /proc/$PID/cmdline 2>/dev/null | tr '\0' ' ')
PROC_EXE=$(readlink /proc/$PID/exe 2>/dev/null)

echo "  进程名: $PROC_NAME"
echo "  命令行: $PROC_CMDLINE"
echo "  可执行文件: $PROC_EXE"
echo

# 保存进程基本信息
INFO_FILE="$OUTPUT_DIR/process_${PID}_${TIMESTAMP}_info.txt"
echo "PID: $PID" > "$INFO_FILE"
echo "Name: $PROC_NAME" >> "$INFO_FILE"
echo "Cmdline: $PROC_CMDLINE" >> "$INFO_FILE"
echo "Exe: $PROC_EXE" >> "$INFO_FILE"
echo "Timestamp: $(date)" >> "$INFO_FILE"
echo

# 方法1: 使用gcore（如果可用）
echo "[*] 尝试使用gcore导出内存..."
if command -v gcore &> /dev/null; then
    CORE_FILE="$OUTPUT_DIR/core_${PID}_${TIMESTAMP}"
    gcore -o "$CORE_FILE" $PID 2>&1 | tee -a "$INFO_FILE"

    if [ $? -eq 0 ]; then
        echo "[+] 内存导出成功: $CORE_FILE.*"
        ls -lh "$CORE_FILE".*
    else
        echo "[!] gcore导出失败，尝试其他方法..."
    fi
else
    echo "[*] gcore未安装，尝试手动方法..."
fi
echo

# 方法2: 导出内存映射信息
echo "[*] 导出内存映射信息..."
MAPS_FILE="$OUTPUT_DIR/maps_${PID}_${TIMESTAMP}.txt"
cat /proc/$PID/maps > "$MAPS_FILE" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "[+] 内存映射已保存: $MAPS_FILE"
    echo "  总映射区域: $(wc -l < $MAPS_FILE)"
else
    echo "[!] 无法读取内存映射"
fi
echo

# 方法3: 导出关键内存区域
echo "[*] 导出关键内存区域..."
MEM_DIR="$OUTPUT_DIR/memory_regions_${PID}_${TIMESTAMP}"
mkdir -p "$MEM_DIR"

# 读取可读写的内存区域（可能包含恶意代码）
cat /proc/$PID/maps 2>/dev/null | grep -E 'rw' | head -n 20 | while read line; do
    RANGE=$(echo $line | awk '{print $1}')
    PERMS=$(echo $line | awk '{print $2}')
    OFFSET=$(echo $line | awk '{print $3}')
    PATHNAME=$(echo $line | awk '{for(i=6;i<=NF;i++) printf $i" "; print ""}')

    START_ADDR=$(echo $RANGE | cut -d'-' -f1)
    END_ADDR=$(echo $RANGE | cut -d'-' -f2)

    echo "  [*] 导出区域: $RANGE ($PERMS) - $PATHNAME"

    # 使用dd导出内存区域
    REGION_FILE="$MEM_DIR/${START_ADDR}_${END_ADDR}.bin"

    # 尝试从/proc/pid/mem读取
    dd if=/proc/$PID/mem of="$REGION_FILE" bs=1 skip=$((0x$START_ADDR)) count=$((0x$END_ADDR - 0x$START_ADDR)) 2>/dev/null

    if [ -f "$REGION_FILE" ] && [ -s "$REGION_FILE" ]; then
        SIZE=$(stat -f%z "$REGION_FILE" 2>/dev/null || stat -c%s "$REGION_FILE" 2>/dev/null)
        echo "    [+] 已导出: $REGION_FILE ($SIZE bytes)"
    else
        rm -f "$REGION_FILE"
    fi
done
echo

# 方法4: 导出堆内存
echo "[*] 导出堆内存..."
HEAP_REGIONS=$(cat /proc/$PID/maps 2>/dev/null | grep '\[heap\]')
if [ ! -z "$HEAP_REGIONS" ]; then
    echo "$HEAP_REGIONS" | while read line; do
        RANGE=$(echo $line | awk '{print $1}')
        START_ADDR=$(echo $RANGE | cut -d'-' -f1)
        END_ADDR=$(echo $RANGE | cut -d'-' -f2)

        HEAP_FILE="$OUTPUT_DIR/heap_${PID}_${TIMESTAMP}.bin"
        echo "  [*] 堆地址范围: $RANGE"

        dd if=/proc/$PID/mem of="$HEAP_FILE" bs=1 skip=$((0x$START_ADDR)) count=$((0x$END_ADDR - 0x$START_ADDR)) 2>/dev/null

        if [ -f "$HEAP_FILE" ] && [ -s "$HEAP_FILE" ]; then
            SIZE=$(stat -f%z "$HEAP_FILE" 2>/dev/null || stat -c%s "$HEAP_FILE" 2>/dev/null)
            echo "  [+] 堆内存已导出: $HEAP_FILE ($SIZE bytes)"
        fi
    done
else
    echo "  [*] 未找到堆内存区域"
fi
echo

# 方法5: 导出栈内存
echo "[*] 导出栈内存..."
STACK_REGIONS=$(cat /proc/$PID/maps 2>/dev/null | grep '\[stack\]')
if [ ! -z "$STACK_REGIONS" ]; then
    echo "$STACK_REGIONS" | while read line; do
        RANGE=$(echo $line | awk '{print $1}')
        START_ADDR=$(echo $RANGE | cut -d'-' -f1)
        END_ADDR=$(echo $RANGE | cut -d'-' -f2)

        STACK_FILE="$OUTPUT_DIR/stack_${PID}_${TIMESTAMP}.bin"
        echo "  [*] 栈地址范围: $RANGE"

        dd if=/proc/$PID/mem of="$STACK_FILE" bs=1 skip=$((0x$START_ADDR)) count=$((0x$END_ADDR - 0x$START_ADDR)) 2>/dev/null

        if [ -f "$STACK_FILE" ] && [ -s "$STACK_FILE" ]; then
            SIZE=$(stat -f%z "$STACK_FILE" 2>/dev/null || stat -c%s "$STACK_FILE" 2>/dev/null)
            echo "  [+] 栈内存已导出: $STACK_FILE ($SIZE bytes)"
        fi
    done
else
    echo "  [*] 未找到栈内存区域"
fi
echo

# 导出其他有用信息
echo "[*] 导出其他取证信息..."

# 环境变量
ENV_FILE="$OUTPUT_DIR/environ_${PID}_${TIMESTAMP}.txt"
cat /proc/$PID/environ 2>/dev/null | tr '\0' '\n' > "$ENV_FILE"
if [ -s "$ENV_FILE" ]; then
    echo "  [+] 环境变量已保存: $ENV_FILE"
fi

# 文件描述符
FD_FILE="$OUTPUT_DIR/fd_${PID}_${TIMESTAMP}.txt"
ls -l /proc/$PID/fd/ 2>/dev/null > "$FD_FILE"
if [ -s "$FD_FILE" ]; then
    echo "  [+] 文件描述符已保存: $FD_FILE"
fi

# 打开的文件
MAPS_LIBS="$OUTPUT_DIR/libs_${PID}_${TIMESTAMP}.txt"
cat /proc/$PID/maps 2>/dev/null | awk '{print $6}' | grep '^/' | sort -u > "$MAPS_LIBS"
if [ -s "$MAPS_LIBS" ]; then
    echo "  [+] 加载的库文件已保存: $MAPS_LIBS"
fi

# 进程状态
STATUS_FILE="$OUTPUT_DIR/status_${PID}_${TIMESTAMP}.txt"
cat /proc/$PID/status 2>/dev/null > "$STATUS_FILE"
if [ -s "$STATUS_FILE" ]; then
    echo "  [+] 进程状态已保存: $STATUS_FILE"
fi
echo

# 生成取证摘要
SUMMARY_FILE="$OUTPUT_DIR/SUMMARY_${PID}_${TIMESTAMP}.txt"
echo "=========================================" > "$SUMMARY_FILE"
echo "进程内存取证摘要" >> "$SUMMARY_FILE"
echo "=========================================" >> "$SUMMARY_FILE"
echo >> "$SUMMARY_FILE"
echo "PID: $PID" >> "$SUMMARY_FILE"
echo "进程名: $PROC_NAME" >> "$SUMMARY_FILE"
echo "命令行: $PROC_CMDLINE" >> "$SUMMARY_FILE"
echo "可执行文件: $PROC_EXE" >> "$SUMMARY_FILE"
echo "导出时间: $(date)" >> "$SUMMARY_FILE"
echo "输出目录: $OUTPUT_DIR" >> "$SUMMARY_FILE"
echo >> "$SUMMARY_FILE"
echo "导出的文件:" >> "$SUMMARY_FILE"
ls -lh "$OUTPUT_DIR" | grep "${PID}_${TIMESTAMP}" >> "$SUMMARY_FILE"
echo >> "$SUMMARY_FILE"

# 计算总大小
TOTAL_SIZE=$(du -sh "$OUTPUT_DIR" | awk '{print $1}')
echo "总大小: $TOTAL_SIZE" >> "$SUMMARY_FILE"

echo "=========================================="
echo "内存导出完成"
echo "=========================================="
echo "摘要文件: $SUMMARY_FILE"
echo "总大小: $TOTAL_SIZE"
echo
echo "[*] 建议后续分析:"
echo "  1. 使用 strings 命令查找可读字符串"
echo "  2. 使用 binwalk 或 foremost 提取嵌入文件"
echo "  3. 使用 yara 规则扫描恶意代码特征"
echo "  4. 使用 volatility 进行深度内存分析"
echo "=========================================="
