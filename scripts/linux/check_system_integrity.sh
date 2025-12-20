#!/bin/bash
################################################################################
# Linux 系统完整性检查脚本
# 功能: 检测ELF文件篡改、可疑二进制文件、系统命令完整性
################################################################################

echo "=========================================="
echo "系统完整性检查 - $(date)"
echo "=========================================="
echo

# ============================================================
# 1. 检测可疑的ELF文件
# ============================================================
echo "[1] 检测可疑位置的ELF可执行文件..."
echo "------------------------------------------------------------"

# 检查临时目录中的ELF文件
echo "  [*] 检查临时目录中的ELF文件..."
for dir in /tmp /dev/shm /var/tmp; do
    echo "    目录: $dir"
    find "$dir" -type f -executable 2>/dev/null | while read file; do
        # 检查是否是ELF文件
        if file "$file" | grep -q 'ELF'; then
            echo "      [!] 可疑ELF文件: $file"
            ls -lh "$file"
            file "$file"

            # 显示文件的字符串内容（查找可疑字符串）
            strings "$file" 2>/dev/null | grep -iE 'socket|connect|bind|exec|system|/bin/sh|/bin/bash|http|tcp|backdoor|shell|root' | head -5 | while read str; do
                echo "        关键字符串: $str"
            done
        fi
    done
done
echo

# ============================================================
# 2. 检测隐藏的ELF文件
# ============================================================
echo "[2] 检测隐藏的ELF文件（以.开头）..."
echo "------------------------------------------------------------"

for dir in /tmp /dev/shm /var/tmp /home /root; do
    if [ -d "$dir" ]; then
        echo "  [*] 检查目录: $dir"
        find "$dir" -name ".*" -type f -executable 2>/dev/null | head -20 | while read file; do
            if file "$file" | grep -q 'ELF'; then
                echo "    [!] 隐藏ELF文件: $file"
                ls -lah "$file"
                file "$file"
            fi
        done
    fi
done
echo

# ============================================================
# 3. 检测关键系统命令的完整性
# ============================================================
echo "[3] 检测关键系统命令的完整性..."
echo "------------------------------------------------------------"

# 关键系统命令列表
critical_commands=(
    "ls" "ps" "netstat" "ss" "lsof" "top" "htop"
    "find" "grep" "awk" "sed" "cut" "sort"
    "su" "sudo" "ssh" "sshd" "login"
    "passwd" "useradd" "userdel" "usermod"
    "chmod" "chown" "chgrp"
    "systemctl" "service" "init"
    "iptables" "firewalld"
    "cat" "more" "less" "head" "tail"
    "who" "w" "last" "lastlog"
    "crontab" "at"
)

echo "  [*] 检查关键命令..."
for cmd in "${critical_commands[@]}"; do
    cmd_path=$(which "$cmd" 2>/dev/null)

    if [ ! -z "$cmd_path" ]; then
        # 检查文件类型
        file_type=$(file "$cmd_path" | cut -d: -f2)

        # 检查是否是ELF文件
        if echo "$file_type" | grep -q 'ELF'; then
            # 检查文件大小
            size=$(stat -c %s "$cmd_path" 2>/dev/null || stat -f %z "$cmd_path" 2>/dev/null)

            # 检查修改时间
            mtime=$(stat -c %Y "$cmd_path" 2>/dev/null || stat -f %m "$cmd_path" 2>/dev/null)
            current_time=$(date +%s)
            days_ago=$(( (current_time - mtime) / 86400 ))

            # 如果最近7天内修改过
            if [ $days_ago -lt 7 ]; then
                mtime_readable=$(date -d @$mtime 2>/dev/null || date -r $mtime 2>/dev/null)
                echo "    [!] 最近修改 - $cmd: $cmd_path"
                echo "        修改时间: $mtime_readable ($days_ago 天前)"
                echo "        文件大小: $size bytes"
                file "$cmd_path"
            fi

            # 如果文件特别小（可能是脚本替换）
            if [ $size -lt 10000 ]; then
                echo "    [!] 异常大小 - $cmd: $cmd_path ($size bytes - 可能被替换)"
            fi

        elif echo "$file_type" | grep -q 'script'; then
            echo "    [!] 警告 - $cmd 是脚本而非二进制: $cmd_path"
            echo "        类型: $file_type"

        elif [ -L "$cmd_path" ]; then
            target=$(readlink -f "$cmd_path")
            if echo "$target" | grep -qE '/tmp/|/dev/shm/|/var/tmp/'; then
                echo "    [!] 可疑链接 - $cmd: $cmd_path -> $target"
            fi
        fi
    fi
done
echo

# ============================================================
# 4. 检测SUID/SGID可执行文件
# ============================================================
echo "[4] 检测可疑的SUID/SGID文件..."
echo "------------------------------------------------------------"

echo "  [*] 查找SUID文件（最近7天修改）..."
find / -type f -perm -4000 -mtime -7 2>/dev/null | while read file; do
    echo "    [!] 最近修改的SUID文件: $file"
    ls -lh "$file"
    file "$file"
done

echo "  [*] 查找SGID文件（最近7天修改）..."
find / -type f -perm -2000 -mtime -7 2>/dev/null | while read file; do
    echo "    [!] 最近修改的SGID文件: $file"
    ls -lh "$file"
    file "$file"
done

echo "  [*] 检查可疑位置的SUID/SGID文件..."
for dir in /tmp /dev/shm /var/tmp /home; do
    suid_files=$(find "$dir" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    if [ ! -z "$suid_files" ]; then
        echo "    [!] 发现SUID/SGID文件 in $dir:"
        echo "$suid_files" | while read file; do
            echo "      $file"
            ls -lh "$file"
        done
    fi
done
echo

# ============================================================
# 5. 检测无所有者的文件
# ============================================================
echo "[5] 检测无所有者的文件（可能是攻击者删除账户后遗留）..."
echo "------------------------------------------------------------"

echo "  [*] 查找无所有者的文件..."
find / -nouser -o -nogroup 2>/dev/null | head -50 | while read file; do
    if [ -f "$file" ]; then
        echo "    [!] 无所有者文件: $file"
        ls -lh "$file"

        # 如果是ELF文件，特别标记
        if file "$file" | grep -q 'ELF'; then
            echo "      类型: ELF可执行文件"
        fi
    fi
done
echo

# ============================================================
# 6. 检测文件时间戳异常
# ============================================================
echo "[6] 检测文件时间戳异常..."
echo "------------------------------------------------------------"

echo "  [*] 检查系统目录中的最近修改文件（3天内）..."
for dir in /bin /sbin /usr/bin /usr/sbin /lib /lib64 /usr/lib /usr/lib64; do
    if [ -d "$dir" ]; then
        recent_files=$(find "$dir" -type f -mtime -3 2>/dev/null | head -20)
        if [ ! -z "$recent_files" ]; then
            echo "    目录: $dir"
            echo "$recent_files" | while read file; do
                mtime=$(stat -c %y "$file" 2>/dev/null | cut -d'.' -f1)
                echo "      [!] $file (修改于: $mtime)"
            done
        fi
    fi
done
echo

# ============================================================
# 7. 检测包管理器数据库完整性
# ============================================================
echo "[7] 检测包管理器数据库完整性..."
echo "------------------------------------------------------------"

if command -v rpm &> /dev/null; then
    echo "  [*] 使用RPM验证系统文件完整性..."
    echo "    （这可能需要一些时间...）"

    # 验证所有已安装包的文件
    rpm -Va 2>&1 | grep '^..5' | head -20 | while read line; do
        echo "    [!] 文件被修改: $line"
    done

elif command -v debsums &> /dev/null; then
    echo "  [*] 使用debsums验证系统文件完整性..."
    echo "    （这可能需要一些时间...）"

    # 验证关键包
    for pkg in coreutils bash sudo ssh openssh-server; do
        result=$(debsums -s "$pkg" 2>&1)
        if [ ! -z "$result" ]; then
            echo "    [!] 包 $pkg 的文件被修改:"
            echo "$result"
        fi
    done

elif command -v dpkg &> /dev/null; then
    echo "  [*] dpkg可用，但debsums未安装"
    echo "    建议安装: apt-get install debsums"

else
    echo "  [*] 未找到包管理器验证工具"
fi
echo

# ============================================================
# 8. 检测ELF文件中的可疑字符串
# ============================================================
echo "[8] 分析关键ELF文件中的可疑字符串..."
echo "------------------------------------------------------------"

# 分析关键命令中的字符串
echo "  [*] 扫描关键命令中的可疑字符串..."
critical_bins=("/bin/bash" "/bin/sh" "/usr/bin/sudo" "/usr/sbin/sshd")

for bin in "${critical_bins[@]}"; do
    if [ -f "$bin" ]; then
        echo "    文件: $bin"

        # 查找可疑字符串
        suspicious=$(strings "$bin" 2>/dev/null | grep -iE 'backdoor|rootkit|keylog|password|/tmp/|/dev/tcp|socket|bind|connect' | head -5)

        if [ ! -z "$suspicious" ]; then
            echo "      [!] 发现可疑字符串:"
            echo "$suspicious" | while read str; do
                echo "        $str"
            done
        else
            echo "      [+] 未发现明显可疑字符串"
        fi
    fi
done
echo

# ============================================================
# 9. 检测动态链接异常
# ============================================================
echo "[9] 检测关键命令的动态链接异常..."
echo "------------------------------------------------------------"

echo "  [*] 检查关键命令的依赖库..."
for cmd in bash sudo sshd; do
    cmd_path=$(which "$cmd" 2>/dev/null)
    if [ ! -z "$cmd_path" ] && [ -f "$cmd_path" ]; then
        echo "    命令: $cmd ($cmd_path)"

        # 使用ldd查看依赖
        if command -v ldd &> /dev/null; then
            libs=$(ldd "$cmd_path" 2>&1 | grep -vE 'linux-vdso|ld-linux')

            # 检查是否有来自可疑位置的库
            echo "$libs" | while read line; do
                if echo "$line" | grep -qE '/tmp/|/dev/shm/|/var/tmp/'; then
                    echo "      [!] 可疑依赖库: $line"
                fi
            done
        fi
    fi
done
echo

# ============================================================
# 10. 生成完整性基线（可选）
# ============================================================
echo "[10] 生成系统基线信息..."
echo "------------------------------------------------------------"

baseline_file="/tmp/system_baseline_$(date +%Y%m%d_%H%M%S).txt"

echo "  [*] 生成关键文件的MD5校验值..."
echo "# 系统完整性基线 - $(date)" > "$baseline_file"
echo "# 关键系统文件的MD5校验值" >> "$baseline_file"
echo "" >> "$baseline_file"

for cmd in ls ps netstat ss su sudo ssh sshd bash; do
    cmd_path=$(which "$cmd" 2>/dev/null)
    if [ ! -z "$cmd_path" ]; then
        md5=$(md5sum "$cmd_path" 2>/dev/null | awk '{print $1}')
        echo "$cmd_path: $md5" >> "$baseline_file"
    fi
done

echo "  [+] 基线文件已保存: $baseline_file"
echo "      可用于后续对比检测"
echo

# ============================================================
# 输出摘要
# ============================================================
echo "=========================================="
echo "系统完整性检查完成"
echo "时间: $(date)"
echo "=========================================="
echo ""
echo "[*] 建议:"
echo "  1. 保存基线文件用于定期对比"
echo "  2. 对可疑ELF文件进行深度分析（使用 strings, strace, ltrace）"
echo "  3. 对最近修改的系统命令进行验证"
echo "  4. 检查无所有者文件的来源"
echo "  5. 使用包管理器重装被篡改的文件"
