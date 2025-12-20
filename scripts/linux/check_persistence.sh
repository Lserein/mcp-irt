#!/bin/bash
################################################################################
# Linux 持久化机制全面检测脚本
# 功能: 检测Alias、PAM后门、动态库劫持、命令替换等持久化手段
################################################################################

echo "=========================================="
echo "持久化机制全面检测 - $(date)"
echo "=========================================="
echo

# ============================================================
# 1. Alias 后门检测
# ============================================================
echo "[1] 检测 Alias 命令劫持后门..."
echo "------------------------------------------------------------"

# 检查系统级别的alias配置
echo "  [*] 检查系统级别的alias配置..."
for file in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/zshrc; do
    if [ -f "$file" ]; then
        aliases=$(grep -E '^\s*alias\s+' "$file" 2>/dev/null | grep -v '^#')
        if [ ! -z "$aliases" ]; then
            echo "    文件: $file"
            echo "$aliases" | while read line; do
                # 检查可疑的alias
                if echo "$line" | grep -qE 'ls=|ps=|netstat=|ss=|top=|who=|w=|last=|sudo=|su='; then
                    echo "      [!] 可疑 - $line"
                else
                    echo "      $line"
                fi
            done
        fi
    fi
done

# 检查用户级别的alias配置
echo "  [*] 检查用户级别的alias配置..."
for homedir in /root /home/*; do
    if [ -d "$homedir" ]; then
        username=$(basename $homedir)
        for file in "$homedir/.bashrc" "$homedir/.bash_profile" "$homedir/.profile" "$homedir/.zshrc"; do
            if [ -f "$file" ]; then
                aliases=$(grep -E '^\s*alias\s+' "$file" 2>/dev/null | grep -v '^#')
                if [ ! -z "$aliases" ]; then
                    echo "    用户: $username, 文件: $(basename $file)"
                    echo "$aliases" | while read line; do
                        # 检查可疑的alias
                        if echo "$line" | grep -qE 'ls=|ps=|netstat=|ss=|top=|who=|w=|last=|sudo=|su=|wget=|curl='; then
                            echo "      [!] 可疑 - $line"
                        else
                            echo "      $line"
                        fi
                    done
                fi
            fi
        done
    fi
done
echo

# ============================================================
# 2. PAM 后门检测
# ============================================================
echo "[2] 检测 PAM (Pluggable Authentication Modules) 后门..."
echo "------------------------------------------------------------"

echo "  [*] 检查 PAM 配置文件..."
if [ -d /etc/pam.d ]; then
    # 检查所有PAM配置
    for pamfile in /etc/pam.d/*; do
        if [ -f "$pamfile" ]; then
            # 检查可疑的PAM模块
            suspicious=$(grep -vE '^#|^$' "$pamfile" 2>/dev/null | grep -E '\.so' | grep -vE 'pam_(unix|systemd|permit|deny|securetty|nologin|env|limits|cap|loginuid|keyinit|wheel|succeed_if|faildelay|faillock|access|group|time|listfile|pwquality|cracklib|echo|exec|motd|mail|lastlog|shells|tty|umask|warn|xauth|timestamp|selinux|namespace|rhosts|rootok|localuser)')

            if [ ! -z "$suspicious" ]; then
                echo "    [!] 可疑PAM模块 in $(basename $pamfile):"
                echo "$suspicious" | while read line; do
                    echo "      $line"
                done
            fi
        fi
    done

    # 检查自定义PAM模块
    echo "  [*] 检查自定义 PAM 模块库..."
    for libdir in /lib/security /lib64/security /usr/lib/security /usr/lib64/security; do
        if [ -d "$libdir" ]; then
            # 查找最近修改的PAM模块（7天内）
            find "$libdir" -name "pam_*.so" -mtime -7 -type f 2>/dev/null | while read pamlib; do
                echo "    [!] 最近修改的PAM模块: $pamlib"
                ls -lh "$pamlib"
            done

            # 查找非标准的PAM模块
            find "$libdir" -name "pam_*.so" -type f 2>/dev/null | while read pamlib; do
                module_name=$(basename "$pamlib")
                # 检查是否是非标准模块名
                if ! echo "$module_name" | grep -qE 'pam_(unix|systemd|permit|deny|securetty|nologin|env|limits|cap|loginuid|keyinit|wheel|succeed_if|faildelay|faillock|access|group|time|listfile|pwquality|cracklib|echo|exec|motd|mail|lastlog|shells|tty|umask|warn|xauth|timestamp|selinux|namespace|rhosts|rootok|localuser|mkhomedir|systemd_home)\.so'; then
                    echo "    [!] 非标准PAM模块: $pamlib"
                    ls -lh "$pamlib"
                fi
            done
        fi
    done
fi
echo

# ============================================================
# 3. 动态链接库劫持检测
# ============================================================
echo "[3] 检测动态链接库劫持（LD_PRELOAD/LD_LIBRARY_PATH）..."
echo "------------------------------------------------------------"

# 检查LD_PRELOAD环境变量
echo "  [*] 检查当前LD_PRELOAD环境变量..."
if [ ! -z "$LD_PRELOAD" ]; then
    echo "    [!] 警告 - 检测到LD_PRELOAD: $LD_PRELOAD"
else
    echo "    [+] 正常 - 未设置LD_PRELOAD"
fi

# 检查/etc/ld.so.preload
echo "  [*] 检查 /etc/ld.so.preload..."
if [ -f /etc/ld.so.preload ]; then
    echo "    [!] 警告 - 存在 /etc/ld.so.preload 文件:"
    cat /etc/ld.so.preload | while read lib; do
        echo "      预加载库: $lib"
        if [ -f "$lib" ]; then
            ls -lh "$lib"
            # 检查文件类型
            file "$lib"
        fi
    done
else
    echo "    [+] 正常 - /etc/ld.so.preload 不存在"
fi

# 检查环境变量配置文件中的LD_PRELOAD/LD_LIBRARY_PATH
echo "  [*] 检查配置文件中的动态库设置..."
for file in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment /etc/ld.so.conf /root/.bashrc /root/.bash_profile; do
    if [ -f "$file" ]; then
        ld_settings=$(grep -E 'LD_PRELOAD|LD_LIBRARY_PATH' "$file" 2>/dev/null | grep -v '^#')
        if [ ! -z "$ld_settings" ]; then
            echo "    [!] 发现动态库设置 in $file:"
            echo "$ld_settings" | while read line; do
                echo "      $line"
            done
        fi
    fi
done

# 检查可疑的.so文件位置
echo "  [*] 检查可疑位置的.so文件..."
for dir in /tmp /dev/shm /var/tmp; do
    so_files=$(find "$dir" -name "*.so*" -type f 2>/dev/null)
    if [ ! -z "$so_files" ]; then
        echo "    [!] 发现可疑.so文件 in $dir:"
        echo "$so_files" | while read sofile; do
            echo "      $sofile"
            ls -lh "$sofile"
        done
    fi
done
echo

# ============================================================
# 4. 系统命令替换检测
# ============================================================
echo "[4] 检测系统命令替换后门..."
echo "------------------------------------------------------------"

echo "  [*] 检查关键系统命令的完整性..."

# 常见被替换的命令
commands=("ls" "ps" "netstat" "ss" "top" "lsof" "find" "grep" "awk" "sed" "su" "sudo" "ssh" "sshd" "login" "passwd" "who" "w" "last" "lastlog")

for cmd in "${commands[@]}"; do
    cmd_path=$(which $cmd 2>/dev/null)
    if [ ! -z "$cmd_path" ]; then
        # 检查是否是符号链接
        if [ -L "$cmd_path" ]; then
            target=$(readlink -f "$cmd_path")
            echo "    [*] $cmd -> 符号链接: $cmd_path -> $target"

            # 检查链接目标是否可疑
            if echo "$target" | grep -qE '/tmp/|/dev/shm/|/var/tmp/'; then
                echo "      [!] 可疑 - 链接到可疑位置: $target"
            fi
        fi

        # 检查文件修改时间（7天内）
        if find "$cmd_path" -mtime -7 -type f 2>/dev/null | grep -q .; then
            mtime=$(stat -c %y "$cmd_path" 2>/dev/null | cut -d'.' -f1)
            echo "    [!] 最近修改 - $cmd ($cmd_path) at $mtime"
        fi

        # 检查文件大小异常（太小可能是脚本替换）
        size=$(stat -c %s "$cmd_path" 2>/dev/null || stat -f %z "$cmd_path" 2>/dev/null)
        if [ ! -z "$size" ] && [ $size -lt 1000 ]; then
            echo "    [!] 可疑 - $cmd 文件过小 ($size bytes): $cmd_path"
            echo "      前10行内容:"
            head -10 "$cmd_path"
        fi
    fi
done
echo

# ============================================================
# 5. 环境变量劫持检测
# ============================================================
echo "[5] 检测环境变量劫持..."
echo "------------------------------------------------------------"

echo "  [*] 检查PATH环境变量..."
echo "    当前PATH: $PATH"

# 检查PATH中的可疑目录
echo "$PATH" | tr ':' '\n' | while read dir; do
    if echo "$dir" | grep -qE '/tmp|/dev/shm|/var/tmp|^\.|^~'; then
        echo "    [!] 可疑 - PATH中包含不安全目录: $dir"
    fi

    # 检查PATH目录的权限
    if [ -d "$dir" ]; then
        perms=$(stat -c %a "$dir" 2>/dev/null || stat -f %Lp "$dir" 2>/dev/null)
        owner=$(stat -c %U "$dir" 2>/dev/null || stat -f %Su "$dir" 2>/dev/null)

        if [ "$perms" -ge 777 ] || [ "$owner" != "root" ]; then
            echo "    [!] 警告 - 不安全的PATH目录: $dir (权限:$perms, 所有者:$owner)"
        fi
    fi
done

# 检查环境变量配置文件
echo "  [*] 检查环境变量配置文件..."
for file in /etc/profile /etc/environment /etc/bashrc /etc/bash.bashrc; do
    if [ -f "$file" ]; then
        path_settings=$(grep -E '^\s*export\s+PATH|^\s*PATH=' "$file" 2>/dev/null | grep -v '^#')
        if [ ! -z "$path_settings" ]; then
            echo "    文件: $file"
            echo "$path_settings" | while read line; do
                if echo "$line" | grep -qE '/tmp|/dev/shm|/var/tmp'; then
                    echo "      [!] 可疑 - $line"
                else
                    echo "      $line"
                fi
            done
        fi
    fi
done
echo

# ============================================================
# 6. Init/Systemd 持久化检测
# ============================================================
echo "[6] 检测 Init/Systemd 持久化..."
echo "------------------------------------------------------------"

# 检查systemd服务
if command -v systemctl &> /dev/null; then
    echo "  [*] 检查最近修改的systemd服务（7天内）..."
    for dir in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        if [ -d "$dir" ]; then
            find "$dir" -name "*.service" -mtime -7 -type f 2>/dev/null | while read service; do
                echo "    [!] 最近修改的服务: $service"
                echo "      ExecStart 配置:"
                grep -E 'ExecStart|ExecStartPre|ExecStartPost' "$service" | while read line; do
                    echo "        $line"
                    # 检查可疑路径
                    if echo "$line" | grep -qE '/tmp/|/dev/shm/|curl.*sh|wget.*sh'; then
                        echo "          [!] 可疑命令"
                    fi
                done
            done
        fi
    done

    # 检查启用的服务中的可疑服务
    echo "  [*] 检查可疑的启用服务..."
    systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -vE 'systemd|getty|dbus|network|cron|ssh|rsyslog|udev|firewall|selinux' | while read service state; do
        if [ ! -z "$service" ] && [ "$service" != "UNIT" ]; then
            echo "    [*] 服务: $service"
            service_file=$(systemctl show -p FragmentPath "$service" 2>/dev/null | cut -d= -f2)
            if [ -f "$service_file" ]; then
                grep -E 'ExecStart|Description' "$service_file" | while read line; do
                    echo "      $line"
                done
            fi
        fi
    done
fi

# 检查rc.local
echo "  [*] 检查 /etc/rc.local..."
if [ -f /etc/rc.local ]; then
    echo "    [!] 存在 /etc/rc.local:"
    grep -vE '^#|^$|^exit' /etc/rc.local | while read line; do
        echo "      $line"
    done
else
    echo "    [+] /etc/rc.local 不存在"
fi

# 检查init.d
if [ -d /etc/init.d ]; then
    echo "  [*] 检查 /etc/init.d 中最近修改的脚本..."
    find /etc/init.d -type f -mtime -7 2>/dev/null | while read script; do
        echo "    [!] 最近修改: $script"
        ls -lh "$script"
    done
fi
echo

# ============================================================
# 7. 计划任务持久化检测
# ============================================================
echo "[7] 检测计划任务持久化..."
echo "------------------------------------------------------------"

echo "  [*] 检查系统级crontab..."
for cronfile in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/*; do
    if [ -f "$cronfile" ]; then
        content=$(grep -vE '^#|^$|^SHELL|^PATH|^MAILTO|^HOME' "$cronfile" 2>/dev/null)
        if [ ! -z "$content" ]; then
            echo "    文件: $cronfile"
            echo "$content" | while read line; do
                if echo "$line" | grep -qE 'curl.*sh|wget.*sh|bash -i|nc |python.*-c|perl.*-e|/tmp/|/dev/shm/'; then
                    echo "      [!] 可疑 - $line"
                else
                    echo "      $line"
                fi
            done
        fi
    fi
done

echo "  [*] 检查用户crontab..."
for user in $(cut -d: -f1 /etc/passwd); do
    crontab_content=$(crontab -l -u "$user" 2>/dev/null)
    if [ ! -z "$crontab_content" ]; then
        echo "    用户: $user"
        echo "$crontab_content" | grep -vE '^#|^$' | while read line; do
            if echo "$line" | grep -qE 'curl.*sh|wget.*sh|bash -i|nc |/tmp/|/dev/shm/'; then
                echo "      [!] 可疑 - $line"
            else
                echo "      $line"
            fi
        done
    fi
done
echo

# ============================================================
# 8. SSH 后门检测
# ============================================================
echo "[8] 检测 SSH 后门..."
echo "------------------------------------------------------------"

echo "  [*] 检查 SSH 配置文件..."
if [ -f /etc/ssh/sshd_config ]; then
    echo "    检查 /etc/ssh/sshd_config 中的危险配置:"

    # PermitRootLogin
    root_login=$(grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}')
    if [ "$root_login" == "yes" ]; then
        echo "      [!] 警告 - PermitRootLogin yes"
    else
        echo "      [+] PermitRootLogin: $root_login"
    fi

    # PasswordAuthentication
    pass_auth=$(grep -E '^\s*PasswordAuthentication' /etc/ssh/sshd_config | awk '{print $2}')
    echo "      PasswordAuthentication: $pass_auth"

    # 空密码登录
    empty_pass=$(grep -E '^\s*PermitEmptyPasswords' /etc/ssh/sshd_config | awk '{print $2}')
    if [ "$empty_pass" == "yes" ]; then
        echo "      [!] 高危 - PermitEmptyPasswords yes"
    fi

    # 检查额外的AuthorizedKeysFile配置
    auth_keys=$(grep -E '^\s*AuthorizedKeysFile' /etc/ssh/sshd_config 2>/dev/null)
    if [ ! -z "$auth_keys" ]; then
        echo "      AuthorizedKeysFile配置:"
        echo "$auth_keys" | while read line; do
            echo "        $line"
        done
    fi
fi

echo "  [*] 检查SSH wrapper或替换..."
ssh_binary=$(which sshd 2>/dev/null)
if [ ! -z "$ssh_binary" ]; then
    # 检查是否被替换
    if [ -L "$ssh_binary" ]; then
        echo "    [!] 警告 - sshd是符号链接: $ssh_binary -> $(readlink -f $ssh_binary)"
    fi

    # 检查文件大小
    size=$(stat -c %s "$ssh_binary" 2>/dev/null || stat -f %z "$ssh_binary" 2>/dev/null)
    echo "    sshd 文件大小: $size bytes"
fi
echo

# ============================================================
# 9. 内核模块后门检测
# ============================================================
echo "[9] 检测内核模块后门..."
echo "------------------------------------------------------------"

echo "  [*] 检查加载的内核模块..."
lsmod | tail -n +2 | while read module size used_by; do
    # 检查可疑模块名
    if echo "$module" | grep -qiE 'rootkit|backdoor|hide|evil|hack'; then
        echo "    [!] 可疑模块名: $module"
    fi
done

echo "  [*] 检查最近安装的内核模块（7天内）..."
find /lib/modules/$(uname -r) -name "*.ko*" -mtime -7 -type f 2>/dev/null | while read module; do
    echo "    [!] 最近修改的模块: $module"
    ls -lh "$module"
done

echo "  [*] 检查模块自动加载配置..."
for conf in /etc/modules /etc/modules-load.d/*.conf; do
    if [ -f "$conf" ]; then
        modules=$(grep -vE '^#|^$' "$conf" 2>/dev/null)
        if [ ! -z "$modules" ]; then
            echo "    配置文件: $conf"
            echo "$modules" | while read line; do
                echo "      $line"
            done
        fi
    fi
done
echo

# ============================================================
# 输出摘要
# ============================================================
echo "=========================================="
echo "持久化机制检测完成"
echo "时间: $(date)"
echo "=========================================="
