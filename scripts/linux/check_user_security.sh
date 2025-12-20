#!/bin/bash
################################################################################
# Linux 用户权限和账户安全检测脚本
# 功能: 检测影子用户、恶意用户、权限异常等
################################################################################

echo "=========================================="
echo "用户权限安全检测 - $(date)"
echo "=========================================="
echo

# 1. 检测影子用户（UID为0的非root用户）
echo "[*] 检测影子用户（UID=0的非root用户）..."
awk -F: '$3 == 0 {print $1}' /etc/passwd | while read username; do
    if [ "$username" != "root" ]; then
        echo "  [!] 高危 - 发现影子用户（UID=0）: $username"
        echo "      完整信息: $(grep "^$username:" /etc/passwd)"
        echo "      最后登录: $(lastlog -u $username 2>/dev/null | tail -1)"
    else
        echo "  [+] 正常 - root 用户"
    fi
done
echo

# 2. 检测可疑的系统用户（UID < 1000但有shell）
echo "[*] 检测可疑的系统用户..."
awk -F: '$3 < 1000 && $3 != 0 && $7 !~ /nologin|false/ {print $0}' /etc/passwd | while read line; do
    username=$(echo $line | cut -d: -f1)
    uid=$(echo $line | cut -d: -f3)
    shell=$(echo $line | cut -d: -f7)
    echo "  [!] 可疑 - 系统用户有登录shell: $username (UID:$uid, Shell:$shell)"
done
echo

# 3. 检测最近创建的用户（最近7天）
echo "[*] 检测最近创建的用户（7天内）..."
current_time=$(date +%s)
seven_days_ago=$((current_time - 604800))

if [ -f /var/log/secure ]; then
    log_file="/var/log/secure"
elif [ -f /var/log/auth.log ]; then
    log_file="/var/log/auth.log"
else
    log_file=""
fi

if [ ! -z "$log_file" ]; then
    grep -i "useradd\|new user" $log_file 2>/dev/null | tail -20 | while read line; do
        echo "  [*] 发现用户创建记录: $line"
    done
else
    echo "  [*] 未找到用户操作日志文件"
fi

# 检查/etc/passwd修改时间
passwd_mtime=$(stat -c %Y /etc/passwd 2>/dev/null || stat -f %m /etc/passwd 2>/dev/null)
if [ ! -z "$passwd_mtime" ] && [ $passwd_mtime -gt $seven_days_ago ]; then
    passwd_modified_date=$(date -d @$passwd_mtime 2>/dev/null || date -r $passwd_mtime 2>/dev/null)
    echo "  [!] 警告 - /etc/passwd 最近被修改: $passwd_modified_date"
fi
echo

# 4. 检测空密码用户
echo "[*] 检测空密码用户..."
awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | while read username; do
    echo "  [!] 高危 - 空密码用户: $username"
done

# 替代方法（如果没有权限读取shadow）
awk -F: '$2 == "" || $2 == "!" || $2 == "*" {print $1, $2}' /etc/passwd | while read username status; do
    if [ "$status" == "" ]; then
        echo "  [!] 高危 - 空密码用户: $username"
    fi
done
echo

# 5. 检测可疑的sudo权限用户
echo "[*] 检测sudo权限用户..."
if [ -f /etc/sudoers ]; then
    echo "  [*] /etc/sudoers 中的配置:"
    grep -vE '^#|^$' /etc/sudoers | grep -E 'ALL.*ALL' | while read line; do
        echo "    $line"
    done
fi

if [ -d /etc/sudoers.d ]; then
    echo "  [*] /etc/sudoers.d/ 中的配置:"
    for file in /etc/sudoers.d/*; do
        if [ -f "$file" ]; then
            echo "    文件: $file"
            grep -vE '^#|^$' "$file" 2>/dev/null | while read line; do
                echo "      $line"
            done
        fi
    done
fi

# 检查sudo组成员
echo "  [*] sudo/wheel 组成员:"
getent group sudo 2>/dev/null | cut -d: -f4
getent group wheel 2>/dev/null | cut -d: -f4
echo

# 6. 检测异常用户home目录
echo "[*] 检测异常用户home目录..."
awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $6}' /etc/passwd | while read username homedir; do
    if [ ! -d "$homedir" ]; then
        echo "  [!] 异常 - 用户 $username 的home目录不存在: $homedir"
    elif [ "$homedir" == "/tmp" ] || [ "$homedir" == "/dev/null" ]; then
        echo "  [!] 可疑 - 用户 $username 的home目录异常: $homedir"
    fi
done
echo

# 7. 检测用户shell异常
echo "[*] 检测异常的用户shell..."
awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $7}' /etc/passwd | while read username shell; do
    # 检查shell是否是可执行文件
    if [ ! -x "$shell" ] && [ "$shell" != "/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
        echo "  [!] 异常 - 用户 $username 的shell不可执行: $shell"
    fi

    # 检查可疑的shell
    if echo "$shell" | grep -qE '/tmp/|/dev/shm/|\.sh$'; then
        echo "  [!] 可疑 - 用户 $username 使用可疑shell: $shell"
    fi
done
echo

# 8. 检测用户的.ssh目录
echo "[*] 检测用户SSH配置..."
find /root /home -maxdepth 2 -name ".ssh" -type d 2>/dev/null | while read sshdir; do
    username=$(echo $sshdir | cut -d'/' -f3)
    [ -z "$username" ] && username="root"

    echo "  [*] 检查用户 $username 的SSH配置: $sshdir"

    # 检查authorized_keys
    if [ -f "$sshdir/authorized_keys" ]; then
        key_count=$(wc -l < "$sshdir/authorized_keys")
        echo "    authorized_keys: $key_count 个密钥"

        if [ $key_count -gt 10 ]; then
            echo "      [!] 警告 - 密钥数量异常（>10）"
        fi

        # 检查可疑的密钥注释
        grep -iE 'test|temp|backdoor|hack|shell|pwn' "$sshdir/authorized_keys" 2>/dev/null | while read key; do
            echo "      [!] 可疑密钥: ${key:0:80}..."
        done
    fi

    # 检查私钥文件
    find "$sshdir" -name "id_*" -not -name "*.pub" -type f 2>/dev/null | while read keyfile; do
        perms=$(stat -c %a "$keyfile" 2>/dev/null || stat -f %Lp "$keyfile" 2>/dev/null)
        if [ "$perms" != "600" ]; then
            echo "    [!] 警告 - 私钥权限不安全: $keyfile ($perms)"
        fi
    done
done
echo

# 9. 检测最近登录的用户
echo "[*] 检测最近登录活动..."
echo "  [*] 最近10次成功登录:"
last -n 10 | head -11
echo

echo "  [*] 最近10次失败登录:"
lastb -n 10 2>/dev/null | head -11 || echo "    无权限读取失败登录记录"
echo

# 10. 检测当前登录的用户
echo "[*] 检测当前登录用户..."
w | while read line; do
    echo "  $line"
done
echo

# 11. 检测用户密码策略
echo "[*] 检测密码策略..."
if [ -f /etc/login.defs ]; then
    echo "  [*] 密码过期策略:"
    grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE' /etc/login.defs | grep -v '^#'
fi

if [ -f /etc/pam.d/system-auth ] || [ -f /etc/pam.d/common-password ]; then
    echo "  [*] PAM密码策略:"
    grep -h 'pam_pwquality\|pam_cracklib' /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null | grep -v '^#'
fi
echo

# 12. 检测组权限异常
echo "[*] 检测组权限异常..."
echo "  [*] 敏感组的成员:"
for group in root sudo wheel adm admin; do
    members=$(getent group $group 2>/dev/null | cut -d: -f4)
    if [ ! -z "$members" ]; then
        echo "    $group: $members"
    fi
done
echo

# 13. 检测/etc/passwd和/etc/shadow的完整性
echo "[*] 检测用户文件完整性..."
passwd_checksum=$(md5sum /etc/passwd 2>/dev/null | awk '{print $1}')
shadow_checksum=$(md5sum /etc/shadow 2>/dev/null | awk '{print $1}')

echo "  /etc/passwd MD5: $passwd_checksum"
echo "  /etc/shadow MD5: $shadow_checksum"

# 检查文件权限
passwd_perms=$(stat -c %a /etc/passwd 2>/dev/null || stat -f %Lp /etc/passwd 2>/dev/null)
shadow_perms=$(stat -c %a /etc/shadow 2>/dev/null || stat -f %Lp /etc/shadow 2>/dev/null)

echo "  /etc/passwd 权限: $passwd_perms"
echo "  /etc/shadow 权限: $shadow_perms"

if [ "$passwd_perms" != "644" ]; then
    echo "  [!] 警告 - /etc/passwd 权限异常（应为644）"
fi

if [ "$shadow_perms" != "000" ] && [ "$shadow_perms" != "400" ] && [ "$shadow_perms" != "600" ]; then
    echo "  [!] 警告 - /etc/shadow 权限异常（应为000/400/600）"
fi
echo

# 14. 检测可疑的用户crontab
echo "[*] 检测用户crontab任务..."
for user in $(cut -d: -f1 /etc/passwd); do
    user_cron=$(crontab -l -u $user 2>/dev/null)
    if [ ! -z "$user_cron" ]; then
        echo "  [*] 用户 $user 的crontab:"
        echo "$user_cron" | while read line; do
            if echo "$line" | grep -qE 'curl.*sh|wget.*sh|bash -i|nc |/tmp/|/dev/shm/'; then
                echo "    [!] 可疑 - $line"
            else
                echo "    $line"
            fi
        done
    fi
done
echo

# 15. 检测历史命令中的敏感操作
echo "[*] 检测历史命令中的敏感操作..."
for homedir in /root /home/*; do
    if [ -d "$homedir" ]; then
        username=$(basename $homedir)
        for histfile in "$homedir/.bash_history" "$homedir/.zsh_history" "$homedir/.history"; do
            if [ -f "$histfile" ]; then
                echo "  [*] 检查 $username 的历史命令: $histfile"

                # 检查可疑命令
                grep -iE 'useradd|userdel|passwd|chmod 777|rm -rf /|wget.*sh|curl.*sh|nc.*-e|bash -i|/dev/tcp/' "$histfile" 2>/dev/null | tail -10 | while read cmd; do
                    echo "    [!] 可疑命令: $cmd"
                done
            fi
        done
    fi
done
echo

# 输出摘要
echo "=========================================="
echo "用户权限安全检测完成"
echo "=========================================="
