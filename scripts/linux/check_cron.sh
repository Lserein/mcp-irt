#!/bin/bash
################################################################################
# Linux 计划任务检查脚本
# 功能: 检查 cron、at、systemd timer 等计划任务
################################################################################

echo "=========================================="
echo "计划任务检查 - $(date)"
echo "=========================================="
echo

# 1. 检查系统crontab
echo "[*] 检查系统crontab (/etc/crontab)..."
if [ -f /etc/crontab ]; then
    cat /etc/crontab
    echo
fi

# 2. 检查 /etc/cron.d/
echo "[*] 检查 /etc/cron.d/ 目录..."
if [ -d /etc/cron.d ]; then
    ls -la /etc/cron.d/
    echo
    for file in /etc/cron.d/*; do
        if [ -f "$file" ]; then
            echo "--- $file ---"
            cat "$file"
            echo
        fi
    done
fi

# 3. 检查 cron.hourly, cron.daily, cron.weekly, cron.monthly
for interval in hourly daily weekly monthly; do
    dir="/etc/cron.$interval"
    if [ -d "$dir" ]; then
        echo "[*] 检查 $dir..."
        ls -la "$dir"
        echo
    fi
done

# 4. 检查所有用户的crontab
echo "[*] 检查用户crontab..."
for user in $(cut -f1 -d: /etc/passwd); do
    cron_content=$(crontab -u $user -l 2>/dev/null)
    if [ ! -z "$cron_content" ]; then
        echo "--- User: $user ---"
        echo "$cron_content"
        # 检查可疑内容
        if echo "$cron_content" | grep -qE "(curl|wget|nc|bash|sh|python).*http"; then
            echo "  [!] 可疑 - 发现网络下载命令"
        fi
        if echo "$cron_content" | grep -qE "/tmp|/dev/shm|/var/tmp"; then
            echo "  [!] 可疑 - 使用临时目录"
        fi
        echo
    fi
done

# 5. 检查anacron
echo "[*] 检查anacron配置..."
if [ -f /etc/anacrontab ]; then
    cat /etc/anacrontab
    echo
fi

# 6. 检查at任务
echo "[*] 检查at任务..."
if command -v atq &> /dev/null; then
    atq
    echo
    # 显示at任务详情
    for job in $(atq | awk '{print $1}'); do
        echo "--- At job: $job ---"
        at -c $job 2>/dev/null | tail -n 20
        echo
    done
fi

# 7. 检查systemd timer
echo "[*] 检查systemd timer..."
if command -v systemctl &> /dev/null; then
    systemctl list-timers --all
    echo

    # 检查可疑timer
    for timer in $(systemctl list-unit-files | grep timer | awk '{print $1}'); do
        timer_file=$(systemctl show -p FragmentPath $timer 2>/dev/null | cut -d= -f2)
        if [ -f "$timer_file" ]; then
            # 检查最近修改的timer文件
            mod_time=$(stat -c %Y "$timer_file" 2>/dev/null)
            current_time=$(date +%s)
            days_diff=$(( ($current_time - $mod_time) / 86400 ))

            if [ $days_diff -lt 7 ]; then
                echo "  [!] 注意 - 最近7天内修改的timer: $timer"
                echo "  文件: $timer_file"
                echo
            fi
        fi
    done
fi

# 8. 检查 /var/spool/cron/
echo "[*] 检查 /var/spool/cron/..."
if [ -d /var/spool/cron ]; then
    ls -laR /var/spool/cron/
    echo
fi

# 9. 检查最近修改的cron相关文件
echo "[*] 检查最近修改的cron文件（7天内）..."
find /etc/cron* /var/spool/cron -type f -mtime -7 2>/dev/null | while read file; do
    echo "  [!] 最近修改: $file"
    ls -la "$file"
done
echo

# 10. 检查可疑的cron内容
echo "[*] 搜索可疑的cron命令模式..."
grep -r -E "(curl|wget).*\|.*sh|nc.*-e|bash -i|python.*socket" /etc/cron* /var/spool/cron 2>/dev/null | while read line; do
    echo "  [!] 可疑 - $line"
done
echo

echo "=========================================="
echo "计划任务检查完成"
echo "=========================================="
