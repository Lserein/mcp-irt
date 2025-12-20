# ################################################################################
# Windows 日志检查脚本
# 功能: 检查安全日志、登录事件、异常行为等
################################################################################

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "日志检查 - $(Get-Date)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. 检查最近的登录失败 (EventID 4625)
Write-Host "[*] 检查最近的登录失败 (最后30条)..." -ForegroundColor Yellow
try {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 30 -ErrorAction SilentlyContinue | `
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $targetUser = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'
            $sourceIP = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -ExpandProperty '#text'

            Write-Host "  时间: $($_.TimeCreated)"
            Write-Host "  用户: $targetUser"
            Write-Host "  来源IP: $sourceIP"
            Write-Host ""
        }
} catch {
    Write-Host "  无法读取安全日志或无登录失败记录" -ForegroundColor Yellow
}
Write-Host ""

# 2. 检查成功的登录 (EventID 4624)
Write-Host "[*] 检查成功的登录 (最后20条)..." -ForegroundColor Yellow
try {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20 -ErrorAction SilentlyContinue | `
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $targetUser = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'
            $logonType = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' } | Select-Object -ExpandProperty '#text'
            $sourceIP = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -ExpandProperty '#text'

            Write-Host "  时间: $($_.TimeCreated)"
            Write-Host "  用户: $targetUser"
            Write-Host "  登录类型: $logonType"
            Write-Host "  来源IP: $sourceIP"
            Write-Host ""
        }
} catch {
    Write-Host "  无法读取安全日志" -ForegroundColor Yellow
}
Write-Host ""

# 3. 检查账户锁定 (EventID 4740)
Write-Host "[*] 检查账户锁定事件..." -ForegroundColor Yellow
try {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740} -MaxEvents 20 -ErrorAction SilentlyContinue | `
        ForEach-Object {
            Write-Host "  [!] 账户锁定: $($_.TimeCreated) - $($_.Message)" -ForegroundColor Red
        }
} catch {
    Write-Host "  无账户锁定记录"
}
Write-Host ""

# 4. 检查新用户创建 (EventID 4720)
Write-Host "[*] 检查新用户创建..." -ForegroundColor Yellow
try {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} -MaxEvents 10 -ErrorAction SilentlyContinue | `
        ForEach-Object {
            Write-Host "  [!] 新用户创建: $($_.TimeCreated)" -ForegroundColor Yellow
            Write-Host "  $($_.Message)"
            Write-Host ""
        }
} catch {
    Write-Host "  无新用户创建记录"
}
Write-Host ""

# 5. 检查用户加入管理员组 (EventID 4732)
Write-Host "[*] 检查用户加入管理员组..." -ForegroundColor Yellow
try {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4732} -MaxEvents 10 -ErrorAction SilentlyContinue | `
        ForEach-Object {
            Write-Host "  [!] 用户加入组: $($_.TimeCreated)" -ForegroundColor Red
            Write-Host "  $($_.Message)"
            Write-Host ""
        }
} catch {
    Write-Host "  无用户组变更记录"
}
Write-Host ""

# 6. 检查特权使用 (EventID 4672)
Write-Host "[*] 检查特权使用 (管理员登录)..." -ForegroundColor Yellow
try {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -MaxEvents 15 -ErrorAction SilentlyContinue | `
        Select-Object TimeCreated, Message | Format-Table -Wrap
} catch {
    Write-Host "  无特权使用记录"
}
Write-Host ""

# 7. 检查系统错误日志
Write-Host "[*] 检查系统错误日志 (最后20条)..." -ForegroundColor Yellow
try {
    Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 20 -ErrorAction SilentlyContinue | `
        Select-Object TimeCreated, Id, ProviderName, Message | Format-Table -Wrap
} catch {
    Write-Host "  无系统错误记录"
}
Write-Host ""

# 8. 检查应用程序错误日志
Write-Host "[*] 检查应用程序错误日志 (最后20条)..." -ForegroundColor Yellow
try {
    Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2} -MaxEvents 20 -ErrorAction SilentlyContinue | `
        Select-Object TimeCreated, Id, ProviderName, Message | Format-Table -Wrap
} catch {
    Write-Host "  无应用程序错误记录"
}
Write-Host ""

# 9. 检查PowerShell执行日志 (EventID 4104)
Write-Host "[*] 检查PowerShell脚本执行日志..." -ForegroundColor Yellow
try {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 20 -ErrorAction SilentlyContinue | `
        ForEach-Object {
            $scriptBlock = $_.Properties[2].Value
            Write-Host "  时间: $($_.TimeCreated)"
            Write-Host "  脚本内容: $($scriptBlock.Substring(0, [Math]::Min(200, $scriptBlock.Length)))..."
            Write-Host ""
        }
} catch {
    Write-Host "  无PowerShell执行记录或日志未启用"
}
Write-Host ""

# 10. 检查Windows Defender检测
Write-Host "[*] 检查Windows Defender威胁检测..." -ForegroundColor Yellow
try {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117} -MaxEvents 20 -ErrorAction SilentlyContinue | `
        ForEach-Object {
            Write-Host "  [!] 威胁检测: $($_.TimeCreated)" -ForegroundColor Red
            Write-Host "  $($_.Message)"
            Write-Host ""
        }
} catch {
    Write-Host "  无威胁检测记录"
}
Write-Host ""

# 11. 检查凌晨时段的异常活动 (02:00-05:59)
Write-Host "[*] 检查凌晨时段异常活动..." -ForegroundColor Yellow
try {
    $startTime = (Get-Date).Date.AddHours(2)
    $endTime = (Get-Date).Date.AddHours(6)

    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$startTime; EndTime=$endTime} -ErrorAction SilentlyContinue | `
        ForEach-Object {
            Write-Host "  [!] 异常时段登录: $($_.TimeCreated)" -ForegroundColor Yellow
            $xml = [xml]$_.ToXml()
            $targetUser = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'
            Write-Host "  用户: $targetUser"
            Write-Host ""
        }
} catch {
    Write-Host "  无凌晨时段活动记录"
}
Write-Host ""

# 12. 检查暴力破解迹象（同一IP多次失败）
Write-Host "[*] 检查暴力破解迹象..." -ForegroundColor Yellow
try {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 1000 -ErrorAction SilentlyContinue | `
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $sourceIP = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -ExpandProperty '#text'
            $sourceIP
        } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
            if ($_.Count -gt 10) {
                Write-Host "  [!] 可疑 - IP $($_.Name) 失败次数: $($_.Count)" -ForegroundColor Red
            } else {
                Write-Host "  IP $($_.Name) 失败次数: $($_.Count)"
            }
        }
} catch {
    Write-Host "  无法分析暴力破解迹象"
}
Write-Host ""

# 13. 检查当前登录会话
Write-Host "[*] 检查当前登录会话..." -ForegroundColor Yellow
query user 2>$null
Write-Host ""

# 14. 检查最近的RDP连接
Write-Host "[*] 检查最近的RDP连接..." -ForegroundColor Yellow
try {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21,25} -MaxEvents 20 -ErrorAction SilentlyContinue | `
        Select-Object TimeCreated, Id, Message | Format-Table -Wrap
} catch {
    Write-Host "  无RDP连接记录"
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "日志检查完成" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
