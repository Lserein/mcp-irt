# ################################################################################
# Windows 计划任务检查脚本
# 功能: 检查可疑的计划任务
################################################################################

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "计划任务检查 - $(Get-Date)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. 检查所有启用的计划任务
Write-Host "[*] 检查启用的计划任务..." -ForegroundColor Yellow
Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -or $_.State -eq 'Running' } | `
    Select-Object -First 30 | `
    Select-Object TaskName, TaskPath, State, @{Name="NextRunTime";Expression={$_.Triggers.StartBoundary}} | `
    Format-Table -AutoSize
Write-Host ""

# 2. 检查最近创建的计划任务 (7天内)
Write-Host "[*] 检查最近创建的计划任务 (7天内)..." -ForegroundColor Yellow
$recentDate = (Get-Date).AddDays(-7)
Get-ScheduledTask | Where-Object {
    $taskInfo = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
    $taskInfo -and $taskInfo.LastTaskResult -ne $null
} | ForEach-Object {
    $task = $_
    $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
    # 注意: PowerShell的ScheduledTask没有CreationDate，我们检查最近运行的
    if ($taskInfo.LastRunTime -gt $recentDate -or $taskInfo.NextRunTime -gt (Get-Date)) {
        Write-Host "  [!] 任务: $($task.TaskPath)$($task.TaskName)" -ForegroundColor Yellow
        Write-Host "      状态: $($task.State)"
        Write-Host "      最后运行: $($taskInfo.LastRunTime)"
        Write-Host "      下次运行: $($taskInfo.NextRunTime)"
        Write-Host ""
    }
}
Write-Host ""

# 3. 检查可疑的任务（使用powershell、cmd、wscript等）
Write-Host "[*] 检查包含可疑命令的计划任务..." -ForegroundColor Yellow
$suspiciousKeywords = @('powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'regsvr32', 'rundll32', 'certutil', 'bitsadmin')

Get-ScheduledTask | ForEach-Object {
    $task = $_
    $taskActions = $task.Actions

    foreach ($action in $taskActions) {
        $execute = $action.Execute
        $arguments = $action.Arguments

        foreach ($keyword in $suspiciousKeywords) {
            if ($execute -like "*$keyword*" -or $arguments -like "*$keyword*") {
                Write-Host "  [!] 可疑 - 任务: $($task.TaskPath)$($task.TaskName)" -ForegroundColor Red
                Write-Host "      执行: $execute" -ForegroundColor Red
                Write-Host "      参数: $arguments" -ForegroundColor Red
                Write-Host ""
                break
            }
        }
    }
}
Write-Host ""

# 4. 检查从临时目录执行的任务
Write-Host "[*] 检查从临时目录执行的任务..." -ForegroundColor Yellow
$tempPaths = @('C:\Windows\Temp', 'C:\Temp', $env:TEMP, $env:TMP, 'C:\Users\Public')

Get-ScheduledTask | ForEach-Object {
    $task = $_
    $taskActions = $task.Actions

    foreach ($action in $taskActions) {
        $execute = $action.Execute

        foreach ($tempPath in $tempPaths) {
            if ($execute -like "$tempPath*") {
                Write-Host "  [!] 可疑 - 从临时目录执行: $($task.TaskPath)$($task.TaskName)" -ForegroundColor Red
                Write-Host "      执行: $execute" -ForegroundColor Red
                Write-Host ""
                break
            }
        }
    }
}
Write-Host ""

# 5. 检查以SYSTEM权限运行的任务
Write-Host "[*] 检查以SYSTEM权限运行的任务..." -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {
    $_.Principal.UserId -eq 'S-1-5-18' -or $_.Principal.UserId -eq 'NT AUTHORITY\SYSTEM'
} | Select-Object -First 20 | ForEach-Object {
    Write-Host "  任务: $($_.TaskPath)$($_.TaskName)"
    Write-Host "  用户: $($_.Principal.UserId)"
    Write-Host "  执行: $($_.Actions.Execute)"
    Write-Host ""
}
Write-Host ""

# 6. 检查包含网络操作的任务
Write-Host "[*] 检查包含网络操作的任务..." -ForegroundColor Yellow
$networkKeywords = @('http', 'https', 'ftp', 'download', 'wget', 'curl', 'invoke-webrequest', 'start-bitstransfer')

Get-ScheduledTask | ForEach-Object {
    $task = $_
    $taskActions = $task.Actions

    foreach ($action in $taskActions) {
        $execute = $action.Execute
        $arguments = $action.Arguments

        foreach ($keyword in $networkKeywords) {
            if ($arguments -like "*$keyword*") {
                Write-Host "  [!] 可疑 - 包含网络操作: $($task.TaskPath)$($task.TaskName)" -ForegroundColor Red
                Write-Host "      执行: $execute" -ForegroundColor Red
                Write-Host "      参数: $arguments" -ForegroundColor Red
                Write-Host ""
                break
            }
        }
    }
}
Write-Host ""

# 7. 检查隐藏的计划任务（任务名包含空格或特殊字符）
Write-Host "[*] 检查可疑命名的计划任务..." -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {
    $_.TaskName -match '\s{2,}' -or
    $_.TaskName -match '[^\x20-\x7E]' -or
    $_.TaskName -like '*  *'
} | ForEach-Object {
    Write-Host "  [!] 可疑任务名: $($_.TaskPath)$($_.TaskName)" -ForegroundColor Red
    Write-Host ""
}
Write-Host ""

# 8. 检查启动项 (WMI)
Write-Host "[*] 检查启动项..." -ForegroundColor Yellow
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-Table -Wrap
Write-Host ""

# 9. 检查注册表启动项
Write-Host "[*] 检查注册表启动项..." -ForegroundColor Yellow
$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Write-Host "  注册表键: $key"
        Get-ItemProperty -Path $key | ForEach-Object {
            $_.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                Write-Host "    $($_.Name) = $($_.Value)"
            }
        }
        Write-Host ""
    }
}

# 10. 检查服务
Write-Host "[*] 检查可疑服务..." -ForegroundColor Yellow
Get-Service | Where-Object {
    $_.Status -eq 'Running' -and
    $_.DisplayName -notmatch 'Microsoft|Windows|Intel|AMD|NVIDIA'
} | Select-Object -First 20 | ForEach-Object {
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'"
    Write-Host "  服务: $($_.Name)"
    Write-Host "  显示名: $($_.DisplayName)"
    Write-Host "  路径: $($service.PathName)"
    Write-Host ""
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "计划任务检查完成" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
