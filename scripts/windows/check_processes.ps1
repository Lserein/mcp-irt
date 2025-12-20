# ################################################################################
# Windows 进程检查脚本
# 功能: 检查异常进程（高CPU、可疑路径、无签名等）
################################################################################

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "进程检查 - $(Get-Date)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. 检查高CPU占用进程
Write-Host "[*] 检查高CPU占用进程 (>70%)..." -ForegroundColor Yellow
Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 | ForEach-Object {
    $cpuPercent = $_.CPU
    if ($cpuPercent -gt 70) {
        Write-Host "  [!] 高危 - 进程: $($_.Name) PID: $($_.Id) CPU: $cpuPercent" -ForegroundColor Red
    } else {
        Write-Host "  进程: $($_.Name) PID: $($_.Id) CPU: $cpuPercent"
    }
}
Write-Host ""

# 2. 检查高内存占用进程
Write-Host "[*] 检查高内存占用进程 (TOP 10)..." -ForegroundColor Yellow
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 | `
    Select-Object Name, Id, @{Name="MemoryMB";Expression={[math]::Round($_.WorkingSet/1MB,2)}} | Format-Table
Write-Host ""

# 3. 检查可疑路径进程
Write-Host "[*] 检查可疑路径进程..." -ForegroundColor Yellow
$suspiciousPaths = @(
    "$env:TEMP",
    "$env:TMP",
    "C:\Users\Public",
    "C:\ProgramData",
    "C:\Windows\Temp"
)

Get-Process | Where-Object { $_.Path } | ForEach-Object {
    $processPath = $_.Path
    foreach ($suspPath in $suspiciousPaths) {
        if ($processPath -like "$suspPath*") {
            Write-Host "  [!] 可疑 - 进程从临时目录运行: $($_.Name) PID: $($_.Id)" -ForegroundColor Red
            Write-Host "      路径: $processPath" -ForegroundColor Red
        }
    }
}
Write-Host ""

# 4. 检查无签名进程
Write-Host "[*] 检查未签名进程..." -ForegroundColor Yellow
Get-Process | Where-Object { $_.Path } | Select-Object -First 30 | ForEach-Object {
    try {
        $signature = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction SilentlyContinue
        if ($signature.Status -ne 'Valid') {
            Write-Host "  [!] 可疑 - 未签名进程: $($_.Name) PID: $($_.Id)" -ForegroundColor Red
            Write-Host "      路径: $($_.Path)" -ForegroundColor Red
            Write-Host "      签名状态: $($signature.Status)" -ForegroundColor Red
        }
    } catch {
        # 忽略错误
    }
}
Write-Host ""

# 5. 检查网络连接进程
Write-Host "[*] 检查有网络连接的进程..." -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | `
    Select-Object -First 20 | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "  进程: $($proc.Name) PID: $($proc.Id) -> $($_.RemoteAddress):$($_.RemotePort)"
    }
}
Write-Host ""

# 6. 检查隐藏窗口进程
Write-Host "[*] 检查隐藏窗口进程..." -ForegroundColor Yellow
Get-Process | Where-Object { $_.MainWindowHandle -eq 0 -and $_.ProcessName -notlike "svchost*" } | `
    Select-Object -First 20 | Select-Object Name, Id, StartTime | Format-Table
Write-Host ""

# 7. 检查最近启动的进程 (10分钟内)
Write-Host "[*] 检查最近10分钟内启动的进程..." -ForegroundColor Yellow
$recentTime = (Get-Date).AddMinutes(-10)
Get-Process | Where-Object { $_.StartTime -gt $recentTime } | `
    Sort-Object StartTime -Descending | `
    Select-Object Name, Id, StartTime, Path | Format-Table
Write-Host ""

# 8. 检查PowerShell进程
Write-Host "[*] 检查PowerShell进程..." -ForegroundColor Yellow
Get-Process | Where-Object { $_.Name -like "*powershell*" -or $_.Name -like "*pwsh*" } | `
    Select-Object Name, Id, StartTime, @{Name="CommandLine";Expression={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}} | `
    Format-Table -Wrap
Write-Host ""

# 9. 检查CMD进程
Write-Host "[*] 检查CMD进程..." -ForegroundColor Yellow
Get-Process | Where-Object { $_.Name -eq "cmd" } | ForEach-Object {
    $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine
    Write-Host "  CMD PID: $($_.Id) 启动时间: $($_.StartTime)"
    Write-Host "  命令行: $cmdLine"
}
Write-Host ""

# 10. 检查可疑服务
Write-Host "[*] 检查可疑服务..." -ForegroundColor Yellow
Get-Service | Where-Object { $_.Status -eq 'Running' -and $_.DisplayName -notmatch 'Microsoft|Windows' } | `
    Select-Object -First 20 | Select-Object Name, DisplayName, Status | Format-Table
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "进程检查完成" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
