# ################################################################################
# Windows 网络连接检查脚本
# 功能: 检查监听端口、异常连接、可疑IP等
################################################################################

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "网络连接检查 - $(Get-Date)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. 检查所有监听端口
Write-Host "[*] 检查监听端口..." -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        ProcessName = if($proc) { $proc.Name } else { "Unknown" }
        PID = $_.OwningProcess
    }
} | Format-Table -AutoSize
Write-Host ""

# 2. 检查已建立的连接
Write-Host "[*] 检查已建立的网络连接..." -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort = $_.RemotePort
        ProcessName = if($proc) { $proc.Name } else { "Unknown" }
        PID = $_.OwningProcess
    }
} | Format-Table -AutoSize
Write-Host ""

# 3. 检查可疑端口
Write-Host "[*] 检查可疑端口..." -ForegroundColor Yellow
$suspiciousPorts = @(1234, 4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321)

foreach ($port in $suspiciousPorts) {
    $listening = Get-NetTCPConnection | Where-Object { $_.LocalPort -eq $port -and $_.State -eq 'Listen' }
    if ($listening) {
        Write-Host "  [!] 异常 - 发现可疑端口监听: $port" -ForegroundColor Red
        $listening | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            Write-Host "      进程: $($proc.Name) PID: $($_.OwningProcess)" -ForegroundColor Red
        }
    }
}
Write-Host ""

# 4. 检查对外连接统计
Write-Host "[*] 检查对外连接IP统计 (TOP 20)..." -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' } | `
    Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 20 | `
    Select-Object @{Name="IP";Expression={$_.Name}}, Count | Format-Table -AutoSize
Write-Host ""

# 5. 检查UDP连接
Write-Host "[*] 检查UDP连接..." -ForegroundColor Yellow
Get-NetUDPEndpoint | Select-Object -First 30 | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        ProcessName = if($proc) { $proc.Name } else { "Unknown" }
        PID = $_.OwningProcess
    }
} | Format-Table -AutoSize
Write-Host ""

# 6. 检查网络配置
Write-Host "[*] 检查网络接口配置..." -ForegroundColor Yellow
Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, DNSServer | Format-Table -AutoSize
Write-Host ""

# 7. 检查路由表
Write-Host "[*] 检查路由表..." -ForegroundColor Yellow
Get-NetRoute | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0' } | `
    Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric | Format-Table -AutoSize
Write-Host ""

# 8. 检查防火墙规则
Write-Host "[*] 检查防火墙状态..." -ForegroundColor Yellow
Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize
Write-Host ""

Write-Host "[*] 检查最近添加的防火墙规则 (7天内)..." -ForegroundColor Yellow
$recentDate = (Get-Date).AddDays(-7)
Get-NetFirewallRule | Where-Object { $_.CreationDate -gt $recentDate } | `
    Select-Object -First 10 | `
    Select-Object DisplayName, Direction, Action, Enabled, CreationDate | Format-Table -Wrap
Write-Host ""

# 9. 检查ARP缓存
Write-Host "[*] 检查ARP缓存..." -ForegroundColor Yellow
Get-NetNeighbor | Where-Object { $_.State -ne 'Unreachable' } | `
    Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias | Format-Table -AutoSize
Write-Host ""

# 10. 检查DNS缓存
Write-Host "[*] 检查DNS缓存..." -ForegroundColor Yellow
Get-DnsClientCache | Select-Object -First 30 | `
    Select-Object Entry, RecordName, RecordType, TimeToLive | Format-Table -AutoSize
Write-Host ""

# 11. 检查Hosts文件
Write-Host "[*] 检查Hosts文件..." -ForegroundColor Yellow
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    Write-Host "Hosts文件内容:"
    Get-Content $hostsPath | Where-Object { $_ -notmatch '^\s*#' -and $_ -ne '' } | ForEach-Object {
        Write-Host "  $_"
    }
}
Write-Host ""

# 12. 检查网络共享
Write-Host "[*] 检查网络共享..." -ForegroundColor Yellow
Get-SmbShare | Select-Object Name, Path, Description | Format-Table -AutoSize
Write-Host ""

# 13. 检查网络连接的进程详情
Write-Host "[*] 检查有外部连接的进程详情..." -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object {
    $_.State -eq 'Established' -and
    $_.RemoteAddress -ne '127.0.0.1' -and
    $_.RemoteAddress -notlike '192.168.*' -and
    $_.RemoteAddress -notlike '10.*'
} | Select-Object -First 15 | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Host "  连接: $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)"
    Write-Host "  进程: $($proc.Name) PID: $($proc.Id)"
    if ($proc.Path) {
        Write-Host "  路径: $($proc.Path)"
    }
    Write-Host ""
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "网络检查完成" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
