# ################################################################################
# Windows IP阻断脚本
# 功能: 使用Windows防火墙阻断指定IP地址
################################################################################

param(
    [Parameter(Mandatory=$true)]
    [string]$IPAddress
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "IP阻断 - $(Get-Date)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 验证IP地址格式
if ($IPAddress -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
    Write-Host "[!] 错误: 无效的IP地址格式: $IPAddress" -ForegroundColor Red
    exit 1
}

# 检查是否为本地IP
if ($IPAddress -match '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') {
    Write-Host "[!] 警告: $IPAddress 看起来是本地IP地址" -ForegroundColor Yellow
    $confirm = Read-Host "确认要阻断此IP吗? (yes/no)"
    if ($confirm -ne "yes") {
        Write-Host "[*] 操作已取消" -ForegroundColor Yellow
        exit 0
    }
}

# 检查防火墙服务状态
$firewallService = Get-Service -Name mpssvc -ErrorAction SilentlyContinue
if ($firewallService.Status -ne 'Running') {
    Write-Host "[!] 警告: Windows防火墙服务未运行" -ForegroundColor Yellow
}

# 检查是否已经存在阻断规则
$existingRules = Get-NetFirewallRule | Where-Object {
    $_.DisplayName -like "*Block_$IPAddress*"
}

if ($existingRules) {
    Write-Host "[*] IP $IPAddress 已存在防火墙规则" -ForegroundColor Yellow
}

# 显示当前与该IP的连接
Write-Host "[*] 当前与 $IPAddress 的连接:" -ForegroundColor Yellow
Get-NetTCPConnection | Where-Object {
    $_.RemoteAddress -eq $IPAddress -or $_.LocalAddress -eq $IPAddress
} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Format-Table -AutoSize
Write-Host ""

# 创建防火墙规则阻断入站流量
Write-Host "[*] 创建防火墙规则阻断入站流量..." -ForegroundColor Yellow
try {
    New-NetFirewallRule -DisplayName "IRT_Block_Inbound_$IPAddress" `
        -Direction Inbound `
        -Action Block `
        -RemoteAddress $IPAddress `
        -Enabled True `
        -Profile Any `
        -ErrorAction Stop | Out-Null

    Write-Host "[+] 已阻断来自 $IPAddress 的入站流量" -ForegroundColor Green
} catch {
    Write-Host "[!] 创建入站规则失败: $_" -ForegroundColor Red
}

# 创建防火墙规则阻断出站流量
Write-Host "[*] 创建防火墙规则阻断出站流量..." -ForegroundColor Yellow
try {
    New-NetFirewallRule -DisplayName "IRT_Block_Outbound_$IPAddress" `
        -Direction Outbound `
        -Action Block `
        -RemoteAddress $IPAddress `
        -Enabled True `
        -Profile Any `
        -ErrorAction Stop | Out-Null

    Write-Host "[+] 已阻断到 $IPAddress 的出站流量" -ForegroundColor Green
} catch {
    Write-Host "[!] 创建出站规则失败: $_" -ForegroundColor Red
}

Write-Host ""

# 显示新创建的规则
Write-Host "[*] 当前针对 $IPAddress 的防火墙规则:" -ForegroundColor Yellow
Get-NetFirewallRule | Where-Object {
    $_.DisplayName -like "*$IPAddress*"
} | Select-Object DisplayName, Direction, Action, Enabled | Format-Table -AutoSize
Write-Host ""

# 断开现有连接
Write-Host "[*] 尝试断开与 $IPAddress 的现有连接..." -ForegroundColor Yellow
$connections = Get-NetTCPConnection | Where-Object {
    $_.RemoteAddress -eq $IPAddress
}

foreach ($conn in $connections) {
    try {
        # PowerShell没有直接断开TCP连接的命令
        # 可以尝试终止拥有该连接的进程（谨慎操作）
        Write-Host "  发现连接: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) (PID: $($conn.OwningProcess))" -ForegroundColor Yellow
        # 不自动终止进程，仅记录
    } catch {
        # 忽略错误
    }
}

Write-Host ""

# 保存操作记录
$logPath = "C:\Windows\Temp\irt_block_log.txt"
$logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Blocked IP: $IPAddress"
Add-Content -Path $logPath -Value $logEntry

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "IP $IPAddress 已被阻断" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "撤销阻断命令:" -ForegroundColor Yellow
Write-Host "  Remove-NetFirewallRule -DisplayName 'IRT_Block_Inbound_$IPAddress'" -ForegroundColor Gray
Write-Host "  Remove-NetFirewallRule -DisplayName 'IRT_Block_Outbound_$IPAddress'" -ForegroundColor Gray
Write-Host ""

exit 0
