# ################################################################################
# Windows 进程终止脚本
# 功能: 安全地终止指定进程
################################################################################

param(
    [Parameter(Mandatory=$true)]
    [int]$PID
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "进程终止 - $(Get-Date)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 检查进程是否存在
$process = Get-Process -Id $PID -ErrorAction SilentlyContinue

if (-not $process) {
    Write-Host "[!] 错误: 进程 $PID 不存在" -ForegroundColor Red
    exit 1
}

# 显示进程信息
Write-Host "[*] 进程信息:" -ForegroundColor Yellow
$process | Select-Object Id, Name, Path, StartTime, CPU, WorkingSet | Format-List

# 获取进程详细信息
$processDetails = Get-WmiObject Win32_Process -Filter "ProcessId=$PID"
Write-Host "[*] 进程命令行:" -ForegroundColor Yellow
Write-Host "  $($processDetails.CommandLine)"
Write-Host ""

# 显示进程的网络连接
Write-Host "[*] 进程的网络连接:" -ForegroundColor Yellow
Get-NetTCPConnection -OwningProcess $PID -ErrorAction SilentlyContinue | `
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize
Write-Host ""

# 保存取证信息
$evidenceDir = "C:\Windows\Temp\irt_evidence_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null

Write-Host "[*] 保存取证信息到: $evidenceDir" -ForegroundColor Yellow

# 保存进程信息
$process | Select-Object * | Out-File "$evidenceDir\process_info_$PID.txt"
$processDetails | Select-Object * | Out-File "$evidenceDir\process_details_$PID.txt"

# 保存进程的加载模块
Get-Process -Id $PID | Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue | `
    Out-File "$evidenceDir\process_modules_$PID.txt"

# 保存网络连接
Get-NetTCPConnection -OwningProcess $PID -ErrorAction SilentlyContinue | `
    Out-File "$evidenceDir\process_connections_$PID.txt"

# 尝试复制进程可执行文件
if ($process.Path) {
    try {
        Copy-Item -Path $process.Path -Destination "$evidenceDir\process_binary_$PID.exe" -ErrorAction SilentlyContinue
        Write-Host "[+] 已保存进程二进制文件" -ForegroundColor Green
    } catch {
        Write-Host "[!] 无法复制进程文件: $_" -ForegroundColor Yellow
    }
}

# 保存进程内存转储（需要管理员权限）
Write-Host "[*] 尝试创建内存转储..." -ForegroundColor Yellow
try {
    # 使用procdump或者其他工具
    # 这里简化处理
    Write-Host "  (跳过内存转储 - 需要额外工具如procdump)" -ForegroundColor Yellow
} catch {
    Write-Host "  无法创建内存转储" -ForegroundColor Yellow
}

Write-Host ""

# 终止进程
Write-Host "[*] 尝试优雅终止进程..." -ForegroundColor Yellow
try {
    Stop-Process -Id $PID -ErrorAction Stop
    Start-Sleep -Seconds 2

    # 检查进程是否还在运行
    $stillRunning = Get-Process -Id $PID -ErrorAction SilentlyContinue

    if ($stillRunning) {
        Write-Host "[*] 进程仍在运行，强制终止..." -ForegroundColor Yellow
        Stop-Process -Id $PID -Force -ErrorAction Stop
        Start-Sleep -Seconds 1
    }

    # 最终检查
    $finalCheck = Get-Process -Id $PID -ErrorAction SilentlyContinue

    if ($finalCheck) {
        Write-Host "[!] 失败: 进程 $PID 仍在运行" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "[+] 成功: 进程 $PID 已终止" -ForegroundColor Green
    }

} catch {
    Write-Host "[!] 错误: 无法终止进程 - $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "取证数据已保存至: $evidenceDir" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

exit 0
