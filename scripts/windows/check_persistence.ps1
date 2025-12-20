# ################################################################################
# Windows 权限维持检测脚本
# 功能: 全面检测各种Windows权限维持机制
################################################################################

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Windows 权限维持检测 - $(Get-Date)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. 注册表启动项检测
Write-Host "[*] 检查注册表启动项..." -ForegroundColor Yellow

$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
)

$suspiciousPatterns = @("temp", "tmp", "appdata", "programdata", "public", "download", ".vbs", ".js", "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32")

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Write-Host "  [*] 检查: $key" -ForegroundColor Cyan
        Get-ItemProperty -Path $key | ForEach-Object {
            $_.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                $name = $_.Name
                $value = $_.Value

                # 检查可疑模式
                $isSuspicious = $false
                foreach ($pattern in $suspiciousPatterns) {
                    if ($value -like "*$pattern*") {
                        $isSuspicious = $true
                        break
                    }
                }

                if ($isSuspicious) {
                    Write-Host "    [!] 可疑启动项: $name" -ForegroundColor Red
                    Write-Host "        值: $value" -ForegroundColor Red
                } else {
                    Write-Host "    启动项: $name -> $value"
                }
            }
        }
    }
}
Write-Host ""

# 2. 启动文件夹检测
Write-Host "[*] 检查启动文件夹..." -ForegroundColor Yellow

$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        Write-Host "  [*] 检查: $folder" -ForegroundColor Cyan
        Get-ChildItem -Path $folder -Force | ForEach-Object {
            Write-Host "    [!] 发现启动项: $($_.Name)" -ForegroundColor Yellow
            Write-Host "        路径: $($_.FullName)" -ForegroundColor Yellow
            Write-Host "        修改时间: $($_.LastWriteTime)" -ForegroundColor Yellow
        }
    }
}
Write-Host ""

# 3. 计划任务深度检测
Write-Host "[*] 检查可疑计划任务..." -ForegroundColor Yellow

$tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
foreach ($task in $tasks) {
    $taskInfo = $task | Get-ScheduledTaskInfo
    $action = ($task.Actions | Select-Object -First 1).Execute
    $args = ($task.Actions | Select-Object -First 1).Arguments

    # 检查可疑特征
    $isSuspicious = $false
    $reason = ""

    if ($action -like "*powershell*" -or $action -like "*cmd*" -or $action -like "*wscript*" -or $action -like "*cscript*") {
        $isSuspicious = $true
        $reason = "使用脚本执行"
    }

    if ($args -like "*-enc*" -or $args -like "*-encoded*" -or $args -like "*-w hidden*" -or $args -like "*-windowstyle hidden*") {
        $isSuspicious = $true
        $reason = "使用编码或隐藏参数"
    }

    if ($action -like "*temp*" -or $action -like "*tmp*" -or $action -like "*appdata*" -or $action -like "*public*") {
        $isSuspicious = $true
        $reason = "从临时目录执行"
    }

    if ($task.Principal.UserId -eq "SYSTEM" -and $isSuspicious) {
        Write-Host "  [!] 高危计划任务: $($task.TaskName)" -ForegroundColor Red
        Write-Host "      路径: $($task.TaskPath)" -ForegroundColor Red
        Write-Host "      执行: $action $args" -ForegroundColor Red
        Write-Host "      用户: $($task.Principal.UserId)" -ForegroundColor Red
        Write-Host "      原因: $reason" -ForegroundColor Red
        Write-Host "      状态: $($task.State)" -ForegroundColor Red
    } elseif ($isSuspicious) {
        Write-Host "  [!] 可疑计划任务: $($task.TaskName)" -ForegroundColor Yellow
        Write-Host "      执行: $action $args" -ForegroundColor Yellow
        Write-Host "      原因: $reason" -ForegroundColor Yellow
    }
}
Write-Host ""

# 4. 服务持久化检测
Write-Host "[*] 检查可疑服务..." -ForegroundColor Yellow

Get-Service | Where-Object { $_.Status -eq 'Running' } | ForEach-Object {
    try {
        $service = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq $_.Name }
        $path = $service.PathName

        if ($path) {
            # 检查可疑特征
            $isSuspicious = $false
            $reason = ""

            if ($path -like "*temp*" -or $path -like "*tmp*" -or $path -like "*appdata*" -or $path -like "*public*" -or $path -like "*programdata*") {
                $isSuspicious = $true
                $reason = "从临时目录运行"
            }

            if ($path -like "*powershell*" -or $path -like "*cmd*" -or $path -like "*wscript*") {
                $isSuspicious = $true
                $reason = "使用脚本执行"
            }

            # 检查是否为非Microsoft服务
            $isNonMS = $service.DisplayName -notmatch 'Microsoft|Windows' -and $path -notlike "*Windows*" -and $path -notlike "*Program Files*"

            if ($isSuspicious -or ($isNonMS -and $service.StartMode -eq 'Auto')) {
                Write-Host "  [!] 可疑服务: $($service.Name)" -ForegroundColor Yellow
                Write-Host "      显示名: $($service.DisplayName)" -ForegroundColor Yellow
                Write-Host "      路径: $path" -ForegroundColor Yellow
                Write-Host "      启动类型: $($service.StartMode)" -ForegroundColor Yellow
                Write-Host "      运行账户: $($service.StartName)" -ForegroundColor Yellow
                if ($reason) { Write-Host "      原因: $reason" -ForegroundColor Yellow }
            }
        }
    } catch {
        # 忽略错误
    }
}
Write-Host ""

# 5. WMI事件订阅检测 (常见高级持久化)
Write-Host "[*] 检查WMI事件订阅..." -ForegroundColor Yellow

try {
    # 检查WMI事件过滤器
    $filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
    if ($filters) {
        Write-Host "  [!] 发现 $($filters.Count) 个WMI事件过滤器" -ForegroundColor Yellow
        $filters | ForEach-Object {
            Write-Host "    过滤器: $($_.Name)" -ForegroundColor Yellow
            Write-Host "    查询: $($_.Query)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [+] 未发现WMI事件过滤器" -ForegroundColor Green
    }

    # 检查WMI事件消费者
    $consumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    if ($consumers) {
        Write-Host "  [!] 发现 $($consumers.Count) 个WMI事件消费者" -ForegroundColor Red
        $consumers | ForEach-Object {
            Write-Host "    消费者: $($_.Name)" -ForegroundColor Red
            Write-Host "    类型: $($_.__CLASS)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [+] 未发现WMI事件消费者" -ForegroundColor Green
    }

    # 检查WMI绑定
    $bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
    if ($bindings) {
        Write-Host "  [!] 发现 $($bindings.Count) 个WMI过滤器-消费者绑定 (高危!)" -ForegroundColor Red
        $bindings | ForEach-Object {
            Write-Host "    绑定:" -ForegroundColor Red
            Write-Host "      过滤器: $($_.Filter)" -ForegroundColor Red
            Write-Host "      消费者: $($_.Consumer)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [+] 未发现WMI绑定" -ForegroundColor Green
    }
} catch {
    Write-Host "  [!] WMI检查失败: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# 6. COM劫持检测
Write-Host "[*] 检查COM劫持..." -ForegroundColor Yellow

$comKeys = @(
    "HKCU:\Software\Classes\CLSID"
)

foreach ($key in $comKeys) {
    if (Test-Path $key) {
        $items = Get-ChildItem -Path $key -ErrorAction SilentlyContinue | Select-Object -First 50
        $count = ($items | Measure-Object).Count
        if ($count -gt 0) {
            Write-Host "  [!] 发现 $count 个用户级CLSID注册 (可能被劫持)" -ForegroundColor Yellow
            $items | Select-Object -First 10 | ForEach-Object {
                Write-Host "    CLSID: $($_.PSChildName)"
            }
        }
    }
}
Write-Host ""

# 7. AppInit_DLLs检测 (DLL注入)
Write-Host "[*] 检查AppInit_DLLs注入..." -ForegroundColor Yellow

$appInitKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
)

foreach ($key in $appInitKeys) {
    if (Test-Path $key) {
        $appInit = Get-ItemProperty -Path $key -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
        if ($appInit -and $appInit.AppInit_DLLs) {
            Write-Host "  [!] 发现AppInit_DLLs配置: $($appInit.AppInit_DLLs)" -ForegroundColor Red
        }
    }
}
Write-Host ""

# 8. 映像劫持检测 (IFEO)
Write-Host "[*] 检查映像劫持 (IFEO)..." -ForegroundColor Yellow

$ifeoKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
if (Test-Path $ifeoKey) {
    $items = Get-ChildItem -Path $ifeoKey | Where-Object {
        $debugger = Get-ItemProperty -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
        $debugger -and $debugger.Debugger
    }

    if ($items) {
        Write-Host "  [!] 发现 $($items.Count) 个映像劫持配置" -ForegroundColor Red
        $items | ForEach-Object {
            $debugger = Get-ItemProperty -Path $_.PSPath -Name "Debugger"
            Write-Host "    劫持程序: $($_.PSChildName)" -ForegroundColor Red
            Write-Host "    调试器: $($debugger.Debugger)" -ForegroundColor Red
        }
    }
}
Write-Host ""

# 9. 屏幕保护程序后门检测
Write-Host "[*] 检查屏幕保护程序后门..." -ForegroundColor Yellow

$scrKey = "HKCU:\Control Panel\Desktop"
if (Test-Path $scrKey) {
    $scr = Get-ItemProperty -Path $scrKey -Name "SCRNSAVE.EXE" -ErrorAction SilentlyContinue
    if ($scr -and $scr.'SCRNSAVE.EXE') {
        $scrPath = $scr.'SCRNSAVE.EXE'
        if ($scrPath -notlike "*Windows*" -and $scrPath -notlike "*System32*") {
            Write-Host "  [!] 可疑屏幕保护程序: $scrPath" -ForegroundColor Yellow
        }
    }
}
Write-Host ""

# 10. Winlogon持久化检测
Write-Host "[*] 检查Winlogon持久化..." -ForegroundColor Yellow

$winlogonKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)

foreach ($key in $winlogonKeys) {
    if (Test-Path $key) {
        $props = Get-ItemProperty -Path $key

        # 检查Shell
        if ($props.Shell -and $props.Shell -ne "explorer.exe") {
            Write-Host "  [!] 可疑Shell配置: $($props.Shell)" -ForegroundColor Red
        }

        # 检查Userinit
        if ($props.Userinit -and $props.Userinit -notlike "*userinit.exe*") {
            Write-Host "  [!] 可疑Userinit配置: $($props.Userinit)" -ForegroundColor Red
        }

        # 检查Notify
        if ($props.Notify) {
            Write-Host "  [!] 发现Notify配置: $($props.Notify)" -ForegroundColor Yellow
        }
    }
}
Write-Host ""

# 11. 浏览器扩展检测
Write-Host "[*] 检查浏览器扩展..." -ForegroundColor Yellow

# Chrome扩展
$chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
if (Test-Path $chromeExtPath) {
    $extCount = (Get-ChildItem -Path $chromeExtPath -Directory | Measure-Object).Count
    Write-Host "  [*] Chrome扩展数量: $extCount"
    Get-ChildItem -Path $chromeExtPath -Directory | Select-Object -First 10 | ForEach-Object {
        Write-Host "    扩展ID: $($_.Name)"
    }
}

# Edge扩展
$edgeExtPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
if (Test-Path $edgeExtPath) {
    $extCount = (Get-ChildItem -Path $edgeExtPath -Directory | Measure-Object).Count
    Write-Host "  [*] Edge扩展数量: $extCount"
}
Write-Host ""

# 12. Office宏设置检测
Write-Host "[*] 检查Office宏安全设置..." -ForegroundColor Yellow

$officeVersions = @("14.0", "15.0", "16.0")  # Office 2010, 2013, 2016+
foreach ($ver in $officeVersions) {
    $wordKey = "HKCU:\Software\Microsoft\Office\$ver\Word\Security"
    if (Test-Path $wordKey) {
        $vbaWarnings = Get-ItemProperty -Path $wordKey -Name "VBAWarnings" -ErrorAction SilentlyContinue
        if ($vbaWarnings -and $vbaWarnings.VBAWarnings -eq 1) {
            Write-Host "  [!] Word宏安全设置: 全部启用 (高危!)" -ForegroundColor Red
        }
    }
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "权限维持检测完成" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
