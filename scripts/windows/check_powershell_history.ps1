# ################################################################################
# PowerShell历史记录和执行策略检测脚本
# 功能: 检查PowerShell执行历史、可疑命令、配置安全
################################################################################

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PowerShell安全检测 - $(Get-Date)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. PowerShell执行策略检测
Write-Host "[*] 检查PowerShell执行策略..." -ForegroundColor Yellow

$policies = Get-ExecutionPolicy -List
$policies | ForEach-Object {
    $color = switch ($_.ExecutionPolicy) {
        "Restricted" { 'Green' }
        "AllSigned" { 'Green' }
        "RemoteSigned" { 'Yellow' }
        "Unrestricted" { 'Red' }
        "Bypass" { 'Red' }
        default { 'Gray' }
    }
    Write-Host "  $($_.Scope): $($_.ExecutionPolicy)" -ForegroundColor $color
}

$currentPolicy = Get-ExecutionPolicy
if ($currentPolicy -in @("Unrestricted", "Bypass")) {
    Write-Host ""
    Write-Host "  [!] 警告: 当前执行策略为 $currentPolicy，存在安全风险!" -ForegroundColor Red
}
Write-Host ""

# 2. PowerShell历史记录检测
Write-Host "[*] 检查PowerShell命令历史..." -ForegroundColor Yellow

# PSReadLine历史文件
$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $historyPath) {
    Write-Host "  [*] 发现历史记录文件: $historyPath" -ForegroundColor Cyan

    $history = Get-Content $historyPath -ErrorAction SilentlyContinue
    if ($history) {
        Write-Host "  [*] 历史记录总行数: $($history.Count)"

        # 定义可疑命令模式
        $suspiciousPatterns = @(
            @{Pattern='Invoke-Expression|iex'; Name='远程代码执行'; Severity='High'},
            @{Pattern='downloadstring|downloadfile'; Name='下载操作'; Severity='High'},
            @{Pattern='-encodedcommand|-enc|-e\s'; Name='编码命令'; Severity='High'},
            @{Pattern='bypass|-ep\s+bypass'; Name='绕过执行策略'; Severity='High'},
            @{Pattern='hidden|-windowstyle\s+hidden|-w\s+hidden'; Name='隐藏窗口'; Severity='Medium'},
            @{Pattern='mimikatz|invoke-mimikatz'; Name='凭证窃取工具'; Severity='Critical'},
            @{Pattern='powersploit|empire|covenant|metasploit'; Name='渗透测试框架'; Severity='Critical'},
            @{Pattern='invoke-shellcode|invoke-dllinjection'; Name='代码注入'; Severity='Critical'},
            @{Pattern='get-credential|convertto-securestring|convertfrom-securestring'; Name='凭证操作'; Severity='Medium'},
            @{Pattern='new-object\s+net\.webclient'; Name='Web请求'; Severity='Medium'},
            @{Pattern='start-process.*-verb\s+runas'; Name='提权操作'; Severity='Medium'},
            @{Pattern='set-mppreference.*-exclusion|add-mppreference.*-exclusion'; Name='修改Defender排除'; Severity='High'},
            @{Pattern='disable.*defender|stop.*windefend'; Name='禁用Defender'; Severity='Critical'},
            @{Pattern='wmic.*process\s+call\s+create'; Name='WMIC进程创建'; Severity='High'},
            @{Pattern='reg\s+add.*\\run|new-itemproperty.*\\run'; Name='注册表持久化'; Severity='High'},
            @{Pattern='schtasks.*\/create|new-scheduledtask'; Name='计划任务创建'; Severity='Medium'},
            @{Pattern='net\s+user.*\/add|new-localuser'; Name='创建用户'; Severity='High'},
            @{Pattern='net\s+user.*administrators|add-localgroupmember.*administrators'; Name='添加管理员'; Severity='Critical'},
            @{Pattern='odbcconf|regsvr32|rundll32|mshta|certutil'; Name='LOLBins利用'; Severity='High'},
            @{Pattern='base64|frombase64'; Name='Base64编码'; Severity='Medium'},
            @{Pattern='compress|expand-archive'; Name='压缩/解压'; Severity='Low'},
            @{Pattern='out-file|set-content'; Name='文件写入'; Severity='Low'}
        )

        $findings = @{}
        foreach ($pattern in $suspiciousPatterns) {
            $findings[$pattern.Name] = @()
        }

        # 扫描历史记录
        for ($i = 0; $i -lt $history.Count; $i++) {
            $line = $history[$i]
            foreach ($pattern in $suspiciousPatterns) {
                if ($line -match $pattern.Pattern) {
                    $findings[$pattern.Name] += @{
                        Line = $i + 1
                        Command = $line
                        Severity = $pattern.Severity
                    }
                }
            }
        }

        # 报告发现
        $totalFindings = 0
        foreach ($key in $findings.Keys) {
            if ($findings[$key].Count -gt 0) {
                $totalFindings += $findings[$key].Count
            }
        }

        if ($totalFindings -gt 0) {
            Write-Host ""
            Write-Host "  [!] 发现 $totalFindings 条可疑命令!" -ForegroundColor Red
            Write-Host ""

            # 按严重程度排序显示
            foreach ($severity in @('Critical', 'High', 'Medium', 'Low')) {
                foreach ($key in $findings.Keys) {
                    $items = $findings[$key] | Where-Object { $_.Severity -eq $severity }
                    if ($items.Count -gt 0) {
                        $color = switch ($severity) {
                            'Critical' { 'Red' }
                            'High' { 'Red' }
                            'Medium' { 'Yellow' }
                            'Low' { 'Cyan' }
                        }

                        Write-Host "  [$severity] $key - 发现 $($items.Count) 次:" -ForegroundColor $color
                        $items | Select-Object -First 5 | ForEach-Object {
                            Write-Host "    行 $($_.Line): $($_.Command)" -ForegroundColor $color
                        }
                        if ($items.Count -gt 5) {
                            Write-Host "    ... 还有 $($items.Count - 5) 条记录" -ForegroundColor $color
                        }
                        Write-Host ""
                    }
                }
            }
        } else {
            Write-Host "  [+] 未发现可疑命令" -ForegroundColor Green
        }

        # 统计最常用命令
        Write-Host ""
        Write-Host "  [*] 最常用的前10个命令:" -ForegroundColor Cyan
        $history | ForEach-Object { ($_ -split '\s+')[0] } |
            Group-Object | Sort-Object Count -Descending |
            Select-Object -First 10 | ForEach-Object {
                Write-Host "    $($_.Name): $($_.Count) 次"
            }
    } else {
        Write-Host "  [*] 历史记录为空" -ForegroundColor Gray
    }
} else {
    Write-Host "  [*] 未找到历史记录文件" -ForegroundColor Gray
}
Write-Host ""

# 3. PowerShell模块日志检测
Write-Host "[*] 检查PowerShell模块日志..." -ForegroundColor Yellow

try {
    # Event ID 4103: Module logging
    $moduleEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        Id = 4103
    } -MaxEvents 100 -ErrorAction SilentlyContinue

    if ($moduleEvents) {
        Write-Host "  [*] 发现 $($moduleEvents.Count) 条模块执行日志" -ForegroundColor Cyan

        # 分析可疑模块调用
        $suspiciousModules = @('Mimikatz', 'PowerSploit', 'Empire', 'Invoke-', 'Bypass', 'Hidden')
        $suspiciousEvents = $moduleEvents | Where-Object {
            $message = $_.Message
            $suspiciousModules | Where-Object { $message -like "*$_*" }
        }

        if ($suspiciousEvents) {
            Write-Host "  [!] 发现 $($suspiciousEvents.Count) 条可疑模块调用!" -ForegroundColor Red
            $suspiciousEvents | Select-Object -First 10 | ForEach-Object {
                Write-Host "    时间: $($_.TimeCreated)" -ForegroundColor Red
                Write-Host "    消息: $($_.Message.Substring(0, [Math]::Min(200, $_.Message.Length)))..." -ForegroundColor Red
                Write-Host ""
            }
        }
    }
} catch {
    Write-Host "  [*] 无法读取模块日志" -ForegroundColor Gray
}
Write-Host ""

# 4. PowerShell脚本块日志检测 (最详细)
Write-Host "[*] 检查PowerShell脚本块日志..." -ForegroundColor Yellow

try {
    # Event ID 4104: Script block logging
    $scriptEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        Id = 4104
    } -MaxEvents 100 -ErrorAction SilentlyContinue

    if ($scriptEvents) {
        Write-Host "  [*] 发现 $($scriptEvents.Count) 条脚本执行日志" -ForegroundColor Cyan

        # 检查可疑脚本
        $suspiciousScripts = $scriptEvents | Where-Object {
            $_.Message -match 'Invoke-Expression|iex|downloadstring|bypass|hidden|mimikatz|empire'
        }

        if ($suspiciousScripts) {
            Write-Host "  [!] 发现 $($suspiciousScripts.Count) 条可疑脚本执行!" -ForegroundColor Red
            $suspiciousScripts | Select-Object -First 5 | ForEach-Object {
                Write-Host ""
                Write-Host "    [!] 时间: $($_.TimeCreated)" -ForegroundColor Red
                Write-Host "    脚本内容:" -ForegroundColor Red
                Write-Host "    $($_.Message.Substring(0, [Math]::Min(300, $_.Message.Length)))..." -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Host "  [*] 无法读取脚本块日志" -ForegroundColor Gray
}
Write-Host ""

# 5. PowerShell转录日志检测
Write-Host "[*] 检查PowerShell转录日志配置..." -ForegroundColor Yellow

$transcriptKeys = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
    "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
)

foreach ($key in $transcriptKeys) {
    if (Test-Path $key) {
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        if ($props.EnableTranscripting -eq 1) {
            Write-Host "  [+] 转录日志: 已启用" -ForegroundColor Green
            if ($props.OutputDirectory) {
                Write-Host "    输出目录: $($props.OutputDirectory)" -ForegroundColor Green

                # 检查转录文件
                if (Test-Path $props.OutputDirectory) {
                    $transcripts = Get-ChildItem -Path $props.OutputDirectory -Filter "PowerShell_transcript*.txt" -ErrorAction SilentlyContinue
                    if ($transcripts) {
                        Write-Host "    [*] 发现 $($transcripts.Count) 个转录文件"
                        Write-Host "    最新文件: $($transcripts[0].Name) ($($transcripts[0].LastWriteTime))"
                    }
                }
            }
        } else {
            Write-Host "  [!] 转录日志: 未启用" -ForegroundColor Yellow
        }
    }
}
Write-Host ""

# 6. PowerShell模块日志配置检测
Write-Host "[*] 检查PowerShell日志配置..." -ForegroundColor Yellow

$loggingKeys = @(
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name="EnableModuleLogging"; Desc="模块日志"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name="EnableScriptBlockLogging"; Desc="脚本块日志"}
)

foreach ($key in $loggingKeys) {
    if (Test-Path $key.Path) {
        $value = Get-ItemProperty -Path $key.Path -Name $key.Name -ErrorAction SilentlyContinue
        if ($value -and $value.($key.Name) -eq 1) {
            Write-Host "  [+] $($key.Desc): 已启用" -ForegroundColor Green
        } else {
            Write-Host "  [!] $($key.Desc): 未启用 (建议启用)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [!] $($key.Desc): 未配置" -ForegroundColor Yellow
    }
}
Write-Host ""

# 7. PowerShell降级攻击检测
Write-Host "[*] 检查PowerShell版本和降级攻击..." -ForegroundColor Yellow

Write-Host "  当前PowerShell版本: $($PSVersionTable.PSVersion)"
Write-Host "  PowerShell Edition: $($PSVersionTable.PSEdition)"

# 检查是否有使用旧版PowerShell的记录
try {
    $v2Events = Get-WinEvent -FilterHashtable @{
        LogName = 'Windows PowerShell'
        Id = 400
    } -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -like "*EngineVersion=2.*"
    }

    if ($v2Events) {
        Write-Host ""
        Write-Host "  [!] 警告: 发现 PowerShell 2.0 执行记录 (降级攻击特征)!" -ForegroundColor Red
        Write-Host "  [!] PowerShell 2.0 缺少安全日志功能，常被攻击者利用" -ForegroundColor Red

        $v2Events | Select-Object -First 5 | ForEach-Object {
            Write-Host "    时间: $($_.TimeCreated)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [+] 未发现PowerShell 2.0执行记录" -ForegroundColor Green
    }
} catch {
    # 忽略错误
}

# 检查PowerShell 2.0是否安装
$ps2Feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
if ($ps2Feature -and $ps2Feature.State -eq "Enabled") {
    Write-Host ""
    Write-Host "  [!] 警告: PowerShell 2.0 功能已安装 (安全风险!)" -ForegroundColor Red
    Write-Host "  [!] 建议卸载: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root" -ForegroundColor Red
}
Write-Host ""

# 8. PowerShell配置文件检测
Write-Host "[*] 检查PowerShell配置文件..." -ForegroundColor Yellow

$profiles = @(
    $PROFILE.AllUsersAllHosts,
    $PROFILE.AllUsersCurrentHost,
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.CurrentUserCurrentHost
)

foreach ($prof in $profiles) {
    if (Test-Path $prof) {
        Write-Host "  [!] 发现配置文件: $prof" -ForegroundColor Yellow
        Write-Host "    修改时间: $($(Get-Item $prof).LastWriteTime)" -ForegroundColor Yellow

        # 检查配置文件内容
        $content = Get-Content $prof -ErrorAction SilentlyContinue
        if ($content -match 'Invoke-Expression|iex|downloadstring|bypass|hidden') {
            Write-Host "    [!] 警告: 配置文件包含可疑命令!" -ForegroundColor Red
            Write-Host "    内容预览: $($content -join '; ')" -ForegroundColor Red
        }
    }
}
Write-Host ""

# 9. PowerShell Constrained Language Mode检测
Write-Host "[*] 检查PowerShell语言模式..." -ForegroundColor Yellow

$languageMode = $ExecutionContext.SessionState.LanguageMode
$color = switch ($languageMode) {
    "ConstrainedLanguage" { 'Green' }
    "RestrictedLanguage" { 'Green' }
    "NoLanguage" { 'Green' }
    "FullLanguage" { 'Yellow' }
    default { 'Gray' }
}

Write-Host "  当前语言模式: $languageMode" -ForegroundColor $color

if ($languageMode -eq "FullLanguage") {
    Write-Host "  [!] FullLanguage模式允许执行所有PowerShell功能" -ForegroundColor Yellow
}
Write-Host ""

# 10. 检查AMSI (反恶意软件扫描接口)
Write-Host "[*] 检查AMSI状态..." -ForegroundColor Yellow

try {
    # 尝试检测AMSI是否被绕过
    $amsiTest = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    if ($amsiTest) {
        Write-Host "  [+] AMSI: 正常" -ForegroundColor Green
    }
} catch {
    Write-Host "  [!] AMSI: 可能被绕过或禁用!" -ForegroundColor Red
}
Write-Host ""

# 11. 检查PowerShell远程执行配置
Write-Host "[*] 检查PowerShell远程执行..." -ForegroundColor Yellow

$psRemoting = Get-PSSessionConfiguration -ErrorAction SilentlyContinue
if ($psRemoting) {
    Write-Host "  [*] PS Remoting配置:"
    $psRemoting | ForEach-Object {
        Write-Host "    会话: $($_.Name) - 权限: $($_.Permission)" -ForegroundColor Yellow
    }

    # 检查WinRM服务
    $winrm = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
    if ($winrm -and $winrm.Status -eq 'Running') {
        Write-Host ""
        Write-Host "  [!] WinRM服务正在运行 (PowerShell远程已启用)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [+] PowerShell远程未配置" -ForegroundColor Green
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PowerShell安全检测完成" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
