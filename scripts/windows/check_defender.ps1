# ################################################################################
# Windows Defender安全检测脚本
# 功能: 检查Windows Defender状态、配置、威胁历史
################################################################################

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Windows Defender安全检测 - $(Get-Date)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Defender服务状态检测
Write-Host "[*] 检查Windows Defender服务状态..." -ForegroundColor Yellow

$defenderServices = @(
    "WinDefend",           # Windows Defender Antivirus Service
    "WdNisSvc",           # Windows Defender Network Inspection Service
    "Sense",              # Windows Defender Advanced Threat Protection
    "SecurityHealthService"  # Windows Security Health Service
)

foreach ($serviceName in $defenderServices) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        $statusColor = if ($service.Status -eq 'Running') { 'Green' } else { 'Red' }
        Write-Host "  服务: $($service.DisplayName)" -ForegroundColor $statusColor
        Write-Host "    状态: $($service.Status) - 启动类型: $($service.StartType)" -ForegroundColor $statusColor

        if ($service.Status -ne 'Running') {
            Write-Host "    [!] 警告: Defender服务未运行!" -ForegroundColor Red
        }
    }
}
Write-Host ""

# 2. Defender实时保护状态
Write-Host "[*] 检查实时保护状态..." -ForegroundColor Yellow

try {
    $preferences = Get-MpPreference -ErrorAction SilentlyContinue
    if ($preferences) {
        # 实时保护
        $rtpColor = if ($preferences.DisableRealtimeMonitoring -eq $false) { 'Green' } else { 'Red' }
        Write-Host "  实时保护: $(if ($preferences.DisableRealtimeMonitoring -eq $false) { '已启用' } else { '已禁用' })" -ForegroundColor $rtpColor

        # 行为监控
        $behaviorColor = if ($preferences.DisableBehaviorMonitoring -eq $false) { 'Green' } else { 'Red' }
        Write-Host "  行为监控: $(if ($preferences.DisableBehaviorMonitoring -eq $false) { '已启用' } else { '已禁用' })" -ForegroundColor $behaviorColor

        # 云保护
        $cloudColor = if ($preferences.MAPSReporting -ne 0) { 'Green' } else { 'Yellow' }
        $cloudStatus = switch ($preferences.MAPSReporting) {
            0 { "禁用" }
            1 { "基础" }
            2 { "高级" }
            default { "未知" }
        }
        Write-Host "  云保护(MAPS): $cloudStatus" -ForegroundColor $cloudColor

        # 自动样本提交
        $sampleColor = if ($preferences.SubmitSamplesConsent -ne 2) { 'Green' } else { 'Yellow' }
        $sampleStatus = switch ($preferences.SubmitSamplesConsent) {
            0 { "总是提示" }
            1 { "自动发送安全样本" }
            2 { "从不发送" }
            3 { "自动发送所有样本" }
            default { "未知" }
        }
        Write-Host "  自动样本提交: $sampleStatus" -ForegroundColor $sampleColor

        # 入侵防御系统(IPS)
        $ipsColor = if ($preferences.DisableIOAVProtection -eq $false) { 'Green' } else { 'Red' }
        Write-Host "  入侵防御(IOAV): $(if ($preferences.DisableIOAVProtection -eq $false) { '已启用' } else { '已禁用' })" -ForegroundColor $ipsColor

        # 脚本扫描
        $scriptColor = if ($preferences.DisableScriptScanning -eq $false) { 'Green' } else { 'Red' }
        Write-Host "  脚本扫描: $(if ($preferences.DisableScriptScanning -eq $false) { '已启用' } else { '已禁用' })" -ForegroundColor $scriptColor

    } else {
        Write-Host "  [!] 无法获取Defender配置" -ForegroundColor Red
    }
} catch {
    Write-Host "  [!] 读取Defender配置失败: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# 3. Defender排除项检测 (高危配置)
Write-Host "[*] 检查Defender排除项..." -ForegroundColor Yellow

try {
    $preferences = Get-MpPreference -ErrorAction SilentlyContinue
    if ($preferences) {
        # 排除的文件和文件夹
        if ($preferences.ExclusionPath) {
            Write-Host "  [!] 发现 $($preferences.ExclusionPath.Count) 个排除路径:" -ForegroundColor Yellow
            $preferences.ExclusionPath | ForEach-Object {
                Write-Host "    路径: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [+] 无排除路径" -ForegroundColor Green
        }

        # 排除的扩展名
        if ($preferences.ExclusionExtension) {
            Write-Host ""
            Write-Host "  [!] 发现 $($preferences.ExclusionExtension.Count) 个排除扩展名:" -ForegroundColor Yellow
            $preferences.ExclusionExtension | ForEach-Object {
                Write-Host "    扩展: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [+] 无排除扩展名" -ForegroundColor Green
        }

        # 排除的进程
        if ($preferences.ExclusionProcess) {
            Write-Host ""
            Write-Host "  [!] 发现 $($preferences.ExclusionProcess.Count) 个排除进程:" -ForegroundColor Yellow
            $preferences.ExclusionProcess | ForEach-Object {
                Write-Host "    进程: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [+] 无排除进程" -ForegroundColor Green
        }

        # 排除的IP地址
        if ($preferences.ExclusionIpAddress) {
            Write-Host ""
            Write-Host "  [!] 发现 $($preferences.ExclusionIpAddress.Count) 个排除IP:" -ForegroundColor Yellow
            $preferences.ExclusionIpAddress | ForEach-Object {
                Write-Host "    IP: $_" -ForegroundColor Yellow
            }
        }
    }
} catch {
    Write-Host "  [!] 读取排除项失败: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# 4. Defender威胁检测历史
Write-Host "[*] 检查威胁检测历史..." -ForegroundColor Yellow

try {
    $threats = Get-MpThreat -ErrorAction SilentlyContinue
    if ($threats) {
        Write-Host "  [!] 发现 $($threats.Count) 个威胁记录:" -ForegroundColor Red

        $threats | Select-Object -First 20 | ForEach-Object {
            Write-Host ""
            Write-Host "    [!] 威胁: $($_.ThreatName)" -ForegroundColor Red
            Write-Host "        类别: $($_.CategoryID)" -ForegroundColor Red
            Write-Host "        严重级别: $($_.SeverityID)" -ForegroundColor Red
            Write-Host "        初次检测: $($_.InitialDetectionTime)" -ForegroundColor Red
            Write-Host "        资源: $($_.Resources -join ', ')" -ForegroundColor Red

            $statusText = switch ($_.IsActive) {
                $true { "活跃中 (高危!)" }
                $false { "已清除" }
                default { "未知" }
            }
            $statusColor = if ($_.IsActive) { 'Red' } else { 'Yellow' }
            Write-Host "        状态: $statusText" -ForegroundColor $statusColor
        }
    } else {
        Write-Host "  [+] 未发现威胁记录" -ForegroundColor Green
    }
} catch {
    Write-Host "  [!] 读取威胁历史失败: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# 5. Defender扫描历史
Write-Host "[*] 检查最近扫描记录..." -ForegroundColor Yellow

try {
    $computerStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($computerStatus) {
        Write-Host "  最后快速扫描: $($computerStatus.QuickScanStartTime)"
        Write-Host "  最后快速扫描结束: $($computerStatus.QuickScanEndTime)"
        Write-Host "  最后完整扫描: $($computerStatus.FullScanStartTime)"
        Write-Host "  最后完整扫描结束: $($computerStatus.FullScanEndTime)"

        # 签名版本
        Write-Host ""
        Write-Host "  病毒库版本: $($computerStatus.AntivirusSignatureVersion)"
        Write-Host "  病毒库更新时间: $($computerStatus.AntivirusSignatureLastUpdated)"

        # 检查签名是否过期 (超过7天)
        $daysSinceUpdate = ((Get-Date) - $computerStatus.AntivirusSignatureLastUpdated).Days
        if ($daysSinceUpdate -gt 7) {
            Write-Host "  [!] 警告: 病毒库已 $daysSinceUpdate 天未更新!" -ForegroundColor Red
        } elseif ($daysSinceUpdate -gt 3) {
            Write-Host "  [!] 提醒: 病毒库已 $daysSinceUpdate 天未更新" -ForegroundColor Yellow
        } else {
            Write-Host "  [+] 病毒库较新 ($daysSinceUpdate 天前更新)" -ForegroundColor Green
        }

        # 引擎版本
        Write-Host ""
        Write-Host "  引擎版本: $($computerStatus.AMEngineVersion)"
        Write-Host "  产品版本: $($computerStatus.AMProductVersion)"
    }
} catch {
    Write-Host "  [!] 读取扫描历史失败: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# 6. Defender事件日志检测
Write-Host "[*] 检查Defender事件日志 (最近100条)..." -ForegroundColor Yellow

try {
    # 检查Defender检测到威胁的事件
    $defenderEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'
        Id = 1116, 1117  # 1116: 检测到恶意软件, 1117: 采取保护措施
    } -MaxEvents 100 -ErrorAction SilentlyContinue

    if ($defenderEvents) {
        Write-Host "  [!] 最近检测到 $($defenderEvents.Count) 个威胁事件:" -ForegroundColor Red

        $defenderEvents | Select-Object -First 10 | ForEach-Object {
            Write-Host ""
            Write-Host "    时间: $($_.TimeCreated)" -ForegroundColor Yellow
            Write-Host "    事件ID: $($_.Id)" -ForegroundColor Yellow
            Write-Host "    消息: $($_.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [+] 未发现最近的威胁事件" -ForegroundColor Green
    }

    # 检查实时保护被禁用的事件
    Write-Host ""
    $disableEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'
        Id = 5001  # 实时保护被禁用
    } -MaxEvents 50 -ErrorAction SilentlyContinue

    if ($disableEvents) {
        Write-Host "  [!] 发现 $($disableEvents.Count) 次实时保护被禁用事件!" -ForegroundColor Red
        $disableEvents | Select-Object -First 5 | ForEach-Object {
            Write-Host "    时间: $($_.TimeCreated) - $($_.Message)" -ForegroundColor Red
        }
    }

    # 检查Defender引擎更新失败
    Write-Host ""
    $updateFailEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'
        Id = 2001, 2004  # 更新失败
    } -MaxEvents 20 -ErrorAction SilentlyContinue

    if ($updateFailEvents) {
        Write-Host "  [!] 发现 $($updateFailEvents.Count) 次更新失败事件!" -ForegroundColor Yellow
        $updateFailEvents | Select-Object -First 5 | ForEach-Object {
            Write-Host "    时间: $($_.TimeCreated)" -ForegroundColor Yellow
        }
    }

} catch {
    Write-Host "  [!] 读取Defender日志失败: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# 7. Tamper Protection检测 (篡改防护)
Write-Host "[*] 检查篡改防护状态..." -ForegroundColor Yellow

try {
    # 通过注册表检查
    $tamperKey = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
    $tamper = Get-ItemProperty -Path $tamperKey -Name "TamperProtection" -ErrorAction SilentlyContinue

    if ($tamper) {
        $tamperStatus = switch ($tamper.TamperProtection) {
            0 { "已禁用" }
            1 { "已禁用" }
            5 { "已启用" }
            default { "未知($($tamper.TamperProtection))" }
        }

        $tamperColor = if ($tamper.TamperProtection -eq 5) { 'Green' } else { 'Red' }
        Write-Host "  篡改防护: $tamperStatus" -ForegroundColor $tamperColor

        if ($tamper.TamperProtection -ne 5) {
            Write-Host "  [!] 警告: 篡改防护已禁用，Defender可被恶意软件关闭!" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "  [*] 无法检测篡改防护状态" -ForegroundColor Gray
}
Write-Host ""

# 8. Controlled Folder Access (受控文件夹访问)
Write-Host "[*] 检查受控文件夹访问..." -ForegroundColor Yellow

try {
    $preferences = Get-MpPreference -ErrorAction SilentlyContinue
    if ($preferences) {
        $cfaColor = if ($preferences.EnableControlledFolderAccess -eq 1) { 'Green' } else { 'Yellow' }
        $cfaStatus = switch ($preferences.EnableControlledFolderAccess) {
            0 { "已禁用" }
            1 { "已启用" }
            2 { "审核模式" }
            default { "未知" }
        }
        Write-Host "  受控文件夹访问: $cfaStatus" -ForegroundColor $cfaColor

        # 保护的文件夹
        if ($preferences.ControlledFolderAccessProtectedFolders) {
            Write-Host "  保护的文件夹:"
            $preferences.ControlledFolderAccessProtectedFolders | ForEach-Object {
                Write-Host "    $_"
            }
        }

        # 允许的应用
        if ($preferences.ControlledFolderAccessAllowedApplications) {
            Write-Host "  允许的应用:"
            $preferences.ControlledFolderAccessAllowedApplications | ForEach-Object {
                Write-Host "    $_"
            }
        }
    }
} catch {
    Write-Host "  [*] 无法检测受控文件夹访问" -ForegroundColor Gray
}
Write-Host ""

# 9. Attack Surface Reduction (攻击面减少规则)
Write-Host "[*] 检查攻击面减少规则..." -ForegroundColor Yellow

try {
    $preferences = Get-MpPreference -ErrorAction SilentlyContinue
    if ($preferences -and $preferences.AttackSurfaceReductionRules_Ids) {
        Write-Host "  [*] 已配置 $($preferences.AttackSurfaceReductionRules_Ids.Count) 条ASR规则:" -ForegroundColor Cyan

        for ($i = 0; $i -lt $preferences.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $ruleId = $preferences.AttackSurfaceReductionRules_Ids[$i]
            $action = $preferences.AttackSurfaceReductionRules_Actions[$i]

            $actionText = switch ($action) {
                0 { "禁用" }
                1 { "阻止" }
                2 { "审核" }
                6 { "警告" }
                default { "未知($action)" }
            }

            $actionColor = switch ($action) {
                1 { 'Green' }
                2 { 'Yellow' }
                default { 'Gray' }
            }

            Write-Host "    规则ID: $ruleId - 动作: $actionText" -ForegroundColor $actionColor
        }
    } else {
        Write-Host "  [*] 未配置ASR规则" -ForegroundColor Gray
    }
} catch {
    Write-Host "  [*] 无法检测ASR规则" -ForegroundColor Gray
}
Write-Host ""

# 10. Network Protection检测
Write-Host "[*] 检查网络保护..." -ForegroundColor Yellow

try {
    $preferences = Get-MpPreference -ErrorAction SilentlyContinue
    if ($preferences) {
        $npStatus = switch ($preferences.EnableNetworkProtection) {
            0 { "禁用" }
            1 { "启用(阻止模式)" }
            2 { "审核模式" }
            default { "未知" }
        }

        $npColor = if ($preferences.EnableNetworkProtection -eq 1) { 'Green' } else { 'Yellow' }
        Write-Host "  网络保护: $npStatus" -ForegroundColor $npColor
    }
} catch {
    Write-Host "  [*] 无法检测网络保护" -ForegroundColor Gray
}
Write-Host ""

# 11. Exploit Protection配置
Write-Host "[*] 检查Exploit Protection配置..." -ForegroundColor Yellow

try {
    # 通过PowerShell获取
    $exploitConfig = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
    if ($exploitConfig) {
        Write-Host "  系统级别缓解措施:"

        # DEP (数据执行保护)
        if ($exploitConfig.DEP) {
            Write-Host "    DEP: $($exploitConfig.DEP.Enable)" -ForegroundColor Green
        }

        # ASLR (地址空间布局随机化)
        if ($exploitConfig.ASLR) {
            Write-Host "    ASLR: 已配置" -ForegroundColor Green
        }

        # CFG (控制流保护)
        if ($exploitConfig.CFG) {
            Write-Host "    CFG: $($exploitConfig.CFG.Enable)" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "  [*] 无法读取Exploit Protection配置" -ForegroundColor Gray
}
Write-Host ""

# 12. SmartScreen配置检测
Write-Host "[*] 检查SmartScreen配置..." -ForegroundColor Yellow

$smartScreenKeys = @(
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"; Name="SmartScreenEnabled"; Desc="SmartScreen for Windows"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="SmartScreenEnabled"; Desc="SmartScreen for Edge"}
)

foreach ($key in $smartScreenKeys) {
    if (Test-Path $key.Path) {
        $value = Get-ItemProperty -Path $key.Path -Name $key.Name -ErrorAction SilentlyContinue
        if ($value) {
            $ssValue = $value.($key.Name)
            $color = if ($ssValue -eq "On" -or $ssValue -eq 1) { 'Green' } else { 'Red' }
            Write-Host "  $($key.Desc): $ssValue" -ForegroundColor $color
        }
    }
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Windows Defender检测完成" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
