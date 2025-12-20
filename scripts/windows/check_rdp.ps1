# ################################################################################
# Windows RDP远程桌面安全检测脚本
# 功能: 检测RDP配置、连接历史、暴力破解、异常登录
################################################################################

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "RDP远程桌面安全检测 - $(Get-Date)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. RDP服务状态检测
Write-Host "[*] 检查RDP服务状态..." -ForegroundColor Yellow

$rdpService = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
if ($rdpService) {
    Write-Host "  RDP服务状态: $($rdpService.Status)" -ForegroundColor $(if ($rdpService.Status -eq 'Running') { 'Green' } else { 'Yellow' })
    Write-Host "  启动类型: $($rdpService.StartType)"
} else {
    Write-Host "  [!] 未找到RDP服务" -ForegroundColor Red
}
Write-Host ""

# 2. RDP配置检测
Write-Host "[*] 检查RDP配置..." -ForegroundColor Yellow

# 检查RDP是否启用
$rdpEnabled = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
if ($rdpEnabled) {
    if ($rdpEnabled.fDenyTSConnections -eq 0) {
        Write-Host "  [!] RDP已启用" -ForegroundColor Yellow
    } else {
        Write-Host "  [+] RDP已禁用" -ForegroundColor Green
    }
}

# 检查RDP端口
$rdpPort = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue
if ($rdpPort) {
    $port = $rdpPort.PortNumber
    if ($port -eq 3389) {
        Write-Host "  [!] RDP端口: $port (默认端口，建议修改)" -ForegroundColor Yellow
    } else {
        Write-Host "  [*] RDP端口: $port (已修改)" -ForegroundColor Green
    }
}

# 检查网络级别身份验证 (NLA)
$nla = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
if ($nla) {
    if ($nla.UserAuthentication -eq 1) {
        Write-Host "  [+] 网络级别身份验证(NLA): 已启用" -ForegroundColor Green
    } else {
        Write-Host "  [!] 网络级别身份验证(NLA): 已禁用 (安全风险!)" -ForegroundColor Red
    }
}

# 检查加密级别
$encLevel = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
if ($encLevel) {
    $level = switch ($encLevel.MinEncryptionLevel) {
        1 { "低" }
        2 { "客户端兼容" }
        3 { "高" }
        4 { "FIPS兼容" }
        default { "未知" }
    }
    Write-Host "  加密级别: $level ($($encLevel.MinEncryptionLevel))"
}

# 检查最大连接数
$maxConn = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MaxInstanceCount" -ErrorAction SilentlyContinue
if ($maxConn) {
    Write-Host "  最大连接数: $($maxConn.MaxInstanceCount)"
}
Write-Host ""

# 3. 当前RDP连接检测
Write-Host "[*] 检查当前RDP连接..." -ForegroundColor Yellow

try {
    $sessions = quser 2>$null
    if ($sessions) {
        Write-Host "  [!] 发现活跃会话:" -ForegroundColor Yellow
        $sessions | ForEach-Object { Write-Host "    $_" }
    } else {
        Write-Host "  [+] 无活跃RDP会话" -ForegroundColor Green
    }
} catch {
    Write-Host "  [*] 无法查询当前会话" -ForegroundColor Gray
}
Write-Host ""

# 4. RDP连接历史检测 (最近100条)
Write-Host "[*] 检查RDP连接历史 (最近100条)..." -ForegroundColor Yellow

try {
    # Event ID 4624: 登录成功 (LogonType 10 = RemoteInteractive/RDP)
    $rdpLogins = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4624
    } -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {
        $_.Properties[8].Value -eq 10  # LogonType 10 = RDP
    } | Select-Object -First 100

    if ($rdpLogins) {
        Write-Host "  [*] 发现 $($rdpLogins.Count) 条RDP登录成功记录:" -ForegroundColor Cyan

        # 按用户和IP统计
        $loginStats = $rdpLogins | Group-Object {
            $xml = [xml]$_.ToXml()
            "$($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text')@$($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text')"
        } | Sort-Object Count -Descending | Select-Object -First 20

        $loginStats | ForEach-Object {
            Write-Host "    用户@IP: $($_.Name) - 登录次数: $($_.Count)"
        }

        # 显示最近10条登录详情
        Write-Host ""
        Write-Host "  [*] 最近10条RDP登录详情:" -ForegroundColor Cyan
        $rdpLogins | Select-Object -First 10 | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $time = $_.TimeCreated
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
            $domain = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetDomainName'} | Select-Object -ExpandProperty '#text'
            $ip = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
            $logonId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetLogonId'} | Select-Object -ExpandProperty '#text'

            Write-Host "    时间: $time"
            Write-Host "    用户: $domain\$user"
            Write-Host "    来源IP: $ip"
            Write-Host "    登录ID: $logonId"
            Write-Host ""
        }
    } else {
        Write-Host "  [+] 未发现RDP登录记录" -ForegroundColor Green
    }
} catch {
    Write-Host "  [!] 无法读取安全日志: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# 5. RDP登录失败检测 (暴力破解)
Write-Host "[*] 检查RDP登录失败记录 (暴力破解检测)..." -ForegroundColor Yellow

try {
    # Event ID 4625: 登录失败
    $failedLogins = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4625
    } -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {
        $_.Properties[10].Value -eq 10  # LogonType 10 = RDP
    } | Select-Object -First 200

    if ($failedLogins) {
        Write-Host "  [!] 发现 $($failedLogins.Count) 条RDP登录失败记录!" -ForegroundColor Red

        # 按来源IP统计
        $failStats = $failedLogins | Group-Object {
            $xml = [xml]$_.ToXml()
            $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
        } | Sort-Object Count -Descending

        Write-Host ""
        Write-Host "  [!] 按来源IP统计失败次数:" -ForegroundColor Red
        $failStats | Select-Object -First 20 | ForEach-Object {
            $ip = $_.Name
            $count = $_.Count

            if ($count -gt 10) {
                Write-Host "    [!] 高危 - IP: $ip - 失败次数: $count (可能暴力破解!)" -ForegroundColor Red
            } elseif ($count -gt 5) {
                Write-Host "    [!] 可疑 - IP: $ip - 失败次数: $count" -ForegroundColor Yellow
            } else {
                Write-Host "    IP: $ip - 失败次数: $count"
            }
        }

        # 按用户名统计
        Write-Host ""
        Write-Host "  [!] 按目标用户统计失败次数:" -ForegroundColor Red
        $userStats = $failedLogins | Group-Object {
            $xml = [xml]$_.ToXml()
            $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
        } | Sort-Object Count -Descending | Select-Object -First 20

        $userStats | ForEach-Object {
            Write-Host "    用户: $($_.Name) - 失败次数: $($_.Count)"
        }

        # 显示最近失败尝试
        Write-Host ""
        Write-Host "  [*] 最近10条RDP登录失败详情:" -ForegroundColor Yellow
        $failedLogins | Select-Object -First 10 | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $time = $_.TimeCreated
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
            $ip = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
            $reason = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'FailureReason'} | Select-Object -ExpandProperty '#text'

            Write-Host "    时间: $time - 用户: $user - IP: $ip"
            if ($reason) { Write-Host "      原因: $reason" }
        }
    } else {
        Write-Host "  [+] 未发现RDP登录失败记录" -ForegroundColor Green
    }
} catch {
    Write-Host "  [!] 无法读取登录失败日志: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# 6. RDP会话断开/重连检测
Write-Host "[*] 检查RDP会话断开/重连记录..." -ForegroundColor Yellow

try {
    # Event ID 4778: 会话重连, 4779: 会话断开
    $reconnects = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4778
    } -MaxEvents 100 -ErrorAction SilentlyContinue

    $disconnects = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4779
    } -MaxEvents 100 -ErrorAction SilentlyContinue

    if ($reconnects) {
        Write-Host "  [*] 最近 $($reconnects.Count) 次会话重连"
    }
    if ($disconnects) {
        Write-Host "  [*] 最近 $($disconnects.Count) 次会话断开"
    }
} catch {
    # 忽略错误
}
Write-Host ""

# 7. 异常时段登录检测
Write-Host "[*] 检查异常时段RDP登录..." -ForegroundColor Yellow

try {
    # 检查夜间登录 (22:00 - 06:00)
    $nightLogins = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4624
    } -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object {
        $_.Properties[8].Value -eq 10 -and  # LogonType 10 = RDP
        ($_.TimeCreated.Hour -ge 22 -or $_.TimeCreated.Hour -le 6)
    } | Select-Object -First 50

    if ($nightLogins) {
        Write-Host "  [!] 发现 $($nightLogins.Count) 条夜间(22:00-06:00)RDP登录!" -ForegroundColor Yellow

        $nightLogins | Select-Object -First 10 | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $time = $_.TimeCreated
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
            $ip = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'

            Write-Host "    [!] $time - 用户: $user - IP: $ip" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [+] 未发现异常时段登录" -ForegroundColor Green
    }
} catch {
    Write-Host "  [*] 无法检查异常时段登录" -ForegroundColor Gray
}
Write-Host ""

# 8. RDP防火墙规则检测
Write-Host "[*] 检查RDP防火墙规则..." -ForegroundColor Yellow

$rdpRules = Get-NetFirewallRule | Where-Object {
    $_.DisplayName -like "*Remote Desktop*" -or $_.DisplayName -like "*远程桌面*"
} | Select-Object DisplayName, Enabled, Direction, Action

if ($rdpRules) {
    $rdpRules | ForEach-Object {
        $status = if ($_.Enabled -eq $true) { "已启用" } else { "已禁用" }
        $color = if ($_.Enabled -eq $true -and $_.Action -eq "Allow") { "Yellow" } else { "Green" }
        Write-Host "  规则: $($_.DisplayName)" -ForegroundColor $color
        Write-Host "    状态: $status - 方向: $($_.Direction) - 动作: $($_.Action)" -ForegroundColor $color
    }
} else {
    Write-Host "  [*] 未找到RDP防火墙规则" -ForegroundColor Gray
}
Write-Host ""

# 9. 监听3389端口的进程检测
Write-Host "[*] 检查监听RDP端口的进程..." -ForegroundColor Yellow

$rdpListeners = Get-NetTCPConnection | Where-Object {
    $_.LocalPort -eq 3389 -and $_.State -eq 'Listen'
}

if ($rdpListeners) {
    Write-Host "  [!] 发现监听3389端口的进程:" -ForegroundColor Yellow
    $rdpListeners | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "    进程: $($proc.Name) (PID: $($proc.Id))"
            Write-Host "    路径: $($proc.Path)"
        }
    }
} else {
    Write-Host "  [+] 无进程监听3389端口" -ForegroundColor Green
}
Write-Host ""

# 10. RDP影子会话检测 (隐蔽监控)
Write-Host "[*] 检查RDP影子会话配置..." -ForegroundColor Yellow

$shadowKey = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$shadow = Get-ItemProperty -Path $shadowKey -Name "Shadow" -ErrorAction SilentlyContinue

if ($shadow) {
    $shadowValue = switch ($shadow.Shadow) {
        0 { "禁用" }
        1 { "完全控制(需用户同意)" }
        2 { "完全控制(不需用户同意)" }
        3 { "仅查看(需用户同意)" }
        4 { "仅查看(不需用户同意)" }
        default { "未知($($shadow.Shadow))" }
    }

    if ($shadow.Shadow -in @(2, 4)) {
        Write-Host "  [!] 影子会话: $shadowValue (高危!可隐蔽监控)" -ForegroundColor Red
    } else {
        Write-Host "  [*] 影子会话: $shadowValue" -ForegroundColor Green
    }
}
Write-Host ""

# 11. 弱密码账户检测 (RDP高危账户)
Write-Host "[*] 检查潜在RDP高危账户..." -ForegroundColor Yellow

# 检查属于Remote Desktop Users组的用户
try {
    $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
    if ($rdpUsers) {
        Write-Host "  [!] Remote Desktop Users组成员:" -ForegroundColor Yellow
        $rdpUsers | ForEach-Object {
            Write-Host "    用户: $($_.Name)" -ForegroundColor Yellow
        }
    }
} catch {
    # 忽略错误
}

# 检查管理员组成员 (都有RDP权限)
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($admins) {
        Write-Host ""
        Write-Host "  [!] Administrators组成员 (都可RDP):" -ForegroundColor Yellow
        $admins | ForEach-Object {
            Write-Host "    管理员: $($_.Name)" -ForegroundColor Yellow
        }
    }
} catch {
    # 忽略错误
}
Write-Host ""

# 12. RDP证书检测
Write-Host "[*] 检查RDP证书..." -ForegroundColor Yellow

$certKey = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$certHash = Get-ItemProperty -Path $certKey -Name "SSLCertificateSHA1Hash" -ErrorAction SilentlyContinue

if ($certHash -and $certHash.SSLCertificateSHA1Hash) {
    $hash = [System.BitConverter]::ToString($certHash.SSLCertificateSHA1Hash) -replace '-', ''
    Write-Host "  RDP证书SHA1: $hash"

    # 尝试查找证书详情
    try {
        $cert = Get-ChildItem -Path Cert:\LocalMachine\Remote Desktop\ -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $hash }
        if ($cert) {
            Write-Host "  证书主题: $($cert.Subject)"
            Write-Host "  颁发者: $($cert.Issuer)"
            Write-Host "  有效期: $($cert.NotBefore) 到 $($cert.NotAfter)"

            if ($cert.NotAfter -lt (Get-Date)) {
                Write-Host "  [!] 证书已过期!" -ForegroundColor Red
            }
        }
    } catch {
        # 忽略错误
    }
} else {
    Write-Host "  [*] 使用自签名证书" -ForegroundColor Gray
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "RDP安全检测完成" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
