# ################################################################################
# Windows用户账户安全检测脚本 (增强版 - 支持影子用户检测)
# 功能: 检查用户账户、权限、密码策略、登录历史、影子用户
################################################################################

Write-Output "=========================================="
Write-Output "Windows用户账户安全检测 - $(Get-Date)"
Write-Output "=========================================="
Write-Output ""

# 1. 本地用户账户检测
Write-Output "[*] 检查本地用户账户..."

$localUsers = Get-LocalUser
Write-Output "  [*] 发现 $($localUsers.Count) 个本地用户账户"
Write-Output ""

foreach ($user in $localUsers) {
    $warnings = @()

    # 检查是否为管理员
    $isAdmin = $false
    try {
        $adminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if ($adminMembers | Where-Object { $_.Name -like "*$($user.Name)" }) {
            $isAdmin = $true
            $warnings += "管理员权限"
        }
    } catch {}

    # 检查密码策略
    if ($user.PasswordNeverExpires) {
        $warnings += "密码永不过期"
    }
    if (-not $user.PasswordRequired) {
        $warnings += "密码非必需(高危!)"
    }

    # 输出
    Write-Output "  [用户] $($user.Name)"
    Write-Output "    描述: $($user.Description)"
    Write-Output "    启用: $($user.Enabled)"
    Write-Output "    SID: $($user.SID.Value)"
    if ($isAdmin) {
        Write-Output "    [!] 管理员账户"
    }
    Write-Output "    最后登录: $($user.LastLogon)"
    Write-Output "    密码最后设置: $($user.PasswordLastSet)"
    Write-Output "    密码永不过期: $($user.PasswordNeverExpires)"

    if ($warnings.Count -gt 0) {
        Write-Output "    [!] 警告: $($warnings -join ', ')"
    }
    Write-Output ""
}

# 2. 管理员组成员检测
Write-Output "[*] 检查Administrators组成员..."

try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($admins) {
        Write-Output "  [!] 发现 $($admins.Count) 个管理员账户:"

        foreach ($admin in $admins) {
            Write-Output "    [!] $($admin.Name) ($($admin.PrincipalSource))"
            if ($admin.ObjectClass -eq "User") {
                $user = Get-LocalUser -Name $admin.Name.Split('\')[-1] -ErrorAction SilentlyContinue
                if ($user) {
                    Write-Output "        最后登录: $($user.LastLogon)"
                    Write-Output "        SID: $($user.SID.Value)"
                }
            }
        }
    }
} catch {
    Write-Output "  [!] 无法读取管理员组: $($_.Exception.Message)"
}
Write-Output ""

# 3. 影子用户专项检测 (核心增强功能)
Write-Output "[*] ===== 影子用户专项检测 ====="
Write-Output ""

# 3.1 检查隐藏账户 ($结尾)
Write-Output "[*] 检查隐藏账户($结尾)..."
$hiddenAccounts = Get-LocalUser | Where-Object { $_.Name -like '*$' }
if ($hiddenAccounts) {
    Write-Output "  [!] 发现 $($hiddenAccounts.Count) 个可能的隐藏账户:"
    $hiddenAccounts | ForEach-Object {
        Write-Output "    [!] $($_.Name) - 启用: $($_.Enabled) - SID: $($_.SID.Value)"
    }
} else {
    Write-Output "  [+] 未发现$结尾隐藏账户"
}
Write-Output ""

# 3.2 注册表账户枚举 (检测注册表克隆型影子用户)
Write-Output "[*] 检查注册表用户账户 (SAM数据库)..."

try {
    # 从注册表读取所有用户SID
    $samPath = "HKLM:\SAM\SAM\Domains\Account\Users"

    # 需要管理员权限
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Output "  [!] 警告: 需要管理员权限才能检查SAM注册表"
        Write-Output "  [*] 跳过注册表深度检查"
    } else {
        # 尝试读取SAM
        $samUsers = @()

        # 方法1: 通过net user命令
        $netUsers = net user | Where-Object { $_ -match '^\w' -and $_ -notmatch 'The command|命令|用户账户' }

        Write-Output "  [*] 通过net user命令发现的账户:"
        $netUserList = @()
        foreach ($line in $netUsers) {
            $users = $line -split '\s+' | Where-Object { $_ -ne '' }
            $netUserList += $users
        }

        $netUserList = $netUserList | Where-Object { $_ -and $_ -notmatch '^-+$' }

        foreach ($u in $netUserList) {
            Write-Output "    - $u"
        }

        # 比对Get-LocalUser和net user结果
        $localUserNames = (Get-LocalUser).Name
        $onlyInNetUser = $netUserList | Where-Object { $_ -notin $localUserNames }

        if ($onlyInNetUser) {
            Write-Output ""
            Write-Output "  [!] 警告: 以下账户仅在net user中出现，可能是影子用户:"
            foreach ($shadowUser in $onlyInNetUser) {
                Write-Output "    [!] $shadowUser (疑似影子用户!)"
            }
        } else {
            Write-Output "  [+] net user和Get-LocalUser结果一致"
        }
    }
} catch {
    Write-Output "  [!] 注册表检查失败: $($_.Exception.Message)"
}
Write-Output ""

# 3.3 检查WMI用户账户
Write-Output "[*] 通过WMI检查用户账户..."

try {
    $wmiUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True"

    Write-Output "  [*] WMI发现 $($wmiUsers.Count) 个本地账户:"
    foreach ($wmiUser in $wmiUsers) {
        Write-Output "    - $($wmiUser.Name) (SID: $($wmiUser.SID)) - 启用: $(-not $wmiUser.Disabled)"
    }

    # 比对Get-LocalUser和WMI结果
    $localUserNames = (Get-LocalUser).Name
    $wmiUserNames = $wmiUsers.Name

    $onlyInWMI = $wmiUserNames | Where-Object { $_ -notin $localUserNames }
    $onlyInLocal = $localUserNames | Where-Object { $_ -notin $wmiUserNames }

    if ($onlyInWMI) {
        Write-Output ""
        Write-Output "  [!] 警告: 以下账户仅在WMI中出现:"
        foreach ($user in $onlyInWMI) {
            Write-Output "    [!] $user (疑似影子用户!)"
        }
    }

    if ($onlyInLocal) {
        Write-Output ""
        Write-Output "  [!] 警告: 以下账户仅在Get-LocalUser中出现:"
        foreach ($user in $onlyInLocal) {
            Write-Output "    [!] $user"
        }
    }

    if (-not $onlyInWMI -and -not $onlyInLocal) {
        Write-Output "  [+] Get-LocalUser和WMI结果一致"
    }
} catch {
    Write-Output "  [!] WMI查询失败: $($_.Exception.Message)"
}
Write-Output ""

# 3.4 检查RID 500/501账户
Write-Output "[*] 检查特殊RID账户 (Administrator/Guest)..."

$rid500Users = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }
$rid501Users = Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' }

if ($rid500Users) {
    foreach ($u in $rid500Users) {
        if ($u.Name -ne "Administrator") {
            Write-Output "  [!] 警告: RID 500 (Administrator) 账户已重命名为: $($u.Name)"
        } else {
            Write-Output "  [*] RID 500: $($u.Name) (正常)"
        }
    }
}

if ($rid501Users) {
    foreach ($u in $rid501Users) {
        if ($u.Name -ne "Guest") {
            Write-Output "  [!] 警告: RID 501 (Guest) 账户已重命名为: $($u.Name)"
        } else {
            Write-Output "  [*] RID 501: $($u.Name) (正常)"
        }
    }
}
Write-Output ""

# 3.5 检查可疑的用户描述
Write-Output "[*] 检查可疑的用户描述..."

$suspiciousDescriptions = @(
    "Backup",
    "Clone",
    "Shadow",
    "Hidden",
    "Test",
    "Temp",
    "Admin2",
    "Administrator2"
)

$suspiciousUsers = Get-LocalUser | Where-Object {
    $desc = $_.Description
    $name = $_.Name

    # 检查描述是否包含可疑关键词
    $descSuspicious = $false
    foreach ($keyword in $suspiciousDescriptions) {
        if ($desc -like "*$keyword*" -or $name -like "*$keyword*") {
            $descSuspicious = $true
            break
        }
    }

    # 检查空描述的启用账户
    $emptyDesc = [string]::IsNullOrWhiteSpace($desc) -and $_.Enabled

    $descSuspicious -or $emptyDesc
}

if ($suspiciousUsers) {
    Write-Output "  [!] 发现可疑用户:"
    $suspiciousUsers | ForEach-Object {
        $reason = if ([string]::IsNullOrWhiteSpace($_.Description)) { "无描述" } else { "可疑描述" }
        Write-Output "    [!] $($_.Name) - $reason - 描述: '$($_.Description)'"
    }
} else {
    Write-Output "  [+] 未发现可疑用户描述"
}
Write-Output ""

# 3.6 检查最近创建的账户
Write-Output "[*] 检查最近创建/修改的用户(30天内)..."

$recentUsers = Get-LocalUser | Where-Object {
    ($_.PasswordLastSet -and $_.PasswordLastSet -gt (Get-Date).AddDays(-30))
}

if ($recentUsers) {
    Write-Output "  [!] 发现 $($recentUsers.Count) 个最近创建/修改的账户:"
    $recentUsers | ForEach-Object {
        Write-Output "    [!] $($_.Name)"
        Write-Output "        创建/修改: $($_.PasswordLastSet)"
        Write-Output "        启用: $($_.Enabled)"
        Write-Output "        描述: $($_.Description)"
        Write-Output "        SID: $($_.SID.Value)"
    }
} else {
    Write-Output "  [+] 未发现最近创建的账户"
}
Write-Output ""

# 4. 检查用户创建事件
Write-Output "[*] 检查用户创建事件日志..."

try {
    # Event ID 4720: 用户账户创建
    $createEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4720
    } -MaxEvents 20 -ErrorAction SilentlyContinue

    if ($createEvents) {
        Write-Output "  [!] 最近创建了 $($createEvents.Count) 个用户账户:"
        $createEvents | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $username = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
            $creator = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'} | Select-Object -ExpandProperty '#text'

            Write-Output "    时间: $($_.TimeCreated)"
            Write-Output "    创建的用户: $username"
            Write-Output "    创建者: $creator"
            Write-Output ""
        }
    } else {
        Write-Output "  [*] 未发现最近的用户创建事件"
    }
} catch {
    Write-Output "  [!] 无法读取事件日志: $($_.Exception.Message)"
}
Write-Output ""

# 5. 检查添加到管理员组的事件
Write-Output "[*] 检查添加到管理员组的事件..."

try {
    # Event ID 4732: 用户添加到组
    $groupAddEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4732
    } -MaxEvents 50 -ErrorAction SilentlyContinue

    if ($groupAddEvents) {
        # 特别关注添加到Administrators组的操作
        $adminAddEvents = $groupAddEvents | Where-Object {
            $_.Message -like "*Administrators*" -or $_.Message -like "*管理员*"
        }

        if ($adminAddEvents) {
            Write-Output "  [!] 发现 $($adminAddEvents.Count) 次添加到管理员组的操作:"
            $adminAddEvents | Select-Object -First 10 | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $username = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'MemberName'} | Select-Object -ExpandProperty '#text'
                $operator = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'} | Select-Object -ExpandProperty '#text'

                Write-Output "    时间: $($_.TimeCreated)"
                Write-Output "    添加的用户: $username"
                Write-Output "    操作者: $operator"
                Write-Output ""
            }
        } else {
            Write-Output "  [*] 未发现最近添加到管理员组的事件"
        }
    }
} catch {
    Write-Output "  [!] 无法读取事件日志: $($_.Exception.Message)"
}
Write-Output ""

# 6. Guest账户检测
Write-Output "[*] 检查Guest账户..."

$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest) {
    if ($guest.Enabled) {
        Write-Output "  [!] Guest账户已启用 (安全风险!)"
    } else {
        Write-Output "  [+] Guest账户已禁用"
    }
}
Write-Output ""

# 7. Remote Desktop Users组检测
Write-Output "[*] 检查Remote Desktop Users组..."

try {
    $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
    if ($rdpUsers) {
        Write-Output "  [!] 发现 $($rdpUsers.Count) 个RDP用户:"
        foreach ($user in $rdpUsers) {
            Write-Output "    $($user.Name)"
        }
    } else {
        Write-Output "  [+] Remote Desktop Users组为空"
    }
} catch {
    Write-Output "  [*] 无法读取Remote Desktop Users组"
}
Write-Output ""

Write-Output "=========================================="
Write-Output "用户账户安全检测完成"
Write-Output "=========================================="
Write-Output ""

# 确保脚本正常退出并返回输出
exit 0
