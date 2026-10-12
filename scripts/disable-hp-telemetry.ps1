<#
.SYNOPSIS
    禁用惠普笔记本遥测服务与驱动，并阻止Windows更新自动重新下载安装。
.DESCRIPTION
    1. 配置系统设备安装限制策略 (Device Installation Restrictions / DenyDeviceIDs)，阻止Windows Update及即插即用子系统自动重新下载、安装惠普遥测驱动与软件组件 (SWC\HPAnalytics, SWC\HPA000C, SWC\HPTPSH000C 等)。
    2. 禁用并停止惠普遥测与分析服务 (HP Insights / Touchpoint Analytics, HP Services Scan, HP Network HSA 等)，保留暗影精灵(OMEN)专属硬件控制服务与键盘功能键。
    3. 禁用设备管理器中现存的遥测软件组件设备，并清理驱动存储区 (DriverStore) 中的对应 OEM 驱动包。
    4. 禁用计划任务中惠普遥测与数据收集任务。
    5. 修改 hosts 屏蔽惠普遥测与收集端点 (hpanalytics.net, hpdaas.com)。
    6. 注册系统事件与登录触发的守卫任务 (Guardian)，持续监控并防范第三方更新或系统升级复活遥测。
    7. 支持完整卸载并还原系统原始状态与备份配置。
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$Install,

    [Parameter()]
    [switch]$Uninstall,

    [Parameter()]
    [switch]$Guardian,

    [Parameter()]
    [switch]$Status,

    [Parameter()]
    [string]$DataDir = ""
)

$ErrorActionPreference = 'Continue'

# 默认数据存储目录
if (-not $DataDir) {
    $DataDir = Join-Path $PSScriptRoot "data"
}
$BackupFile = Join-Path $DataDir "backup_state.json"

# 需要在设备安装限制策略中屏蔽的遥测硬件ID (Device / Hardware IDs)
$TargetHardwareIDs = @(
    'SWC\HPAnalytics',
    'SWC\HPA000C',
    'SWC\HPTPSH000C',
    'SWC\HPTPSH0003',
    'SWC\HPTPSH0016',
    'SWC\HPNetworkCap',
    'SWC\HPAudioAnalytics',
    'SWC\HPAppHelperCap',
    'SWC\HPDiagsCap',
    'SWC\HPSysInfoCap'
)

# 目标遥测服务名称 (Explicitly excludes HPOmenCap 以保证 OMEN 控制中心灯光/风扇正常)
$TargetServiceNames = @(
    'HpTouchpointAnalyticsService',
    'TouchpointAnalyticsClientService',
    'hpsvcsscan',
    'HPAudioAnalytics',
    'HPNetworkCap',
    'HPAppHelperCap',
    'HPDiagsCap',
    'HPSysInfoCap',
    'HPSupportSolutionsFrameworkService',
    'HPCommRecovery',
    'HPCommRecover',
    'HPInsights',
    'HpAnalyticsService',
    'HP TechPulse',
    'TouchpointAnalytics',
    'CaslAndWin10SessionFramework'
)

# 目标驱动 INF 原始文件名
$TargetInfNames = @(
    'hpanalyticscomp.inf',
    'hpsvcsscancomp.inf',
    'hpsvcsscanext.inf',
    'hptpsmarthealthcomp.inf'
)

# 目标计划任务名称与关键字
$TargetTaskKeywords = @(
    'HP Support Solutions Framework Report',
    'Consent Manager Launcher',
    'SmartCheckTest',
    'HP Touchpoint Analytics Client',
    'HP Services Scan',
    'HP TechPulse',
    'HPAudioAnalytics'
)

# 屏蔽的遥测域名
$BlockedDomains = @(
    'downloads.hpanalytics.net',
    'us-west-2.kinesis.hpanalytics.net',
    'www.hpdaas.com',
    'downloads.hpdaas.com',
    'eu.hpdaas.com',
    'hp-daas.com'
)

$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$GuardianTaskPath = "\AntiHP\"
$GuardianTaskName = "DisableHPTelemetry"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Elevated {
    if (-not (Test-IsAdmin)) {
        Write-Host "检测到当前未具备管理员权限，正在请求提升权限..." -ForegroundColor Cyan
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
        if ($Install) { $argList += '-Install' }
        elseif ($Uninstall) { $argList += '-Uninstall' }
        elseif ($Guardian) { $argList += '-Guardian' }
        elseif ($Status) { $argList += '-Status' }
        if ($DataDir) { $argList += @('-DataDir', "`"$DataDir`"") }

        try {
            $p = Start-Process powershell.exe -Verb RunAs -ArgumentList ($argList -join ' ') -PassThru -Wait
            exit $p.ExitCode
        } catch {
            Write-Error "提升权限失败: $_"
            exit 1
        }
    }
}

function Ensure-Directory([string]$Path) {
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

# -------------------------------------------------------------
# 核心逻辑: 安装并配置遥测阻止策略
# -------------------------------------------------------------
function Invoke-Install {
    Assert-Elevated
    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host " 开始配置惠普笔记本遥测禁用与 Windows Update 自动重装阻断" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green

    Ensure-Directory $DataDir

    # 1. 备份当前系统状态 (若尚未备份)
    $backup = @{}
    if (Test-Path $BackupFile) {
        try {
            $backup = Get-Content $BackupFile -Raw | ConvertFrom-Json -AsHashtable
        } catch {
            $backup = @{}
        }
    }

    if (-not $backup.ContainsKey('CreatedTime')) {
        Write-Host "[1/7] 正在备份系统当前策略与服务配置..." -ForegroundColor Yellow
        $backup['CreatedTime'] = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $backup['Registry'] = @{}

        # 备份 DeviceInstall\Restrictions
        $restrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        $backup['Registry']['RestrictionsExisted'] = (Test-Path $restrPath)
        if (Test-Path $restrPath) {
            $backup['Registry']['DenyDeviceIDs'] = (Get-ItemProperty $restrPath -Name 'DenyDeviceIDs' -ErrorAction SilentlyContinue).DenyDeviceIDs
            $backup['Registry']['DenyDeviceIDsRetroactive'] = (Get-ItemProperty $restrPath -Name 'DenyDeviceIDsRetroactive' -ErrorAction SilentlyContinue).DenyDeviceIDsRetroactive
        }

        # 备份现有 DenyDeviceIDs 列表
        $denySubPath = "$restrPath\DenyDeviceIDs"
        $backup['Registry']['ExistingDenyList'] = @{}
        if (Test-Path $denySubPath) {
            $denyProps = Get-ItemProperty $denySubPath
            foreach ($p in $denyProps.PSObject.Properties) {
                if ($p.Name -notmatch '^PS') {
                    $backup['Registry']['ExistingDenyList'][$p.Name] = $p.Value
                }
            }
        }

        # 备份 WindowsUpdate 驱动排除策略
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        $backup['Registry']['WUExisted'] = (Test-Path $wuPath)
        if (Test-Path $wuPath) {
            $backup['Registry']['ExcludeWUDriversInQualityUpdate'] = (Get-ItemProperty $wuPath -Name 'ExcludeWUDriversInQualityUpdate' -ErrorAction SilentlyContinue).ExcludeWUDriversInQualityUpdate
        }

        # 备份目标服务的原始启动类型
        $backup['Services'] = @{}
        foreach ($svcName in $TargetServiceNames) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc) {
                $backup['Services'][$svcName] = [string]$svc.StartType
            }
        }

        $backup | ConvertTo-Json -Depth 5 | Set-Content -Path $BackupFile -Encoding UTF8
        Write-Host "      备份已保存至: $BackupFile" -ForegroundColor Gray
    } else {
        Write-Host "[1/7] 检测到已有备份，跳过覆盖以保留原始状态。" -ForegroundColor Gray
    }

    # 2. 配置设备安装阻止策略 (DenyDeviceIDs) 阻止 Windows Update 安装遥测驱动
    Write-Host "[2/7] 配置设备硬件阻止策略 (DenyDeviceIDs)，阻止Windows Update下载安装遥测驱动..." -ForegroundColor Yellow
    $restrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
    if (-not (Test-Path $restrPath)) {
        New-Item -Path $restrPath -Force | Out-Null
    }
    Set-ItemProperty -Path $restrPath -Name 'DenyDeviceIDs' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $restrPath -Name 'DenyDeviceIDsRetroactive' -Value 1 -Type DWord -Force

    $denySubPath = "$restrPath\DenyDeviceIDs"
    if (-not (Test-Path $denySubPath)) {
        New-Item -Path $denySubPath -Force | Out-Null
    }

    # 读取当前已有项，找到最大数值编号
    $denyProps = Get-ItemProperty $denySubPath
    $existingValues = @()
    $existingIndexes = @()
    foreach ($p in $denyProps.PSObject.Properties) {
        if ($p.Name -notmatch '^PS') {
            $existingValues += [string]$p.Value
            if ($p.Name -match '^\d+$') {
                $existingIndexes += [int]$p.Name
            }
        }
    }
    $nextIndex = 1
    if ($existingIndexes.Count -gt 0) {
        $nextIndex = ($existingIndexes | Measure-Object -Maximum).Maximum + 1
    }

    $addedIds = @()
    foreach ($hwId in $TargetHardwareIDs) {
        $found = $false
        foreach ($val in $existingValues) {
            if ($val -eq $hwId) { $found = $true; break }
        }
        if (-not $found) {
            Set-ItemProperty -Path $denySubPath -Name ([string]$nextIndex) -Value $hwId -Type String -Force
            $addedIds += [string]$nextIndex
            $nextIndex++
        }
    }
    Write-Host "      已在系统硬件阻止列表中加入 $($TargetHardwareIDs.Count) 个惠普遥测硬件ID。" -ForegroundColor Gray

    # 3. 禁用设备管理器中的遥测软件组件设备 (PnP Devices)
    Write-Host "[3/7] 扫描并禁用设备管理器中的遥测软件组件设备..." -ForegroundColor Yellow
    $pnpDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $matched = $false
        $hwList = $_.HardwareID
        if ($hwList) {
            foreach ($h in $hwList) {
                if ($h -match 'SWC\\(HPAnalytics|HPA000C|HPTPSH|HPNetworkCap|HPAudioAnalytics|HPAppHelperCap|HPDiagsCap|HPSysInfoCap)') {
                    $matched = $true; break
                }
            }
        }
        if (-not $matched -and $_.FriendlyName -match 'HP\s*(Device Health Service|Insights Analytics|Touchpoint|Services Scan|Audio Analytics|Network HSA)' -and $_.Class -eq 'SoftwareComponent') {
            $matched = $true
        }
        return $matched
    }

    if ($pnpDevices) {
        foreach ($dev in $pnpDevices) {
            Write-Host "      禁用设备: $($dev.FriendlyName) [$($dev.InstanceId)]" -ForegroundColor Gray
            Disable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }
    } else {
        Write-Host "      未发现当前活跃的遥测软件组件设备。" -ForegroundColor Gray
    }

    # 4. 清理本地驱动存储区 (DriverStore) 中的 OEM 遥测驱动
    Write-Host "[4/7] 清理 DriverStore 驱动存储区中的惠普遥测 OEM 驱动包..." -ForegroundColor Yellow
    try {
        $enumOutput = & pnputil.exe /enum-drivers
        $currentOem = ""
        $currentInf = ""
        $toDelete = @()

        foreach ($line in $enumOutput) {
            if ($line -match ':\s*(oem\d+\.inf)') {
                $currentOem = $matches[1]
            }
            if ($line -match ':\s*([a-zA-Z0-9_\-\.]+\.inf)') {
                $candInf = $matches[1]
                if ($candInf -ne $currentOem) {
                    $currentInf = $candInf
                    if ($TargetInfNames -contains $currentInf.ToLower()) {
                        $toDelete += @{ Oem = $currentOem; Original = $currentInf }
                    }
                }
            }
        }

        foreach ($item in $toDelete) {
            Write-Host "      正在卸载并删除驱动包: $($item.Oem) (原名: $($item.Original))..." -ForegroundColor Gray
            & pnputil.exe /delete-driver $item.Oem /uninstall /force | Out-Null
        }
        if ($toDelete.Count -eq 0) {
            Write-Host "      本地 DriverStore 中未发现残留的遥测驱动包。" -ForegroundColor Gray
        }
    } catch {
        Write-Warning "检查/删除 OEM 驱动包时发生非致命错误: $_"
    }

    # 5. 停止并禁用所有遥测后台服务
    Write-Host "[5/7] 停止并彻底禁用惠普遥测后台服务..." -ForegroundColor Yellow
    foreach ($svcName in $TargetServiceNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "      处理服务: $svcName ($($svc.DisplayName))" -ForegroundColor Gray
            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
            # 锁定注册表 Start=4 (Disabled)
            $regSvcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
            if (Test-Path $regSvcPath) {
                Set-ItemProperty -Path $regSvcPath -Name "Start" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # 6. 禁用计划任务中惠普遥测/扫描/报告任务
    Write-Host "[6/7] 禁用系统计划任务中的惠普遥测与上报任务..." -ForegroundColor Yellow
    try {
        $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $allTasks) {
            $matchTask = $false
            if ($t.TaskPath -match 'HP|Hewlett-Packard') {
                foreach ($kw in $TargetTaskKeywords) {
                    if ($t.TaskName -match [regex]::Escape($kw)) { $matchTask = $true; break }
                }
                if ($t.TaskName -match 'Analytics|Touchpoint|Telemetry|CEIP|Survey|Report') {
                    $matchTask = $true
                }
            }
            if ($matchTask -and $t.State -ne 'Disabled') {
                Write-Host "      禁用任务: $($t.TaskPath)$($t.TaskName)" -ForegroundColor Gray
                $t | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
            }
        }
    } catch {
        Write-Warning "处理计划任务时发生错误: $_"
    }

    # 7. 配置 hosts 屏蔽遥测数据上传端点
    Write-Host "[7/7] 配置 hosts 黑名单屏蔽遥测收集域名..." -ForegroundColor Yellow
    if (Test-Path $HostsPath) {
        $hostsContent = Get-Content -Path $HostsPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if (-not $hostsContent) { $hostsContent = "" }
        if ($hostsContent -notmatch '# \[Scoop:disable-hp-telemetry start\]') {
            $sb = New-Object System.Text.StringBuilder
            $sb.AppendLine("`r`n# [Scoop:disable-hp-telemetry start]") | Out-Null
            foreach ($domain in $BlockedDomains) {
                $sb.AppendLine("0.0.0.0 $domain") | Out-Null
            }
            $sb.AppendLine("# [Scoop:disable-hp-telemetry end]") | Out-Null
            Add-Content -Path $HostsPath -Value $sb.ToString() -Encoding UTF8 -Force
            Write-Host "      已将遥测域名写入 hosts 文件。" -ForegroundColor Gray
        } else {
            Write-Host "      hosts 规则已存在，跳过添加。" -ForegroundColor Gray
        }
    }

    # 8. 注册系统持久化守卫任务 (Guardian Task)
    Install-GuardianTask

    Write-Host "`n惠普遥测驱动与服务已成功禁用，并已启用驱动安装阻止策略！" -ForegroundColor Green
    Write-Host "Windows Update 将被底层策略禁止重新下载与安装任何被屏蔽的遥测驱动。" -ForegroundColor Green
}

# -------------------------------------------------------------
# 注册/更新 Guardian 任务
# -------------------------------------------------------------
function Install-GuardianTask {
    Write-Host "正在注册系统持久化守卫计划任务 ($GuardianTaskPath$GuardianTaskName)..." -ForegroundColor Yellow
    $scriptPath = $PSCommandPath
    if (-not (Test-Path $scriptPath)) {
        $scriptPath = "$PSScriptRoot\disable-hp-telemetry.ps1"
    }

    $xmlDefinition = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Block and disable HP laptop telemetry services, drivers, and tasks persistently.</Description>
    <URI>$GuardianTaskPath$GuardianTaskName</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT30S</Delay>
    </LogonTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;
         *[System[Provider[@Name='Service Control Manager'] and (EventID=7040 or EventID=7045)]]
         and
         *[EventData[Data[@Name='param4'] and ((Data='HpTouchpointAnalyticsService') or (Data='hpsvcsscan') or (Data='HPAudioAnalytics') or (Data='HPNetworkCap') or (Data='HPAppHelperCap') or (Data='HPSysInfoCap'))]]
       &lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT15M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$scriptPath" -Guardian -DataDir "$DataDir"</Arguments>
      <WorkingDirectory>$PSScriptRoot</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

    $tmpXml = [IO.Path]::GetTempFileName() + ".xml"
    [IO.File]::WriteAllText($tmpXml, $xmlDefinition, [Text.Encoding]::Unicode)
    try {
        & schtasks.exe /create /tn "$GuardianTaskPath$GuardianTaskName" /xml "$tmpXml" /f | Out-Null
        Write-Host "      守卫任务注册成功。" -ForegroundColor Gray
    } catch {
        Write-Warning "注册守卫任务失败: $_"
    } finally {
        Remove-Item -Path $tmpXml -Force -ErrorAction SilentlyContinue
    }
}

# -------------------------------------------------------------
# Guardian 守卫例程 (轻量静默运行)
# -------------------------------------------------------------
function Invoke-Guardian {
    # 1. 确保服务保持停止与禁用
    foreach ($svcName in $TargetServiceNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            }
            if ($svc.StartType -ne 'Disabled') {
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name "Start" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # 2. 确保软件组件设备处于禁用状态
    $pnpDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $matched = $false
        $hwList = $_.HardwareID
        if ($hwList) {
            foreach ($h in $hwList) {
                if ($h -match 'SWC\\(HPAnalytics|HPA000C|HPTPSH|HPNetworkCap|HPAudioAnalytics)') {
                    $matched = $true; break
                }
            }
        }
        return ($matched -and $_.Status -eq 'OK')
    }
    foreach ($dev in $pnpDevices) {
        Disable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }

    # 3. 确保 DenyDeviceIDs 策略处于激活状态
    $restrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
    if (Test-Path $restrPath) {
        $denyVal = (Get-ItemProperty $restrPath -Name 'DenyDeviceIDs' -ErrorAction SilentlyContinue).DenyDeviceIDs
        if ($denyVal -ne 1) {
            Set-ItemProperty -Path $restrPath -Name 'DenyDeviceIDs' -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $restrPath -Name 'DenyDeviceIDsRetroactive' -Value 1 -Type DWord -Force
        }
    }
}

# -------------------------------------------------------------
# 卸载逻辑: 还原系统配置
# -------------------------------------------------------------
function Invoke-Uninstall {
    Assert-Elevated
    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host " 开始还原惠普遥测配置与策略 (卸载过程)" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green

    # 1. 删除守卫任务
    Write-Host "[1/5] 删除系统持久化守卫计划任务..." -ForegroundColor Yellow
    try {
        & schtasks.exe /delete /tn "$GuardianTaskPath$GuardianTaskName" /f | Out-Null
        Write-Host "      守卫任务已移除。" -ForegroundColor Gray
    } catch {
        Write-Host "      未发现守卫任务或已被删除。" -ForegroundColor Gray
    }

    # 2. 读取备份文件
    $backup = $null
    if (Test-Path $BackupFile) {
        try {
            $backup = Get-Content $BackupFile -Raw | ConvertFrom-Json -AsHashtable
        } catch {
            $backup = $null
        }
    }

    # 3. 还原 DeviceInstall 限制策略
    Write-Host "[2/5] 还原设备安装限制策略 (DenyDeviceIDs)..." -ForegroundColor Yellow
    $denySubPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
    $restrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"

    if (Test-Path $denySubPath) {
        $props = Get-ItemProperty $denySubPath
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -notmatch '^PS' -and ($TargetHardwareIDs -contains [string]$p.Value)) {
                Remove-ItemProperty -Path $denySubPath -Name $p.Name -ErrorAction SilentlyContinue | Out-Null
            }
        }
        # 检查是否还有剩余条目
        $remaining = (Get-ItemProperty $denySubPath).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
        if (-not $remaining -or $remaining.Count -eq 0) {
            Remove-Item -Path $denySubPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            if ($backup -and $backup.Registry -and (-not $backup.Registry.RestrictionsExisted)) {
                Remove-Item -Path $restrPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            } else {
                if ($backup -and $backup.Registry -and $backup.Registry.DenyDeviceIDs) {
                    Set-ItemProperty -Path $restrPath -Name 'DenyDeviceIDs' -Value $backup.Registry.DenyDeviceIDs -Force
                } else {
                    Remove-ItemProperty -Path $restrPath -Name 'DenyDeviceIDs' -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }
    }

    # 4. 还原服务启动类型
    Write-Host "[3/5] 还原受影响服务的启动类型..." -ForegroundColor Yellow
    if ($backup -and $backup.Services) {
        foreach ($svcName in $backup.Services.Keys) {
            $origType = $backup.Services[$svcName]
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc -and $origType -and $origType -ne 'Disabled') {
                Write-Host "      还原服务 $svcName -> $origType" -ForegroundColor Gray
                Set-Service -Name $svcName -StartupType $origType -ErrorAction SilentlyContinue
            }
        }
    }

    # 5. 重新启用 PnP 软件组件设备
    Write-Host "[4/5] 重新启用软件组件设备..." -ForegroundColor Yellow
    $pnpDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $matched = $false
        $hwList = $_.HardwareID
        if ($hwList) {
            foreach ($h in $hwList) {
                if ($h -match 'SWC\\(HPAnalytics|HPA000C|HPTPSH|HPNetworkCap|HPAudioAnalytics)') {
                    $matched = $true; break
                }
            }
        }
        return ($matched -and $_.Status -ne 'OK')
    }
    foreach ($dev in $pnpDevices) {
        Write-Host "      启用设备: $($dev.FriendlyName)" -ForegroundColor Gray
        Enable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }

    # 6. 清理 hosts 规则
    Write-Host "[5/5] 清理 hosts 文件中的域名屏蔽规则..." -ForegroundColor Yellow
    if (Test-Path $HostsPath) {
        $content = Get-Content -Path $HostsPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($content -match '(?ms)# \[Scoop:disable-hp-telemetry start\].*?# \[Scoop:disable-hp-telemetry end\]\r?\n?') {
            $cleaned = $content -replace '(?ms)\r?\n?# \[Scoop:disable-hp-telemetry start\].*?# \[Scoop:disable-hp-telemetry end\]\r?\n?', "`r`n"
            Set-Content -Path $HostsPath -Value $cleaned.Trim() -Encoding UTF8 -Force
            Write-Host "      hosts 规则已移除。" -ForegroundColor Gray
        }
    }

    # 清理备份文件
    if (Test-Path $BackupFile) {
        Remove-Item -Path $BackupFile -Force -ErrorAction SilentlyContinue
    }

    Write-Host "`n惠普遥测配置与安装策略已成功还原！" -ForegroundColor Green
}

# -------------------------------------------------------------
# 查询状态例程
# -------------------------------------------------------------
function Invoke-Status {
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host " 惠普遥测与 Windows Update 阻断状态检查" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan

    # 1. 检查设备阻止策略
    $restrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
    $denySubPath = "$restrPath\DenyDeviceIDs"
    $denyActive = $false
    $blockedCount = 0

    if (Test-Path $denySubPath) {
        $props = Get-ItemProperty $denySubPath
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -notmatch '^PS' -and ($TargetHardwareIDs -contains [string]$p.Value)) {
                $blockedCount++
            }
        }
        $denyVal = (Get-ItemProperty $restrPath -Name 'DenyDeviceIDs' -ErrorAction SilentlyContinue).DenyDeviceIDs
        $denyActive = ($denyVal -eq 1 -and $blockedCount -gt 0)
    }

    if ($denyActive) {
        Write-Host "[√] 硬件安装阻止策略 (DenyDeviceIDs): 已生效 (已阻止 $blockedCount 个遥测组件ID)" -ForegroundColor Green
    } else {
        Write-Host "[X] 硬件安装阻止策略 (DenyDeviceIDs): 未生效" -ForegroundColor Red
    }

    # 2. 检查守护任务
    $task = Get-ScheduledTask -TaskPath $GuardianTaskPath -TaskName $GuardianTaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host "[√] 持久化守卫计划任务: 已就绪 (状态: $($task.State))" -ForegroundColor Green
    } else {
        Write-Host "[X] 持久化守卫计划任务: 未注册" -ForegroundColor Yellow
    }

    # 3. 检查 hosts
    $hostsBlocked = $false
    if (Test-Path $HostsPath) {
        $content = Get-Content -Path $HostsPath -Raw -ErrorAction SilentlyContinue
        if ($content -match '# \[Scoop:disable-hp-telemetry start\]') {
            $hostsBlocked = $true
        }
    }
    if ($hostsBlocked) {
        Write-Host "[√] 域名屏蔽 (hosts): 已生效" -ForegroundColor Green
    } else {
        Write-Host "[X] 域名屏蔽 (hosts): 未生效" -ForegroundColor Yellow
    }

    # 4. 检查服务状态
    Write-Host "`n--- 目标遥测服务列表 ---" -ForegroundColor Cyan
    $foundSvcs = 0
    foreach ($svcName in $TargetServiceNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            $foundSvcs++
            $color = if ($svc.StartType -eq 'Disabled' -and $svc.Status -ne 'Running') { 'Green' } else { 'Red' }
            Write-Host "  * $($svc.Name) [$($svc.DisplayName)] -> 状态: $($svc.Status), 启动类型: $($svc.StartType)" -ForegroundColor $color
        }
    }
    if ($foundSvcs -eq 0) {
        Write-Host "  (系统中未安装任何匹配的目标服务)" -ForegroundColor Gray
    }

    # 5. 检查 PnP 软件组件设备
    Write-Host "`n--- 目标 PnP 软件组件设备 ---" -ForegroundColor Cyan
    $pnpDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
        $matched = $false
        $hwList = $_.HardwareID
        if ($hwList) {
            foreach ($h in $hwList) {
                if ($h -match 'SWC\\(HPAnalytics|HPA000C|HPTPSH|HPNetworkCap|HPAudioAnalytics)') {
                    $matched = $true; break
                }
            }
        }
        return $matched
    }
    if ($pnpDevices) {
        foreach ($dev in $pnpDevices) {
            $color = if ($dev.Status -eq 'OK') { 'Red' } else { 'Green' }
            Write-Host "  * $($dev.FriendlyName) [$($dev.InstanceId)] -> 状态: $($dev.Status)" -ForegroundColor $color
        }
    } else {
        Write-Host "  (系统中未发现匹配的遥测软件组件设备)" -ForegroundColor Gray
    }

    Write-Host "==========================================================" -ForegroundColor Cyan
}

# -------------------------------------------------------------
# 分发入口
# -------------------------------------------------------------
if ($Install) {
    Invoke-Install
} elseif ($Uninstall) {
    Invoke-Uninstall
} elseif ($Guardian) {
    Invoke-Guardian
} elseif ($Status) {
    Invoke-Status
} else {
    Invoke-Status
}
