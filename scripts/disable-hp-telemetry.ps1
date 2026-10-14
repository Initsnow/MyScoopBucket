<#
.SYNOPSIS
    Disable HP laptop telemetry services and drivers, and prevent Windows Update from reinstalling them.
.DESCRIPTION
    1. Configure Device Installation Restrictions (DenyDeviceIDs) to block Windows Update and Plug and Play from
       reinstalling HP telemetry drivers and software components (SWC\HPAnalytics, SWC\HPA000C, SWC\HPTPSH000C, etc.).
    2. Disable HP telemetry and analytics services (HP Insights, Touchpoint Analytics, HP Services Scan, HP Network HSA,
       etc.) while preserving OMEN hardware control services and keyboard function keys.
    3. Disable existing telemetry software component devices and remove their OEM driver packages from DriverStore.
    4. Disable HP telemetry and data collection scheduled tasks.
    5. Block HP telemetry endpoints (hpanalytics.net and hpdaas.com) through the hosts file.
    6. Register a logon and event triggered guardian task to prevent telemetry from being restored by third-party updates
       or operating system upgrades.
    7. Support complete uninstall and restoration of the original system state and backup configuration.
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

# Default data directory.
if (-not $DataDir) {
    $DataDir = Join-Path $PSScriptRoot "data"
}
$BackupFile = Join-Path $DataDir "backup_state.json"

# Telemetry hardware IDs to block through Device Installation Restrictions.
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

# Target telemetry service names. HPOmenCap is explicitly excluded so OMEN lighting and fan controls keep working.
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

# Original INF file names for the target drivers.
$TargetInfNames = @(
    'hpanalyticscomp.inf',
    'hpsvcsscancomp.inf',
    'hpsvcsscanext.inf',
    'hptpsmarthealthcomp.inf'
)

# Target scheduled task names and keywords.
$TargetTaskKeywords = @(
    'HP Support Solutions Framework Report',
    'Consent Manager Launcher',
    'SmartCheckTest',
    'HP Touchpoint Analytics Client',
    'HP Services Scan',
    'HP TechPulse',
    'HPAudioAnalytics'
)

# Blocked telemetry domains.
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
        Write-Host "Administrator privileges are required. Requesting elevation..." -ForegroundColor Cyan
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
            Write-Error "Failed to elevate privileges: $_"
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
# Core logic: install and configure telemetry blocking policies.
# -------------------------------------------------------------
function Invoke-Install {
    Assert-Elevated
    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host " Configuring HP telemetry blocking and Windows Update reinstall prevention" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green

    Ensure-Directory $DataDir

    # 1. Back up the current system state if no backup exists yet.
    $backup = @{}
    if (Test-Path $BackupFile) {
        try {
            $backup = Get-Content $BackupFile -Raw | ConvertFrom-Json -AsHashtable
        } catch {
            $backup = @{}
        }
    }

    if (-not $backup.ContainsKey('CreatedTime')) {
        Write-Host "[1/7] Backing up current policies and service configuration..." -ForegroundColor Yellow
        $backup['CreatedTime'] = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $backup['Registry'] = @{}

        # Back up DeviceInstall\Restrictions.
        $restrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
        $backup['Registry']['RestrictionsExisted'] = (Test-Path $restrPath)
        if (Test-Path $restrPath) {
            $backup['Registry']['DenyDeviceIDs'] = (Get-ItemProperty $restrPath -Name 'DenyDeviceIDs' -ErrorAction SilentlyContinue).DenyDeviceIDs
            $backup['Registry']['DenyDeviceIDsRetroactive'] = (Get-ItemProperty $restrPath -Name 'DenyDeviceIDsRetroactive' -ErrorAction SilentlyContinue).DenyDeviceIDsRetroactive
        }

        # Back up the existing DenyDeviceIDs list.
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

        # Back up the Windows Update driver exclusion policy.
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        $backup['Registry']['WUExisted'] = (Test-Path $wuPath)
        if (Test-Path $wuPath) {
            $backup['Registry']['ExcludeWUDriversInQualityUpdate'] = (Get-ItemProperty $wuPath -Name 'ExcludeWUDriversInQualityUpdate' -ErrorAction SilentlyContinue).ExcludeWUDriversInQualityUpdate
        }

        # Back up the original startup type of each target service.
        $backup['Services'] = @{}
        foreach ($svcName in $TargetServiceNames) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc) {
                $backup['Services'][$svcName] = [string]$svc.StartType
            }
        }

        $backup | ConvertTo-Json -Depth 5 | Set-Content -Path $BackupFile -Encoding UTF8
        Write-Host "      Backup saved to: $BackupFile" -ForegroundColor Gray
    } else {
        Write-Host "[1/7] Existing backup found. Keeping it to preserve the original state." -ForegroundColor Gray
    }

    # 2. Configure DenyDeviceIDs to block Windows Update from installing telemetry drivers.
    Write-Host "[2/7] Configuring DenyDeviceIDs to block Windows Update from installing telemetry drivers..." -ForegroundColor Yellow
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

    # Read existing entries and find the highest numeric index.
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
    Write-Host "      Added $($TargetHardwareIDs.Count) HP telemetry hardware IDs to the system block list." -ForegroundColor Gray

    # 3. Disable telemetry software component devices in Device Manager.
    Write-Host "[3/7] Scanning and disabling telemetry software component devices..." -ForegroundColor Yellow
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
            Write-Host "      Disabling device: $($dev.FriendlyName) [$($dev.InstanceId)]" -ForegroundColor Gray
            Disable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }
    } else {
        Write-Host "      No active telemetry software component devices were found." -ForegroundColor Gray
    }

    # 4. Remove OEM telemetry drivers from the local DriverStore.
    Write-Host "[4/7] Removing HP telemetry OEM driver packages from DriverStore..." -ForegroundColor Yellow
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
            Write-Host "      Uninstalling and deleting driver package: $($item.Oem) (original: $($item.Original))..." -ForegroundColor Gray
            & pnputil.exe /delete-driver $item.Oem /uninstall /force | Out-Null
        }
        if ($toDelete.Count -eq 0) {
            Write-Host "      No telemetry driver packages remain in the local DriverStore." -ForegroundColor Gray
        }
    } catch {
        Write-Warning "A non-fatal error occurred while checking or deleting OEM driver packages: $_"
    }

    # 5. Stop and disable all telemetry background services.
    Write-Host "[5/7] Stopping and disabling HP telemetry background services..." -ForegroundColor Yellow
    foreach ($svcName in $TargetServiceNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "      Processing service: $svcName ($($svc.DisplayName))" -ForegroundColor Gray
            if ($svc.Status -eq 'Running') {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
            # Lock the registry Start value to 4 (Disabled).
            $regSvcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
            if (Test-Path $regSvcPath) {
                Set-ItemProperty -Path $regSvcPath -Name "Start" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # 6. Disable HP telemetry, scan, and report scheduled tasks.
    Write-Host "[6/7] Disabling HP telemetry and reporting scheduled tasks..." -ForegroundColor Yellow
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
                Write-Host "      Disabling task: $($t.TaskPath)$($t.TaskName)" -ForegroundColor Gray
                $t | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
            }
        }
    } catch {
        Write-Warning "An error occurred while processing scheduled tasks: $_"
    }

    # 7. Configure the hosts file to block telemetry upload endpoints.
    Write-Host "[7/7] Configuring hosts file blocks for telemetry collection domains..." -ForegroundColor Yellow
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
            Write-Host "      Telemetry domains were added to the hosts file." -ForegroundColor Gray
        } else {
            Write-Host "      hosts rules already exist. Skipping." -ForegroundColor Gray
        }
    }

    # 8. Register the persistent guardian task.
    Install-GuardianTask

    Write-Host "`nHP telemetry drivers and services were disabled successfully, and driver installation blocking is active." -ForegroundColor Green
    Write-Host "Windows Update is blocked by policy from reinstalling any blocked telemetry driver." -ForegroundColor Green
}

# -------------------------------------------------------------
# Register or update the guardian task.
# -------------------------------------------------------------
function Install-GuardianTask {
    Write-Host "Registering persistent guardian scheduled task ($GuardianTaskPath$GuardianTaskName)..." -ForegroundColor Yellow
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
        Write-Host "      Guardian task registered successfully." -ForegroundColor Gray
    } catch {
        Write-Warning "Failed to register the guardian task: $_"
    } finally {
        Remove-Item -Path $tmpXml -Force -ErrorAction SilentlyContinue
    }
}

# -------------------------------------------------------------
# Guardian routine (lightweight and silent).
# -------------------------------------------------------------
function Invoke-Guardian {
    # 1. Keep services stopped and disabled.
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

    # 2. Keep software component devices disabled.
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

    # 3. Keep the DenyDeviceIDs policy active.
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
# Uninstall logic: restore system configuration.
# -------------------------------------------------------------
function Invoke-Uninstall {
    Assert-Elevated
    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host " Restoring HP telemetry configuration and policies (uninstall)" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green

    # 1. Delete the guardian task.
    Write-Host "[1/5] Deleting the persistent guardian scheduled task..." -ForegroundColor Yellow
    try {
        & schtasks.exe /delete /tn "$GuardianTaskPath$GuardianTaskName" /f | Out-Null
        Write-Host "      Guardian task removed." -ForegroundColor Gray
    } catch {
        Write-Host "      Guardian task was not found or was already deleted." -ForegroundColor Gray
    }

    # 2. Read the backup file.
    $backup = $null
    if (Test-Path $BackupFile) {
        try {
            $backup = Get-Content $BackupFile -Raw | ConvertFrom-Json -AsHashtable
        } catch {
            $backup = $null
        }
    }

    # 3. Restore DeviceInstall restrictions.
    Write-Host "[2/5] Restoring DeviceInstall restrictions (DenyDeviceIDs)..." -ForegroundColor Yellow
    $denySubPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
    $restrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"

    if (Test-Path $denySubPath) {
        $props = Get-ItemProperty $denySubPath
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -notmatch '^PS' -and ($TargetHardwareIDs -contains [string]$p.Value)) {
                Remove-ItemProperty -Path $denySubPath -Name $p.Name -ErrorAction SilentlyContinue | Out-Null
            }
        }
        # Check whether any entries remain.
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

    # 4. Restore service startup types.
    Write-Host "[3/5] Restoring startup types for affected services..." -ForegroundColor Yellow
    if ($backup -and $backup.Services) {
        foreach ($svcName in $backup.Services.Keys) {
            $origType = $backup.Services[$svcName]
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc -and $origType -and $origType -ne 'Disabled') {
                Write-Host "      Restoring service $svcName -> $origType" -ForegroundColor Gray
                Set-Service -Name $svcName -StartupType $origType -ErrorAction SilentlyContinue
            }
        }
    }

    # 5. Re-enable PnP software component devices.
    Write-Host "[4/5] Re-enabling software component devices..." -ForegroundColor Yellow
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
        Write-Host "      Enabling device: $($dev.FriendlyName)" -ForegroundColor Gray
        Enable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }

    # 6. Remove hosts file rules.
    Write-Host "[5/5] Removing hostname blocks from the hosts file..." -ForegroundColor Yellow
    if (Test-Path $HostsPath) {
        $content = Get-Content -Path $HostsPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($content -match '(?ms)# \[Scoop:disable-hp-telemetry start\].*?# \[Scoop:disable-hp-telemetry end\]\r?\n?') {
            $cleaned = $content -replace '(?ms)\r?\n?# \[Scoop:disable-hp-telemetry start\].*?# \[Scoop:disable-hp-telemetry end\]\r?\n?', "`r`n"
            Set-Content -Path $HostsPath -Value $cleaned.Trim() -Encoding UTF8 -Force
            Write-Host "      hosts rules removed." -ForegroundColor Gray
        }
    }

    # Remove the backup file.
    if (Test-Path $BackupFile) {
        Remove-Item -Path $BackupFile -Force -ErrorAction SilentlyContinue
    }

    Write-Host "`nHP telemetry configuration and installation policies were restored successfully." -ForegroundColor Green
}

# -------------------------------------------------------------
# Status query routine.
# -------------------------------------------------------------
function Invoke-Status {
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host " HP telemetry and Windows Update blocking status" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan

    # 1. Check the device blocking policy.
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
        Write-Host "[OK] Hardware installation blocking policy (DenyDeviceIDs): active ($blockedCount telemetry component IDs blocked)" -ForegroundColor Green
    } else {
        Write-Host "[X] Hardware installation blocking policy (DenyDeviceIDs): inactive" -ForegroundColor Red
    }

    # 2. Check the guardian task.
    $task = Get-ScheduledTask -TaskPath $GuardianTaskPath -TaskName $GuardianTaskName -ErrorAction SilentlyContinue
    if ($task) {
        Write-Host "[OK] Persistent guardian scheduled task: ready (state: $($task.State))" -ForegroundColor Green
    } else {
        Write-Host "[X] Persistent guardian scheduled task: not registered" -ForegroundColor Yellow
    }

    # 3. Check the hosts file.
    $hostsBlocked = $false
    if (Test-Path $HostsPath) {
        $content = Get-Content -Path $HostsPath -Raw -ErrorAction SilentlyContinue
        if ($content -match '# \[Scoop:disable-hp-telemetry start\]') {
            $hostsBlocked = $true
        }
    }
    if ($hostsBlocked) {
        Write-Host "[OK] Hostname blocking (hosts): active" -ForegroundColor Green
    } else {
        Write-Host "[X] Hostname blocking (hosts): inactive" -ForegroundColor Yellow
    }

    # 4. Check service status.
    Write-Host "`n--- Target telemetry services ---" -ForegroundColor Cyan
    $foundSvcs = 0
    foreach ($svcName in $TargetServiceNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            $foundSvcs++
            $color = if ($svc.StartType -eq 'Disabled' -and $svc.Status -ne 'Running') { 'Green' } else { 'Red' }
            Write-Host "  * $($svc.Name) [$($svc.DisplayName)] -> status: $($svc.Status), startup type: $($svc.StartType)" -ForegroundColor $color
        }
    }
    if ($foundSvcs -eq 0) {
        Write-Host "  (No matching target services are installed.)" -ForegroundColor Gray
    }

    # 5. Check PnP software component devices.
    Write-Host "`n--- Target PnP software component devices ---" -ForegroundColor Cyan
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
            Write-Host "  * $($dev.FriendlyName) [$($dev.InstanceId)] -> status: $($dev.Status)" -ForegroundColor $color
        }
    } else {
        Write-Host "  (No matching telemetry software component devices were found.)" -ForegroundColor Gray
    }

    Write-Host "==========================================================" -ForegroundColor Cyan
}

# -------------------------------------------------------------
# Dispatch entry point.
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
