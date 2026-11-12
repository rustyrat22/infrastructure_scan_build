#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Flash_Network — PuTTY/Plink Device Enumerator (PowerShell)
    Uses plink.exe to connect to remote devices via SSH and enumerate
    device information, installed applications, and network configuration.

.DESCRIPTION
    Connects to target devices using plink.exe (PuTTY CLI), auto-detects
    the remote OS, runs an appropriate command suite, and produces a
    structured JSON report per device.

.PARAMETER Target
    Target device IP address or hostname (required)

.PARAMETER Port
    SSH port (default: 22)

.PARAMETER User
    SSH username (default: root)

.PARAMETER Key
    Path to SSH private key file (.ppk)

.PARAMETER Password
    SSH password (not recommended; prefer key-based auth)

.PARAMETER OutputDir
    Output directory for JSON reports (default: ./output/)

.PARAMETER Command
    Run a custom command instead of the default suite

.PARAMETER OsType
    Override OS detection: windows, linux, macos

.PARAMETER Timeout
    SSH connection timeout in seconds (default: 30)

.PARAMETER Batch
    Run in non-interactive mode (accept host key)

.PARAMETER Verbose
    Enable verbose output

.PARAMETER Quiet
    Suppress console output. Only write JSON report.

.PARAMETER Help
    Show usage information

.EXAMPLE
    .\device_enumerator.ps1 -Target 192.168.1.50 -User admin -Key "C:\keys\key.ppk"
    .\device_enumerator.ps1 -Target 192.168.1.100 -User admin -Password "SecretPass"
    .\device_enumerator.ps1 -Target 192.168.1.50 -User root -Key "key.ppk" -Command "uname -a"
    .\device_enumerator.ps1 -Help
#>

param(
    [Alias("t")][string]$Target = "",
    [Alias("p")][int]$Port = 22,
    [Alias("u")][string]$User = "root",
    [Alias("k")][string]$Key = "",
    [Alias("pw")][string]$Password = "",
    [Alias("o")][string]$OutputDir = "./output/",
    [Alias("c")][string]$Command = "",
    [Alias("m")][string]$OsType = "",
    [int]$Timeout = 30,
    [switch]$Batch = $true,
    [switch]$Verbose = $false,
    [switch]$Quiet = $false,
    [Alias("h")][switch]$Help = $false
)

$ErrorActionPreference = "Stop"
$OutputEncoding = [System.Text.Encoding]::UTF8

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host ("-" * 60) -ForegroundColor Yellow
    Write-Host "  $Text" -ForegroundColor Yellow
    Write-Host ("-" * 60) -ForegroundColor Yellow
}

function Write-Usage {
    $usage = @"

Flash_Network — PuTTY/Plink Device Enumerator (PowerShell)
==========================================================

DESCRIPTION:
    Connects to remote devices via SSH using plink.exe (PuTTY CLI) to gather
    device information, installed applications, network configuration,
    and system metadata.

USAGE:
    .\device_enumerator.ps1 [options]

PARAMETERS:
    -Target HOST       Target device IP or hostname (required)
    -Port PORT         SSH port (default: 22)
    -User USER         SSH username (default: root)
    -Key FILE          Path to SSH private key file (.ppk)
    -Password PWD      SSH password (not recommended; use -Key instead)
    -OutputDir DIR     Output directory for JSON reports (default: ./output/)
    -Command CMD       Run a custom command instead of the default suite
    -OsType TYPE       Override OS detection: windows, linux, macos
    -Timeout SEC       SSH connection timeout in seconds (default: 30)
    -Batch             Run in non-interactive mode (accept host key)
    -Verbose           Enable verbose output
    -Quiet             Suppress console output. Only write JSON report.
    -Help              Show this help message

EXAMPLES:
    Scan a Linux device with SSH key:
        .\device_enumerator.ps1 -Target 192.168.1.50 -User admin -Key "C:\keys\key.ppk"

    Scan a Windows device with password:
        .\device_enumerator.ps1 -Target 192.168.1.100 -User admin -Password "SecretPass"

    Run a custom command:
        .\device_enumerator.ps1 -Target 192.168.1.50 -User root -Key "key.ppk" -Command "uname -a"

    Scan with verbose output:
        .\device_enumerator.ps1 -Target 192.168.1.50 -User admin -Key "key.ppk" -Verbose
"@
    Write-Host $usage
    exit 0
}

function Test-Plink {
    try {
        $result = & plink -V 2>&1 | Select-Object -First 1
        if ($result -match "Release") {
            Write-Host "[OK] plink found: $result" -ForegroundColor Green
            return $true
        }
    } catch {}

    try {
        $result = & plink -V 2>&1
        if ($result -match "PuTTY") {
            Write-Host "[OK] plink found" -ForegroundColor Green
            return $true
        }
    } catch {}

    Write-Host "[ERROR] plink not found. Install PuTTY and add to PATH." -ForegroundColor Red
    return $false
}

function Invoke-PlinkCommand {
    param(
        [string]$Target,
        [int]$Port,
        [string]$User,
        [string]$Cmd,
        [array]$AuthArgs = @(),
        [int]$Timeout = 30,
        [bool]$Batch = $true,
        [bool]$Verbose = $false
    )

    $cmdArgs = @("plink")
    if ($Batch) { $cmdArgs += "-batch" }
    $cmdArgs += "-P", $Port.ToString()
    $cmdArgs += "-l", $User
    $cmdArgs += $AuthArgs
    $cmdArgs += $Target, $Cmd

    if ($Verbose) {
        Write-Host "  [SSH] ${User}@${Target}:${Port} > $Cmd" -ForegroundColor DarkGray
    }

    $tmpOut = [System.IO.Path]::GetTempFileName()
    $tmpErr = [System.IO.Path]::GetTempFileName()

    $process = Start-Process -FilePath "plink" -ArgumentList $cmdArgs `
        -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $tmpOut `
        -RedirectStandardError $tmpErr

    $stdout = ""
    $stderr = ""
    if (Test-Path $tmpOut) {
        $stdout = Get-Content $tmpOut -Raw -Encoding UTF8
        Remove-Item $tmpOut -Force
    }
    if (Test-Path $tmpErr) {
        $stderr = Get-Content $tmpErr -Raw -Encoding UTF8
        Remove-Item $tmpErr -Force
    }

    return @{
        stdout = $stdout
        stderr = $stderr
        exitcode = $process.ExitCode
    }
}

function Detect-Os {
    param([string]$Target, [int]$Port, [string]$User, [array]$AuthArgs, [int]$Timeout, [bool]$Verbose)

    $probes = @(
        @{ hint = "linux";   cmd = "uname -s" }
        @{ hint = "windows"; cmd = "echo %OS%" }
        @{ hint = "macos";   cmd = "uname -s" }
    )

    foreach ($probe in $probes) {
        $result = Invoke-PlinkCommand -Target $Target -Port $Port -User $User `
            -Cmd $probe.cmd -AuthArgs $AuthArgs -Timeout $Timeout -Verbose $Verbose

        $output = ($result.stdout + $result.stderr).ToLower()
        if ($probe.hint -eq "linux" -and $output -match "linux") { return "linux" }
        if ($probe.hint -eq "windows" -and $output -match "windows") { return "windows" }
        if ($probe.hint -eq "macos" -and $output -match "darwin") { return "macos" }
    }

    return "unknown"
}

function Get-LinuxCommands {
    return @{
        hostname              = "hostname"
        os_release            = "cat /etc/os-release 2>/dev/null || uname -a"
        architecture          = "uname -m"
        kernel                = "uname -r"
        uptime                = "uptime"
        ip_config             = "ip addr show 2>/dev/null || ifconfig 2>/dev/null"
        default_gateway       = "ip route show default 2>/dev/null"
        dns_servers           = "cat /etc/resolv.conf 2>/dev/null"
        listening_ports       = "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"
        installed_packages_deb = "dpkg-query -W -f='`${Package}|`${Version}|`${Maintainer}|`${Status}\n' 2>/dev/null"
        installed_packages_rpm = "rpm -qa --queryformat '%{NAME}|%{VERSION}|%{VENDOR}|installed\n' 2>/dev/null"
        snap_packages         = "snap list 2>/dev/null"
        cpu_info              = "lscpu 2>/dev/null | head -20"
        memory                = "free -h 2>/dev/null"
        disk                  = "df -h 2>/dev/null"
    }
}

function Get-WindowsCommands {
    return @{
        hostname                = "hostname"
        os_info                 = "systeminfo | findstr /B /C:`"OS Name`" /C:`"OS Version`" /C:`"System Type`""
        architecture            = "echo %PROCESSOR_ARCHITECTURE%"
        ip_config               = "ipconfig /all"
        default_gateway         = "ipconfig | findstr /C:`"Default Gateway`""
        dns_servers             = "ipconfig /all | findstr /C:`"DNS Servers`""
        listening_ports         = "netstat -ano | findstr LISTENING"
        installed_apps_registry = "reg query `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`" /s 2>nul | findstr /C:`"DisplayName`" /C:`"DisplayVersion`" /C:`"Publisher`" /C:`"InstallLocation`" /C:`"InstallDate`""
        installed_apps_wow64    = "reg query `"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`" /s 2>nul | findstr /C:`"DisplayName`" /C:`"DisplayVersion`" /C:`"Publisher`" /C:`"InstallLocation`" /C:`"InstallDate`""
    }
}

function Get-MacOSCommands {
    return @{
        hostname       = "hostname"
        os_info        = "sw_vers"
        architecture   = "uname -m"
        kernel         = "uname -r"
        uptime         = "uptime"
        ip_config      = "ifconfig"
        default_gateway= "netstat -nr | grep default"
        dns_servers    = "cat /etc/resolv.conf 2>/dev/null"
        listening_ports= "lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null | head -50"
        installed_apps = "system_profiler SPApplicationsDataType 2>/dev/null | head -200"
    }
}

function Parse-LinuxPackages {
    param([string]$Stdout)
    $apps = @()
    foreach ($line in $Stdout -split "`n") {
        if ($line -notmatch "\|") { continue }
        $parts = $line -split "\|"
        if ($parts.Count -ge 2) {
            $apps += [PSCustomObject]@{
                name             = $parts[0].Trim()
                version          = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }
                signer           = if ($parts.Count -gt 2) { $parts[2].Trim() } else { "" }
                install_location = ""
                url              = ""
                last_update      = ""
            }
        }
    }
    return $apps
}

function Parse-WindowsRegistry {
    param([string]$Stdout)
    $apps = @()
    $current = $null

    foreach ($line in $Stdout -split "`n") {
        $line = $line.Trim()
        if ($line -match "DisplayName") {
            if ($line -match "REG_SZ\s+(.+)") {
                $current = @{
                    name = $Matches[1].Trim()
                    version = ""
                    signer = ""
                    install_location = ""
                    url = ""
                    last_update = ""
                }
            }
        } elseif ($null -ne $current) {
            if ($line -match "DisplayVersion" -and $line -match "REG_SZ\s+(.+)") {
                $current.version = $Matches[1].Trim()
            } elseif ($line -match "Publisher" -and $line -match "REG_SZ\s+(.+)") {
                $current.signer = $Matches[1].Trim()
            } elseif ($line -match "InstallLocation" -and $line -match "REG_SZ\s+(.+)") {
                $current.install_location = $Matches[1].Trim()
            } elseif ($line -match "InstallDate" -and $line -match "REG_SZ\s+(.+)") {
                $current.last_update = $Matches[1].Trim()
            }

            if ($current.name -and $current.version) {
                $apps += [PSCustomObject]$current
                $current = $null
            }
        }
    }
    return $apps
}

function Parse-Applications {
    param([hashtable]$StdoutMap, [string]$OsType)
    $apps = @()

    if ($OsType -eq "linux") {
        foreach ($key in @("installed_packages_deb", "installed_packages_rpm")) {
            if ($StdoutMap.ContainsKey($key) -and $StdoutMap[$key]) {
                $apps += Parse-LinuxPackages -Stdout $StdoutMap[$key]
            }
        }
    } elseif ($OsType -eq "windows") {
        foreach ($key in @("installed_apps_registry", "installed_apps_wow64")) {
            if ($StdoutMap.ContainsKey($key) -and $StdoutMap[$key]) {
                $apps += Parse-WindowsRegistry -Stdout $StdoutMap[$key]
            }
        }
    } elseif ($OsType -eq "macos") {
        $lines = $StdoutMap["installed_apps"] -split "`n"
        $current = $null
        foreach ($line in $lines) {
            if ($line -match "Version:\s*(.+)") {
                if ($null -eq $current) { $current = @{} }
                $current.version = $Matches[1].Trim()
            }
            if ($line -match "Location:\s*(.+)") {
                if ($null -ne $current -and $current.name) {
                    $current.install_location = $Matches[1].Trim()
                    $current.signer = $current.signer ?: ""
                    $current.url = $current.url ?: ""
                    $current.last_update = $current.last_update ?: ""
                    $apps += [PSCustomObject]$current
                    $current = $null
                }
            } elseif ($line.Trim() -and $line.Trim().Length -gt 2 -and $line -notmatch "^\s") {
                if ($null -eq $current) {
                    $current = @{ name = $line.Trim().TrimEnd(":") }
                }
            }
        }
    }

    # Deduplicate
    $seen = @{}
    $unique = @()
    foreach ($app in $apps) {
        $key = $app.name.ToLower()
        if ($key -and -not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $unique += $app
        }
    }
    return $unique
}

function Enumerate-Device {
    param(
        [string]$Target,
        [int]$Port = 22,
        [string]$User = "root",
        [array]$AuthArgs = @(),
        [string]$OsType = "",
        [int]$Timeout = 30,
        [bool]$Batch = $true,
        [bool]$Verbose = $false,
        [bool]$Quiet = $false
    )

    $startTime = Get-Date

    if (-not $Quiet) {
        Write-Host "`n[ENUM] Connecting to $Target`:$Port as $User..." -ForegroundColor Magenta
    }

    if (-not $OsType) {
        $OsType = Detect-Os -Target $Target -Port $Port -User $User `
            -AuthArgs $AuthArgs -Timeout $Timeout -Verbose $Verbose
        if (-not $Quiet) {
            Write-Host "[ENUM] Detected OS: $OsType" -ForegroundColor Green
        }
    }

    $commandSuites = @{
        linux   = Get-LinuxCommands
        windows = Get-WindowsCommands
        macos   = Get-MacOSCommands
    }
    $commands = $commandSuites[$OsType]

    if (-not $commands) {
        Write-Host "[ERROR] No command suite for OS type: $OsType" -ForegroundColor Red
        return $null
    }

    $stdoutMap = @{}
    $errors = @()

    foreach ($entry in $commands.GetEnumerator()) {
        if ($Verbose -and -not $Quiet) {
            $cmdPreview = if ($entry.Value.Length -gt 60) { $entry.Value.Substring(0, 60) + "..." } else { $entry.Value }
            Write-Host "  [CMD] $($entry.Key): $cmdPreview" -ForegroundColor DarkGray
        }

        $result = Invoke-PlinkCommand -Target $Target -Port $Port -User $User `
            -Cmd $entry.Value -AuthArgs $AuthArgs -Timeout $Timeout `
            -Batch $Batch -Verbose $Verbose

        $stdoutMap[$entry.Key] = $result.stdout
        if ($result.exitcode -ne 0 -and $result.stderr) {
            $errors += [PSCustomObject]@{
                command = $entry.Key
                error = $result.stderr.Substring(0, [Math]::Min(200, $result.stderr.Length))
            }
        }
    }

    $duration = ((Get-Date) - $startTime).TotalSeconds

    $deviceInfo = [PSCustomObject]@{
        hostname        = $stdoutMap["hostname"].Trim()
        os              = ($stdoutMap["os_release"] ?: $stdoutMap["os_info"] ?: "").Trim().Substring(0, [Math]::Min(200, ($stdoutMap["os_release"] ?: $stdoutMap["os_info"] ?: "").Length))
        architecture    = $stdoutMap["architecture"].Trim()
        kernel          = $stdoutMap["kernel"].Trim()
        uptime          = ($stdoutMap["uptime"] ?: "").Trim().Substring(0, [Math]::Min(200, ($stdoutMap["uptime"] ?: "").Length))
        ip_config       = ($stdoutMap["ip_config"] ?: "").Trim().Substring(0, [Math]::Min(500, ($stdoutMap["ip_config"] ?: "").Length))
        default_gateway = ($stdoutMap["default_gateway"] ?: "").Trim()
        dns_servers     = ($stdoutMap["dns_servers"] ?: "").Trim()
        listening_ports = ($stdoutMap["listening_ports"] ?: "").Trim().Substring(0, [Math]::Min(1000, ($stdoutMap["listening_ports"] ?: "").Length))
    }

    $apps = Parse-Applications -StdoutMap $stdoutMap -OsType $OsType

    $authMethod = "unknown"
    if ($AuthArgs -contains "-i") { $authMethod = "key" }
    elseif ($AuthArgs -like "*-pw*") { $authMethod = "password" }

    $report = [PSCustomObject]@{
        scan_metadata = [PSCustomObject]@{
            timestamp        = (Get-Date -Format "o")
            target           = $Target
            port             = $Port
            user             = $User
            os_detected      = $OsType
            auth_method      = $authMethod
            duration_seconds = [Math]::Round($duration, 2)
            errors           = $errors
        }
        device_info       = $deviceInfo
        applications      = $apps
        application_count = $apps.Count
    }

    return $report
}

function Save-Report {
    param([PSCustomObject]$Report, [string]$OutputDir = "./output/")

    if (!(Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $Report.device_info.hostname -replace "\s", "_"
    $target = $Report.scan_metadata.target -replace "\.", "_"

    $filename = "device_enum_${hostname}_${target}_${timestamp}.json"
    $filepath = Join-Path $OutputDir $filename

    $Report | ConvertTo-Json -Depth 5 | Out-File -FilePath $filepath -Encoding UTF8
    return $filepath
}

function Print-Summary {
    param([PSCustomObject]$Report, [string]$Filepath)

    $meta = $Report.scan_metadata
    $dev = $Report.device_info

    Write-Header "FLASH_NETWORK — Device Enumeration Summary"
    Write-Host "  Target      : $($meta.target):$($meta.port)"
    Write-Host "  User        : $($meta.user)"
    Write-Host "  OS          : $($meta.os_detected)"
    Write-Host "  Hostname    : $($dev.hostname)"
    Write-Host "  Architecture: $($dev.architecture)"
    Write-Host "  Duration    : $($meta.duration_seconds)s"
    Write-Section ""

    Write-Host "  APPLICATIONS FOUND: $($Report.application_count)" -ForegroundColor Green
    Write-Section ""

    $count = 0
    foreach ($app in $Report.applications) {
        if ($count -ge 20) { break }
        Write-Host "  [$($count + 1)] $($app.name)" -ForegroundColor White
        if ($app.version) { Write-Host "      Version : $($app.version)" }
        if ($app.signer)  { Write-Host "      Signer  : $($app.signer)" }
        if ($app.install_location) { Write-Host "      Location: $($app.install_location)" }
        Write-Host ""
        $count++
    }
    if ($Report.application_count -gt 20) {
        Write-Host "  ... and $($Report.application_count - 20) more"
    }

    if ($meta.errors.Count -gt 0) {
        Write-Host "`n  ERRORS ($($meta.errors.Count)):" -ForegroundColor Red
        $errCount = 0
        foreach ($err in $meta.errors) {
            if ($errCount -ge 5) { break }
            $errMsg = if ($err.error.Length -gt 100) { $err.error.Substring(0, 100) } else { $err.error }
            Write-Host "    - $($err.command): $errMsg" -ForegroundColor Red
            $errCount++
        }
    }

    Write-Header "Full report saved to: $Filepath"
}

# Main
if ($Help) { Write-Usage; exit 0 }

if (-not $Target) {
    Write-Host "[ERROR] Target is required. Use -Target <host> or -Help for usage." -ForegroundColor Red
    exit 1
}

if (-not $Quiet) {
    Write-Header "Flash_Network — PuTTY/Plink Device Enumerator (PowerShell)"
}

if (-not (Test-Plink)) { exit 1 }

$authArgs = @()
if ($Key) { $authArgs += "-i", $Key }
if ($Password) { $authArgs += "-pw", $Password }

if ($Command) {
    if (-not $Quiet) { Write-Host "`n[ENUM] Running custom command on $Target..." -ForegroundColor Magenta }
    $result = Invoke-PlinkCommand -Target $Target -Port $Port -User $User `
        -Cmd $Command -AuthArgs $authArgs -Timeout $Timeout -Verbose $Verbose
    Write-Host $result.stdout
    if ($result.stderr) { Write-Host "[STDERR] $($result.stderr)" -ForegroundColor Red }
    exit $result.exitcode
}

$report = Enumerate-Device `
    -Target $Target -Port $Port -User $User -AuthArgs $authArgs `
    -OsType $OsType -Timeout $Timeout -Batch $Batch `
    -Verbose:$Verbose -Quiet:$Quiet

if (-not $report) {
    Write-Host "[ERROR] Enumeration failed." -ForegroundColor Red
    exit 1
}

$filepath = Save-Report -Report $report -OutputDir $OutputDir

if (-not $Quiet) {
    Print-Summary -Report $report -Filepath $filepath
} else {
    Write-Host "Report saved to: $filepath"
}
