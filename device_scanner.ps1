#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Flash_Network — Device Scanner & JSON Reporter (PowerShell)
    Discovers devices on the local network, connects via SSH (plink),
    enumerates applications, and generates standardized JSON files per device.

.DESCRIPTION
    Full pipeline: discover -> connect -> enumerate -> JSON report.
    One JSON file per device with device metadata, application inventory,
    and scan summary.

.PARAMETER Range
    Network CIDR range to scan (e.g. 192.168.1.0/24). Default: auto-detect.

.PARAMETER Mode
    Discovery mode: ping, arp, tshark, all (default: all)

.PARAMETER Interface
    Network interface index for tshark discovery.

.PARAMETER MaxDevices
    Maximum number of devices to scan.

.PARAMETER Port
    SSH port (default: 22)

.PARAMETER User
    Default SSH username (default: root)

.PARAMETER Key
    Path to SSH private key (.ppk)

.PARAMETER Password
    SSH password (fallback if key not provided)

.PARAMETER OutputDir
    Output directory for JSON files (default: ./output/)

.PARAMETER Timeout
    Per-device SSH timeout in seconds (default: 30)

.PARAMETER Verbose
    Enable verbose output

.PARAMETER Quiet
    Suppress console output. Only write JSON files.

.PARAMETER Help
    Show usage information

.EXAMPLE
    .\device_scanner.ps1
    .\device_scanner.ps1 -Range "192.168.1.0/24" -Key "C:\keys\key.ppk" -User admin
    .\device_scanner.ps1 -Mode ping -MaxDevices 10
    .\device_scanner.ps1 -Range "10.0.0.0/24" -User admin -Password "SecretPass"
#>

param(
    [Alias("r")][string]$Range = "",
    [Alias("m")][ValidateSet("ping","arp","tshark","all")][string]$Mode = "all",
    [Alias("i")][int]$Interface = -1,
    [Alias("n")][int]$MaxDevices = 0,
    [Alias("p")][int]$Port = 22,
    [Alias("u")][string]$User = "root",
    [Alias("k")][string]$Key = "",
    [Alias("pw")][string]$Password = "",
    [Alias("o")][string]$OutputDir = "./output/",
    [Alias("t")][int]$Timeout = 30,
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

function Write-Usage {
    $usage = @"

Flash_Network — Device Scanner & JSON Reporter (PowerShell)
============================================================

DESCRIPTION:
    Discovers devices on the local network, connects to each via SSH,
    enumerates installed applications and system metadata, and generates
    a standardized JSON file per device.

    The pipeline:
      1. Discover live devices via ARP, ICMP ping sweep, or tshark
      2. Connect via plink.exe (PuTTY SSH client)
      3. Run OS-specific commands to enumerate applications
      4. Generate one JSON file per device

USAGE:
    .\device_scanner.ps1 [options]

PARAMETERS:
    -Range CIDR        Network CIDR range (default: auto-detect)
    -Mode MODE         Discovery mode: ping, arp, tshark, all (default: all)
    -Interface NUM     Interface index for tshark
    -MaxDevices NUM    Maximum devices to scan
    -Port PORT         SSH port (default: 22)
    -User USER         Default SSH username (default: root)
    -Key FILE          Path to SSH private key (.ppk)
    -Password PWD      SSH password
    -OutputDir DIR     Output directory (default: ./output/)
    -Timeout SEC       Per-device SSH timeout (default: 30)
    -Verbose           Enable verbose output
    -Quiet             Suppress console output
    -Help              Show this help

EXAMPLES:
    Auto-detect and scan:
        .\device_scanner.ps1

    Specific range with SSH key:
        .\device_scanner.ps1 -Range "192.168.1.0/24" -Key "C:\keys\key.ppk" -User admin

    Ping-only, max 10 devices:
        .\device_scanner.ps1 -Mode ping -MaxDevices 10

    Verbose with custom output:
        .\device_scanner.ps1 -Range "192.168.1.0/24" -Verbose -OutputDir "./reports/"

JSON OUTPUT (per device):
    {
      "device": { "hostname", "ip_address", "mac_address", "os", "architecture",
                   "scan_timestamp", "scan_methods" },
      "applications": [ { "name", "version", "last_update", "signer",
                          "install_location", "url", "publisher",
                          "install_date", "architecture", "source" } ],
      "scan_summary": { "total_applications", "scan_duration_seconds", "errors" }
    }
"@
    Write-Host $usage
    exit 0
}

function Test-Tool {
    param([string]$Name)
    try {
        $arg = if ($Name -eq "tshark") { "--version" } else { "-V" }
        $result = & $Name $arg 2>&1 | Select-Object -First 1
        if ($result) {
            Write-Host "[OK] $Name`: $result" -ForegroundColor Green
            return $true
        }
    } catch {}
    Write-Host "[ERROR] $Name not found." -ForegroundColor Red
    return $false
}

function Get-LocalNetworkRange {
    try {
        $adapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notmatch "^127\." -and $_.PrefixLength -le 24 -and $_.PrefixLength -gt 0 }
        if ($adapters) {
            $a = $adapters | Select-Object -First 1
            $network = [System.Net.IPAddress]::Parse($a.IPAddress)
            return "$($a.IPAddress)/$($a.PrefixLength)"
        }
    } catch {}
    return "192.168.1.0/24"
}

function Discover-Ping {
    param([string]$NetworkRange, [int]$MaxDevices, [int]$PingTimeout, [bool]$Verbose)

    try {
        $net = [System.Net.IPAddress]::Parse($NetworkRange.Split("/")[0])
        $prefix = [int]$NetworkRange.Split("/")[1]
        $ipBytes = $net.GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
        $hostBits = 32 - $prefix
        $totalHosts = [Math]::Min([Math]::Pow(2, $hostBits) - 2, 254)
    } catch {
        return @()
    }

    $devices = @()
    $count = 0
    for ($i = 1; $i -le $totalHosts; $i++) {
        if ($MaxDevices -gt 0 -and $count -ge $MaxDevices) { break }
        $hostInt = $ipInt -bor $i
        $hostBytes = [BitConverter]::GetBytes($hostInt)
        [Array]::Reverse($hostBytes)
        $hostIP = [System.Net.IPAddress]::new($hostBytes).IPAddressToString

        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($hostIP, $PingTimeout * 1000)
            if ($reply.Status -eq "Success") {
                $devices += @{ ip = $hostIP; mac = "N/A"; hostname = $hostIP; method = "ping" }
                $count++
                if ($Verbose) { Write-Host "  [+] $hostIP is alive" -ForegroundColor Green }
            }
        } catch {}
    }
    return $devices
}

function Discover-Arp {
    param([bool]$Verbose)
    $devices = @()
    try {
        $result = arp -a
        foreach ($line in $result) {
            if ($line -match "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f\-]{17})") {
                $devices += @{
                    ip = $Matches[1]
                    mac = $Matches[2].Replace("-", ":")
                    hostname = $Matches[1]
                    method = "arp"
                }
            }
        }
    } catch {}
    return $devices
}

function Discover-Tshark {
    param([int]$InterfaceIdx, [bool]$Verbose)
    $devices = @()
    $seenIps = @{}

    try {
        $cmdArgs = @("-a", "duration:10", "-T", "fields",
                     "-e", "ip.src", "-e", "ip.dst", "-e", "eth.src",
                     "-E", "separator=|")
        if ($InterfaceIdx -ge 0) { $cmdArgs = @("-i", $InterfaceIdx.ToString()) + $cmdArgs }

        $tmpFile = [System.IO.Path]::GetTempFileName()
        $process = Start-Process -FilePath "tshark" -ArgumentList $cmdArgs `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmpFile
        $lines = Get-Content $tmpFile -Encoding UTF8
        Remove-Item $tmpFile -Force

        foreach ($line in $lines) {
            if (-not $line.Trim()) { continue }
            $parts = $line -split "\|"
            foreach ($ipField in @(0, 1)) {
                $ip = $parts[$ipField].Trim()
                $mac = if ($parts.Count -gt 2) { $parts[2].Trim() } else { "" }
                if ($ip -and $ip -notmatch "^(127\.|224\.|239\.|255\.)" -and -not $seenIps.ContainsKey($ip)) {
                    $seenIps[$ip] = $true
                    $devices += @{
                        ip = $ip
                        mac = if ($mac -and $mac -ne "00:00:00:00:00:00") { $mac } else { "N/A" }
                        hostname = $ip
                        method = "tshark"
                    }
                }
            }
        }
    } catch {
        if ($Verbose) { Write-Host "[WARN] tshark discovery failed: $_" -ForegroundColor Yellow }
    }
    return $devices
}

function Discover-Devices {
    param([string]$NetworkRange, [string]$Mode, [int]$Interface, [int]$MaxDevices,
          [int]$PingTimeout, [bool]$Verbose)

    $allDevices = @{}

    if ($Mode -in @("ping", "all")) {
        foreach ($dev in (Discover-Ping -NetworkRange $NetworkRange -MaxDevices $MaxDevices `
                                          -PingTimeout $PingTimeout -Verbose $Verbose)) {
            $allDevices[$dev.ip] = $dev
        }
    }

    if ($Mode -in @("arp", "all")) {
        foreach ($dev in (Discover-Arp -Verbose $Verbose)) {
            if (-not $allDevices.ContainsKey($dev.ip)) {
                $allDevices[$dev.ip] = $dev
            }
        }
    }

    if ($Mode -in @("tshark", "all") -and $Interface -ge 0) {
        foreach ($dev in (Discover-Tshark -InterfaceIdx $Interface -Verbose $Verbose)) {
            if (-not $allDevices.ContainsKey($dev.ip)) {
                $allDevices[$dev.ip] = $dev
            }
        }
    }

    $devices = @($allDevices.Values)
    if ($MaxDevices -gt 0 -and $devices.Count -gt $MaxDevices) {
        $devices = $devices | Select-Object -First $MaxDevices
    }
    return $devices
}

function Invoke-Plink {
    param([string]$Target, [int]$Port, [string]$User, [string]$Cmd,
          [array]$AuthArgs, [int]$Timeout, [bool]$Batch, [bool]$Verbose)

    $cmdArgs = @("plink")
    if ($Batch) { $cmdArgs += "-batch" }
    $cmdArgs += "-P", $Port.ToString(), "-l", $User
    $cmdArgs += $AuthArgs
    $cmdArgs += $Target, $Cmd

    if ($Verbose) { Write-Host "  [SSH] ${User}@${Target}:${Port} > $($Cmd.Substring(0, [Math]::Min(60, $Cmd.Length)))" -ForegroundColor DarkGray }

    $tmpOut = [System.IO.Path]::GetTempFileName()
    $tmpErr = [System.IO.Path]::GetTempFileName()

    $process = Start-Process -FilePath "plink" -ArgumentList $cmdArgs `
        -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr

    $stdout = ""; $stderr = ""
    if (Test-Path $tmpOut) { $stdout = Get-Content $tmpOut -Raw -Encoding UTF8; Remove-Item $tmpOut -Force }
    if (Test-Path $tmpErr) { $stderr = Get-Content $tmpErr -Raw -Encoding UTF8; Remove-Item $tmpErr -Force }

    return @{ stdout = $stdout; stderr = $stderr; exitcode = $process.ExitCode }
}

function Detect-Os {
    param([string]$Target, [int]$Port, [string]$User, [array]$AuthArgs, [int]$Timeout, [bool]$Verbose)

    $probes = @(
        @{ hint="linux";   cmd="uname -s" },
        @{ hint="windows"; cmd="echo %OS%" },
        @{ hint="macos";   cmd="uname -s" }
    )

    foreach ($probe in $probes) {
        $result = Invoke-Plink -Target $Target -Port $Port -User $User -Cmd $probe.cmd `
            -AuthArgs $AuthArgs -Timeout $Timeout -Verbose $Verbose
        $output = ($result.stdout + $result.stderr).ToLower()
        if ($probe.hint -eq "linux" -and $output -match "linux") { return "linux" }
        if ($probe.hint -eq "windows" -and $output -match "windows") { return "windows" }
        if ($probe.hint -eq "macos" -and $output -match "darwin") { return "macos" }
    }
    return "unknown"
}

function Get-LinuxCommands {
    return @{
        hostname   = "hostname"
        os_info    = "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 || uname -s"
        architecture = "uname -m"
        dpkg       = "dpkg-query -W -f='`${Package}|`${Version}|`${Maintainer}|`${Status}\n' 2>/dev/null"
        rpm        = "rpm -qa --queryformat '%{NAME}|%{VERSION}|%{VENDOR}|installed\n' 2>/dev/null"
        snap       = "snap list 2>/dev/null"
        pip        = "pip3 list --format=json 2>/dev/null || pip list --format=json 2>/dev/null"
    }
}

function Get-WindowsCommands {
    return @{
        hostname   = "hostname"
        os_info    = "systeminfo | findstr /B /C:`"OS Name`" /C:`"OS Version`""
        architecture = "echo %PROCESSOR_ARCHITECTURE%"
        reg32      = "reg query `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`" /s 2>nul | findstr /C:`"DisplayName`" /C:`"DisplayVersion`" /C:`"Publisher`" /C:`"InstallLocation`" /C:`"InstallDate`""
        reg64      = "reg query `"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`" /s 2>nul | findstr /C:`"DisplayName`" /C:`"DisplayVersion`" /C:`"Publisher`" /C:`"InstallLocation`" /C:`"InstallDate`""
        winget     = "winget list --accept-source-agreements 2>nul"
    }
}

function Get-MacOSCommands {
    return @{
        hostname   = "hostname"
        os_info    = "sw_vers -productName && sw_vers -productVersion"
        architecture = "uname -m"
        apps       = "system_profiler SPApplicationsDataType 2>/dev/null"
        brew       = "brew list --versions 2>/dev/null"
    }
}

function Parse-LinuxApps {
    param([hashtable]$StdoutMap)
    $apps = @()
    $sources = @{ dpkg="dpkg"; rpm="rpm"; snap="snap"; pip="pip" }

    foreach ($entry in $sources.GetEnumerator()) {
        $output = $StdoutMap[$entry.Key]
        if (-not $output) { continue }

        if ($entry.Value -eq "pip") {
            try {
                $pkgs = $output | ConvertFrom-Json -ErrorAction Stop
                foreach ($pkg in $pkgs) {
                    $apps += [PSCustomObject]@{
                        name=$pkg.name; version=$pkg.version; last_update=""; signer="";
                        install_location=""; url=""; publisher=""; install_date="";
                        architecture=""; source="pip"
                    }
                }
            } catch {}
        } else {
            foreach ($line in $output -split "`n") {
                if ($line -notmatch "\|") { continue }
                $parts = $line -split "\|"
                $apps += [PSCustomObject]@{
                    name=$parts[0].Trim(); version=if($parts.Count -gt 1){$parts[1].Trim()}else{""};
                    last_update=""; signer=if($parts.Count -gt 2){$parts[2].Trim()}else{""};
                    install_location=""; url=""; publisher=if($parts.Count -gt 2){$parts[2].Trim()}else{""};
                    install_date=""; architecture=""; source=$entry.Value
                }
            }
        }
    }
    return $apps
}

function Parse-WindowsApps {
    param([hashtable]$StdoutMap)
    $apps = @()

    foreach ($key in @("reg32", "reg64")) {
        $output = $StdoutMap[$key]
        if (-not $output) { continue }
        $current = $null
        foreach ($line in $output -split "`n") {
            $line = $line.Trim()
            if ($line -match "DisplayName" -and $line -match "REG_SZ\s+(.+)") {
                $current = @{
                    name=$Matches[1].Trim(); version=""; last_update=""; signer="";
                    install_location=""; url=""; publisher=""; install_date="";
                    architecture=if($key -eq "reg32"){"x86"}else{"x64"}; source="registry"
                }
            } elseif ($null -ne $current) {
                foreach ($pair in @(
                    @{ f="version"; k="DisplayVersion" }, @{ f="publisher"; k="Publisher" },
                    @{ f="signer"; k="Publisher" }, @{ f="install_location"; k="InstallLocation" },
                    @{ f="install_date"; k="InstallDate" }, @{ f="last_update"; k="InstallDate" }
                )) {
                    if ($line -match $pair.k -and $line -match "REG_SZ\s+(.+)") {
                        $current[$pair.f] = $Matches[1].Trim()
                    }
                }
                if ($current.name -and $current.version) {
                    $apps += [PSCustomObject]$current
                    $current = $null
                }
            }
        }
    }

    $wingetOut = $StdoutMap["winget"]
    if ($wingetOut) {
        $lines = $wingetOut -split "`n"
        for ($i = 3; $i -lt $lines.Count; $i++) {
            $parts = $lines[$i].Trim() -split "\s+"
            if ($parts.Count -ge 3) {
                $apps += [PSCustomObject]@{
                    name=($parts[0..($parts.Count-3)] -join " "); version=$parts[-2];
                    last_update=""; signer=""; install_location=""; url="";
                    publisher=if($parts.Count -gt 3){$parts[-1]}else{""}; install_date="";
                    architecture=""; source="winget"
                }
            }
        }
    }
    return $apps
}

function Parse-MacOSApps {
    param([hashtable]$StdoutMap)
    $apps = @()
    $output = $StdoutMap["apps"]
    if (-not $output) { return $apps }

    $current = $null
    foreach ($line in $output -split "`n") {
        if ($line.Trim() -and -not $line.StartsWith(" ") -and -not $line.StartsWith("-")) {
            $name = $line.Trim().TrimEnd(":")
            if ($name -and $name.Length -gt 2 -and $name -notmatch "Version") {
                if ($null -ne $current -and $current.name) { $apps += [PSCustomObject]$current }
                $current = @{ name=$name; version=""; last_update=""; signer="";
                              install_location=""; url=""; publisher=""; install_date="";
                              architecture=""; source="macos_apps" }
            }
        } elseif ($null -ne $current) {
            if ($line -match "Version:\s*(.+)") { $current.version = $Matches[1].Trim() }
            if ($line -match "Location:\s*(.+)") { $current.install_location = $Matches[1].Trim() }
        }
    }
    if ($null -ne $current -and $current.name) { $apps += [PSCustomObject]$current }

    $brewOut = $StdoutMap["brew"]
    if ($brewOut) {
        foreach ($line in ($brewOut -split "`n")) {
            $parts = $line.Trim() -split "\s+"
            if ($parts.Count -ge 1) {
                $apps += [PSCustomObject]@{
                    name=$parts[0]; version=if($parts.Count -gt 1){$parts[1]}else{""};
                    last_update=""; signer=""; install_location=""; url=""; publisher="";
                    install_date=""; architecture=""; source="brew"
                }
            }
        }
    }
    return $apps
}

function Enumerate-Device {
    param([string]$Target, [int]$Port, [string]$User, [array]$AuthArgs,
          [int]$Timeout, [bool]$Verbose)

    $startTime = Get-Date
    $scanMethods = @("ssh")

    $osType = Detect-Os -Target $Target -Port $Port -User $User -AuthArgs $AuthArgs `
        -Timeout $Timeout -Verbose $Verbose
    $scanMethods += "os_detect_$osType"

    $commandSuites = @{
        linux = Get-LinuxCommands; windows = Get-WindowsCommands; macos = Get-MacOSCommands
    }
    $commands = $commandSuites[$osType]
    if (-not $commands) { $commands = @{} }

    $stdoutMap = @{}
    $errors = @()

    foreach ($entry in $commands.GetEnumerator()) {
        $result = Invoke-Plink -Target $Target -Port $Port -User $User -Cmd $entry.Value `
            -AuthArgs $AuthArgs -Timeout $Timeout -Batch $true -Verbose $Verbose
        $stdoutMap[$entry.Key] = $result.stdout
        $scanMethods += $entry.Key
        if ($result.exitcode -ne 0 -and $result.stderr) {
            $errors += @{ command=$entry.Key; error=$result.stderr.Substring(0, [Math]::Min(200, $result.stderr.Length)) }
        }
    }

    $parsers = @{ linux = { param($m) Parse-LinuxApps -StdoutMap $m };
                  windows = { param($m) Parse-WindowsApps -StdoutMap $m };
                  macos = { param($m) Parse-MacOSApps -StdoutMap $m } }
    $parseFn = $parsers[$osType]
    $apps = if ($parseFn) { & $parseFn $stdoutMap } else { @() }

    # Deduplicate
    $seen = @{}; $unique = @()
    foreach ($app in $apps) {
        $key = "$($app.name)|$($app.version)".ToLower()
        if ($app.name -and -not $seen.ContainsKey($key)) {
            $seen[$key] = $true; $unique += $app
        }
    }

    $duration = ((Get-Date) - $startTime).TotalSeconds

    return @{
        hostname = $stdoutMap["hostname"].Trim()
        os = ($stdoutMap["os_info"] ?: "").Trim().Substring(0, [Math]::Min(200, ($stdoutMap["os_info"] ?: "").Length))
        architecture = $stdoutMap["architecture"].Trim()
        applications = $unique
        scan_methods = $scanMethods
        os_detected = $osType
        duration = [Math]::Round($duration, 2)
        errors = $errors
    }
}

function Build-DeviceJson {
    param([hashtable]$DeviceInfo, [hashtable]$EnumResult, [string]$Ip, [string]$Mac, [string]$Timestamp)

    $hostname = if ($EnumResult.hostname) { $EnumResult.hostname } elseif ($DeviceInfo.hostname) { $DeviceInfo.hostname } else { $Ip }

    return @{
        device = @{
            hostname = $hostname
            ip_address = $Ip
            mac_address = $Mac
            os = $EnumResult.os
            architecture = $EnumResult.architecture
            scan_timestamp = $Timestamp
            scan_methods = $EnumResult.scan_methods
        }
        applications = @($EnumResult.applications)
        scan_summary = @{
            total_applications = $EnumResult.applications.Count
            scan_duration_seconds = $EnumResult.duration
            errors = $EnumResult.errors
        }
    }
}

function Save-DeviceJson {
    param([hashtable]$Report, [string]$OutputDir, [string]$Ip, [string]$Hostname)

    if (!(Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

    $safeHostname = ($Hostname ?: $Ip) -replace "[\s/]", "_"
    $safeIp = $Ip -replace "\.", "_"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "${safeHostname}_${safeIp}_${timestamp}.json"
    $filepath = Join-Path $OutputDir $filename

    $Report | ConvertTo-Json -Depth 5 | Out-File -FilePath $filepath -Encoding UTF8
    return $filepath
}

function Scan-AndPopulate {
    param(
        [string]$NetworkRange, [string]$Mode, [int]$Interface, [int]$MaxDevices,
        [int]$Port, [string]$User, [array]$AuthArgs, [int]$Timeout,
        [string]$OutputDir, [bool]$Verbose, [bool]$Quiet
    )

    $startTime = Get-Date

    if (-not $Quiet) {
        Write-Header "Flash_Network — Device Scanner & JSON Reporter (PowerShell)"
    }

    # Check prerequisites
    if (-not (Test-Tool "plink")) {
        Write-Host "[FATAL] plink is required. Install PuTTY and add to PATH." -ForegroundColor Red
        exit 1
    }
    if ($Mode -match "tshark" -and -not (Test-Tool "tshark")) {
        if ($Mode -ne "all") {
            Write-Host "[WARN] tshark not found, skipping tshark discovery." -ForegroundColor Yellow
        }
    }

    if (-not $NetworkRange) {
        $NetworkRange = Get-LocalNetworkRange
        if (-not $Quiet) { Write-Host "[AUTO] Detected network range: $NetworkRange" -ForegroundColor Cyan }
    }

    if (-not $Quiet) { Write-Host "`n[DISCOVERY] Scanning $NetworkRange (mode: $Mode)..." -ForegroundColor Magenta }

    $devices = Discover-Devices -NetworkRange $NetworkRange -Mode $Mode -Interface $Interface `
        -MaxDevices $MaxDevices -PingTimeout 2 -Verbose $Verbose

    if ($devices.Count -eq 0) {
        Write-Host "[INFO] No devices discovered." -ForegroundColor Yellow
        return @()
    }

    if (-not $Quiet) { Write-Host "`n[SCAN] Found $($devices.Count) device(s). Enumerating..." -ForegroundColor Magenta }

    $results = @()
    $idx = 1
    foreach ($dev in $devices) {
        $ip = $dev.ip; $mac = $dev.mac; $hostname = $dev.hostname
        $timestamp = Get-Date -Format "o"

        if (-not $Quiet) { Write-Host "`n  [$idx/$($devices.Count)] $hostname ($ip)..." -ForegroundColor White }

        try {
            $enumResult = Enumerate-Device -Target $ip -Port $Port -User $User `
                -AuthArgs $AuthArgs -Timeout $Timeout -Verbose $Verbose

            $report = Build-DeviceJson -DeviceInfo $dev -EnumResult $enumResult `
                -Ip $ip -Mac $mac -Timestamp $timestamp

            $filepath = Save-DeviceJson -Report $report -OutputDir $OutputDir `
                -Ip $ip -Hostname $enumResult.hostname

            $results += @{
                ip = $ip; hostname = $hostname; status = "success"; file = $filepath
                apps = $report.applications.Count; duration = $enumResult.duration
            }

            if (-not $Quiet) {
                Write-Host "    [+] $($enumResult.os_detected) | $($report.applications.Count) apps | $($enumResult.duration)s | $filepath" -ForegroundColor Green
            }
        } catch {
            $results += @{ ip = $ip; hostname = $hostname; status = "error"; error = $_.Exception.Message }
            if (-not $Quiet) { Write-Host "    [-] Failed: $_" -ForegroundColor Red }
        }
        $idx++
    }

    $totalTime = ((Get-Date) - $startTime).TotalSeconds
    $successful = ($results | Where-Object { $_.status -eq "success" }).Count
    $totalApps = ($results | Where-Object { $_.status -eq "success" } | Measure-Object -Property apps -Sum).Sum

    # Write index
    if (!(Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
    $index = @{
        scan_timestamp = Get-Date -Format "o"
        network_range = $NetworkRange
        mode = $Mode
        total_devices_discovered = $devices.Count
        total_devices_scanned = $successful
        total_applications_found = $totalApps
        total_duration_seconds = [Math]::Round($totalTime, 2)
        devices = $results
    }
    $indexPath = Join-Path $OutputDir "scan_index.json"
    $index | ConvertTo-Json -Depth 4 | Out-File -FilePath $indexPath -Encoding UTF8

    if (-not $Quiet) {
        Write-Header "SCAN COMPLETE"
        Write-Host "  Devices discovered : $($devices.Count)"
        Write-Host "  Devices scanned    : $successful"
        Write-Host "  Total applications : $totalApps"
        Write-Host "  Total duration     : $([Math]::Round($totalTime, 2))s"
        Write-Host "  Output directory   : $(Resolve-Path $OutputDir)"
        Write-Host "  Scan index         : $indexPath"
        Write-Header ""
    }

    return $results
}

# Main
if ($Help) { Write-Usage; exit 0 }

if (-not $Quiet) {
    Write-Header "Flash_Network — Device Scanner & JSON Reporter"
}

$authArgs = @()
if ($Key) { $authArgs += "-i", $Key }
if ($Password) { $authArgs += "-pw", $Password }

Scan-AndPopulate `
    -NetworkRange $Range -Mode $Mode -Interface $Interface `
    -MaxDevices $MaxDevices -Port $Port -User $User `
    -AuthArgs $authArgs -Timeout $Timeout `
    -OutputDir $OutputDir -Verbose:$Verbose -Quiet:$Quiet
