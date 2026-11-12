#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Flash_Network — Wireshark Network Scanner (PowerShell)
    Uses tshark to capture and analyze local network traffic.

.DESCRIPTION
    Captures network traffic via tshark CLI, extracts active IPs, MAC addresses,
    device types, protocols, and throughput statistics.

.PARAMETER Duration
    Capture duration in seconds (default: 15)

.PARAMETER Interface
    Network interface index (default: auto-detect first non-loopback)

.PARAMETER OutputDir
    Output directory for the JSON report (default: output)

.PARAMETER KeepPcap
    Keep the temporary capture file. By default it is created in the system
    temp directory with owner-only permissions and deleted after analysis.

.EXAMPLE
    .\network_scanner.ps1
    .\network_scanner.ps1 -Duration 30
    .\network_scanner.ps1 -Interface 3 -Duration 20
#>

param(
    [int]$Duration = 15,
    [int]$Interface = -1,
    [string]$OutputDir = "output",
    [switch]$KeepPcap = $false
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$OutputEncoding = [System.Text.Encoding]::UTF8

$script:TsharkPath = $null
$script:MaxToolOutputBytes = 8 * 1024 * 1024
$script:MaxCaptureOutputBytes = 48 * 1024 * 1024
$script:MaxCapturePackets = 200000

function Resolve-TrustedTool {
    # Resolve a native tool to an absolute path, ignoring relative PATH entries
    # and anything inside the current directory. This blocks PATH hijacking by
    # a plink.exe/tshark.exe dropped into the scan directory.
    param([string]$Name, [string[]]$FallbackDirs = @())
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }

    $cwdFull = [System.IO.Path]::GetFullPath((Get-Location).Path)
    $cwd = $cwdFull.TrimEnd([char[]]@('\', '/'))
    # Running from a drive/share root must not make every absolute path look
    # "inside the working directory", which would reject all tools on it.
    $cwdIsRoot = ($cwd -eq [System.IO.Path]::GetPathRoot($cwdFull).TrimEnd([char[]]@('\', '/')))
    $extensions = @("")
    if ($env:OS -eq "Windows_NT" -and -not [System.IO.Path]::HasExtension($Name)) {
        $extensions = @(".exe", ".cmd", ".bat", "")
    }

    $directories = @()
    foreach ($entry in ($env:PATH -split [System.IO.Path]::PathSeparator)) {
        $candidateDir = $entry.Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($candidateDir)) { continue }
        if (-not [System.IO.Path]::IsPathRooted($candidateDir)) { continue }
        $directories += $candidateDir
    }
    if ($env:OS -eq "Windows_NT" -and $env:SystemRoot) {
        $directories += [System.IO.Path]::Combine($env:SystemRoot, "System32")
    }
    $directories += $FallbackDirs

    foreach ($directory in $directories) {
        if ([string]::IsNullOrWhiteSpace($directory)) { continue }
        foreach ($extension in $extensions) {
            $candidate = [System.IO.Path]::Combine($directory, $Name + $extension)
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
            $full = [System.IO.Path]::GetFullPath($candidate)
            if (-not $cwdIsRoot -and ($full -eq $cwd -or $full.StartsWith($cwd + [System.IO.Path]::DirectorySeparatorChar,
                    [System.StringComparison]::OrdinalIgnoreCase))) { continue }
            return $full
        }
    }
    return $null
}

function Clear-UnsafeText {
    # Remove ANSI escapes, control characters, and bidi overrides from text that
    # originated on the network or in remote command output.
    param([string]$Value, [int]$MaxLength = 200)
    if ($null -eq $Value) { return "" }
    $text = [regex]::Replace([string]$Value, "\x1B\[[0-?]*[ -/]*[@-~]", "")
    $text = [regex]::Replace($text, "\x1B\][^\x07]*(?:\x07|\x1B\\)", "")
    $text = [regex]::Replace($text, "\x1B[@-_]", "")
    $text = [regex]::Replace($text, "[\u202A-\u202E\u2066-\u2069]", "")
    $text = [regex]::Replace($text, "[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "")
    $text = $text -replace "`r|`n", " "
    if ($MaxLength -gt 0 -and $text.Length -gt $MaxLength) {
        $text = $text.Substring(0, $MaxLength)
    }
    return $text
}

function Stop-ProcessTree {
    param([System.Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    try {
        if ($Process.HasExited) { return }
        if ($env:OS -eq "Windows_NT") {
            $taskkill = $null
            if ($env:SystemRoot) {
                $candidate = [System.IO.Path]::Combine($env:SystemRoot, "System32", "taskkill.exe")
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { $taskkill = $candidate }
            }
            if ($taskkill) {
                & $taskkill /F /T /PID $Process.Id 2>$null | Out-Null
            } else {
                & taskkill /F /T /PID $Process.Id 2>$null | Out-Null
            }
        } else {
            & kill -KILL $Process.Id 2>$null
        }
    } catch { }
    try {
        if (-not $Process.HasExited) { $Process.Kill() }
    } catch { }
}

function New-SecureTempFile {
    param([string]$Extension = ".tmp")
    $path = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(),
        "flashnet_" + [guid]::NewGuid().ToString("N") + $Extension)
    $stream = [System.IO.File]::Create($path)
    $stream.Close()
    Set-RestrictiveFileAcl -Path $path
    return $path
}

function Read-BoundedTextFile {
    # Read at most MaxBytes from a file. Never let a remote command decide how
    # much memory the scanner allocates.
    param([string]$Path, [int]$MaxBytes = 8388608)
    if (-not (Test-Path -LiteralPath $Path)) { return "" }
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $length = [int][Math]::Min($stream.Length, [long]$MaxBytes)
            if ($length -le 0) { return "" }
            $buffer = New-Object byte[] $length
            $read = 0
            while ($read -lt $length) {
                $count = $stream.Read($buffer, $read, $length - $read)
                if ($count -le 0) { break }
                $read += $count
            }
            return [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
        } finally {
            $stream.Dispose()
        }
    } catch {
        return ""
    }
}

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

function ConvertTo-ProcessArgument {
    # Quote one argument using the Windows CommandLineToArgvW rules. Start-Process
    # joins ArgumentList with spaces and lets the child re-parse it.
    param([string]$Value)
    if ($null -eq $Value -or $Value -eq "") { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '\') { $backslashes++; continue }
        if ($ch -eq '"') {
            [void]$builder.Append('\' * (($backslashes * 2) + 1))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append('\' * $backslashes)
            $backslashes = 0
        }
        [void]$builder.Append($ch)
    }
    if ($backslashes -gt 0) { [void]$builder.Append('\' * ($backslashes * 2)) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Join-ProcessArguments {
    param([string[]]$Arguments)
    $quoted = foreach ($arg in $Arguments) { ConvertTo-ProcessArgument -Value $arg }
    return ($quoted -join ' ')
}

function Invoke-ProcessWithTimeout {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [int]$TimeoutSeconds,
        [string]$StdOutPath = "",
        [string]$StdErrPath = "",
        [int]$MaxOutputBytes = 8388608
    )

    $startParams = @{
        FilePath     = $FilePath
        ArgumentList = (Join-ProcessArguments -Arguments $Arguments)
        NoNewWindow  = $true
        PassThru     = $true
    }
    if ($StdOutPath) { $startParams.RedirectStandardOutput = $StdOutPath }
    if ($StdErrPath) { $startParams.RedirectStandardError = $StdErrPath }

    $process = Start-Process @startParams
    $timedOut = $false
    $overflow = $false

    try {
        $deadline = $null
        if ($TimeoutSeconds -gt 0) { $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds) }

        while (-not $process.HasExited) {
            if ($MaxOutputBytes -gt 0) {
                $total = 0
                foreach ($path in @($StdOutPath, $StdErrPath)) {
                    if ($path -and (Test-Path -LiteralPath $path)) {
                        try { $total += (Get-Item -LiteralPath $path -ErrorAction Stop).Length } catch { }
                    }
                }
                if ($total -gt $MaxOutputBytes) {
                    $overflow = $true
                    Stop-ProcessTree -Process $process
                    break
                }
            }
            if ($null -ne $deadline -and [DateTime]::UtcNow -ge $deadline) {
                $timedOut = $true
                Stop-ProcessTree -Process $process
                break
            }
            try {
                if ($process.WaitForExit(200)) { break }
            } catch {
                break
            }
        }

        if (-not $process.HasExited) {
            Stop-ProcessTree -Process $process
            try { [void]$process.WaitForExit(2000) } catch { }
        }
    } catch {
        Stop-ProcessTree -Process $process
        throw
    }

    $exitCode = if ($timedOut -or $overflow) { -1 } else { $process.ExitCode }
    return @{ Process = $process; TimedOut = $timedOut; Truncated = $overflow; ExitCode = $exitCode }
}

function Set-RestrictiveFileAcl {
    param([string]$Path)
    if ($env:OS -eq "Windows_NT") {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    } else {
        & chmod 600 $Path
        if ($LASTEXITCODE -ne 0) { throw "chmod 600 failed for $Path" }
    }
}

function Set-RestrictiveDirectoryAcl {
    param([string]$Path)
    if ($env:OS -eq "Windows_NT") {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    } else {
        & chmod 700 $Path
        if ($LASTEXITCODE -ne 0) { throw "chmod 700 failed for $Path" }
    }
}

function New-TemporaryCaptureFile {
    return New-SecureTempFile -Extension ".pcapng"
}

function Test-Tshark {
    if (-not $script:TsharkPath) {
        Write-Host "[ERROR] tshark not found in a trusted absolute PATH directory." -ForegroundColor Red
        return $false
    }
    try {
        $result = & $script:TsharkPath --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $result) {
            $versionLine = Clear-UnsafeText -Value ([string]$result[0]) -MaxLength 200
            Write-Host "[OK] tshark found: $versionLine" -ForegroundColor Green
            return $true
        }
    } catch { }

    try {
        $result = & $script:TsharkPath --version 2>&1 | Select-Object -First 1
        if ($result -match "TShark") {
            Write-Host "[OK] tshark found: $(Clear-UnsafeText -Value ([string]$result) -MaxLength 200)" -ForegroundColor Green
            return $true
        }
    } catch {}

    Write-Host "[ERROR] tshark could not be executed." -ForegroundColor Red
    return $false
}

function Get-Interfaces {
    if (-not $script:TsharkPath) { return @() }
    $result = & $script:TsharkPath -D 2>$null
    $interfaces = @()
    foreach ($line in $result) {
        if ($line -match "^(\d+)\.\s+([^\s]+)\s+(.*)") {
            $interfaces += [PSCustomObject]@{
                Index       = [int]$Matches[1]
                Name        = Clear-UnsafeText -Value $Matches[2] -MaxLength 128
                Description = Clear-UnsafeText -Value $Matches[3] -MaxLength 256
            }
        }
    }
    return $interfaces
}

function Get-ActiveInterface {
    param([array]$Interfaces)
    foreach ($iface in $Interfaces) {
        # Real tshark adapters are named \Device\NPF_{GUID}; only loopback and
        # pseudo devices should be skipped.
        if ($iface.Description -notmatch "Loopback|Pseudo" -and $iface.Name -notmatch "Loopback") {
            return $iface
        }
    }
    return $Interfaces[0]
}

function Capture-Traffic {
    param(
        [PSCustomObject]$Interface,
        [int]$Duration
    )

    $pcapFile = New-TemporaryCaptureFile

    $fields = @(
        "frame.time_epoch", "frame.number", "eth.src", "eth.dst",
        "ip.src", "ip.dst", "frame.len", "frame.protocols",
        "_ws.col.Protocol", "dhcp.options.hostname",
        "http.host", "http.user_agent", "mdns.host_name"
    )

    $cmdArgs = @(
        "-i", $Interface.Index.ToString()
        "-a", "duration:$Duration"
        "-w", $pcapFile
        "-T", "fields"
        "-E", "separator=|"
    )
    foreach ($f in $fields) {
        $cmdArgs += "-e", $f
    }

    Write-Host ""
    Write-Host "[CAPTURE] Capturing ${Duration}s on interface $($Interface.Name) ($($Interface.Description))..." -ForegroundColor Magenta
    Write-Host "          Temporary capture: $pcapFile"

    $tmpOut = New-SecureTempFile -Extension ".tshark"
    $packets = New-Object System.Collections.Generic.List[object]
    try {
        if (-not $script:TsharkPath) {
            Write-Host "[ERROR] tshark is not available." -ForegroundColor Red
            return $pcapFile, $packets.ToArray()
        }
        $run = Invoke-ProcessWithTimeout -FilePath $script:TsharkPath -Arguments $cmdArgs `
            -TimeoutSeconds ($Duration + 60) -StdOutPath $tmpOut `
            -MaxOutputBytes $script:MaxCaptureOutputBytes
        if ($run.TimedOut) {
            Write-Host "[WARN] tshark capture timed out after $($Duration + 60)s; analyzing partial output." -ForegroundColor Yellow
        }
        if ($run.Truncated) {
            Write-Host "[WARN] tshark output exceeded the capture cap; analysis may be incomplete." -ForegroundColor Yellow
        }

        $text = Read-BoundedTextFile -Path $tmpOut -MaxBytes $script:MaxCaptureOutputBytes
        if ($text) {
            foreach ($line in ($text -split "`n")) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                if ($packets.Count -ge $script:MaxCapturePackets) {
                    Write-Host "[WARN] Capture exceeded $($script:MaxCapturePackets) packets; analysis truncated." -ForegroundColor Yellow
                    break
                }
                $parts = $line -split '\|'
                $pkt = [ordered]@{}
                for ($i = 0; $i -lt $fields.Count; $i++) {
                    $value = if ($i -lt $parts.Count) { $parts[$i].Trim() } else { "" }
                    $pkt[$fields[$i]] = Clear-UnsafeText -Value $value -MaxLength 256
                }
                $packets.Add($pkt)
            }
        }
    } finally {
        Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue
    }

    return $pcapFile, $packets.ToArray()
}

function Analyze-Packets {
    param([array]$Packets)

    $devices = @{}
    $protocolCounts = @{}
    $timeline = New-Object System.Collections.Generic.List[object]
    $totalBytes = 0
    $timelineStride = [Math]::Max(1, [int]($Packets.Count / 20000))
    $packetIndex = 0

    foreach ($pkt in $Packets) {
        $srcMac   = $pkt["eth.src"]
        $dstMac   = $pkt["eth.dst"]
        $srcIp    = $pkt["ip.src"]
        $dstIp    = $pkt["ip.dst"]
        $proto    = $pkt["_ws.col.Protocol"]
        $hostname = $pkt["dhcp.options.hostname"]
        $httpHost = $pkt["http.host"]
        $userAgent= $pkt["http.user_agent"]
        $mdnsName = $pkt["mdns.host_name"]
        $epoch    = $pkt["frame.time_epoch"]

        $frameLen = 0
        [void][int]::TryParse([string]$pkt["frame.len"], [ref]$frameLen)

        if ([string]::IsNullOrWhiteSpace($srcMac) -and [string]::IsNullOrWhiteSpace($srcIp)) {
            $packetIndex++
            continue
        }

        $totalBytes += $frameLen

        if ($proto) {
            if ($protocolCounts.ContainsKey($proto)) { $protocolCounts[$proto]++ }
            else { $protocolCounts[$proto] = 1 }
        }

        $epochValue = 0.0
        $epochOk = [double]::TryParse(
            [string]$epoch,
            [System.Globalization.NumberStyles]::Float,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$epochValue)
        if ($epochOk -and $epochValue -gt 0 -and ($packetIndex % $timelineStride) -eq 0) {
            $timeline.Add(@{ time = $epochValue; len = $frameLen; proto = $proto })
        }
        $packetIndex++

        foreach ($entry in @(
            @{ mac=$srcMac; ip=$srcIp; dir="sent" },
            @{ mac=$dstMac; ip=$dstIp; dir="received" }
        )) {
            $mac = $entry.mac
            if ([string]::IsNullOrWhiteSpace($mac)) { continue }
            if ($mac -in @("ff:ff:ff:ff:ff:ff","00:00:00:00:00:00")) { continue }

            if (-not $devices.ContainsKey($mac)) {
                $devices[$mac] = @{
                    mac       = $mac
                    ips       = [System.Collections.Generic.HashSet[string]]::new()
                    protocols = [System.Collections.Generic.HashSet[string]]::new()
                    bytes_sent = 0
                    bytes_received = 0
                    pkts_sent = 0
                    pkts_received = 0
                    hostname  = ""
                    device_type = "Unknown"
                    hints     = [System.Collections.Generic.List[string]]::new()
                }
            }

            $dev = $devices[$mac]
            if ($entry.ip) { $dev.ips.Add($entry.ip) | Out-Null }
            $dev["bytes_$($entry.dir)"] += $frameLen
            $dev["pkts_$($entry.dir)"]++

            $protoParts = $pkt["frame.protocols"] -split ':'
            foreach ($p in $protoParts) {
                $p = $p.Trim()
                if ($p -and $p -notin @("eth","ethertype","ip","ipv6","frame")) {
                    $dev.protocols.Add($p) | Out-Null
                }
            }
        }

        # Hints belong to the source MAC only. Guard the key check so an empty
        # or destination-only MAC cannot throw or create a phantom device.
        if ([string]::IsNullOrWhiteSpace($srcMac) -or -not $devices.ContainsKey($srcMac)) {
            continue
        }
        $srcDev = $devices[$srcMac]

        if ($hostname -and [string]::IsNullOrWhiteSpace($srcDev.hostname)) {
            $srcDev.hostname = $hostname
        }
        if ($mdnsName -and [string]::IsNullOrWhiteSpace($srcDev.hostname)) {
            $srcDev.hostname = $mdnsName
        }
        if ($userAgent) {
            $srcDev.hints.Add("UA: $userAgent") | Out-Null
            $uaLower = $userAgent.ToLower()
            # Mobile first: Android UAs contain "Linux", iOS UAs contain "Macintosh".
            if ($uaLower -match "android") { $srcDev.device_type = "Android" }
            elseif ($uaLower -match "iphone|ipad") { $srcDev.device_type = "iOS" }
            elseif ($uaLower -match "windows") { $srcDev.device_type = "Windows PC" }
            elseif ($uaLower -match "macintosh|darwin") { $srcDev.device_type = "macOS" }
            elseif ($uaLower -match "linux") { $srcDev.device_type = "Linux" }
        }
        if ($httpHost) {
            $srcDev.hints.Add("HTTP Host: $httpHost") | Out-Null
        }
    }

    return @{
        devices = $devices
        totalBytes = $totalBytes
        protocolCounts = $protocolCounts
        timeline = $timeline.ToArray()
    }
}

function Calculate-Throughput {
    param([array]$Timeline, [long]$TotalBytes = -1, [int]$TotalPackets = -1)

    if (-not $Timeline -or $Timeline.Count -eq 0) {
        return @{ avg_bps=0; peak_bps=0; total_bytes=0; duration_sec=0 }
    }

    $sorted = @($Timeline | Sort-Object { $_.time })
    $start = [double]$sorted[0].time
    $end = [double]$sorted[$sorted.Count - 1].time
    $duration = [Math]::Max($end - $start, [double]0.001)
    if ($TotalBytes -lt 0) {
        $TotalBytes = ($sorted | Measure-Object -Property len -Sum).Sum
    }
    $avgBps = ($TotalBytes * 8) / $duration

    $windows = @{}
    foreach ($p in $sorted) {
        $w = [int](($p.time - $start) / 1.0)
        if (-not $windows.ContainsKey($w)) { $windows[$w] = 0 }
        $windows[$w] += $p.len
    }

    $peakBytes = 0
    if ($windows.Count -gt 0) {
        $peakBytes = ($windows.Values | Measure-Object -Maximum).Maximum
    }
    $peakBps = ($peakBytes * 8) / 1.0

    $packetCount = if ($TotalPackets -ge 0) { $TotalPackets } else { $sorted.Count }

    return @{
        avg_bps = [Math]::Round($avgBps, 2)
        avg_mbps = [Math]::Round($avgBps / 1000000, 4)
        peak_bps = [Math]::Round($peakBps, 2)
        peak_mbps = [Math]::Round($peakBps / 1000000, 4)
        total_bytes = $TotalBytes
        duration_sec = [Math]::Round($duration, 2)
        total_packets = $packetCount
        timeline_sampled = ($packetCount -gt $sorted.Count)
    }
}

function Generate-Report {
    param(
        [hashtable]$Devices,
        [hashtable]$Throughput,
        [hashtable]$ProtocolCounts,
        [PSCustomObject]$Interface,
        [int]$Duration,
        [string]$CaptureFile,
        [string]$OutputDir = "output"
    )

    $deviceList = @()
    $sortedDevices = $Devices.GetEnumerator() | Sort-Object { $_.Value.bytes_sent + $_.Value.bytes_received } -Descending

    foreach ($entry in $sortedDevices) {
        $dev = $entry.Value
        $deviceList += [PSCustomObject]@{
            mac_address = $dev.mac
            ip_addresses = @($dev.ips | Sort-Object)
            hostname = if ($dev.hostname) { $dev.hostname } else { "N/A" }
            device_type = $dev.device_type
            protocols_observed = @($dev.protocols | Sort-Object)
            traffic = [PSCustomObject]@{
                bytes_sent = $dev.bytes_sent
                bytes_received = $dev.bytes_received
                total_bytes = $dev.bytes_sent + $dev.bytes_received
                packets_sent = $dev.pkts_sent
                packets_received = $dev.pkts_received
            }
            hints = $dev.hints | Select-Object -First 10
        }
    }

    $report = [PSCustomObject]@{
        scan_metadata = [PSCustomObject]@{
            timestamp = (Get-Date -Format "o")
            interface = $Interface.Name
            interface_description = $Interface.Description
            capture_duration_sec = $Duration
            capture_file = $CaptureFile
        }
        throughput = $Throughput
        protocol_distribution = $ProtocolCounts
        devices_detected = $deviceList.Count
        devices = $deviceList
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    if (!(Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }
    Set-RestrictiveDirectoryAcl -Path $OutputDir

    $jsonPath = Join-Path $OutputDir "network_scan_$timestamp.json"
    $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
    Set-RestrictiveFileAcl -Path $jsonPath

    return $report, $jsonPath
}

function Print-Summary {
    param([PSCustomObject]$Report, [string]$OutputPath)

    $meta = $Report.scan_metadata
    $tp = $Report.throughput

    Write-Header "FLASH_NETWORK — Wireshark Scan Summary"
    Write-Host "  Interface   : $(Clear-UnsafeText -Value $meta.interface_description -MaxLength 256)"
    Write-Host "  Duration    : $($meta.capture_duration_sec)s"
    Write-Host "  Timestamp   : $(Clear-UnsafeText -Value $meta.timestamp -MaxLength 64)"
    Write-Section ""

    Write-Host "  THROUGHPUT:" -ForegroundColor Green
    Write-Host ("    Avg  : {0:N4} Mbps ({1:N0} bps)" -f $tp.avg_mbps, $tp.avg_bps)
    Write-Host ("    Peak : {0:N4} Mbps ({1:N0} bps)" -f $tp.peak_mbps, $tp.peak_bps)
    Write-Host ("    Total: {0:N0} bytes over {1}s" -f $tp.total_bytes, $tp.duration_sec)
    Write-Host ("    Packets: {0:N0}" -f $tp.total_packets)

    Write-Section "PROTOCOL DISTRIBUTION (Top 15)"
    $sortedProtos = $Report.protocol_distribution.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15
    foreach ($entry in $sortedProtos) {
        $bar = "#" * [Math]::Min($entry.Value, 50)
        Write-Host ("    {0,-20} {1,6}  {2}" -f (Clear-UnsafeText -Value $entry.Name -MaxLength 64), $entry.Value, $bar)
    }

    Write-Host ""
    Write-Host "  DEVICES DETECTED: $($Report.devices_detected)" -ForegroundColor Green
    Write-Section ""

    $idx = 1
    foreach ($dev in $Report.devices) {
        Write-Host "  [$idx] $(Clear-UnsafeText -Value $dev.hostname -MaxLength 128)" -ForegroundColor White
        Write-Host "      MAC     : $(Clear-UnsafeText -Value $dev.mac_address -MaxLength 64)"
        $ipText = @($dev.ip_addresses | ForEach-Object { Clear-UnsafeText -Value $_ -MaxLength 64 }) -join ', '
        Write-Host "      IPs     : $ipText"
        Write-Host "      Type    : $(Clear-UnsafeText -Value $dev.device_type -MaxLength 64)"
        Write-Host "      Traffic : $($dev.traffic.total_bytes) bytes ($($dev.traffic.packets_sent)↑ / $($dev.traffic.packets_received)↓)"
        if ($dev.protocols_observed.Count -gt 0) {
            $protoStr = (@($dev.protocols_observed | Select-Object -First 8 |
                ForEach-Object { Clear-UnsafeText -Value $_ -MaxLength 64 })) -join ", "
            Write-Host "      Protocols: $protoStr"
        }
        foreach ($h in ($dev.hints | Select-Object -First 3)) {
            Write-Host "      Hint    : $(Clear-UnsafeText -Value $h -MaxLength 220)"
        }
        Write-Host ""
        $idx++
    }

    Write-Header "Full report saved to: $OutputPath"
}

# Main
Write-Header "Flash_Network — Wireshark Network Scanner (PowerShell)"

if ($args.Count -gt 0) {
    Write-Host "[ERROR] Unknown argument(s): $($args -join ' ')." -ForegroundColor Red
    exit 1
}

if ($Duration -lt 1 -or $Duration -gt 3600) {
    Write-Host "[ERROR] -Duration must be between 1 and 3600 seconds." -ForegroundColor Red
    exit 1
}

$script:TsharkPath = Resolve-TrustedTool -Name "tshark"
if (-not (Test-Tshark)) { exit 1 }

$interfaces = @(Get-Interfaces)
if ($interfaces.Count -eq 0) {
    Write-Host "[ERROR] No network interfaces found." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Available interfaces:"
foreach ($iface in $interfaces) {
    Write-Host "    [$($iface.Index)] $($iface.Name) — $($iface.Description)"
}

if ($Interface -ge 0) {
    $selected = $interfaces | Where-Object { $_.Index -eq $Interface } | Select-Object -First 1
    if (-not $selected) {
        Write-Host "[ERROR] Interface index $Interface not found." -ForegroundColor Red
        exit 1
    }
} else {
    $selected = Get-ActiveInterface -Interfaces $interfaces
}

if (-not $selected) {
    Write-Host "[ERROR] No suitable interface found." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Selected: [$($selected.Index)] $($selected.Description)" -ForegroundColor Green

$captureFile, $packetOutput = Capture-Traffic -Interface $selected -Duration $Duration
# The pipeline unrolls a single packet to a scalar and emits nothing for an
# empty capture; normalise both cases to an array.
$packets = @()
if ($null -ne $packetOutput) { $packets = @($packetOutput) }

try {
    if ($packets.Count -eq 0) {
        Write-Host "[WARN] No packets captured. Run as Administrator or check interface." -ForegroundColor Yellow
    } else {
        Write-Host ""
        Write-Host "[ANALYSIS] Processing $($packets.Count) packets..." -ForegroundColor Magenta

        $analysis = Analyze-Packets -Packets $packets
        $throughput = Calculate-Throughput -Timeline $analysis.timeline `
            -TotalBytes $analysis.totalBytes -TotalPackets $packets.Count

        $retained = if ($KeepPcap) { $captureFile } else { "(not retained)" }
        $report, $outputPath = Generate-Report `
            -Devices $analysis.devices `
            -Throughput $throughput `
            -ProtocolCounts $analysis.protocolCounts `
            -Interface $selected `
            -Duration $Duration `
            -CaptureFile $retained `
            -OutputDir $OutputDir

        Print-Summary -Report $report -OutputPath $outputPath
    }
} finally {
    if (-not $KeepPcap -and $captureFile -and (Test-Path -LiteralPath $captureFile)) {
        Remove-Item -LiteralPath $captureFile -Force -ErrorAction SilentlyContinue
    }
}
