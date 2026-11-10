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

.EXAMPLE
    .\network_scanner.ps1
    .\network_scanner.ps1 -Duration 30
    .\network_scanner.ps1 -Interface 3 -Duration 20
#>

param(
    [int]$Duration = 15,
    [int]$Interface = -1
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

function Test-Tshark {
    try {
        $result = & tshark --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $versionLine = $result[0]
            Write-Host "[OK] tshark found: $versionLine" -ForegroundColor Green
            return $true
        }
    } catch {
        # tshark prints version to stderr
    }

    try {
        $result = & tshark --version 2>&1 | Select-Object -First 1
        if ($result -match "TShark") {
            Write-Host "[OK] tshark found: $result" -ForegroundColor Green
            return $true
        }
    } catch {}

    Write-Host "[ERROR] tshark not found. Install Wireshark and add to PATH." -ForegroundColor Red
    return $false
}

function Get-Interfaces {
    $result = & tshark -D 2>$null
    $interfaces = @()
    foreach ($line in $result) {
        if ($line -match "^(\d+)\.\s+([^\s]+)\s+(.*)") {
            $interfaces += [PSCustomObject]@{
                Index       = [int]$Matches[1]
                Name        = $Matches[2]
                Description = $Matches[3]
            }
        }
    }
    return $interfaces
}

function Get-ActiveInterface {
    param([array]$Interfaces)
    foreach ($iface in $Interfaces) {
        if ($iface.Description -notmatch "Loopback|Pseudo" -and $iface.Name -notmatch "Loopback|NPF_") {
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

    $timestamp = [int][decimal]::Parse((Get-Date -UFormat %s))
    $pcapFile = "flash_capture_$timestamp.pcapng"

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
    Write-Host "          Saved to: $pcapFile"

    $process = Start-Process -FilePath "tshark" -ArgumentList $cmdArgs `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput "tshark_stdout.tmp"

    $packets = @()
    if (Test-Path "tshark_stdout.tmp") {
        $lines = Get-Content "tshark_stdout.tmp" -Encoding UTF8
        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $parts = $line -split '\|'
            $pkt = [ordered]@{}
            for ($i = 0; $i -lt $fields.Count; $i++) {
                $pkt[$fields[$i]] = if ($i -lt $parts.Count) { $parts[$i].Trim() } else { "" }
            }
            $packets += $pkt
        }
        Remove-Item "tshark_stdout.tmp" -Force -ErrorAction SilentlyContinue
    }

    return $pcapFile, $packets
}

function Analyze-Packets {
    param([array]$Packets)

    $devices = @{}
    $protocolCounts = @{}
    $timeline = @()
    $totalBytes = 0

    foreach ($pkt in $Packets) {
        $srcMac   = $pkt["eth.src"]
        $dstMac   = $pkt["eth.dst"]
        $srcIp    = $pkt["ip.src"]
        $dstIp    = $pkt["ip.dst"]
        $frameLen = [int]$pkt["frame.len"]
        $proto    = $pkt["_ws.col.Protocol"]
        $hostname = $pkt["dhcp.options.hostname"]
        $httpHost = $pkt["http.host"]
        $userAgent= $pkt["http.user_agent"]
        $mdnsName = $pkt["mdns.host_name"]
        $epoch    = $pkt["frame.time_epoch"]

        if ([string]::IsNullOrWhiteSpace($srcMac) -and [string]::IsNullOrWhiteSpace($srcIp)) {
            continue
        }

        $totalBytes += $frameLen

        if ($proto) {
            $protocolCounts[$proto] = ($protocolCounts[$proto] + 1)
        }

        if ($epoch) {
            $timeline += @{ time=[double]$epoch; len=$frameLen; proto=$proto }
        }

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

        if ($hostname -and [string]::IsNullOrWhiteSpace($devices[$srcMac].hostname)) {
            $devices[$srcMac].hostname = $hostname
        }
        if ($mdnsName -and [string]::IsNullOrWhiteSpace($devices[$srcMac].hostname)) {
            $devices[$srcMac].hostname = $mdnsName
        }
        if ($userAgent) {
            $devices[$srcMac].hints.Add("UA: $userAgent") | Out-Null
            $uaLower = $userAgent.ToLower()
            if ($uaLower -match "windows") { $devices[$srcMac].device_type = "Windows PC" }
            elseif ($uaLower -match "linux") { $devices[$srcMac].device_type = "Linux" }
            elseif ($uaLower -match "macintosh|darwin") { $devices[$srcMac].device_type = "macOS" }
            elseif ($uaLower -match "android") { $devices[$srcMac].device_type = "Android" }
            elseif ($uaLower -match "iphone|ipad") { $devices[$srcMac].device_type = "iOS" }
        }
    }

    return @{
        devices = $devices
        totalBytes = $totalBytes
        protocolCounts = $protocolCounts
        timeline = $timeline
    }
}

function Calculate-Throughput {
    param([array]$Timeline)

    if ($Timeline.Count -eq 0) {
        return @{ avg_bps=0; peak_bps=0; total_bytes=0; duration_sec=0 }
    }

    $sorted = $Timeline | Sort-Object { $_.time }
    $start = $sorted[0].time
    $end = $sorted[-1].time
    $duration = [Math]::Max($end - $start, 0.001)
    $totalBytes = ($sorted | Measure-Object -Property len -Sum).Sum
    $avgBps = ($totalBytes * 8) / $duration

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

    return @{
        avg_bps = [Math]::Round($avgBps, 2)
        avg_mbps = [Math]::Round($avgBps / 1000000, 4)
        peak_bps = [Math]::Round($peakBps, 2)
        peak_mbps = [Math]::Round($peakBps / 1000000, 4)
        total_bytes = $totalBytes
        duration_sec = [Math]::Round($duration, 2)
        total_packets = $sorted.Count
    }
}

function Generate-Report {
    param(
        [hashtable]$Devices,
        [hashtable]$Throughput,
        [hashtable]$ProtocolCounts,
        [PSCustomObject]$Interface,
        [int]$Duration,
        [string]$CaptureFile
    )

    $deviceList = @()
    $sortedDevices = $Devices.GetEnumerator() | Sort-Object { $_.Value.bytes_sent + $_.Value.bytes_received } -Descending

    foreach ($entry in $sortedDevices) {
        $dev = $entry.Value
        $deviceList += [PSCustomObject]@{
            mac_address = $dev.mac
            ip_addresses = @($dev.ips) | Sort-Object
            hostname = if ($dev.hostname) { $dev.hostname } else { "N/A" }
            device_type = $dev.device_type
            protocols_observed = @($dev.protocols) | Sort-Object
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
    $outputDir = "output"
    if (!(Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }

    $jsonPath = Join-Path $outputDir "network_scan_$timestamp.json"
    $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8

    return $report, $jsonPath
}

function Print-Summary {
    param([PSCustomObject]$Report, [string]$OutputPath)

    $meta = $Report.scan_metadata
    $tp = $Report.throughput

    Write-Header "FLASH_NETWORK — Wireshark Scan Summary"
    Write-Host "  Interface   : $($meta.interface_description)"
    Write-Host "  Duration    : $($meta.capture_duration_sec)s"
    Write-Host "  Timestamp   : $($meta.timestamp)"
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
        Write-Host ("    {0,-20} {1,6}  {2}" -f $entry.Name, $entry.Value, $bar)
    }

    Write-Host ""
    Write-Host "  DEVICES DETECTED: $($Report.devices_detected)" -ForegroundColor Green
    Write-Section ""

    $idx = 1
    foreach ($dev in $Report.devices) {
        Write-Host "  [$idx] $($dev.hostname)" -ForegroundColor White
        Write-Host "      MAC     : $($dev.mac_address)"
        Write-Host "      IPs     : $($dev.ip_addresses -join ', ')"
        Write-Host "      Type    : $($dev.device_type)"
        Write-Host "      Traffic : $($dev.traffic.total_bytes) bytes ($($dev.traffic.packets_sent)↑ / $($dev.traffic.packets_received)↓)"
        if ($dev.protocols_observed.Count -gt 0) {
            $protoStr = ($dev.protocols_observed | Select-Object -First 8) -join ", "
            Write-Host "      Protocols: $protoStr"
        }
        foreach ($h in ($dev.hints | Select-Object -First 3)) {
            Write-Host "      Hint    : $h"
        }
        Write-Host ""
        $idx++
    }

    Write-Header "Full report saved to: $OutputPath"
}

# Main
Write-Header "Flash_Network — Wireshark Network Scanner (PowerShell)"

if (-not (Test-Tshark)) { exit 1 }

$interfaces = Get-Interfaces
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
} else {
    $selected = Get-ActiveInterface -Interfaces $interfaces
}

if (-not $selected) {
    Write-Host "[ERROR] No suitable interface found." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Selected: [$($selected.Index)] $($selected.Description)" -ForegroundColor Green

$captureFile, $packets = Capture-Traffic -Interface $selected -Duration $Duration

if ($packets.Count -eq 0) {
    Write-Host "[WARN] No packets captured. Run as Administrator or check interface." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "[ANALYSIS] Processing $($packets.Count) packets..." -ForegroundColor Magenta

$analysis = Analyze-Packets -Packets $packets
$throughput = Calculate-Throughput -Timeline $analysis.timeline

$report, $outputPath = Generate-Report `
    -Devices $analysis.devices `
    -Throughput $throughput `
    -ProtocolCounts $analysis.protocolCounts `
    -Interface $selected `
    -Duration $Duration `
    -CaptureFile $captureFile

Print-Summary -Report $report -OutputPath $outputPath
