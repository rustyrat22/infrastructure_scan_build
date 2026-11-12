<#
.SYNOPSIS
    Flash_Network — Mermaid Network Diagram Builder (PowerShell)
    Reads Flash_Network scan output (JSON) and builds a Markdown network
    diagram report using mermaid.js diagram syntax.

.DESCRIPTION
    The generated .md file contains:
      - Network topology flowchart (gateway -> devices, grouped by device type)
      - Protocol distribution pie chart
      - Device inventory flowchart (grouped by OS, with application counts)
      - Scan results pie chart (success vs errors)
      - Device and traffic tables

    Supported inputs (default input dir: ./output/):
      - network_scan_*.json     from network_scanner.py / network_scanner.ps1
      - device_enum_*.json      from device_enumerator.py / device_enumerator.ps1
      - {hostname}_{ip}_*.json  from device_scanner.py / device_scanner.ps1
      - scan_index.json         from device_scanner.py / device_scanner.ps1

.PARAMETER InputDir
    Input directory with scan JSON files (default: ./output/)

.PARAMETER OutputDir
    Output directory for the Markdown file (default: ./output/)

.PARAMETER Scan
    Use a specific network_scan JSON file

.PARAMETER Title
    Report title (default: Flash_Network Network Diagram)

.PARAMETER MaxDevices
    Max devices shown in diagrams (default: 40, 0 = unlimited)

.PARAMETER Verbose
    Enable verbose output

.PARAMETER Quiet
    Suppress console output. Only write Markdown file.

.PARAMETER Help
    Show usage information

.EXAMPLE
    .\network_diagram.ps1
    .\network_diagram.ps1 -Scan "output\network_scan_20260502_200000.json" -Title "Home Network"
    .\network_diagram.ps1 -MaxDevices 100 -Quiet
#>

param(
    [Alias("i")][string]$InputDir = "./output/",
    [Alias("o")][string]$OutputDir = "./output/",
    [Alias("s")][string]$Scan = "",
    [Alias("t")][string]$Title = "Flash_Network Network Diagram",
    [Alias("n")][int]$MaxDevices = 40,
    [switch]$Verbose = $false,
    [switch]$Quiet = $false,
    [Alias("h")][switch]$Help = $false
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$OutputEncoding = [System.Text.Encoding]::UTF8

function ConvertTo-MarkdownCell {
    param([object]$Value, [string]$Fallback = "N/A")
    $text = if ($null -eq $Value) { "" } else { [string]$Value }
    if ([string]::IsNullOrWhiteSpace($text)) { $text = $Fallback }
    $text = $text.Replace("`r", " ").Replace("`n", " ")
    $text = $text.Replace("|", "\|")
    $text = $text.Replace("<", "&lt;").Replace(">", "&gt;")
    $text = $text.Replace("``", "'")
    $text = [regex]::Replace($text, "\s+", " ").Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $Fallback }
    return $text
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

function Write-Usage {
    $usage = @"

Flash_Network — Mermaid Network Diagram Builder (PowerShell)
=============================================================

DESCRIPTION:
    Reads Flash_Network scan output (JSON) and builds a Markdown network
    diagram report using mermaid.js diagram syntax.

    Generated diagrams:
      - Network topology flowchart (gateway to devices, by device type)
      - Protocol distribution pie chart
      - Device inventory flowchart (by OS, with application counts)
      - Scan results pie chart (success vs errors)
      - Device and traffic tables

USAGE:
    .\network_diagram.ps1 [options]

PARAMETERS:
    -InputDir DIR       Input directory with scan JSON files (default: ./output/)
    -OutputDir DIR      Output directory for the Markdown file (default: ./output/)
    -Scan FILE          Use a specific network_scan JSON file
    -Title TITLE        Report title (default: Flash_Network Network Diagram)
    -MaxDevices NUM     Max devices shown in diagrams (default: 40, 0 = unlimited)
    -Verbose            Enable verbose output
    -Quiet              Suppress console output. Only write Markdown file.
    -Help               Show this help message

EXAMPLES:
    Build a diagram from the newest scans in .\output\:
        .\network_diagram.ps1

    Use a specific network scan and a custom title:
        .\network_diagram.ps1 -Scan "output\network_scan_20260502_200000.json" -Title "Home Network"

    Show up to 100 devices, quiet mode:
        .\network_diagram.ps1 -MaxDevices 100 -Quiet

REQUIREMENTS:
    - One or more scan JSON files in the input directory:
        network_scan_*.json, device_enum_*.json, {hostname}_{ip}_*.json
    - A Markdown viewer with mermaid.js support (GitHub, VS Code, Obsidian)

OUTPUT:
    Markdown report saved to: output/network_diagram_YYYYMMDD_HHMMSS.md
"@
    Write-Host $usage
    exit 0
}

function Format-MermaidLabel {
    param([string]$Text)
    if ($null -eq $Text) { $Text = "" }
    $Text = $Text.Replace("\", "/")
    $safe = [regex]::Replace($Text, "[^A-Za-z0-9 ._,@/+=%':-]", "")
    $safe = [regex]::Replace($safe, "\s+", " ").Trim()
    if (-not $safe) { return "unknown" }
    return $safe
}

function Format-Bytes {
    param([object]$Value)
    $num = 0.0
    if ($null -ne $Value) {
        $parsed = 0.0
        if ([double]::TryParse("$Value", [System.Globalization.NumberStyles]::Float, $null, [ref]$parsed)) {
            $num = $parsed
        }
    }
    $units = @("B", "KB", "MB", "GB", "TB")
    $u = 0
    while ($num -ge 1024 -and $u -lt 4) { $num /= 1024; $u++ }
    return ("{0:N1} {1}" -f $num, $units[$u])
}

function Get-OsCategory {
    param([string]$OsText)
    $text = "$OsText".ToLower()
    if ($text -match "windows") { return "Windows" }
    if ($text -match "darwin|macos|mac os") { return "macOS" }
    if ($text -match "linux|ubuntu|debian|centos|rhel|fedora") { return "Linux" }
    if ($text -and $text -ne "unknown") {
        if ("$OsText".Length -gt 30) { return "$OsText".Substring(0, 30) }
        return "$OsText"
    }
    return "Unknown / Other"
}

function Read-JsonFile {
    param([string]$Path)
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.Length -gt 64MB) {
            Write-Host "[WARN] Refusing to read oversized JSON file: $Path" -ForegroundColor Yellow
            return $null
        }
        return (Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        Write-Host "[WARN] Could not read ${Path}: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

function Find-LatestFile {
    param([string]$Dir, [string]$Prefix)
    if (-not (Test-Path $Dir)) { return $null }
    $files = @(Get-ChildItem -Path $Dir -Filter "$Prefix*.json" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime, Name)
    if ($files.Count -gt 0) { return $files[-1].FullName }
    return $null
}

function Load-ScanData {
    param([string]$Dir, [string]$ScanFile)

    $data = @{
        network_scan      = $null
        network_scan_file = ""
        scan_index        = $null
        device_reports    = @()
        enum_reports      = @()
    }

    if ($ScanFile) {
        if (-not (Test-Path $ScanFile)) {
            Write-Host "[ERROR] Scan file not found: $ScanFile" -ForegroundColor Red
            return $null
        }
        $report = Read-JsonFile -Path $ScanFile
        if ($null -ne $report) {
            $data.network_scan = $report
            $data.network_scan_file = $ScanFile
        }
    } else {
        $path = Find-LatestFile -Dir $Dir -Prefix "network_scan_"
        if ($path) {
            $report = Read-JsonFile -Path $path
            if ($null -ne $report -and $report.PSObject.Properties["devices"]) {
                $data.network_scan = $report
                $data.network_scan_file = $path
            }
        }
    }

    $indexPath = Join-Path $Dir "scan_index.json"
    if (Test-Path $indexPath) {
        $data.scan_index = Read-JsonFile -Path $indexPath
    }

    if (-not (Test-Path $Dir)) { return $data }

    foreach ($file in (Get-ChildItem -Path $Dir -Filter "*.json" -File | Sort-Object Name)) {
        if ($file.Name -like "network_scan_*" -or $file.Name -like "scan_index*") { continue }

        $report = Read-JsonFile -Path $file.FullName
        if ($null -eq $report) { continue }

        $hasDevice = ($report.PSObject.Properties["device"] -and $report.device -and
            $report.device.PSObject.Properties["ip_address"])
        $hasEnum = ($report.PSObject.Properties["scan_metadata"] -and $report.scan_metadata -and
            $report.scan_metadata.PSObject.Properties["target"])

        if ($hasDevice) {
            $report | Add-Member -NotePropertyName "_source_file" -NotePropertyValue $file.Name -Force
            $data.device_reports += $report
        } elseif ($hasEnum) {
            $report | Add-Member -NotePropertyName "_source_file" -NotePropertyValue $file.Name -Force
            $data.enum_reports += $report
        }
    }

    return $data
}

function Build-Inventory {
    param([hashtable]$Data)

    $inventory = @()

    foreach ($report in @($Data.device_reports)) {
        $dev = $report.device
        $apps = 0
        if ($report.PSObject.Properties["applications"] -and $report.applications) {
            $apps = @($report.applications).Count
        }
        $inventory += @{
            hostname = if ($dev.hostname) { "$($dev.hostname)" } else { "$($dev.ip_address)" }
            ip       = "$($dev.ip_address)"
            mac      = "$($dev.mac_address)"
            os       = if ($dev.os) { "$($dev.os)" } else { "Unknown" }
            apps     = $apps
            source   = "$($report._source_file)"
        }
    }

    foreach ($report in @($Data.enum_reports)) {
        $meta = $report.scan_metadata
        $apps = 0
        if ($report.PSObject.Properties["application_count"] -and $null -ne $report.application_count) {
            $apps = [int]$report.application_count
        }
        $inventory += @{
            hostname = if ($report.device_info.hostname) { "$($report.device_info.hostname)" } else { "$($meta.target)" }
            ip       = "$($meta.target)"
            mac      = ""
            os       = if ($meta.os_detected) { "$($meta.os_detected)" } else { "Unknown" }
            apps     = $apps
            source   = "$($report._source_file)"
        }
    }

    # Deduplicate by IP, keeping the entry with the most applications
    $byIp = @{}
    foreach ($item in $inventory) {
        if (-not $byIp.ContainsKey($item.ip) -or $item.apps -gt $byIp[$item.ip].apps) {
            $byIp[$item.ip] = $item
        }
    }

    return @($byIp.Values | Sort-Object { "$($_.hostname)".ToLower() })
}

function Build-TopologyDiagram {
    param([object]$NetworkScan, [int]$MaxDevices)

    $devices = @()
    if ($null -ne $NetworkScan -and $NetworkScan.PSObject.Properties["devices"]) {
        $devices = @($NetworkScan.devices)
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("flowchart TD")
    $lines.Add('    INET["Internet"]')
    $lines.Add('    GW["Gateway / Router"]')
    $lines.Add("    INET --> GW")
    $lines.Add('    NET["Local Network"]')
    $lines.Add("    GW --> NET")

    if ($devices.Count -eq 0) {
        $lines.Add('    NODEV["No devices captured"]')
        $lines.Add("    NET --> NODEV")
        return ($lines -join "`n")
    }

    $shown = $devices
    if ($MaxDevices -gt 0) { $shown = @($devices | Select-Object -First $MaxDevices) }

    $groups = @{}
    foreach ($dev in $shown) {
        $dtype = if ($dev.device_type) { "$($dev.device_type)" } else { "Unknown" }
        if (-not $groups.ContainsKey($dtype)) { $groups[$dtype] = @() }
        $groups[$dtype] += $dev
    }

    $gi = 0
    foreach ($dtype in ($groups.Keys | Sort-Object)) {
        $gi++
        $subId = "G$gi"
        $groupLabel = "$(Format-MermaidLabel $dtype) - $(@($groups[$dtype]).Count) device(s)"
        $lines.Add(('    subgraph {0}["{1}"]' -f $subId, $groupLabel))

        $di = 0
        foreach ($dev in @($groups[$dtype])) {
            $di++
            $nodeId = "${subId}D$di"

            $ips = (@($dev.ip_addresses) | Where-Object { $_ }) -join ", "
            $hostName = "$($dev.hostname)"
            if (-not $hostName) { $hostName = $ips }
            if (-not $hostName) { $hostName = "$($dev.mac_address)" }
            if (-not $hostName) { $hostName = "unknown" }

            $parts = @(Format-MermaidLabel "$hostName")
            if ($ips) { $parts += Format-MermaidLabel "$ips" }
            if ($dev.mac_address) { $parts += Format-MermaidLabel "$($dev.mac_address)" }
            if ($dev.traffic -and $dev.traffic.PSObject.Properties["total_bytes"] -and $dev.traffic.total_bytes) {
                $parts += Format-MermaidLabel "$(Format-Bytes $dev.traffic.total_bytes) traffic"
            }

            $label = $parts -join "<br/>"
            $lines.Add(('        {0}["{1}"]' -f $nodeId, $label))
            $lines.Add("        NET --> $nodeId")
        }
        $lines.Add("    end")
    }

    $hidden = $devices.Count - $shown.Count
    if ($hidden -gt 0) {
        $lines.Add('    MORE["... {0} more device(s) not shown - raise -MaxDevices"]' -f $hidden)
        $lines.Add("    NET --> MORE")
    }

    return ($lines -join "`n")
}

function Build-ProtocolPie {
    param([object]$NetworkScan, [int]$TopN = 10)

    if ($null -eq $NetworkScan -or -not $NetworkScan.PSObject.Properties["protocol_distribution"]) {
        return $null
    }

    $items = @()
    foreach ($prop in $NetworkScan.protocol_distribution.PSObject.Properties) {
        $items += [PSCustomObject]@{ proto = $prop.Name; count = [int]$prop.Value }
    }
    if ($items.Count -eq 0) { return $null }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("pie title Protocol Distribution - packets captured")
    foreach ($item in ($items | Sort-Object count -Descending | Select-Object -First $TopN)) {
        $lines.Add(('    "{0}" : {1}' -f (Format-MermaidLabel "$($item.proto)"), $item.count))
    }
    return ($lines -join "`n")
}

function Build-InventoryDiagram {
    param([array]$Inventory, [int]$MaxDevices)

    if (-not $Inventory -or $Inventory.Count -eq 0) { return $null }

    $shown = $Inventory
    if ($MaxDevices -gt 0) { $shown = @($Inventory | Select-Object -First $MaxDevices) }

    $groups = @{}
    foreach ($item in $shown) {
        $osName = Get-OsCategory "$($item.os)"
        if (-not $groups.ContainsKey($osName)) { $groups[$osName] = @() }
        $groups[$osName] += $item
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("flowchart LR")
    $lines.Add('    SCAN["Flash_Network Scan"]')

    $gi = 0
    foreach ($osName in ($groups.Keys | Sort-Object)) {
        $gi++
        $subId = "OS$gi"
        $groupLabel = "$(Format-MermaidLabel $osName) - $(@($groups[$osName]).Count) device(s)"
        $lines.Add(('    subgraph {0}["{1}"]' -f $subId, $groupLabel))

        $di = 0
        foreach ($item in @($groups[$osName])) {
            $di++
            $nodeId = "${subId}D$di"

            $parts = @(
                (Format-MermaidLabel "$($item.hostname)"),
                (Format-MermaidLabel "$($item.ip)")
            )
            if ($item.mac) { $parts += Format-MermaidLabel "$($item.mac)" }
            if ($item.apps) { $parts += Format-MermaidLabel "$($item.apps) applications" }

            $label = $parts -join "<br/>"
            $lines.Add(('        {0}["{1}"]' -f $nodeId, $label))
            $lines.Add("        SCAN --> $nodeId")
        }
        $lines.Add("    end")
    }

    $hidden = $Inventory.Count - $shown.Count
    if ($hidden -gt 0) {
        $lines.Add('    MORE["... {0} more device(s) not shown - raise -MaxDevices"]' -f $hidden)
        $lines.Add("    SCAN --> MORE")
    }

    return ($lines -join "`n")
}

function Build-ScanStatusPie {
    param([object]$ScanIndex)

    if ($null -eq $ScanIndex -or -not $ScanIndex.PSObject.Properties["devices"]) { return $null }
    $devices = @($ScanIndex.devices)
    if ($devices.Count -eq 0) { return $null }

    $ok = @($devices | Where-Object { $_.status -eq "success" }).Count
    $errors = $devices.Count - $ok

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("pie title Device Scan Results - success vs errors")
    $lines.Add(('    "Scanned OK" : {0}' -f $ok))
    $lines.Add(('    "Errors" : {0}' -f $errors))
    return ($lines -join "`n")
}

function Build-TrafficTable {
    param([object]$NetworkScan, [int]$MaxDevices)

    $devices = @()
    if ($null -ne $NetworkScan -and $NetworkScan.PSObject.Properties["devices"]) {
        $devices = @($NetworkScan.devices)
    }
    if ($devices.Count -eq 0) { return $null }

    $shown = $devices
    if ($MaxDevices -gt 0) { $shown = @($devices | Select-Object -First $MaxDevices) }

    $rows = @(
        "| # | Hostname | IP Address(es) | MAC Address | Type | Traffic |",
        "|---|----------|----------------|-------------|------|---------|"
    )
    $i = 0
    foreach ($dev in $shown) {
        $i++
        $ips = (@($dev.ip_addresses) | Where-Object { $_ }) -join ", "
        if (-not $ips) { $ips = "N/A" }
        $mac = if ($dev.mac_address) { "$($dev.mac_address)" } else { "N/A" }
        $dtype = if ($dev.device_type) { "$($dev.device_type)" } else { "Unknown" }
        $totalBytes = 0
        if ($dev.traffic -and $dev.traffic.PSObject.Properties["total_bytes"]) {
            $totalBytes = $dev.traffic.total_bytes
        }
        $rows += ("| {0} | {1} | {2} | {3} | {4} | {5} |" -f `
            $i,
            (ConvertTo-MarkdownCell -Value $dev.hostname),
            (ConvertTo-MarkdownCell -Value $ips),
            (ConvertTo-MarkdownCell -Value $mac),
            (ConvertTo-MarkdownCell -Value $dtype),
            (Format-Bytes $totalBytes))
    }
    return ($rows -join "`n")
}

function Build-InventoryTable {
    param([array]$Inventory)

    if (-not $Inventory -or $Inventory.Count -eq 0) { return $null }

    $rows = @(
        "| # | Hostname | IP Address | OS | Applications | Source File |",
        "|---|----------|------------|----|--------------|-------------|"
    )
    $i = 0
    foreach ($item in $Inventory) {
        $i++
        $os = "$($item.os)"
        if ($os.Length -gt 60) { $os = $os.Substring(0, 60) }
        $rows += ("| {0} | {1} | {2} | {3} | {4} | {5} |" -f `
            $i,
            (ConvertTo-MarkdownCell -Value $item.hostname),
            (ConvertTo-MarkdownCell -Value $item.ip),
            (ConvertTo-MarkdownCell -Value $os),
            (ConvertTo-MarkdownCell -Value $item.apps -Fallback "0"),
            (ConvertTo-MarkdownCell -Value $item.source))
    }
    return ($rows -join "`n")
}

function Build-Markdown {
    param([hashtable]$Data, [string]$ReportTitle, [int]$MaxDevices, [string]$InputDir)

    $network = $Data.network_scan
    $inventory = @(Build-Inventory -Data $Data)
    $now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")

    $md = New-Object System.Collections.Generic.List[string]
    $md.Add("# $ReportTitle")
    $md.Add("")
    $md.Add("> Generated by Flash_Network ``network_diagram.ps1`` on $now")
    $md.Add("> Input directory: ``$InputDir``")
    $md.Add("")

    # --- Overview ---------------------------------------------------------
    $md.Add("## Network Overview")
    $md.Add("")

    $devicesDetected = $inventory.Count
    if ($null -ne $network -and $network.PSObject.Properties["devices_detected"]) {
        $devicesDetected = $network.devices_detected
    }
    $md.Add("- **Devices detected:** $devicesDetected")

    if ($null -ne $network -and $network.PSObject.Properties["scan_metadata"] -and $network.scan_metadata) {
        $meta = $network.scan_metadata
        if ($meta.interface_description) {
            $md.Add("- **Capture interface:** $($meta.interface_description)")
        } elseif ($meta.interface) {
            $md.Add("- **Capture interface:** $($meta.interface)")
        }
        if ($meta.capture_duration_sec) {
            $md.Add("- **Capture duration:** $($meta.capture_duration_sec)s")
        }
    }

    if ($null -ne $network -and $network.PSObject.Properties["throughput"] -and $network.throughput) {
        $tp = $network.throughput
        $md.Add("- **Avg throughput:** $($tp.avg_mbps) Mbps / **Peak:** $($tp.peak_mbps) Mbps")
    }

    if ($inventory.Count -gt 0) {
        $totalApps = 0
        foreach ($item in $inventory) { $totalApps += [int]$item.apps }
        $md.Add("- **Devices enumerated:** $($inventory.Count) ($totalApps applications total)")
    }
    $md.Add("")

    # --- Topology ---------------------------------------------------------
    $md.Add("## Network Topology")
    $md.Add("")
    $md.Add('```mermaid')
    $md.Add((Build-TopologyDiagram -NetworkScan $network -MaxDevices $MaxDevices))
    $md.Add('```')
    $md.Add("")

    # --- Protocol distribution --------------------------------------------
    $protocolPie = Build-ProtocolPie -NetworkScan $network
    if ($protocolPie) {
        $md.Add("## Protocol Distribution")
        $md.Add("")
        $md.Add('```mermaid')
        $md.Add($protocolPie)
        $md.Add('```')
        $md.Add("")
    }

    # --- Device inventory --------------------------------------------------
    $inventoryDiagram = Build-InventoryDiagram -Inventory $inventory -MaxDevices $MaxDevices
    if ($inventoryDiagram) {
        $md.Add("## Device Inventory")
        $md.Add("")
        $md.Add("Devices enumerated via SSH (``device_scanner`` / ``device_enumerator``), grouped by detected OS.")
        $md.Add("")
        $md.Add('```mermaid')
        $md.Add($inventoryDiagram)
        $md.Add('```')
        $md.Add("")
    }

    $inventoryTable = Build-InventoryTable -Inventory $inventory
    if ($inventoryTable) {
        $md.Add("### Enumerated Devices")
        $md.Add("")
        $md.Add($inventoryTable)
        $md.Add("")
    }

    # --- Scan results ------------------------------------------------------
    $statusPie = Build-ScanStatusPie -ScanIndex $Data.scan_index
    if ($statusPie) {
        $md.Add("## Scan Results")
        $md.Add("")
        $md.Add('```mermaid')
        $md.Add($statusPie)
        $md.Add('```')
        $md.Add("")
    }

    # --- Traffic -----------------------------------------------------------
    $trafficTable = Build-TrafficTable -NetworkScan $network -MaxDevices $MaxDevices
    if ($trafficTable) {
        $md.Add("## Traffic Summary (Top Talkers)")
        $md.Add("")
        $md.Add($trafficTable)
        $md.Add("")
    }

    # --- Notes -------------------------------------------------------------
    $md.Add("## Viewing")
    $md.Add("")
    $md.Add("This file uses [mermaid.js](https://mermaid.js.org) diagrams embedded in Markdown. Render it with GitHub, GitLab, VS Code (built-in Markdown preview), Obsidian, or any mermaid-aware viewer.")
    $md.Add("")

    return @{
        markdown  = ($md -join "`n")
        inventory = $inventory
    }
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

function Save-Markdown {
    param([string]$Markdown, [string]$Dir = "./output/")

    if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir | Out-Null }
    Set-RestrictiveDirectoryAcl -Path $Dir

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "network_diagram_${timestamp}.md"
    $filepath = Join-Path $Dir $filename

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($filepath, $Markdown, $utf8NoBom)
    Set-RestrictiveFileAcl -Path $filepath

    return $filepath
}

function Print-Summary {
    param([string]$Filepath, [hashtable]$Data, [array]$Inventory)

    $network = $Data.network_scan

    Write-Header "FLASH_NETWORK — Network Diagram Summary"
    if ($Data.network_scan_file) {
        Write-Host "  Network scan : $($Data.network_scan_file)"
    }
    if ($null -ne $network) {
        Write-Host "  Devices      : $($network.devices_detected) detected in capture"
    }
    Write-Host "  Enumerated   : $($Inventory.Count) device report(s)"

    $totalApps = 0
    foreach ($item in $Inventory) { $totalApps += [int]$item.apps }
    Write-Host "  App inventory: $totalApps applications"
    Write-Section ""

    Write-Host "  Diagrams generated:"
    Write-Host "    - Network topology flowchart"
    Write-Host "    - Protocol distribution pie chart"
    Write-Host "    - Device inventory flowchart (by OS)"
    Write-Host "    - Scan results pie chart"
    Write-Host "    - Traffic and inventory tables"

    Write-Header "Markdown saved to: $Filepath"
}

# Main
if ($Help) { Write-Usage; exit 0 }

if ($args.Count -gt 0) {
    Write-Host "[ERROR] Unknown argument(s): $($args -join ' '). Use -Help for usage." -ForegroundColor Red
    exit 1
}

if ($Scan -and $InputDir -eq "./output/") {
    # Default the input dir to the scan file's directory so sibling
    # device/enum reports are picked up automatically.
    $resolved = Resolve-Path $Scan -ErrorAction SilentlyContinue
    if ($resolved) {
        $scanDir = Split-Path -Parent $resolved.Path
        if ($scanDir -and (Test-Path $scanDir)) { $InputDir = $scanDir }
    }
}

if (-not $Quiet) {
    Write-Header "Flash_Network — Mermaid Network Diagram Builder (PowerShell)"
}

$data = Load-ScanData -Dir $InputDir -ScanFile $Scan
if ($null -eq $data) { exit 1 }

if ($null -eq $data.network_scan -and $data.device_reports.Count -eq 0 -and $data.enum_reports.Count -eq 0) {
    Write-Host "[ERROR] No scan JSON files found in: $InputDir" -ForegroundColor Red
    Write-Host "        Run network_scanner.ps1, device_scanner.ps1, or device_enumerator.ps1 first," -ForegroundColor Red
    Write-Host "        or point -InputDir at a directory containing their output." -ForegroundColor Red
    exit 1
}

if ($Verbose -and -not $Quiet) {
    $scanFileDisplay = if ($data.network_scan_file) { $data.network_scan_file } else { "none found" }
    Write-Host "[INPUT] Network scan : $scanFileDisplay"
    Write-Host "[INPUT] Device reports: $($data.device_reports.Count)"
    Write-Host "[INPUT] Enum reports : $($data.enum_reports.Count)"
    Write-Host "[INPUT] Scan index   : $(if ($data.scan_index) { 'found' } else { 'none found' })"
}

$result = Build-Markdown -Data $data -ReportTitle $Title -MaxDevices $MaxDevices -InputDir $InputDir
$filepath = Save-Markdown -Markdown $result.markdown -Dir $OutputDir

if (-not $Quiet) {
    Print-Summary -Filepath $filepath -Data $data -Inventory $result.inventory
} else {
    Write-Host "Markdown diagram saved to: $filepath"
}
