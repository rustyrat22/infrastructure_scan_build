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

.PARAMETER PasswordFile
    Read the SSH password from the first line of this file.

.PARAMETER AskPassword
    Prompt for the SSH password. The password is passed to plink via a
    private temp file (-pwfile) and never appears in the process list.

.PARAMETER HostKey
    Pin the server host key fingerprint (e.g. SHA256:...). Required unless
    -InsecureHostKey is specified.

.PARAMETER InsecureHostKey
    Accept any server host key. UNSAFE: enables man-in-the-middle attacks.

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
    .\device_scanner.ps1 -Range "10.0.0.0/24" -User admin -AskPassword -HostKey "SHA256:abc123"
#>

param(
    [Alias("r")][string]$Range = "",
    [Alias("m")][ValidateSet("ping","arp","tshark","all")][string]$Mode = "all",
    [Alias("i")][int]$Interface = -1,
    [Alias("n")][int]$MaxDevices = 0,
    [Alias("p")][int]$Port = 22,
    [Alias("u")][string]$User = "root",
    [Alias("k")][string]$Key = "",
    [string]$PasswordFile = "",
    [switch]$AskPassword = $false,
    [string]$HostKey = "",
    [switch]$InsecureHostKey = $false,
    [Alias("o")][string]$OutputDir = "./output/",
    [Alias("t")][int]$Timeout = 30,
    [switch]$Verbose = $false,
    [switch]$Quiet = $false,
    [Alias("h")][switch]$Help = $false
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$OutputEncoding = [System.Text.Encoding]::UTF8

$script:PlinkPath = $null
$script:TsharkPath = $null
$script:MaxToolOutputBytes = 8 * 1024 * 1024

function Resolve-TrustedTool {
    # Resolve a native tool to an absolute path, ignoring relative PATH entries
    # and anything inside the current directory. This blocks PATH hijacking.
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

function Test-ValidTarget {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value.StartsWith("-")) { return $false }
    if ($Value.Length -gt 253) { return $false }
    if ($Value -match '[\s\x00-\x1F\x7F]') { return $false }
    return $true
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
    -PasswordFile FILE Read SSH password from the first line of FILE
    -AskPassword       Prompt for the SSH password (never echoed)
    -HostKey FP        Pin the server host key (required for verification)
    -InsecureHostKey   Accept any server key (UNSAFE: MITM risk)
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

function ConvertTo-SafeFileName {
    param([string]$Value, [string]$Fallback = "unknown")
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Fallback }
    $safe = [regex]::Replace($Value, '[^A-Za-z0-9._-]+', '_').Trim([char[]]@('.', '_', '-'))
    if ([string]::IsNullOrWhiteSpace($safe) -or $safe -eq '.' -or $safe -eq '..') { return $Fallback }
    if ($safe.Length -gt 64) { $safe = $safe.Substring(0, 64) }
    $reserved = @('CON','PRN','AUX','NUL')
    $reserved += 1..9 | ForEach-Object { "COM$_" }
    $reserved += 1..9 | ForEach-Object { "LPT$_" }
    if ($reserved -contains $safe.Split('.')[0].ToUpperInvariant()) { $safe = "_$safe" }
    return $safe
}

function Assert-NoReparsePoints {
    # Reject writes that traverse a junction/symlink. GetFullPath does not
    # resolve reparse points, so containment must be checked explicitly.
    param([string]$Base, [string]$Target)
    $baseFull = [System.IO.Path]::GetFullPath($Base).TrimEnd([char[]]@('\', '/'))
    $current = [System.IO.Path]::GetFullPath($Target)
    $root = [System.IO.Path]::GetPathRoot($baseFull)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Refusing to write through a reparse point: $current"
            }
        }
        if ($current -eq $baseFull -or $current -eq $root) { break }
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
}

function Join-SafeOutputPath {
    param([string]$OutputDir, [string]$FileName)
    $base = [System.IO.Path]::GetFullPath($OutputDir).TrimEnd([char[]]@('\', '/'))
    $full = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($base, $FileName))
    $prefix = $base + [System.IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to write outside output directory: $full"
    }
    Assert-NoReparsePoints -Base $base -Target $full
    return $full
}

function Test-IPInRange {
    param([string]$IP, [string]$NetworkRange)
    try {
        $parts = $NetworkRange.Split('/')
        if ($parts.Count -ne 2) { return $false }
        $network = [System.Net.IPAddress]::Parse($parts[0])
        $prefix = [int]$parts[1]
        if ($prefix -lt 0 -or $prefix -gt 32) { return $false }
        $address = [System.Net.IPAddress]::Parse($IP)
        if ($address.AddressFamily -ne $network.AddressFamily) { return $false }
        $netBytes = $network.GetAddressBytes()
        $ipBytes = $address.GetAddressBytes()
        $fullBytes = [int][Math]::Floor($prefix / 8)
        for ($i = 0; $i -lt $fullBytes; $i++) {
            if ($netBytes[$i] -ne $ipBytes[$i]) { return $false }
        }
        $remaining = $prefix % 8
        if ($remaining -gt 0) {
            $mask = [byte]((0xFF -shl (8 - $remaining)) -band 0xFF)
            if (($netBytes[$fullBytes] -band $mask) -ne ($ipBytes[$fullBytes] -band $mask)) { return $false }
        }
        return $true
    } catch { return $false }
}

function New-PasswordFile {
    param([string]$Password)
    $path = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(),
        "flashnet_pw_" + [guid]::NewGuid().ToString("N") + ".txt")
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, $Password, $utf8)
    Set-RestrictiveFileAcl -Path $path
    return $path
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

function Remove-PasswordFile {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    try {
        $size = (Get-Item -LiteralPath $Path).Length
        if ($size -gt 0) {
            [System.IO.File]::WriteAllBytes($Path, (New-Object byte[] $size))
        }
    } catch { }
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}

function ConvertTo-ProcessArgument {
    # Quote one argument using the Windows CommandLineToArgvW rules that
    # .NET/plink/tshark use. Start-Process joins ArgumentList with spaces and
    # lets the child re-parse it, so every argument must be quoted explicitly.
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
    # Start a native process with correctly quoted arguments and enforce a real
    # timeout. Start-Process -Wait ignores -Timeout entirely and can block
    # forever on a stalled SSH session.
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

function Test-Tool {
    param([string]$Name)
    $path = if ($Name -eq "tshark") { $script:TsharkPath } else { $script:PlinkPath }
    if (-not $path) {
        Write-Host "[ERROR] $Name not found in a trusted absolute PATH directory." -ForegroundColor Red
        return $false
    }
    try {
        $arg = if ($Name -eq "tshark") { "--version" } else { "-V" }
        $result = & $path $arg 2>&1 | Select-Object -First 1
        if ($result) {
            Write-Host "[OK] $Name`: $(Clear-UnsafeText -Value ([string]$result) -MaxLength 200)" -ForegroundColor Green
            return $true
        }
    } catch {}
    Write-Host "[ERROR] $Name could not be executed." -ForegroundColor Red
    return $false
}

function ConvertTo-NetworkAddress {
    param([string]$Address, [int]$PrefixLength)
    $ip = [System.Net.IPAddress]::Parse($Address)
    if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Only IPv4 ranges are supported."
    }
    $bytes = $ip.GetAddressBytes()
    [Array]::Reverse($bytes)
    $value = [uint64][BitConverter]::ToUInt32($bytes, 0)
    $mask = [uint64]0
    if ($PrefixLength -gt 0) {
        $mask = ([uint64]4294967295 -shl (32 - $PrefixLength)) -band [uint64]4294967295
    }
    $network = $value -band $mask
    $netBytes = [BitConverter]::GetBytes([uint32]$network)
    [Array]::Reverse($netBytes)
    return [System.Net.IPAddress]::new($netBytes).IPAddressToString
}

function Get-LocalNetworkRange {
    try {
        $adapters = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.IPAddress -notmatch "^127\." -and
                $_.IPAddress -notmatch "^169\.254\." -and
                $_.PrefixLength -le 30 -and $_.PrefixLength -ge 8
            })
        if ($adapters.Count -eq 0) { return $null }

        $gatewayIndices = @()
        try {
            $gatewayIndices = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
                ForEach-Object { $_.InterfaceIndex })
        } catch { }

        # Deprioritise VPN, tunnel, container, and hypervisor adapters. A
        # scanner should not silently sweep a VPN tunnel instead of the LAN.
        $virtualPattern = "VPN|TAP|TUN|Virtual|VMware|Hyper-V|vEthernet|Docker|WSL|Loopback|Bluetooth|ZeroTier|Tailscale|WireGuard|OpenVPN|Hamachi|Pseudo|Npcap|vBox"
        $physical = @($adapters | Where-Object { $_.InterfaceAlias -notmatch $virtualPattern })
        $preferred = @($physical | Where-Object {
            ($gatewayIndices -contains $_.InterfaceIndex) -and $_.PrefixOrigin -ne "WellKnown"
        })
        if ($preferred.Count -eq 0) {
            $preferred = @($physical | Where-Object { $_.PrefixOrigin -ne "WellKnown" })
        }
        if ($preferred.Count -eq 0) { $preferred = $physical }
        if ($preferred.Count -eq 0) {
            $preferred = @($adapters | Where-Object { $gatewayIndices -contains $_.InterfaceIndex })
        }
        if ($preferred.Count -eq 0) { $preferred = $adapters }

        $a = $preferred | Select-Object -First 1
        $network = ConvertTo-NetworkAddress -Address $a.IPAddress -PrefixLength ([int]$a.PrefixLength)
        return "$network/$($a.PrefixLength)"
    } catch {}
    return $null
}

function Complete-PingBatch {
    param([array]$Batch)
    $alive = @()
    if (-not $Batch -or $Batch.Count -eq 0) { return $alive }
    $tasks = [System.Threading.Tasks.Task[]]@($Batch | ForEach-Object { $_.Task })
    try { [void][System.Threading.Tasks.Task]::WaitAll($tasks, 60000) } catch { }
    foreach ($item in $Batch) {
        try {
            if ($item.Task.IsCompleted -and -not $item.Task.IsFaulted -and
                $item.Task.Result.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                $alive += $item.IP
            }
        } catch { }
        try { $item.Ping.Dispose() } catch { }
    }
    return $alive
}

function Discover-Ping {
    param([string]$NetworkRange, [int]$MaxDevices, [int]$PingTimeout, [bool]$Verbose)

    try {
        $parts = $NetworkRange.Split("/")
        if ($parts.Count -ne 2) { throw "CIDR expected" }
        $ip = [System.Net.IPAddress]::Parse($parts[0])
        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw "IPv4 only" }
        $prefix = [int]$parts[1]
        if ($prefix -lt 0 -or $prefix -gt 32) { throw "bad prefix" }

        $bytes = $ip.GetAddressBytes()
        [Array]::Reverse($bytes)
        $baseValue = [uint64][BitConverter]::ToUInt32($bytes, 0)
        $hostBits = 32 - $prefix
        $total = [uint64][Math]::Pow(2, $hostBits)
        $mask = [uint64]0
        if ($prefix -gt 0) {
            $mask = ([uint64]4294967295 -shl $hostBits) -band [uint64]4294967295
        }
        $network = $baseValue -band $mask
        if ($total -gt 2) {
            $first = $network + 1
            $last = $network + $total - 2
        } else {
            $first = $network
            $last = $network + $total - 1
        }
    } catch {
        Write-Host "[ERROR] Invalid network range: $NetworkRange" -ForegroundColor Red
        return @()
    }

    $hostCount = $last - $first + 1
    if ($hostCount -gt 65536) {
        Write-Host "[ERROR] Range $NetworkRange contains $hostCount addresses; narrow it (max 65536)." -ForegroundColor Red
        return @()
    }

    if ($Verbose) { Write-Host "[PING] Sweeping $hostCount hosts in $NetworkRange..." }

    $devices = @()
    $batch = @()
    $batchSize = 64
    for ($addr = $first; $addr -le $last; $addr++) {
        if ($MaxDevices -gt 0 -and $devices.Count -ge $MaxDevices) { break }
        $addrBytes = [BitConverter]::GetBytes([uint32]$addr)
        [Array]::Reverse($addrBytes)
        $hostIP = [System.Net.IPAddress]::new($addrBytes).IPAddressToString
        $ping = New-Object System.Net.NetworkInformation.Ping
        $task = $ping.SendPingAsync($hostIP, $PingTimeout * 1000)
        $batch += @{ IP = $hostIP; Ping = $ping; Task = $task }
        if ($batch.Count -ge $batchSize) {
            foreach ($alive in (Complete-PingBatch -Batch $batch)) {
                $devices += @{ ip = $alive; mac = "N/A"; hostname = $alive; method = "ping" }
                if ($Verbose) { Write-Host "  [+] $alive is alive" -ForegroundColor Green }
            }
            $batch = @()
        }
    }
    if ($batch.Count -gt 0) {
        foreach ($alive in (Complete-PingBatch -Batch $batch)) {
            $devices += @{ ip = $alive; mac = "N/A"; hostname = $alive; method = "ping" }
            if ($Verbose) { Write-Host "  [+] $alive is alive" -ForegroundColor Green }
        }
    }

    if ($MaxDevices -gt 0 -and $devices.Count -gt $MaxDevices) {
        $devices = @($devices | Select-Object -First $MaxDevices)
    }
    return $devices
}

function Discover-Arp {
    param([string]$NetworkRange, [bool]$Verbose)
    $devices = @()
    try {
        $arpPath = Resolve-TrustedTool -Name "arp"
        if (-not $arpPath) {
            if ($Verbose) { Write-Host "[WARN] arp not found in a trusted location" -ForegroundColor Yellow }
            return $devices
        }
        $result = & $arpPath -a
        foreach ($line in $result) {
            if ($line -match "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f\-]{17})") {
                $ip = $Matches[1]
                # The ARP cache contains unrelated hosts; never SSH into them.
                if ($NetworkRange -and -not (Test-IPInRange -IP $ip -NetworkRange $NetworkRange)) { continue }
                $devices += @{
                    ip = $ip
                    mac = Clear-UnsafeText -Value $Matches[2].Replace("-", ":") -MaxLength 64
                    hostname = $ip
                    method = "arp"
                }
            }
        }
    } catch {}
    return $devices
}

function Discover-Tshark {
    param([int]$InterfaceIdx, [string]$NetworkRange, [bool]$Verbose)
    $devices = @()
    $seenIps = @{}

    try {
        if (-not $script:TsharkPath) {
            if ($Verbose) { Write-Host "[WARN] tshark not found in a trusted location" -ForegroundColor Yellow }
            return $devices
        }
        $cmdArgs = @("-a", "duration:10", "-T", "fields",
                     "-e", "ip.src", "-e", "ip.dst", "-e", "eth.src",
                     "-E", "separator=|")
        if ($NetworkRange) { $cmdArgs = @("-f", "net $NetworkRange") + $cmdArgs }
        if ($InterfaceIdx -ge 0) { $cmdArgs = @("-i", $InterfaceIdx.ToString()) + $cmdArgs }

        $tmpFile = New-SecureTempFile -Extension ".tshark"
        try {
            $run = Invoke-ProcessWithTimeout -FilePath $script:TsharkPath -Arguments $cmdArgs `
                -TimeoutSeconds 60 -StdOutPath $tmpFile -MaxOutputBytes $script:MaxToolOutputBytes
            if ($run.TimedOut -and $Verbose) { Write-Host "[WARN] tshark discovery timed out" -ForegroundColor Yellow }
            if ($run.Truncated -and $Verbose) { Write-Host "[WARN] tshark discovery output was truncated" -ForegroundColor Yellow }
            $text = Read-BoundedTextFile -Path $tmpFile -MaxBytes $script:MaxToolOutputBytes
            $lines = @($text -split "`n")
        } finally {
            Remove-Item -LiteralPath $tmpFile -Force -ErrorAction SilentlyContinue
        }

        foreach ($line in $lines) {
            if (-not $line.Trim()) { continue }
            $parts = $line -split "\|"
            foreach ($ipField in @(0, 1)) {
                if ($ipField -ge $parts.Count) { continue }
                $ip = Clear-UnsafeText -Value $parts[$ipField].Trim() -MaxLength 64
                $mac = if ($parts.Count -gt 2) { Clear-UnsafeText -Value $parts[2].Trim() -MaxLength 64 } else { "" }
                $parsed = $null
                if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsed)) { continue }
                if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
                if ($ip -and $ip -notmatch "^(127\.|224\.|239\.|255\.)" -and -not $seenIps.ContainsKey($ip) `
                        -and ((-not $NetworkRange) -or (Test-IPInRange -IP $ip -NetworkRange $NetworkRange))) {
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
        if ($Verbose) { Write-Host "[WARN] tshark discovery failed: $($_ | Out-String)" -ForegroundColor Yellow }
    }
    return $devices
}

function Discover-Devices {
    param([string]$NetworkRange, [string]$Mode, [int]$Interface, [int]$MaxDevices,
          [int]$PingTimeout, [bool]$Verbose)

    $allDevices = @{}

    if ($Mode -in @("ping", "all")) {
        foreach ($dev in @(Discover-Ping -NetworkRange $NetworkRange -MaxDevices $MaxDevices `
                                          -PingTimeout $PingTimeout -Verbose $Verbose)) {
            $allDevices[$dev.ip] = $dev
        }
    }

    if ($Mode -in @("arp", "all")) {
        foreach ($dev in @(Discover-Arp -NetworkRange $NetworkRange -Verbose $Verbose)) {
            if (-not $allDevices.ContainsKey($dev.ip)) {
                $allDevices[$dev.ip] = $dev
            }
        }
    }

    if ($Mode -in @("tshark", "all") -and $Interface -ge 0) {
        foreach ($dev in @(Discover-Tshark -InterfaceIdx $Interface -NetworkRange $NetworkRange -Verbose $Verbose)) {
            if (-not $allDevices.ContainsKey($dev.ip)) {
                $allDevices[$dev.ip] = $dev
            }
        }
    }

    $devices = @($allDevices.Values)
    if ($MaxDevices -gt 0 -and $devices.Count -gt $MaxDevices) {
        $devices = @($devices | Select-Object -First $MaxDevices)
    }
    return $devices
}

function Invoke-Plink {
    param([string]$Target, [int]$Port, [string]$User, [string]$Cmd,
          [array]$AuthArgs, [int]$Timeout, [bool]$Batch, [bool]$Verbose)

    if (-not $script:PlinkPath) {
        throw "plink is not available in a trusted location."
    }
    if (-not (Test-ValidTarget -Value $Target)) {
        return @{ stdout = ""; stderr = "Refusing invalid target"; exitcode = -1 }
    }
    if (-not (Test-ValidTarget -Value $User)) {
        return @{ stdout = ""; stderr = "Refusing invalid username"; exitcode = -1 }
    }

    $cmdArgs = @()
    if ($Batch) { $cmdArgs += "-batch" }
    $cmdArgs += "-P", $Port.ToString(), "-l", $User
    $cmdArgs += $AuthArgs
    $cmdArgs += $Target, $Cmd

    if ($Verbose) {
        Write-Host "  [SSH] $(Clear-UnsafeText -Value $User -MaxLength 64)@$(Clear-UnsafeText -Value $Target -MaxLength 128):${Port} > $(Clear-UnsafeText -Value $Cmd -MaxLength 60)" -ForegroundColor DarkGray
    }

    $tmpOut = New-SecureTempFile -Extension ".out"
    $tmpErr = New-SecureTempFile -Extension ".err"

    try {
        $run = Invoke-ProcessWithTimeout -FilePath $script:PlinkPath -Arguments $cmdArgs `
            -TimeoutSeconds $Timeout -StdOutPath $tmpOut -StdErrPath $tmpErr `
            -MaxOutputBytes $script:MaxToolOutputBytes

        $stdout = Read-BoundedTextFile -Path $tmpOut -MaxBytes $script:MaxToolOutputBytes
        $stderr = Read-BoundedTextFile -Path $tmpErr -MaxBytes $script:MaxToolOutputBytes
    } finally {
        Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $tmpErr -Force -ErrorAction SilentlyContinue
    }

    if ($run.TimedOut) {
        if ($stderr) { $stderr += "`n" }
        $stderr += "Command timed out after ${Timeout}s"
    } elseif ($run.Truncated) {
        if ($stderr) { $stderr += "`n" }
        $stderr += "Command output exceeded the ${script:MaxToolOutputBytes}-byte cap"
    }

    return @{ stdout = $stdout; stderr = $stderr; exitcode = $run.ExitCode }
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
        pacman     = "pacman -Qi --color never 2>/dev/null | grep -E '^(Name|Version|Packager|Install Date|Architecture|URL)'"
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
        choco      = "choco list -l -r 2>nul"
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

function New-AppRecord {
    param(
        [string]$Name = "", [string]$Version = "", [string]$LastUpdate = "",
        [string]$Signer = "", [string]$InstallLocation = "", [string]$Url = "",
        [string]$Publisher = "", [string]$InstallDate = "",
        [string]$Architecture = "", [string]$Source = ""
    )
    return [PSCustomObject]@{
        name             = Clear-UnsafeText -Value $Name -MaxLength 256
        version          = Clear-UnsafeText -Value $Version -MaxLength 128
        last_update      = Clear-UnsafeText -Value $LastUpdate -MaxLength 64
        signer           = Clear-UnsafeText -Value $Signer -MaxLength 256
        install_location = Clear-UnsafeText -Value $InstallLocation -MaxLength 512
        url              = Clear-UnsafeText -Value $Url -MaxLength 512
        publisher        = Clear-UnsafeText -Value $Publisher -MaxLength 256
        install_date     = Clear-UnsafeText -Value $InstallDate -MaxLength 64
        architecture     = Clear-UnsafeText -Value $Architecture -MaxLength 32
        source           = Clear-UnsafeText -Value $Source -MaxLength 32
    }
}

function ConvertFrom-SnapList {
    param([string]$Text)
    $apps = @()
    foreach ($line in ($Text -split "`n")) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed -match "^(Name\s|error:|No snaps)") { continue }
        $parts = $trimmed -split "\s+"
        if ($parts.Count -lt 2) { continue }
        $name = $parts[0]
        if ($name -notmatch "^[A-Za-z0-9][A-Za-z0-9._+-]*$") { continue }
        $publisher = if ($parts.Count -gt 4) { $parts[4].TrimEnd([char[]]@('*', [char]0x2713)) } else { "" }
        $apps += New-AppRecord -Name $name -Version $parts[1] -Publisher $publisher -Source "snap"
    }
    return $apps
}

function ConvertFrom-PacmanQuery {
    param([string]$Text)
    $apps = @()
    $current = @{}

    foreach ($line in ($Text -split "`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            if ($current.ContainsKey("Name")) {
                $apps += New-AppRecord -Name $current["Name"] `
                    -Version $current["Version"] -Signer $current["Packager"] `
                    -Publisher $current["Packager"] -Url $current["URL"] `
                    -InstallDate $current["Install Date"] -Architecture $current["Architecture"] `
                    -Source "pacman"
            }
            $current = @{}
            continue
        }
        $index = $line.IndexOf(":")
        if ($index -lt 1) { continue }
        $key = $line.Substring(0, $index).Trim()
        $value = $line.Substring($index + 1).Trim()
        if ($key -in @("Name", "Version", "Packager", "Install Date", "Architecture", "URL")) {
            $current[$key] = $value
        }
    }
    if ($current.ContainsKey("Name")) {
        $apps += New-AppRecord -Name $current["Name"] -Version $current["Version"] `
            -Signer $current["Packager"] -Publisher $current["Packager"] `
            -Url $current["URL"] -InstallDate $current["Install Date"] `
            -Architecture $current["Architecture"] -Source "pacman"
    }
    return $apps
}

function ConvertFrom-ChocoList {
    param([string]$Text)
    $apps = @()
    foreach ($line in ($Text -split "`n")) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed -notmatch "\|") { continue }
        $parts = $trimmed -split "\|", 2
        $name = $parts[0].Trim()
        if (-not $name -or $name -match "^chocolatey") { continue }
        $version = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }
        $apps += New-AppRecord -Name $name -Version $version -Source "choco"
    }
    return $apps
}

function Parse-LinuxApps {
    param([hashtable]$StdoutMap)
    $apps = @()

    foreach ($source in @("dpkg", "rpm")) {
        $output = $StdoutMap[$source]
        if (-not $output) { continue }
        foreach ($line in ($output -split "`n")) {
            if ($line -notmatch "\|") { continue }
            $parts = $line -split "\|"
            $apps += New-AppRecord -Name $parts[0].Trim() `
                -Version $(if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }) `
                -Signer $(if ($parts.Count -gt 2) { $parts[2].Trim() } else { "" }) `
                -Publisher $(if ($parts.Count -gt 2) { $parts[2].Trim() } else { "" }) `
                -Source $source
        }
    }

    if ($StdoutMap["pacman"]) { $apps += ConvertFrom-PacmanQuery -Text $StdoutMap["pacman"] }
    if ($StdoutMap["snap"]) { $apps += ConvertFrom-SnapList -Text $StdoutMap["snap"] }

    $pipOutput = $StdoutMap["pip"]
    if ($pipOutput) {
        try {
            foreach ($pkg in @($pipOutput | ConvertFrom-Json -ErrorAction Stop)) {
                $name = if ($pkg.PSObject.Properties.Name -contains "name") { [string]$pkg.name } else { "" }
                $version = if ($pkg.PSObject.Properties.Name -contains "version") { [string]$pkg.version } else { "" }
                $apps += New-AppRecord -Name $name -Version $version -Source "pip"
            }
        } catch {}
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
        $architecture = if ($key -eq "reg32") { "x86" } else { "x64" }

        foreach ($line in ($output -split "`n")) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                if ($null -ne $current -and $current.name) { $apps += $current }
                $current = $null
                continue
            }
            $match = [regex]::Match($trimmed,
                '^(DisplayName|DisplayVersion|Publisher|InstallLocation|InstallDate)\s+REG_\w+\s+(.+)$')
            if (-not $match.Success) { continue }
            $field = $match.Groups[1].Value
            $value = $match.Groups[2].Value.Trim()

            if ($field -eq "DisplayName") {
                if ($null -ne $current -and $current.name) { $apps += $current }
                $current = New-AppRecord -Name $value -Architecture $architecture -Source "registry"
                continue
            }
            if ($null -eq $current) { continue }
            if ($field -eq "DisplayVersion") { $current.version = Clear-UnsafeText -Value $value -MaxLength 128 }
            elseif ($field -eq "Publisher") {
                $current.publisher = Clear-UnsafeText -Value $value -MaxLength 256
                $current.signer = Clear-UnsafeText -Value $value -MaxLength 256
            }
            elseif ($field -eq "InstallLocation") { $current.install_location = Clear-UnsafeText -Value $value -MaxLength 512 }
            elseif ($field -eq "InstallDate") {
                $current.install_date = Clear-UnsafeText -Value $value -MaxLength 64
                $current.last_update = Clear-UnsafeText -Value $value -MaxLength 64
            }
        }
        if ($null -ne $current -and $current.name) { $apps += $current }
    }

    $wingetOut = $StdoutMap["winget"]
    if ($wingetOut) {
        $lines = @($wingetOut -split "`n")
        for ($i = 3; $i -lt $lines.Count; $i++) {
            $trimmed = $lines[$i].Trim()
            if (-not $trimmed -or $trimmed -match "^-+$") { continue }
            $parts = $trimmed -split "\s+"
            if ($parts.Count -ge 3) {
                $apps += New-AppRecord -Name ($parts[0..($parts.Count-3)] -join " ") `
                    -Version $parts[-2] -Publisher $(if ($parts.Count -gt 3) { $parts[-1] } else { "" }) `
                    -Source "winget"
            }
        }
    }

    if ($StdoutMap["choco"]) { $apps += ConvertFrom-ChocoList -Text $StdoutMap["choco"] }
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
                if ($null -ne $current -and $current.name) { $apps += $current }
                $current = New-AppRecord -Name $name -Source "macos_apps"
            }
        } elseif ($null -ne $current) {
            if ($line -match "Version:\s*(.+)") { $current.version = Clear-UnsafeText -Value $Matches[1].Trim() -MaxLength 128 }
            if ($line -match "Location:\s*(.+)") { $current.install_location = Clear-UnsafeText -Value $Matches[1].Trim() -MaxLength 512 }
        }
    }
    if ($null -ne $current -and $current.name) { $apps += $current }

    $brewOut = $StdoutMap["brew"]
    if ($brewOut) {
        foreach ($line in ($brewOut -split "`n")) {
            $parts = $line.Trim() -split "\s+"
            if ($parts.Count -ge 1 -and $parts[0]) {
                $apps += New-AppRecord -Name $parts[0] `
                    -Version $(if ($parts.Count -gt 1) { $parts[1] } else { "" }) -Source "brew"
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
            $errors += @{ command = Clear-UnsafeText -Value $entry.Key -MaxLength 64;
                          error = Clear-UnsafeText -Value $result.stderr -MaxLength 200 }
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
    $osText = if ($null -ne $stdoutMap["os_info"]) { [string]$stdoutMap["os_info"] } else { "" }
    $osText = Clear-UnsafeText -Value $osText.Trim() -MaxLength 200

    return @{
        hostname = Clear-UnsafeText -Value (([string]$stdoutMap["hostname"]).Trim()) -MaxLength 128
        os = $osText
        architecture = Clear-UnsafeText -Value (([string]$stdoutMap["architecture"]).Trim()) -MaxLength 64
        applications = $unique
        scan_methods = @($scanMethods | ForEach-Object { Clear-UnsafeText -Value $_ -MaxLength 64 })
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
            total_applications = @($EnumResult.applications).Count
            scan_duration_seconds = $EnumResult.duration
            errors = $EnumResult.errors
        }
    }
}

function Save-DeviceJson {
    param([hashtable]$Report, [string]$OutputDir, [string]$Ip, [string]$Hostname)

    if (!(Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }
    Set-RestrictiveDirectoryAcl -Path $OutputDir

    $hostValue = if ([string]::IsNullOrWhiteSpace($Hostname)) { $Ip } else { $Hostname }
    $safeHostname = ConvertTo-SafeFileName -Value $hostValue -Fallback "unknown"
    $safeIp = ConvertTo-SafeFileName -Value ($Ip -replace "\.", "_") -Fallback "ip"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "${safeHostname}_${safeIp}_${timestamp}.json"
    $filepath = Join-SafeOutputPath -OutputDir $OutputDir -FileName $filename

    $Report | ConvertTo-Json -Depth 5 | Out-File -FilePath $filepath -Encoding UTF8
    Set-RestrictiveFileAcl -Path $filepath
    return $filepath
}

function Scan-AndPopulate {
    param(
        [string]$NetworkRange, [string]$Mode, [int]$Interface, [int]$MaxDevices,
        [int]$Port, [string]$User, [array]$AuthArgs, [int]$Timeout,
        [string]$OutputDir, [bool]$Verbose, [bool]$Quiet
    )

    $startTime = Get-Date

    # Resolve native tools once per scan, from trusted locations only.
    $script:PlinkPath = Resolve-TrustedTool -Name "plink"
    $script:TsharkPath = Resolve-TrustedTool -Name "tshark"

    if (-not $Quiet) {
        Write-Header "Flash_Network — Device Scanner & JSON Reporter (PowerShell)"
    }

    $validModes = @("ping", "arp", "tshark", "all")
    if ($Mode -notin $validModes) {
        Write-Host "[ERROR] Invalid mode '$Mode'. Choose one of: $($validModes -join ', ')." -ForegroundColor Red
        return @()
    }
    if ($Mode -eq "tshark" -and $Interface -lt 0) {
        Write-Host "[ERROR] -Mode tshark requires -Interface <index>." -ForegroundColor Red
        return @()
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
        if (-not $NetworkRange) {
            Write-Host "[ERROR] Could not auto-detect a usable IPv4 network. Pass -Range explicitly." -ForegroundColor Red
            return @()
        }
        if (-not $Quiet) { Write-Host "[AUTO] Detected network range: $NetworkRange" -ForegroundColor Cyan }
    }

    if (-not $Quiet) { Write-Host "`n[DISCOVERY] Scanning $NetworkRange (mode: $Mode)..." -ForegroundColor Magenta }

    $devices = @(Discover-Devices -NetworkRange $NetworkRange -Mode $Mode -Interface $Interface `
        -MaxDevices $MaxDevices -PingTimeout 2 -Verbose $Verbose)

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

        if (-not $Quiet) { Write-Host "`n  [$idx/$($devices.Count)] $(Clear-UnsafeText -Value $hostname -MaxLength 128) ($ip)..." -ForegroundColor White }

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
                Write-Host "    [+] $(Clear-UnsafeText -Value $enumResult.os_detected -MaxLength 32) | $($report.applications.Count) apps | $($enumResult.duration)s | $filepath" -ForegroundColor Green
            }
        } catch {
            $results += @{ ip = $ip; hostname = $hostname; status = "error"; error = $_.Exception.Message }
            if (-not $Quiet) { Write-Host "    [-] Failed: $(Clear-UnsafeText -Value $_ -MaxLength 200)" -ForegroundColor Red }
        }
        $idx++
    }

    $totalTime = ((Get-Date) - $startTime).TotalSeconds
    $successful = @($results | Where-Object { $_.status -eq "success" }).Count
    $totalApps = 0
    foreach ($result in $results) {
        if ($result.status -eq "success") { $totalApps += [int]$result.apps }
    }

    # Write index
    if (!(Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }
    Set-RestrictiveDirectoryAcl -Path $OutputDir
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
    $indexPath = Join-SafeOutputPath -OutputDir $OutputDir -FileName "scan_index.json"
    if (Test-Path -LiteralPath $indexPath) {
        $archiveName = "scan_index_" + (Get-Date -Format "yyyyMMdd_HHmmss_fff") + ".json"
        $archivePath = Join-SafeOutputPath -OutputDir $OutputDir -FileName $archiveName
        try {
            Move-Item -LiteralPath $indexPath -Destination $archivePath -Force
            Set-RestrictiveFileAcl -Path $archivePath
        } catch {
            Write-Host "[WARN] Could not archive previous scan index: $(Clear-UnsafeText -Value $_ -MaxLength 200)" -ForegroundColor Yellow
        }
    }
    $index | ConvertTo-Json -Depth 4 | Out-File -FilePath $indexPath -Encoding UTF8
    Set-RestrictiveFileAcl -Path $indexPath

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

if ($args.Count -gt 0) {
    Write-Host "[ERROR] Unknown argument(s): $($args -join ' '). Use -Help for usage." -ForegroundColor Red
    exit 1
}

if (-not $Quiet) {
    Write-Header "Flash_Network — Device Scanner & JSON Reporter"
}

if (-not (Test-ValidTarget -Value $User)) {
    Write-Host "[ERROR] -User must not be empty, start with '-', or contain whitespace/control characters." -ForegroundColor Red
    exit 1
}

if ($Range -and -not (Test-ValidTarget -Value $Range)) {
    Write-Host "[ERROR] -Range must not contain whitespace or control characters." -ForegroundColor Red
    exit 1
}

if ($PasswordFile -and $AskPassword) {
    Write-Host "[ERROR] Use only one of -PasswordFile or -AskPassword." -ForegroundColor Red
    exit 1
}

if (-not $HostKey -and -not $InsecureHostKey) {
    Write-Host "[ERROR] Host key verification is required to protect credentials from" -ForegroundColor Red
    Write-Host "        man-in-the-middle attacks. Pass -HostKey <fingerprint> or, only" -ForegroundColor Red
    Write-Host "        if you accept that risk, -InsecureHostKey." -ForegroundColor Red
    exit 1
}

$authArgs = @()
if ($Key) {
    if (-not (Test-Path -LiteralPath $Key)) {
        Write-Host "[ERROR] SSH key not found: $Key" -ForegroundColor Red
        exit 1
    }
    $authArgs += "-i", (Resolve-Path -LiteralPath $Key).Path
}
if ($HostKey) {
    $authArgs += "-hostkey", $HostKey
} elseif ($InsecureHostKey) {
    Write-Host "[WARN] -InsecureHostKey set: server identity is NOT verified; MITM is possible." -ForegroundColor Yellow
}

$pwTemp = $null
$plainPassword = $null
try {
    if ($PasswordFile) {
        if (-not (Test-Path -LiteralPath $PasswordFile)) { throw "Password file not found: $PasswordFile" }
        $pwItem = Get-Item -LiteralPath $PasswordFile -ErrorAction Stop
        if ($pwItem.Length -gt 65536) { throw "Password file is too large (max 64 KiB)." }
        $plainPassword = Get-Content -LiteralPath $PasswordFile -TotalCount 1
    } elseif ($AskPassword) {
        $secure = Read-Host -AsSecureString "SSH password"
        $plainPassword = [System.Net.NetworkCredential]::new("", $secure).Password
    }

    if ($null -ne $plainPassword) {
        if ($plainPassword -eq "") { throw "Password is empty." }
        $pwTemp = New-PasswordFile -Password $plainPassword
        $authArgs += "-pwfile", $pwTemp
    }

    Scan-AndPopulate `
        -NetworkRange $Range -Mode $Mode -Interface $Interface `
        -MaxDevices $MaxDevices -Port $Port -User $User `
        -AuthArgs $authArgs -Timeout $Timeout `
        -OutputDir $OutputDir -Verbose:$Verbose -Quiet:$Quiet
} finally {
    Remove-PasswordFile -Path $pwTemp
    $plainPassword = $null
}
