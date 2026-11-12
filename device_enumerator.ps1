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
    .\device_enumerator.ps1 -Target 192.168.1.50 -User admin -Key "C:\keys\key.ppk" -HostKey "SHA256:abc123"
    .\device_enumerator.ps1 -Target 192.168.1.100 -User admin -AskPassword -HostKey "SHA256:abc123"
    .\device_enumerator.ps1 -Target 192.168.1.50 -User root -Key "key.ppk" -Command "uname -a"
    .\device_enumerator.ps1 -Help
#>

param(
    [Alias("t")][string]$Target = "",
    [Alias("p")][int]$Port = 22,
    [Alias("u")][string]$User = "root",
    [Alias("k")][string]$Key = "",
    [string]$PasswordFile = "",
    [switch]$AskPassword = $false,
    [string]$HostKey = "",
    [switch]$InsecureHostKey = $false,
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
Set-StrictMode -Version Latest
$OutputEncoding = [System.Text.Encoding]::UTF8

$script:PlinkPath = $null
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

function Clear-UnsafeBlock {
    # Strip terminal escapes from command output while preserving the line
    # structure the operator explicitly asked to see.
    param([string]$Value, [int]$MaxLength = 0)
    if ($null -eq $Value) { return "" }
    $text = [regex]::Replace([string]$Value, "\x1B\[[0-?]*[ -/]*[@-~]", "")
    $text = [regex]::Replace($text, "\x1B\][^\x07]*(?:\x07|\x1B\\)", "")
    $text = [regex]::Replace($text, "\x1B[@-_]", "")
    $text = [regex]::Replace($text, "[\u202A-\u202E\u2066-\u2069]", "")
    $text = [regex]::Replace($text, "[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "")
    $text = $text -replace "`r", ""
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
    -PasswordFile FILE Read SSH password from the first line of FILE
    -AskPassword       Prompt for the SSH password (never echoed)
    -HostKey FP        Pin the server host key (required for verification)
    -InsecureHostKey   Accept any server key (UNSAFE: MITM risk)
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
        .\device_enumerator.ps1 -Target 192.168.1.100 -User admin -AskPassword -HostKey "SHA256:abc123"

    Run a custom command:
        .\device_enumerator.ps1 -Target 192.168.1.50 -User root -Key "key.ppk" -Command "uname -a"

    Scan with verbose output:
        .\device_enumerator.ps1 -Target 192.168.1.50 -User admin -Key "key.ppk" -Verbose
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

function New-PasswordFile {
    param([string]$Password)
    $path = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(),
        "flashnet_pw_" + [guid]::NewGuid().ToString("N") + ".txt")
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($path, $Password, $utf8)
        Set-RestrictiveFileAcl -Path $path
        return $path
    } catch {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        throw
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

function Test-Plink {
    $script:PlinkPath = Resolve-TrustedTool -Name "plink"
    if (-not $script:PlinkPath) {
        Write-Host "[ERROR] plink not found in a trusted absolute PATH directory." -ForegroundColor Red
        return $false
    }
    try {
        $result = & $script:PlinkPath -V 2>&1 | Select-Object -First 1
        if ($result -match "Release|PuTTY") {
            Write-Host "[OK] plink found: $(Clear-UnsafeText -Value ([string]$result) -MaxLength 200)" -ForegroundColor Green
            return $true
        }
    } catch {}

    try {
        $result = & $script:PlinkPath -V 2>&1
        if ($result -match "PuTTY") {
            Write-Host "[OK] plink found" -ForegroundColor Green
            return $true
        }
    } catch {}

    Write-Host "[ERROR] plink could not be executed." -ForegroundColor Red
    return $false
}

function ConvertTo-ProcessArgument {
    # Quote one argument using the Windows CommandLineToArgvW rules that
    # .NET/plink use. Start-Process joins ArgumentList with spaces and lets the
    # child re-parse it, so paths and commands must be quoted explicitly.
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

    if (-not $script:PlinkPath) { $script:PlinkPath = Resolve-TrustedTool -Name "plink" }
    if (-not $script:PlinkPath) {
        return @{ stdout = ""; stderr = "plink is not available in a trusted location"; exitcode = -1 }
    }
    if (-not (Test-ValidTarget -Value $Target)) {
        return @{ stdout = ""; stderr = "Refusing invalid target"; exitcode = -1 }
    }
    if (-not (Test-ValidTarget -Value $User)) {
        return @{ stdout = ""; stderr = "Refusing invalid username"; exitcode = -1 }
    }

    $cmdArgs = @()
    if ($Batch) { $cmdArgs += "-batch" }
    $cmdArgs += "-P", $Port.ToString()
    $cmdArgs += "-l", $User
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

    return @{
        stdout = $stdout
        stderr = $stderr
        exitcode = $run.ExitCode
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
        installed_packages_pacman = "pacman -Qi --color never 2>/dev/null | grep -E '^(Name|Version|Packager|Install Date|Architecture|URL)'"
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
        installed_apps_choco    = "choco list -l -r 2>nul"
        winget_apps             = "winget list --accept-source-agreements 2>nul"
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

function New-AppRecord {
    param(
        [string]$Name = "", [string]$Version = "", [string]$Signer = "",
        [string]$InstallLocation = "", [string]$Url = "", [string]$LastUpdate = ""
    )
    return [PSCustomObject]@{
        name             = Clear-UnsafeText -Value $Name -MaxLength 256
        version          = Clear-UnsafeText -Value $Version -MaxLength 128
        signer           = Clear-UnsafeText -Value $Signer -MaxLength 256
        install_location = Clear-UnsafeText -Value $InstallLocation -MaxLength 512
        url              = Clear-UnsafeText -Value $Url -MaxLength 512
        last_update      = Clear-UnsafeText -Value $LastUpdate -MaxLength 64
    }
}

function Parse-LinuxPackages {
    param([string]$Stdout)
    $apps = @()
    foreach ($line in ($Stdout -split "`n")) {
        if ($line -notmatch "\|") { continue }
        $parts = $line -split "\|"
        $name = $parts[0].Trim()
        if (-not $name) { continue }
        $apps += New-AppRecord -Name $name `
            -Version $(if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }) `
            -Signer $(if ($parts.Count -gt 2) { $parts[2].Trim() } else { "" })
    }
    return $apps
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
        $apps += New-AppRecord -Name $name -Version $parts[1] -Signer $publisher
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
                $apps += New-AppRecord -Name $current["Name"] -Version $current["Version"] `
                    -Signer $current["Packager"] -Url $current["URL"] `
                    -LastUpdate $current["Install Date"]
            }
            $current = @{}
            continue
        }
        $index = $line.IndexOf(":")
        if ($index -lt 1) { continue }
        $key = $line.Substring(0, $index).Trim()
        $value = $line.Substring($index + 1).Trim()
        if ($key -in @("Name", "Version", "Packager", "Install Date", "URL")) {
            $current[$key] = $value
        }
    }
    if ($current.ContainsKey("Name")) {
        $apps += New-AppRecord -Name $current["Name"] -Version $current["Version"] `
            -Signer $current["Packager"] -Url $current["URL"] `
            -LastUpdate $current["Install Date"]
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
        $apps += New-AppRecord -Name $name -Version $version
    }
    return $apps
}

function Parse-WindowsRegistry {
    param([string]$Stdout)
    $apps = @()
    $current = $null

    foreach ($line in ($Stdout -split "`n")) {
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
            $current = New-AppRecord -Name $value
            continue
        }
        if ($null -eq $current) { continue }
        if ($field -eq "DisplayVersion") { $current.version = Clear-UnsafeText -Value $value -MaxLength 128 }
        elseif ($field -eq "Publisher") { $current.signer = Clear-UnsafeText -Value $value -MaxLength 256 }
        elseif ($field -eq "InstallLocation") { $current.install_location = Clear-UnsafeText -Value $value -MaxLength 512 }
        elseif ($field -eq "InstallDate") { $current.last_update = Clear-UnsafeText -Value $value -MaxLength 64 }
    }
    if ($null -ne $current -and $current.name) { $apps += $current }
    return $apps
}

function Parse-Winget {
    param([string]$Stdout)
    $apps = @()
    $lines = @($Stdout -split "`n")
    for ($i = 3; $i -lt $lines.Count; $i++) {
        $trimmed = $lines[$i].Trim()
        if (-not $trimmed -or $trimmed -match "^-+$") { continue }
        $parts = $trimmed -split "\s+"
        if ($parts.Count -ge 3) {
            $apps += New-AppRecord -Name ($parts[0..($parts.Count-3)] -join " ") `
                -Version $parts[-2] -Signer $(if ($parts.Count -gt 3) { $parts[-1] } else { "" })
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
        if ($StdoutMap.ContainsKey("installed_packages_pacman") -and $StdoutMap["installed_packages_pacman"]) {
            $apps += ConvertFrom-PacmanQuery -Text $StdoutMap["installed_packages_pacman"]
        }
        if ($StdoutMap.ContainsKey("snap_packages") -and $StdoutMap["snap_packages"]) {
            $apps += ConvertFrom-SnapList -Text $StdoutMap["snap_packages"]
        }
    } elseif ($OsType -eq "windows") {
        foreach ($key in @("installed_apps_registry", "installed_apps_wow64")) {
            if ($StdoutMap.ContainsKey($key) -and $StdoutMap[$key]) {
                $apps += Parse-WindowsRegistry -Stdout $StdoutMap[$key]
            }
        }
        if ($StdoutMap.ContainsKey("installed_apps_choco") -and $StdoutMap["installed_apps_choco"]) {
            $apps += ConvertFrom-ChocoList -Text $StdoutMap["installed_apps_choco"]
        }
        if ($StdoutMap.ContainsKey("winget_apps") -and $StdoutMap["winget_apps"]) {
            $apps += Parse-Winget -Stdout $StdoutMap["winget_apps"]
        }
    } elseif ($OsType -eq "macos") {
        $lines = @(($StdoutMap["installed_apps"]) -split "`n")
        $current = $null
        foreach ($line in $lines) {
            if ($line -match "Version:\s*(.+)") {
                if ($null -eq $current) { $current = New-AppRecord -Name "" }
                $current.version = Clear-UnsafeText -Value $Matches[1].Trim() -MaxLength 128
            }
            if ($line -match "Location:\s*(.+)") {
                if ($null -ne $current -and $current.name) {
                    $current.install_location = Clear-UnsafeText -Value $Matches[1].Trim() -MaxLength 512
                    $apps += $current
                    $current = $null
                }
            } elseif ($line.Trim() -and $line.Trim().Length -gt 2 -and $line -notmatch "^\s") {
                if ($null -eq $current) {
                    $current = New-AppRecord -Name ($line.Trim().TrimEnd(":"))
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
                command = Clear-UnsafeText -Value $entry.Key -MaxLength 64
                error = Clear-UnsafeText -Value $result.stderr -MaxLength 200
            }
        }
    }

    $duration = ((Get-Date) - $startTime).TotalSeconds

    $osValue = Clear-UnsafeText -Value (([string]$stdoutMap["os_release"]).Trim()) -MaxLength 200
    if (-not $osValue) { $osValue = Clear-UnsafeText -Value (([string]$stdoutMap["os_info"]).Trim()) -MaxLength 200 }
    $uptimeValue = Clear-UnsafeText -Value (([string]$stdoutMap["uptime"]).Trim()) -MaxLength 200
    $ipConfigValue = Clear-UnsafeText -Value (([string]$stdoutMap["ip_config"]).Trim()) -MaxLength 500
    $portsValue = Clear-UnsafeText -Value (([string]$stdoutMap["listening_ports"]).Trim()) -MaxLength 1000

    $deviceInfo = [PSCustomObject]@{
        hostname        = Clear-UnsafeText -Value (([string]$stdoutMap["hostname"]).Trim()) -MaxLength 128
        os              = $osValue
        architecture    = Clear-UnsafeText -Value (([string]$stdoutMap["architecture"]).Trim()) -MaxLength 64
        kernel          = Clear-UnsafeText -Value (([string]$stdoutMap["kernel"]).Trim()) -MaxLength 128
        uptime          = $uptimeValue
        ip_config       = $ipConfigValue
        default_gateway = Clear-UnsafeText -Value (([string]$stdoutMap["default_gateway"]).Trim()) -MaxLength 256
        dns_servers     = Clear-UnsafeText -Value (([string]$stdoutMap["dns_servers"]).Trim()) -MaxLength 500
        listening_ports = $portsValue
    }

    $apps = @(Parse-Applications -StdoutMap $stdoutMap -OsType $OsType)

    $authMethod = "unknown"
    if ($AuthArgs -contains "-i") { $authMethod = "key" }
    elseif ($AuthArgs -contains "-pwfile") { $authMethod = "password" }

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

    if (!(Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }
    Set-RestrictiveDirectoryAcl -Path $OutputDir

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = ConvertTo-SafeFileName -Value $Report.device_info.hostname -Fallback "unknown"
    $target = ConvertTo-SafeFileName -Value ($Report.scan_metadata.target -replace "\.", "_") -Fallback "target"

    $filename = "device_enum_${hostname}_${target}_${timestamp}.json"
    $filepath = Join-SafeOutputPath -OutputDir $OutputDir -FileName $filename

    $Report | ConvertTo-Json -Depth 5 | Out-File -FilePath $filepath -Encoding UTF8
    Set-RestrictiveFileAcl -Path $filepath
    return $filepath
}

function Print-Summary {
    param([PSCustomObject]$Report, [string]$Filepath)

    $meta = $Report.scan_metadata
    $dev = $Report.device_info

    Write-Header "FLASH_NETWORK — Device Enumeration Summary"
    Write-Host "  Target      : $(Clear-UnsafeText -Value $meta.target -MaxLength 128):$($meta.port)"
    Write-Host "  User        : $(Clear-UnsafeText -Value $meta.user -MaxLength 64)"
    Write-Host "  OS          : $(Clear-UnsafeText -Value $meta.os_detected -MaxLength 64)"
    Write-Host "  Hostname    : $(Clear-UnsafeText -Value $dev.hostname -MaxLength 128)"
    Write-Host "  Architecture: $(Clear-UnsafeText -Value $dev.architecture -MaxLength 64)"
    Write-Host "  Duration    : $($meta.duration_seconds)s"
    Write-Section ""

    Write-Host "  APPLICATIONS FOUND: $($Report.application_count)" -ForegroundColor Green
    Write-Section ""

    $count = 0
    foreach ($app in $Report.applications) {
        if ($count -ge 20) { break }
        Write-Host "  [$($count + 1)] $(Clear-UnsafeText -Value $app.name -MaxLength 256)" -ForegroundColor White
        if ($app.version) { Write-Host "      Version : $(Clear-UnsafeText -Value $app.version -MaxLength 128)" }
        if ($app.signer)  { Write-Host "      Signer  : $(Clear-UnsafeText -Value $app.signer -MaxLength 256)" }
        if ($app.install_location) { Write-Host "      Location: $(Clear-UnsafeText -Value $app.install_location -MaxLength 512)" }
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
            $errMsg = Clear-UnsafeText -Value $err.error -MaxLength 100
            Write-Host "    - $(Clear-UnsafeText -Value $err.command -MaxLength 64): $errMsg" -ForegroundColor Red
            $errCount++
        }
    }

    Write-Header "Full report saved to: $Filepath"
}

# Main
if ($Help) { Write-Usage; exit 0 }

if ($args.Count -gt 0) {
    Write-Host "[ERROR] Unknown argument(s): $($args -join ' '). Use -Help for usage." -ForegroundColor Red
    exit 1
}

if (-not $Target) {
    Write-Host "[ERROR] Target is required. Use -Target <host> or -Help for usage." -ForegroundColor Red
    exit 1
}

if (-not (Test-ValidTarget -Value $Target)) {
    Write-Host "[ERROR] -Target must not start with '-', exceed 253 characters, or contain whitespace/control characters." -ForegroundColor Red
    exit 1
}

if (-not (Test-ValidTarget -Value $User)) {
    Write-Host "[ERROR] -User must not be empty, start with '-', or contain whitespace/control characters." -ForegroundColor Red
    exit 1
}

if (-not $Quiet) {
    Write-Header "Flash_Network — PuTTY/Plink Device Enumerator (PowerShell)"
}

if (-not (Test-Plink)) { exit 1 }

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

    if ($Command) {
        if (-not $Quiet) { Write-Host "`n[ENUM] Running custom command on $(Clear-UnsafeText -Value $Target -MaxLength 128)..." -ForegroundColor Magenta }
        $result = Invoke-PlinkCommand -Target $Target -Port $Port -User $User `
            -Cmd $Command -AuthArgs $authArgs -Timeout $Timeout -Verbose $Verbose
        Write-Host (Clear-UnsafeBlock -Value $result.stdout)
        if ($result.stderr) { Write-Host "[STDERR] $(Clear-UnsafeBlock -Value $result.stderr)" -ForegroundColor Red }
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
} finally {
    Remove-PasswordFile -Path $pwTemp
    $plainPassword = $null
}
