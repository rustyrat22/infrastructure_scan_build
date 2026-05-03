"""
Flash_Network — PuTTY/Plink Device Enumerator (Python)
Uses plink.exe (PuTTY CLI) to connect to remote devices via SSH and execute
commands to gather device information, installed applications, and network details.

Requirements:
  - PuTTY installed with plink.exe in PATH
  - SSH access to target devices (credentials or key-based auth)
"""

import subprocess
import sys
import json
import os
import re
from datetime import datetime, timezone


def check_plink():
    """Check if plink.exe is available on the system."""
    try:
        result = subprocess.run(
            ["plink", "-V"],
            capture_output=True, text=True, timeout=10
        )
        version = result.stderr.strip().split("\n")[0] if result.stderr else "Unknown"
        print(f"[OK] plink found: {version}")
        return True
    except FileNotFoundError:
        print("[ERROR] plink not found. Install PuTTY and add to PATH.")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def print_usage():
    """Display detailed usage information."""
    usage = """
Flash_Network — PuTTY/Plink Device Enumerator
==============================================

DESCRIPTION:
    Connects to remote devices via SSH using plink.exe (PuTTY CLI) to gather
    device information, installed applications, network configuration,
    and system metadata.

USAGE:
    python device_enumerator.py [options]

OPTIONS:
    -t, --target HOST      Target device IP or hostname (required)
    -p, --port PORT        SSH port (default: 22)
    -u, --user USER        SSH username (default: current user)
    -k, --key FILE         Path to SSH private key file (.ppk)
    -pw, --password PWD    SSH password (not recommended; use -k instead)
    -o, --output DIR       Output directory for JSON reports (default: ./output/)
    -c, --command CMD      Run a custom command instead of the default suite
    -m, --os-type TYPE     Override OS detection: windows, linux, macos
    --timeout SEC          SSH connection timeout in seconds (default: 30)
    --batch                Run in non-interactive mode (accept host key)
    -v, --verbose          Enable verbose output
    -q, --quiet            Suppress console output. Only write JSON report.
    -h, --help             Show this help message and exit.

EXAMPLES:
    Scan a Linux device with SSH key:
        python device_enumerator.py -t 192.168.1.50 -u admin -k ~/.ssh/key.ppk

    Scan a Windows device with password:
        python device_enumerator.py -t 192.168.1.100 -u admin -pw SecretPass

    Run a custom command:
        python device_enumerator.py -t 192.168.1.50 -u root -k key.ppk -c "uname -a"

    Scan with verbose output:
        python device_enumerator.py -t 192.168.1.50 -u admin -k key.ppk -v

REQUIREMENTS:
    - PuTTY installed with plink.exe in PATH
    - SSH access to target device
    - SSH key (.ppk) or password for authentication

OUTPUT:
    JSON report saved to: output/device_enum_YYYYMMDD_HHMMSS.json

    The report contains:
      - device_info: hostname, OS, architecture, uptime, IP config
      - applications: list of installed apps with version, signer, path
      - network: interfaces, routes, open ports
      - scan_metadata: timestamp, target, auth method, duration
"""
    print(usage)


def run_plink(target, port, user, cmd, auth_args=None, timeout=30, batch=True, verbose=False):
    """Execute a single command on a remote device via plink."""
    base_cmd = ["plink"]

    if batch:
        base_cmd.extend(["-batch"])

    base_cmd.extend(["-P", str(port)])
    base_cmd.extend(["-l", user])

    if auth_args:
        base_cmd.extend(auth_args)

    if verbose:
        print(f"  [SSH] {user}@{target}:{port} > {cmd}")

    base_cmd.extend([target, cmd])

    try:
        result = subprocess.run(
            base_cmd,
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0 and verbose:
            err = result.stderr.strip()
            if err:
                print(f"  [WARN] plink exit {result.returncode}: {err[:200]}")
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except Exception as e:
        return "", str(e), -1


def detect_os(target, port, user, auth_args, timeout, verbose):
    """Detect remote OS by running lightweight probe commands."""
    probes = [
        ("linux", "uname -s"),
        ("windows", "echo %OS%"),
        ("macos", "uname -s"),
    ]

    for os_hint, cmd in probes:
        stdout, stderr, rc = run_plink(target, port, user, cmd, auth_args, timeout, verbose=verbose)
        output = (stdout + stderr).lower()
        if os_hint == "linux" and "linux" in output:
            return "linux"
        if os_hint == "windows" and "windows" in output:
            return "windows"
        if os_hint == "macos" and "darwin" in output:
            return "macos"

    return "unknown"


def get_linux_commands():
    """Return the command suite for Linux devices."""
    return {
        "hostname": "hostname",
        "os_release": "cat /etc/os-release 2>/dev/null || uname -a",
        "architecture": "uname -m",
        "kernel": "uname -r",
        "uptime": "uptime",
        "ip_config": "ip addr show 2>/dev/null || ifconfig 2>/dev/null || cat /etc/hosts",
        "default_gateway": "ip route show default 2>/dev/null || route -n | grep '^0.0.0.0'",
        "dns_servers": "cat /etc/resolv.conf 2>/dev/null",
        "listening_ports": "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
        "installed_packages_deb": "dpkg-query -W -f='${Package}|${Version}|${Maintainer}|${Status}\\n' 2>/dev/null",
        "installed_packages_rpm": "rpm -qa --queryformat '%{NAME}|%{VERSION}|%{VENDOR}|installed\\n' 2>/dev/null",
        "installed_packages_pacman": "pacman -Qi --color never 2>/dev/null | grep -E '^(Name|Version|Packager|Installed Size)'",
        "snap_packages": "snap list 2>/dev/null",
        "open_ports": "ss -tlnp 2>/dev/null | head -50",
        "cpu_info": "lscpu 2>/dev/null | head -20",
        "memory": "free -h 2>/dev/null",
        "disk": "df -h 2>/dev/null",
    }


def get_windows_commands():
    """Return the command suite for Windows devices."""
    return {
        "hostname": "hostname",
        "os_info": "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\"",
        "architecture": "echo %PROCESSOR_ARCHITECTURE%",
        "uptime": "systeminfo | findstr /C:\"System Boot Time\"",
        "ip_config": "ipconfig /all",
        "default_gateway": "ipconfig | findstr /C:\"Default Gateway\"",
        "dns_servers": "ipconfig /all | findstr /C:\"DNS Servers\"",
        "listening_ports": "netstat -ano | findstr LISTENING",
        "installed_apps_registry": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s 2>nul | findstr /C:\"DisplayName\" /C:\"DisplayVersion\" /C:\"Publisher\" /C:\"InstallLocation\" /C:\"InstallDate\"",
        "installed_apps_wow64": "reg query \"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s 2>nul | findstr /C:\"DisplayName\" /C:\"DisplayVersion\" /C:\"Publisher\" /C:\"InstallLocation\" /C:\"InstallDate\"",
        "winget_apps": "winget list --accept-source-agreements 2>nul",
        "open_ports": "netstat -ano | findstr LISTENING | head -50",
        "services": "sc query state= all | findstr /C:\"SERVICE_NAME\" /C:\"STATE\"",
    }


def get_macos_commands():
    """Return the command suite for macOS devices."""
    return {
        "hostname": "hostname",
        "os_info": "sw_vers",
        "architecture": "uname -m",
        "kernel": "uname -r",
        "uptime": "uptime",
        "ip_config": "ifconfig",
        "default_gateway": "netstat -nr | grep default",
        "dns_servers": "cat /etc/resolv.conf 2>/dev/null; networksetup -getdnsservers Wi-Fi 2>/dev/null",
        "listening_ports": "lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null | head -50",
        "installed_apps": "system_profiler SPApplicationsDataType 2>/dev/null | head -200",
        "brew_packages": "brew list --versions 2>/dev/null",
        "app_folder": "ls -la /Applications/ 2>/dev/null",
    }


def parse_linux_packages(stdout):
    """Parse Linux package list into structured dicts."""
    apps = []
    for line in stdout.strip().split("\n"):
        if "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) >= 2:
            app = {
                "name": parts[0].strip(),
                "version": parts[1].strip() if len(parts) > 1 else "",
                "signer": parts[2].strip() if len(parts) > 2 else "",
                "install_location": "",
                "url": "",
                "last_update": "",
            }
            if app["name"]:
                apps.append(app)
    return apps


def parse_windows_registry(stdout):
    """Parse Windows registry uninstall keys into structured dicts."""
    apps = []
    current = {}

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if "DisplayName" in line:
            match = re.search(r"REG_SZ\s+(.+)", line)
            if match:
                current["name"] = match.group(1).strip()
        elif "DisplayVersion" in line:
            match = re.search(r"REG_SZ\s+(.+)", line)
            if match:
                current["version"] = match.group(1).strip()
        elif "Publisher" in line:
            match = re.search(r"REG_SZ\s+(.+)", line)
            if match:
                current["signer"] = match.group(1).strip()
        elif "InstallLocation" in line:
            match = re.search(r"REG_SZ\s+(.+)", line)
            if match:
                current["install_location"] = match.group(1).strip()
        elif "InstallDate" in line:
            match = re.search(r"REG_SZ\s+(.+)", line)
            if match:
                current["last_update"] = match.group(1).strip()

        if "name" in current:
            current.setdefault("url", "")
            apps.append(current)
            current = {}

    return apps


def parse_winget(stdout):
    """Parse winget list output."""
    apps = []
    lines = stdout.strip().split("\n")
    for line in lines[3:]:
        parts = line.split()
        if len(parts) >= 3:
            apps.append({
                "name": " ".join(parts[:-2]),
                "version": parts[-2],
                "signer": parts[-1] if len(parts) > 3 else "",
                "install_location": "",
                "url": "",
                "last_update": "",
            })
    return apps


def parse_applications(stdout_map, os_type):
    """Parse application inventory based on OS type."""
    apps = []

    if os_type == "linux":
        for key in ("installed_packages_deb", "installed_packages_rpm", "installed_packages_pacman"):
            if key in stdout_map and stdout_map[key]:
                apps.extend(parse_linux_packages(stdout_map[key]))

    elif os_type == "windows":
        for key in ("installed_apps_registry", "installed_apps_wow64"):
            if key in stdout_map and stdout_map[key]:
                apps.extend(parse_windows_registry(stdout_map[key]))
        if "winget_apps" in stdout_map and stdout_map["winget_apps"]:
            apps.extend(parse_winget(stdout_map["winget_apps"]))

    elif os_type == "macos":
        lines = stdout_map.get("installed_apps", "").split("\n")
        current = {}
        for line in lines:
            if "Version:" in line:
                match = re.search(r"Version:\s*(.+)", line)
                if match:
                    current["version"] = match.group(1).strip()
            if "Location:" in line:
                match = re.search(r"Location:\s*(.+)", line)
                if match:
                    current["install_location"] = match.group(1).strip()
                    if current.get("name"):
                        current.setdefault("signer", "")
                        current.setdefault("url", "")
                        current.setdefault("last_update", "")
                        apps.append(current)
                        current = {}
            elif line.strip() and not line.startswith(" "):
                name = line.strip().rstrip(":")
                if name and len(name) > 2:
                    current = {"name": name}

    # Deduplicate by name
    seen = set()
    unique = []
    for app in apps:
        name_key = app.get("name", "").lower()
        if name_key and name_key not in seen:
            seen.add(name_key)
            unique.append(app)

    return unique


def enumerate_device(target, port=22, user="root", auth_args=None, os_type=None,
                     timeout=30, batch=True, verbose=False, quiet=False):
    """Main enumeration function: connect, detect OS, run commands, parse results."""
    start_time = datetime.now(timezone.utc)

    if auth_args is None:
        auth_args = []

    if not quiet:
        print(f"\n[ENUM] Connecting to {target}:{port} as {user}...")

    if os_type is None:
        os_type = detect_os(target, port, user, auth_args, timeout, verbose)
        if not quiet:
            print(f"[ENUM] Detected OS: {os_type}")

    commands = {
        "linux": get_linux_commands(),
        "windows": get_windows_commands(),
        "macos": get_macos_commands(),
    }.get(os_type, {})

    if not commands:
        print(f"[ERROR] No command suite for OS type: {os_type}")
        return None

    stdout_map = {}
    errors = []

    for label, cmd in commands.items():
        if verbose and not quiet:
            print(f"  [CMD] {label}: {cmd[:60]}...")
        stdout, stderr, rc = run_plink(target, port, user, cmd, auth_args, timeout, batch, verbose)
        stdout_map[label] = stdout
        if rc != 0 and stderr:
            errors.append({"command": label, "error": stderr[:200]})

    duration = (datetime.now(timezone.utc) - start_time).total_seconds()

    device_info = {
        "hostname": stdout_map.get("hostname", "").strip(),
        "os": stdout_map.get("os_release", stdout_map.get("os_info", "")).strip()[:200],
        "architecture": stdout_map.get("architecture", "").strip(),
        "kernel": stdout_map.get("kernel", "").strip(),
        "uptime": stdout_map.get("uptime", "").strip()[:200],
        "ip_config": stdout_map.get("ip_config", "").strip()[:500],
        "default_gateway": stdout_map.get("default_gateway", "").strip(),
        "dns_servers": stdout_map.get("dns_servers", "").strip(),
        "listening_ports": stdout_map.get("listening_ports", "").strip()[:1000],
    }

    apps = parse_applications(stdout_map, os_type)

    report = {
        "scan_metadata": {
            "timestamp": start_time.isoformat(),
            "target": target,
            "port": port,
            "user": user,
            "os_detected": os_type,
            "auth_method": "key" if ("-i" in auth_args or "-ikey" in " ".join(auth_args)) else "password" if any("-pw" in a for a in auth_args) else "unknown",
            "duration_seconds": round(duration, 2),
            "errors": errors,
        },
        "device_info": device_info,
        "applications": apps,
        "application_count": len(apps),
    }

    return report


def save_report(report, output_dir="./output"):
    """Save enumeration report to JSON file."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = report["device_info"].get("hostname", "unknown").replace(" ", "_")
    target = report["scan_metadata"]["target"].replace(".", "_")

    filename = f"device_enum_{hostname}_{target}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return filepath


def print_summary(report, filepath):
    """Print a human-readable summary."""
    meta = report["scan_metadata"]
    dev = report["device_info"]

    print("\n" + "=" * 60)
    print("  FLASH_NETWORK — Device Enumeration Summary")
    print("=" * 60)
    print(f"  Target      : {meta['target']}:{meta['port']}")
    print(f"  User        : {meta['user']}")
    print(f"  OS          : {meta['os_detected']}")
    print(f"  Hostname    : {dev['hostname']}")
    print(f"  Architecture: {dev['architecture']}")
    print(f"  Duration    : {meta['duration_seconds']}s")
    print("-" * 60)

    print(f"\n  APPLICATIONS FOUND: {report['application_count']}")
    print("-" * 60)
    for i, app in enumerate(report["applications"][:20], 1):
        print(f"  [{i}] {app['name']}")
        if app.get("version"):
            print(f"      Version : {app['version']}")
        if app.get("signer"):
            print(f"      Signer  : {app['signer']}")
        if app.get("install_location"):
            print(f"      Location: {app['install_location']}")
    if report["application_count"] > 20:
        print(f"  ... and {report['application_count'] - 20} more")

    if meta["errors"]:
        print(f"\n  ERRORS ({len(meta['errors'])}):")
        for err in meta["errors"][:5]:
            print(f"    - {err['command']}: {err['error'][:100]}")

    print("\n" + "=" * 60)
    print(f"  Full report saved to: {filepath}")
    print("=" * 60 + "\n")


def main():
    target = None
    port = 22
    user = "root"
    key_file = None
    password = None
    output_dir = "./output"
    custom_cmd = None
    os_type = None
    timeout = 30
    batch = True
    verbose = False
    quiet = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("-t", "--target") and i + 1 < len(args):
            target = args[i + 1]
            i += 2
        elif args[i] in ("-p", "--port") and i + 1 < len(args):
            port = int(args[i + 1])
            i += 2
        elif args[i] in ("-u", "--user") and i + 1 < len(args):
            user = args[i + 1]
            i += 2
        elif args[i] in ("-k", "--key") and i + 1 < len(args):
            key_file = args[i + 1]
            i += 2
        elif args[i] in ("-pw", "--password") and i + 1 < len(args):
            password = args[i + 1]
            i += 2
        elif args[i] in ("-o", "--output") and i + 1 < len(args):
            output_dir = args[i + 1]
            i += 2
        elif args[i] in ("-c", "--command") and i + 1 < len(args):
            custom_cmd = args[i + 1]
            i += 2
        elif args[i] in ("-m", "--os-type") and i + 1 < len(args):
            os_type = args[i + 1].lower()
            i += 2
        elif args[i] == "--timeout" and i + 1 < len(args):
            timeout = int(args[i + 1])
            i += 2
        elif args[i] == "--batch":
            batch = True
            i += 1
        elif args[i] in ("-v", "--verbose"):
            verbose = True
            i += 1
        elif args[i] in ("-q", "--quiet"):
            quiet = True
            i += 1
        elif args[i] in ("-h", "--help"):
            print_usage()
            sys.exit(0)
        else:
            i += 1

    if target is None:
        print("[ERROR] Target is required. Use -t <host> or --help for usage.")
        sys.exit(1)

    if not quiet:
        print("=" * 60)
        print("  Flash_Network — PuTTY/Plink Device Enumerator")
        print("=" * 60)

    if not check_plink():
        sys.exit(1)

    auth_args = []
    if key_file:
        auth_args.extend(["-i", key_file])
    if password:
        auth_args.extend(["-pw", password])

    if custom_cmd:
        if not quiet:
            print(f"\n[ENUM] Running custom command on {target}...")
        stdout, stderr, rc = run_plink(target, port, user, custom_cmd, auth_args, timeout, batch, verbose)
        print(stdout)
        if stderr:
            print(f"[STDERR] {stderr}", file=sys.stderr)
        sys.exit(rc)

    report = enumerate_device(
        target=target, port=port, user=user, auth_args=auth_args,
        os_type=os_type, timeout=timeout, batch=batch,
        verbose=verbose, quiet=quiet
    )

    if report is None:
        print("[ERROR] Enumeration failed.")
        sys.exit(1)

    filepath = save_report(report, output_dir)

    if not quiet:
        print_summary(report, filepath)
    else:
        print(f"Report saved to: {filepath}")


if __name__ == "__main__":
    main()
