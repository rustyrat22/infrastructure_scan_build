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
import getpass
import tempfile
from datetime import datetime, timezone


# --- Security helpers -------------------------------------------------------

WINDOWS_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL"}
WINDOWS_RESERVED_NAMES.update(f"COM{i}" for i in range(1, 10))
WINDOWS_RESERVED_NAMES.update(f"LPT{i}" for i in range(1, 10))


def sanitize_filename_component(value, fallback="unknown", max_length=64):
    """Return a safe single path component derived from *value*."""
    text = str(value or "").strip()
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    text = text.strip("._-")
    if not text or text in (".", ".."):
        return fallback
    if text.split(".")[0].upper() in WINDOWS_RESERVED_NAMES:
        text = f"_{text}"
    return text[:max_length] or fallback


def safe_output_path(output_dir, filename):
    """Join *filename* to *output_dir* and refuse any path escape."""
    base = os.path.realpath(output_dir)
    candidate = os.path.realpath(os.path.join(base, filename))
    try:
        contained = os.path.commonpath([base, candidate]) == base
    except ValueError:
        contained = False
    if not contained:
        raise ValueError(f"Refusing to write outside output directory: {filename!r}")
    return candidate


def write_password_file(password):
    """Write *password* to a private temp file for `plink -pwfile`."""
    fd, path = tempfile.mkstemp(prefix="flashnet_pw_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(password)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def remove_password_file(path):
    """Overwrite then delete a temporary password file."""
    if not path:
        return
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as handle:
            handle.write(b"\x00" * size)
        os.unlink(path)
    except OSError:
        pass


def read_password_file(path):
    """Read the first line of a password file without the trailing newline."""
    with open(path, "r", encoding="utf-8") as handle:
        return handle.readline().rstrip("\r\n")


def secure_output_dir(path):
    """Create *path* and, on POSIX, restrict it to the owner."""
    os.makedirs(path, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    return path


def secure_file(path):
    """Restrict *path* to the owner on POSIX."""
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return path


def parse_int_arg(value, option, minimum=None, maximum=None):
    """Parse a CLI integer and exit with a clear message when invalid."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        sys.exit(f"[ERROR] {option} expects an integer, got: {value!r}")
    if minimum is not None and number < minimum:
        sys.exit(f"[ERROR] {option} must be >= {minimum}, got: {number}")
    if maximum is not None and number > maximum:
        sys.exit(f"[ERROR] {option} must be <= {maximum}, got: {number}")
    return number


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
    -pw, --ask-password    Prompt for the SSH password (never echoed). The
                           password is passed to plink via -pwfile.
    --password-file FILE   Read the SSH password from the first line of FILE.
    --password-stdin       Read the SSH password from standard input.
    --hostkey FINGERPRINT  Pin the server host key (e.g. SHA256:...). Required
                           unless --insecure-host-key is given.
    --insecure-host-key    Accept any server key. UNSAFE: enables MITM.
    -o, --output DIR       Output directory for JSON reports (default: ./output/)
    -c, --command CMD      Run a custom command instead of the default suite
    -m, --os-type TYPE     Override OS detection: windows, linux, macos
    --timeout SEC          SSH connection timeout in seconds (default: 30)
    --batch                Run in non-interactive mode (disables prompts)
    -v, --verbose          Enable verbose output
    -q, --quiet            Suppress console output. Only write JSON report.
    -h, --help             Show this help message and exit.

EXAMPLES:
    Scan a Linux device with SSH key:
        python device_enumerator.py -t 192.168.1.50 -u admin -k ~/.ssh/key.ppk --hostkey SHA256:abc123

    Scan a Windows device with an interactive password prompt:
        python device_enumerator.py -t 192.168.1.100 -u admin -pw --hostkey SHA256:abc123

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
        "open_ports": "netstat -ano | findstr LISTENING",
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
    """Parse Windows registry uninstall keys into structured dicts.

    `reg query /s` emits one field per line. A new DisplayName starts the next
    application, so fields must accumulate until then or until a blank line.
    """
    apps = []
    current = None

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            if current and current.get("name"):
                apps.append(current)
            current = None
            continue

        match = re.match(
            r"^(DisplayName|DisplayVersion|Publisher|InstallLocation|InstallDate)\s+REG_\w+\s+(.+)$",
            line,
        )
        if not match:
            continue
        field, value = match.group(1), match.group(2).strip()

        if field == "DisplayName":
            if current and current.get("name"):
                apps.append(current)
            current = {
                "name": value,
                "version": "",
                "signer": "",
                "install_location": "",
                "url": "",
                "last_update": "",
            }
            continue

        if current is None:
            continue
        if field == "DisplayVersion":
            current["version"] = value
        elif field == "Publisher":
            current["signer"] = value
        elif field == "InstallLocation":
            current["install_location"] = value
        elif field == "InstallDate":
            current["last_update"] = value

    if current and current.get("name"):
        apps.append(current)

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
    """Save enumeration report to a JSON file inside *output_dir*."""
    secure_output_dir(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = sanitize_filename_component(report["device_info"].get("hostname"), fallback="unknown")
    target = sanitize_filename_component(
        report["scan_metadata"]["target"].replace(".", "_"), fallback="target"
    )

    filename = f"device_enum_{hostname}_{target}_{timestamp}.json"
    filepath = safe_output_path(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    secure_file(filepath)

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
    password_file = None
    ask_password = False
    password_stdin = False
    hostkey = None
    insecure_hostkey = False
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
            port = parse_int_arg(args[i + 1], args[i], minimum=1, maximum=65535)
            i += 2
        elif args[i] in ("-u", "--user") and i + 1 < len(args):
            user = args[i + 1]
            i += 2
        elif args[i] in ("-k", "--key") and i + 1 < len(args):
            key_file = args[i + 1]
            i += 2
        elif args[i] in ("-pw", "--password", "--ask-password"):
            if i + 1 < len(args) and not args[i + 1].startswith("-"):
                sys.exit(
                    "[ERROR] Passing a password directly on the command line is insecure.\n"
                    "        Use --ask-password (or -pw with no value) to be prompted,\n"
                    "        --password-file FILE, or --password-stdin."
                )
            ask_password = True
            i += 1
        elif args[i].startswith(("--password=", "-pw=")):
            sys.exit(
                "[ERROR] Passing a password directly on the command line is insecure.\n"
                "        Use --ask-password, --password-file FILE, or --password-stdin."
            )
        elif args[i] == "--password-file" and i + 1 < len(args):
            password_file = args[i + 1]
            i += 2
        elif args[i] == "--password-stdin":
            password_stdin = True
            i += 1
        elif args[i] == "--hostkey" and i + 1 < len(args):
            hostkey = args[i + 1]
            i += 2
        elif args[i] == "--insecure-host-key":
            insecure_hostkey = True
            i += 1
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
            timeout = parse_int_arg(args[i + 1], args[i], minimum=1, maximum=3600)
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
            sys.exit(f"[ERROR] Unknown option: {args[i]}\n        Use --help for usage.")

    if os_type is not None and os_type not in ("windows", "linux", "macos"):
        sys.exit(f"[ERROR] Invalid OS type {os_type!r}. Choose windows, linux, or macos.")

    if target is None:
        print("[ERROR] Target is required. Use -t <host> or --help for usage.")
        sys.exit(1)

    if not quiet:
        print("=" * 60)
        print("  Flash_Network — PuTTY/Plink Device Enumerator")
        print("=" * 60)

    if not check_plink():
        sys.exit(1)

    selected_password_sources = sum(bool(v) for v in (password_file, password_stdin, ask_password))
    if selected_password_sources > 1:
        sys.exit("[ERROR] Choose only one of --ask-password, --password-file, --password-stdin.")

    if not hostkey and not insecure_hostkey:
        sys.exit(
            "[ERROR] Host key verification is required to protect credentials from\n"
            "        man-in-the-middle attacks. Pass --hostkey <fingerprint> or,\n"
            "        only if you accept that risk, --insecure-host-key."
        )

    auth_args = []
    if key_file:
        key_path = os.path.expanduser(key_file)
        if not os.path.isfile(key_path):
            sys.exit(f"[ERROR] SSH key not found: {key_path}")
        auth_args.extend(["-i", key_path])
    if hostkey:
        auth_args.extend(["-hostkey", hostkey])
    elif insecure_hostkey:
        print("[WARN] --insecure-host-key set: server identity is NOT verified; MITM is possible.")

    password = None
    try:
        if password_file:
            password = read_password_file(os.path.expanduser(password_file))
        elif password_stdin:
            password = sys.stdin.readline().rstrip("\r\n")
        elif ask_password:
            password = getpass.getpass("SSH password: ")
    except OSError as e:
        sys.exit(f"[ERROR] Could not read password: {e}")

    if password is not None and password == "":
        sys.exit("[ERROR] Password is empty.")

    password_path = None
    if password:
        password_path = write_password_file(password)
        auth_args.extend(["-pwfile", password_path])

    try:
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
    finally:
        remove_password_file(password_path)


if __name__ == "__main__":
    main()
