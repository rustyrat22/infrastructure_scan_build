"""
Flash_Network — Device Scanner & JSON Reporter (Python)
Discovers devices on the local network, connects to each via SSH (plink),
enumerates installed applications, and generates standardized JSON files
per device.

Combines network discovery, device enumeration, and JSON reporting
into a single pipeline.

Requirements:
  - Wireshark (tshark) for network discovery
  - PuTTY (plink.exe) for remote device access
  - Run as Administrator for packet capture
"""

import subprocess
import sys
import json
import os
import re
import time
import getpass
import ipaddress
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from collections import defaultdict

from flashnet_common import (
    create_secure_temp_file,
    resolve_tool,
    run_bounded,
    sanitize_console_text,
    secure_file,
    secure_output_dir,
)


# --- Security helpers -------------------------------------------------------

MAX_PING_HOSTS = 65536
PING_WORKERS = 64

WINDOWS_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL"}
WINDOWS_RESERVED_NAMES.update(f"COM{i}" for i in range(1, 10))
WINDOWS_RESERVED_NAMES.update(f"LPT{i}" for i in range(1, 10))


def sanitize_filename_component(value, fallback="unknown", max_length=64):
    """Return a safe single path component derived from *value*.

    Strips path separators, traversal sequences, control characters and
    Windows-reserved device names so a remote-controlled hostname can never
    escape the output directory.
    """
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


def clean_text(value, limit=200):
    """Sanitise attacker-controlled text before storing or printing it."""
    return sanitize_console_text(value, limit)


def plink_path():
    """Return the absolute path to a trusted plink, or raise FileNotFoundError."""
    path = resolve_tool("plink")
    if not path:
        raise FileNotFoundError(
            "plink was not found in a trusted absolute PATH directory"
        )
    return path


def validate_target(value):
    """Validate a user-supplied SSH target and reject option injection."""
    text = str(value or "").strip()
    if not text:
        sys.exit("[ERROR] Target must not be empty.")
    if text.startswith("-"):
        sys.exit(f"[ERROR] Refusing target that looks like an option: {text!r}")
    if len(text) > 253:
        sys.exit("[ERROR] Target is too long (max 253 characters).")
    if re.search(r"[\s\x00-\x1f\x7f]", text):
        sys.exit("[ERROR] Target must not contain whitespace or control characters.")
    return text


def validate_user(value):
    """Validate an SSH username before it is handed to plink."""
    text = str(value or "").strip()
    if not text:
        sys.exit("[ERROR] SSH username must not be empty.")
    if text.startswith("-"):
        sys.exit(f"[ERROR] Refusing username that looks like an option: {text!r}")
    if re.search(r"[\s\x00-\x1f\x7f]", text):
        sys.exit("[ERROR] Username must not contain whitespace or control characters.")
    return text


def is_valid_ipv4(value):
    """Return True only for a syntactically valid IPv4 address."""
    try:
        return ipaddress.ip_address(str(value)).version == 4
    except (TypeError, ValueError):
        return False


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


def write_password_file(password):
    """Write *password* to a private temp file for `plink -pwfile`."""
    fd, path = create_secure_temp_file(prefix="flashnet_pw_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(password)
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
    if os.path.getsize(path) > 64 * 1024:
        raise OSError("Password file is too large (max 64 KiB).")
    with open(path, "r", encoding="utf-8") as handle:
        return handle.readline(4096).rstrip("\r\n")


def parse_network(network_range):
    """Return an ip_network for *network_range*, or None if it is invalid."""
    try:
        return ipaddress.ip_network(network_range, strict=False)
    except (TypeError, ValueError):
        return None


def ip_in_network(ip, network):
    """Return True when *ip* is a valid address inside *network*."""
    if network is None:
        return False
    try:
        return ipaddress.ip_address(ip) in network
    except (TypeError, ValueError):
        return False


def print_usage():
    """Display detailed usage information."""
    usage = """
Flash_Network — Device Scanner & JSON Reporter
===============================================

DESCRIPTION:
    Discovers devices on the local network, connects to each via SSH,
    enumerates installed applications and system metadata, and generates
    a standardized JSON file per device.

    The pipeline:
      1. Discover live devices via ARP scan, ICMP ping sweep, or tshark
      2. Connect to each device via plink.exe (PuTTY SSH client)
      3. Run OS-specific commands to enumerate applications
      4. Generate one JSON file per device with full inventory

USAGE:
    python device_scanner.py [options]

OPTIONS:
    -r, --range CIDR       Network CIDR range to scan (e.g. 192.168.1.0/24)
                           Default: auto-detect local subnet

    -i, --interface NUM    Network interface index for discovery.
                           Use --list-interfaces to see available interfaces.

    -t, --timeout SEC      Per-device SSH timeout in seconds (default: 30)

    -p, --port PORT        SSH port for all devices (default: 22)

    -u, --user USER        Default SSH username (default: root)

    -k, --key FILE         Path to SSH private key (.ppk)

    -pw, --ask-password    Prompt for the SSH password (never echoed). The
                           password is written to a private temp file and
                           passed to plink via -pwfile; it never appears in
                           the process list.
    --password-file FILE   Read the SSH password from the first line of FILE.
    --password-stdin       Read the SSH password from standard input.

    --hostkey FINGERPRINT  Pin the server host key (e.g. a SHA256:... value
                           printed by plink). Required unless
                           --insecure-host-key is given.
    --insecure-host-key    Disable host key pinning and accept any key.
                           UNSAFE: enables man-in-the-middle attacks.

    -o, --output DIR       Output directory for JSON files (default: ./output/)

    -m, --mode MODE        Discovery mode: ping, arp, tshark, all (default: all)

    -n, --max-devices NUM  Maximum number of devices to scan (default: unlimited)

    --users FILE           Path to a file with usernames to try (one per line)

    -v, --verbose          Enable verbose output with per-command details

    -q, --quiet            Suppress console output. Only write JSON files.

    --list-interfaces      List available network interfaces and exit.

    -h, --help             Show this help message and exit.

EXAMPLES:
    Scan local subnet with auto-detection:
        python device_scanner.py

    Scan specific range with SSH key:
        python device_scanner.py -r 192.168.1.0/24 -k ~/.ssh/key.ppk -u admin

    Quick ping-only discovery, scan up to 10 devices:
        python device_scanner.py -m ping -n 10

    Scan with password authentication (prompts, never echoes):
        python device_scanner.py -r 10.0.0.0/24 -u admin -pw --hostkey SHA256:abc123

    Read the password from a protected file:
        python device_scanner.py -r 10.0.0.0/24 -u admin --password-file .secret --hostkey SHA256:abc123

    Verbose scan with custom output:
        python device_scanner.py -r 192.168.1.0/24 -v -o ./reports/

JSON OUTPUT SCHEMA (per device):
    {
      "device": {
        "hostname": "...",
        "ip_address": "...",
        "mac_address": "...",
        "os": "...",
        "architecture": "...",
        "scan_timestamp": "...",
        "scan_methods": ["ping", "ssh", "dpkg", "registry"]
      },
      "applications": [
        {
          "name": "Application Name",
          "version": "1.2.3",
          "last_update": "2026-01-15",
          "signer": "Publisher / Code Signer",
          "install_location": "/usr/bin or C:\\Program Files\\...",
          "url": "",
          "publisher": "Publisher Name",
          "install_date": "2026-01-15",
          "architecture": "x64",
          "source": "dpkg|rpm|winget|registry"
        }
      ],
      "scan_summary": {
        "total_applications": 42,
        "scan_duration_seconds": 15.3,
        "errors": []
      }
    }
"""
    print(usage)


def check_prerequisites(verbose=False):
    """Check if tshark and plink are available in trusted locations."""
    tools = {}
    for tool in ("tshark", "plink"):
        path = resolve_tool(tool)
        if not path:
            tools[tool] = {"available": False, "version": None, "path": None}
            print(f"[ERROR] {tool} not found in a trusted absolute PATH directory.")
            continue
        try:
            result = run_bounded(
                [path, "--version" if tool == "tshark" else "-V"],
                timeout=10,
                max_stdout=8192,
                max_stderr=8192,
            )
            out = (result.stdout + result.stderr).strip()
            version = clean_text(out.split("\n")[0], 200) if out else "found"
            tools[tool] = {"available": True, "version": version, "path": path}
            if not verbose:
                print(f"[OK] {tool}: {version}")
        except Exception as e:
            tools[tool] = {"available": False, "version": None, "path": path}
            print(f"[ERROR] {tool} check failed: {clean_text(e, 200)}")
    return tools


_VIRTUAL_ADAPTER_RE = re.compile(
    r"(vpn|tap|tun|virtual|vmware|hyper-?v|vethernet|docker|wsl|loopback|"
    r"bluetooth|zerotier|tailscale|wireguard|openvpn|hamachi|teredo|isatap|"
    r"6to4|pseudo|npcap|vbox|virtualbox|virbr|cni|flannel|podman|bridge)",
    re.IGNORECASE,
)


def _is_virtual_adapter(name):
    return bool(_VIRTUAL_ADAPTER_RE.search(str(name or "")))


def _select_network_candidate(candidates):
    """Prefer a physical adapter that carries the default route."""
    if not candidates:
        return None
    candidates = sorted(
        candidates,
        key=lambda item: (
            item["virtual"],
            not item["has_gateway"],
            item["apipa"],
        ),
    )
    return candidates[0]


def _windows_network_candidates():
    """Parse ipconfig into per-adapter IPv4 network candidates."""
    ipconfig = resolve_tool("ipconfig")
    if not ipconfig:
        return []
    result = run_bounded([ipconfig], timeout=10, max_stdout=1024 * 1024,
                         max_stderr=64 * 1024)
    text = result.stdout
    candidates = []
    # Each adapter section starts with a non-indented "... adapter ...:" line.
    blocks = re.split(r"(?im)(?=^[^\s].*\badapter\b[^\r\n]*:\s*$)", text)
    for block in blocks:
        if not block.strip():
            continue
        header = block.splitlines()[0].strip().rstrip(":")
        ip_match = re.search(
            r"IPv4[^:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})", block
        )
        mask_match = re.search(
            r"Subnet Mask[^:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})", block
        )
        gateway_match = re.search(
            r"Default Gateway[^:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})", block
        )
        if not ip_match or not mask_match:
            continue
        ip, mask = ip_match.group(1), mask_match.group(1)
        if ip.startswith("127.") or mask == "0.0.0.0":
            continue
        try:
            network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except ValueError:
            continue
        if not 8 <= network.prefixlen <= 30:
            continue
        candidates.append({
            "name": header,
            "network": str(network),
            "prefixlen": network.prefixlen,
            "has_gateway": bool(gateway_match),
            "virtual": _is_virtual_adapter(header),
            "apipa": ip.startswith("169.254."),
        })
    return candidates


def _posix_ip_path():
    path = resolve_tool("ip")
    if path:
        return path
    for candidate in ("/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _posix_network_candidates():
    """Parse `ip -4 addr` into per-interface IPv4 network candidates."""
    ip_tool = _posix_ip_path()
    if not ip_tool:
        return []

    default_iface = None
    try:
        routes = run_bounded([ip_tool, "route", "show", "default"], timeout=10,
                             max_stdout=64 * 1024, max_stderr=16 * 1024)
        match = re.search(r"\bdev\s+(\S+)", routes.stdout)
        if match:
            default_iface = match.group(1)
    except OSError:
        pass

    result = run_bounded([ip_tool, "-4", "addr", "show"], timeout=10,
                         max_stdout=1024 * 1024, max_stderr=64 * 1024)
    candidates = []
    current_iface = ""
    for line in result.stdout.splitlines():
        header = re.match(r"^\d+:\s+([^:@]+?)(?:@\S+)?:\s", line)
        if header:
            current_iface = header.group(1).strip()
            continue
        match = re.search(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})", line)
        if not match or not current_iface:
            continue
        ip, prefix = match.group(1), int(match.group(2))
        if ip.startswith("127.") or not 8 <= prefix <= 30:
            continue
        try:
            network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        except ValueError:
            continue
        candidates.append({
            "name": current_iface,
            "network": str(network),
            "prefixlen": network.prefixlen,
            "has_gateway": current_iface == default_iface,
            "virtual": _is_virtual_adapter(current_iface),
            "apipa": ip.startswith("169.254."),
        })
    return candidates


def get_local_network_range():
    """Auto-detect the local IPv4 network, or None when it cannot be determined.

    Physical adapters carrying the default route are preferred; VPN, virtual,
    container, and loopback adapters are deprioritised so a scan does not
    silently target a tunnel instead of the LAN.
    """
    try:
        candidates = (
            _windows_network_candidates()
            if sys.platform == "win32"
            else _posix_network_candidates()
        )
        selected = _select_network_candidate(candidates)
        return selected["network"] if selected else None
    except Exception:
        return None


def _ping_host(host, timeout):
    """Ping a single host; return its address when it replies."""
    ip = str(host)
    cmd = (["ping", "-n", "1", "-w", str(timeout * 1000), ip]
           if sys.platform == "win32"
           else ["ping", "-c", "1", "-W", str(timeout), ip])
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=max(timeout + 5, 10),
        )
        return ip if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def discover_devices_ping(network_range, max_devices=None, timeout=2, verbose=False):
    """Discover live devices via ICMP ping sweep with bounded concurrency."""
    try:
        net = ipaddress.ip_network(network_range, strict=False)
    except ValueError:
        print(f"[ERROR] Invalid network range: {network_range}")
        return []

    if net.num_addresses > MAX_PING_HOSTS:
        print(f"[ERROR] Range {network_range} contains {net.num_addresses} addresses; "
              f"refusing to sweep more than {MAX_PING_HOSTS}. Narrow --range.")
        return []

    hosts = list(net.hosts())
    if max_devices:
        hosts = hosts[:max_devices]

    if verbose:
        print(f"\n[PING] Sweeping {len(hosts)} hosts in {network_range}...")

    devices = []
    if not hosts:
        return devices

    with ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
        for ip in pool.map(lambda h: _ping_host(h, timeout), hosts):
            if ip:
                devices.append({"ip": ip, "mac": "N/A", "hostname": ip, "method": "ping"})
                if verbose:
                    print(f"  [+] {ip} is alive")

    return devices


def discover_devices_arp(network_range, verbose=False):
    """Discover devices via the neighbour/ARP cache, scoped to *network_range*."""
    devices = []
    network = parse_network(network_range)
    if network is None:
        print(f"[ERROR] Invalid network range: {network_range}")
        return devices

    try:
        if sys.platform == "win32":
            arp_tool = resolve_tool("arp")
            if not arp_tool:
                if verbose:
                    print("[WARN] arp not found in a trusted location")
                return devices
            result = run_bounded([arp_tool, "-a"], timeout=10,
                                 max_stdout=1024 * 1024, max_stderr=64 * 1024)
            for line in result.stdout.split("\n"):
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f\-]{17})", line)
                if match:
                    ip = match.group(1)
                    if not is_valid_ipv4(ip) or not ip_in_network(ip, network):
                        continue
                    mac = match.group(2).replace("-", ":")
                    devices.append({"ip": ip, "mac": mac, "hostname": ip, "method": "arp"})
        else:
            ip_tool = _posix_ip_path()
            if not ip_tool:
                if verbose:
                    print("[WARN] ip not found in a trusted location")
                return devices
            result = run_bounded([ip_tool, "neigh"], timeout=10,
                                 max_stdout=1024 * 1024, max_stderr=64 * 1024)
            for line in result.stdout.split("\n"):
                parts = line.split()
                if len(parts) >= 3 and parts[2] not in ("FAILED", "INCOMPLETE"):
                    ip = parts[0]
                    if not is_valid_ipv4(ip) or not ip_in_network(ip, network):
                        continue
                    devices.append({"ip": ip, "mac": parts[2], "hostname": ip, "method": "arp"})
    except Exception as e:
        if verbose:
            print(f"[WARN] ARP discovery failed: {clean_text(e, 200)}")

    return devices


def discover_devices_tshark(interface_idx=None, duration=10, network_range=None, verbose=False):
    """Discover devices via tshark packet capture, scoped to *network_range*."""
    devices = []
    network = parse_network(network_range) if network_range else None
    if network_range and network is None:
        print(f"[ERROR] Invalid network range: {network_range}")
        return devices

    try:
        tshark = resolve_tool("tshark")
        if not tshark:
            if verbose:
                print("[WARN] tshark not found in a trusted location")
            return devices

        cmd = [tshark, "-a", f"duration:{duration}", "-T", "fields",
               "-e", "ip.src", "-e", "ip.dst", "-e", "eth.src", "-e", "eth.dst",
               "-e", "dhcp.options.hostname", "-e", "mdns.host_name",
               "-E", "separator=|"]
        if network is not None:
            # Capture filter keeps unrelated LAN traffic out of the scan and
            # out of any credential-bearing SSH attempts.
            cmd[1:1] = ["-f", f"net {network}"]
        if interface_idx is not None:
            cmd[1:1] = ["-i", str(interface_idx)]

        if verbose:
            print(f"\n[TSHARK] Capturing {duration}s for device discovery...")

        result = run_bounded(
            cmd, timeout=duration + 30,
            max_stdout=16 * 1024 * 1024, max_stderr=64 * 1024,
        )
        if result.timed_out and verbose:
            print("[WARN] tshark discovery timed out; using partial output.")
        seen_ips = {}

        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("|")
            for ip_field in (0, 1):
                ip = parts[ip_field].strip() if ip_field < len(parts) else ""
                mac = parts[2].strip() if len(parts) > 2 else ""
                hostname = parts[4].strip() if len(parts) > 4 else ""
                if not hostname:
                    hostname = parts[5].strip() if len(parts) > 5 else ""
                ip = clean_text(ip, 64)
                mac = clean_text(mac, 64)
                hostname = clean_text(hostname, 128)

                if (is_valid_ipv4(ip) and not ip.startswith(("127.", "224.", "239.", "255."))
                        and ip not in seen_ips
                        and (network is None or ip_in_network(ip, network))):
                    seen_ips[ip] = True
                    devices.append({
                        "ip": ip,
                        "mac": mac if mac and mac != "00:00:00:00:00:00" else "N/A",
                        "hostname": hostname if hostname else ip,
                        "method": "tshark",
                    })
    except Exception as e:
        if verbose:
            print(f"[WARN] tshark discovery failed: {clean_text(e, 200)}")

    return devices


def discover_devices(network_range, mode="all", interface_idx=None, max_devices=None, verbose=False):
    """Run device discovery using specified mode(s)."""
    all_devices = {}

    if mode in ("ping", "all"):
        for dev in discover_devices_ping(network_range, max_devices, verbose=verbose):
            all_devices[dev["ip"]] = dev

    if mode in ("arp", "all"):
        for dev in discover_devices_arp(network_range, verbose=verbose):
            if dev["ip"] not in all_devices:
                all_devices[dev["ip"]] = dev

    if mode in ("tshark", "all") and interface_idx is not None:
        for dev in discover_devices_tshark(interface_idx, network_range=network_range, verbose=verbose):
            if dev["ip"] not in all_devices:
                all_devices[dev["ip"]] = dev

    devices = list(all_devices.values())
    if max_devices:
        devices = devices[:max_devices]

    return devices


def run_plink(target, port, user, cmd, auth_args, timeout=30, batch=True, verbose=False):
    """Execute a single command on a remote device via plink."""
    if not is_valid_ipv4(target):
        return "", "Refusing non-IPv4 target", -1
    base_cmd = [plink_path()]
    if batch:
        base_cmd.append("-batch")
    base_cmd.extend(["-P", str(port), "-l", user])
    if auth_args:
        base_cmd.extend(auth_args)
    base_cmd.extend([target, cmd])

    try:
        result = run_bounded(
            base_cmd,
            timeout=timeout,
            max_stdout=4 * 1024 * 1024,
            max_stderr=1024 * 1024,
        )
        stderr = result.stderr
        if result.timed_out:
            stderr = (stderr + "\n" if stderr else "") + f"Timeout after {timeout}s"
        if result.stdout_truncated and verbose:
            print(f"  [WARN] plink stdout for {target} was truncated")
        return result.stdout, stderr, result.returncode
    except FileNotFoundError:
        return "", "plink not found in a trusted location", -1
    except Exception as e:
        return "", clean_text(e, 200), -1


def get_device_commands(os_type):
    """Get command suite for the detected OS."""
    suites = {
        "linux": {
            "hostname": "hostname",
            "os_info": "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 || uname -s",
            "architecture": "uname -m",
            "dpkg": "dpkg-query -W -f='${Package}|${Version}|${Maintainer}|${Status}|${installed-size}\\n' 2>/dev/null",
            "rpm": "rpm -qa --queryformat '%{NAME}|%{VERSION}|%{VENDOR}|installed|%{INSTALLTIME}\\n' 2>/dev/null",
            "pacman": "pacman -Qi --color never 2>/dev/null | grep -E '^(Name|Version|Packager|Install Date|Architecture|URL)'",
            "snap": "snap list 2>/dev/null",
            "pip": "pip3 list --format=json 2>/dev/null || pip list --format=json 2>/dev/null",
            "cpu": "lscpu 2>/dev/null | grep 'Model name' | cut -d: -f2",
            "memory": "free -h 2>/dev/null | grep Mem",
        },
        "windows": {
            "hostname": "hostname",
            "os_info": "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",
            "architecture": "echo %PROCESSOR_ARCHITECTURE%",
            "reg32": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s 2>nul | findstr /C:\"DisplayName\" /C:\"DisplayVersion\" /C:\"Publisher\" /C:\"InstallLocation\" /C:\"InstallDate\"",
            "reg64": "reg query \"HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s 2>nul | findstr /C:\"DisplayName\" /C:\"DisplayVersion\" /C:\"Publisher\" /C:\"InstallLocation\" /C:\"InstallDate\"",
            "winget": "winget list --accept-source-agreements 2>nul",
            "choco": "choco list -l -r 2>nul",
            "cpu": "wmic cpu get name 2>nul",
            "memory": "wmic computersystem get totalphysicalmemory 2>nul",
        },
        "macos": {
            "hostname": "hostname",
            "os_info": "sw_vers -productName && sw_vers -productVersion",
            "architecture": "uname -m",
            "apps": "system_profiler SPApplicationsDataType 2>/dev/null",
            "brew": "brew list --versions 2>/dev/null",
            "app_dir": "ls -1 /Applications/ 2>/dev/null",
            "cpu": "sysctl -n machdep.cpu.brand_string 2>/dev/null",
            "memory": "sysctl -n hw.memsize 2>/dev/null",
        },
    }
    return suites.get(os_type, {})


def detect_os(target, port, user, auth_args, timeout, verbose):
    """Detect remote OS via probe commands."""
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
        if os_hint == "windows" and ("windows" in output or "windows_nt" in output):
            return "windows"
        if os_hint == "macos" and "darwin" in output:
            return "macos"
    return "unknown"


def _app_record(name="", version="", source="", signer="", publisher="",
                install_location="", install_date="", architecture="", url=""):
    """Build a sanitised application record."""
    return {
        "name": clean_text(name, 256),
        "version": clean_text(version, 128),
        "last_update": clean_text(install_date, 64),
        "signer": clean_text(signer, 256),
        "install_location": clean_text(install_location, 512),
        "url": clean_text(url, 512),
        "publisher": clean_text(publisher, 256),
        "install_date": clean_text(install_date, 64),
        "architecture": clean_text(architecture, 32),
        "source": clean_text(source, 32),
    }


def parse_snap_list(output):
    """Parse `snap list` output (whitespace columns, not pipe-delimited)."""
    apps = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("name ", "error:", "no snaps")):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$", name):
            continue
        publisher = parts[4].rstrip("*✓") if len(parts) > 4 else ""
        apps.append(_app_record(
            name=name, version=parts[1], source="snap", publisher=publisher,
        ))
    return apps


def parse_pacman_query(output):
    """Parse `pacman -Qi` key/value blocks."""
    apps = []
    current = {}

    def flush():
        if current.get("Name"):
            apps.append(_app_record(
                name=current.get("Name", ""),
                version=current.get("Version", ""),
                source="pacman",
                signer=current.get("Packager", ""),
                publisher=current.get("Packager", ""),
                url=current.get("URL", ""),
                install_date=current.get("Install Date", ""),
                architecture=current.get("Architecture", ""),
            ))

    for line in output.splitlines():
        if not line.strip():
            flush()
            current = {}
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key in ("Name", "Version", "Packager", "Install Date",
                   "Architecture", "URL", "Description"):
            current[key] = value.strip()
    flush()
    return apps


def parse_choco_list(output):
    """Parse `choco list -l -r` output (`name|version`)."""
    apps = []
    for line in output.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        name, _, version = line.partition("|")
        name, version = name.strip(), version.strip()
        if not name or name.lower().startswith("chocolatey"):
            continue
        apps.append(_app_record(name=name, version=version, source="choco"))
    return apps


def parse_linux_apps(stdout_map):
    """Parse Linux application lists from dpkg, rpm, pacman, snap, and pip."""
    apps = []

    for source in ("dpkg", "rpm"):
        output = stdout_map.get(source, "")
        for line in output.splitlines():
            if "|" not in line:
                continue
            parts = line.split("|")
            app = _app_record(
                name=parts[0].strip(),
                version=parts[1].strip() if len(parts) > 1 else "",
                source=source,
                signer=parts[2].strip() if len(parts) > 2 else "",
                publisher=parts[2].strip() if len(parts) > 2 else "",
            )
            if app["name"]:
                apps.append(app)

    apps.extend(parse_pacman_query(stdout_map.get("pacman", "")))
    apps.extend(parse_snap_list(stdout_map.get("snap", "")))

    pip_out = stdout_map.get("pip", "")
    if pip_out:
        try:
            for pkg in json.loads(pip_out):
                apps.append(_app_record(
                    name=pkg.get("name", ""),
                    version=pkg.get("version", ""),
                    source="pip",
                ))
        except (json.JSONDecodeError, TypeError):
            pass

    return apps


def parse_windows_apps(stdout_map):
    """Parse Windows application lists.

    `reg query /s` emits one field per line inside a key block. A new
    DisplayName starts the next block, so fields must accumulate until then
    (or until a blank line) instead of being flushed as soon as a name exists.
    """
    apps = []

    for key in ("reg32", "reg64"):
        output = stdout_map.get(key, "")
        if not output:
            continue

        current = None

        def flush(apps=apps, current=None):
            if current and current.get("name"):
                apps.append(current)
            return None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                current = flush(apps, current)
                continue

            match = re.match(r"^(DisplayName|DisplayVersion|Publisher|InstallLocation|InstallDate)\s+REG_\w+\s+(.+)$", line)
            if not match:
                continue
            field, value = match.group(1), match.group(2).strip()

            if field == "DisplayName":
                current = flush(apps, current)
                current = _app_record(
                    name=value,
                    architecture="x86" if key == "reg32" else "x64",
                    source="registry",
                )
                continue

            if current is None:
                continue
            if field == "DisplayVersion":
                current["version"] = clean_text(value, 128)
            elif field == "Publisher":
                current["publisher"] = clean_text(value, 256)
                current["signer"] = clean_text(value, 256)
            elif field == "InstallLocation":
                current["install_location"] = clean_text(value, 512)
            elif field == "InstallDate":
                current["install_date"] = clean_text(value, 64)
                current["last_update"] = clean_text(value, 64)

        flush(apps, current)

    # winget
    winget_out = stdout_map.get("winget", "")
    if winget_out:
        for line in winget_out.strip().split("\n")[3:]:
            parts = line.split()
            if len(parts) >= 3 and not line.strip().startswith("-"):
                apps.append(_app_record(
                    name=" ".join(parts[:-2]),
                    version=parts[-2],
                    source="winget",
                    publisher=parts[-1] if len(parts) > 3 else "",
                ))

    apps.extend(parse_choco_list(stdout_map.get("choco", "")))
    return apps


def parse_macos_apps(stdout_map):
    """Parse macOS application lists."""
    apps = []
    output = stdout_map.get("apps", "")
    current = {}

    for line in output.split("\n"):
        if line.strip() and not line.startswith(" ") and not line.startswith("-"):
            name = line.strip().rstrip(":")
            if name and len(name) > 2 and "Version" not in name:
                if current.get("name"):
                    apps.append(current)
                current = _app_record(name=name, source="macos_apps")
        elif "Version:" in line and current:
            match = re.search(r"Version:\s*(.+)", line)
            if match:
                current["version"] = clean_text(match.group(1).strip(), 128)
        elif "Location:" in line and current:
            match = re.search(r"Location:\s*(.+)", line)
            if match:
                current["install_location"] = clean_text(match.group(1).strip(), 512)

    if current.get("name"):
        apps.append(current)

    # brew
    brew_out = stdout_map.get("brew", "")
    if brew_out:
        for line in brew_out.strip().split("\n"):
            parts = line.split()
            if parts:
                apps.append(_app_record(
                    name=parts[0],
                    version=parts[1] if len(parts) > 1 else "",
                    source="brew",
                ))

    return apps


def enumerate_device(target, port, user, auth_args, timeout, verbose):
    """Connect to a device, detect OS, run commands, and return structured data."""
    start = time.time()
    scan_methods = ["ssh"]

    os_type = detect_os(target, port, user, auth_args, timeout, verbose)
    scan_methods.append(f"os_detect_{os_type}")

    commands = get_device_commands(os_type)
    stdout_map = {}
    errors = []

    for label, cmd in commands.items():
        stdout, stderr, rc = run_plink(target, port, user, cmd, auth_args, timeout, verbose=verbose)
        stdout_map[label] = stdout
        scan_methods.append(label)
        if rc != 0 and stderr.strip():
            errors.append({"command": clean_text(label, 64),
                           "error": clean_text(stderr, 200)})

    # Parse applications
    parsers = {"linux": parse_linux_apps, "windows": parse_windows_apps, "macos": parse_macos_apps}
    apps = parsers.get(os_type, lambda x: [])(stdout_map)

    # Deduplicate
    seen = set()
    unique_apps = []
    for app in apps:
        key = f"{app['name']}|{app['version']}".lower()
        if key not in seen and app["name"]:
            seen.add(key)
            unique_apps.append(app)

    duration = time.time() - start

    return {
        "hostname": clean_text(stdout_map.get("hostname", "").strip(), 128),
        "os": clean_text(stdout_map.get("os_info", "").strip(), 200),
        "architecture": clean_text(stdout_map.get("architecture", "").strip(), 64),
        "cpu": clean_text(stdout_map.get("cpu", "").strip(), 200),
        "memory": clean_text(stdout_map.get("memory", "").strip(), 128),
        "applications": unique_apps,
        "scan_methods": [clean_text(method, 64) for method in scan_methods],
        "os_detected": os_type,
        "duration": round(duration, 2),
        "errors": errors,
    }


def build_device_json(device_info, enum_result, ip, mac, timestamp):
    """Build the final standardized JSON structure for a device."""
    return {
        "device": {
            "hostname": enum_result.get("hostname") or device_info.get("hostname") or ip,
            "ip_address": ip,
            "mac_address": mac,
            "os": enum_result.get("os") or "Unknown",
            "architecture": enum_result.get("architecture") or "",
            "scan_timestamp": timestamp,
            "scan_methods": enum_result.get("scan_methods", []),
        },
        "applications": enum_result.get("applications") or [],
        "scan_summary": {
            "total_applications": len(enum_result.get("applications") or []),
            "scan_duration_seconds": enum_result.get("duration", 0),
            "errors": enum_result.get("errors", []),
        },
    }


def save_device_json(report, output_dir, ip, hostname):
    """Save device report to a JSON file inside *output_dir*."""
    secure_output_dir(output_dir)
    safe_hostname = sanitize_filename_component(hostname or ip)
    safe_ip = sanitize_filename_component(str(ip).replace(".", "_"))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = f"{safe_hostname}_{safe_ip}_{timestamp}.json"
    filepath = safe_output_path(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    secure_file(filepath)

    return filepath


def scan_and_populate(network_range=None, mode="all", interface_idx=None, max_devices=None,
                      port=22, user="root", auth_args=None, timeout=30,
                      output_dir="./output/", verbose=False, quiet=False):
    """Main pipeline: discover devices, enumerate each, write JSON files."""
    if auth_args is None:
        auth_args = []

    start_time = time.time()

    if not quiet:
        print("=" * 60)
        print("  Flash_Network — Device Scanner & JSON Reporter")
        print("=" * 60)

    prereqs = check_prerequisites(verbose)
    if not prereqs["plink"]["available"]:
        print("[FATAL] plink is required. Install PuTTY and add to PATH.")
        sys.exit(1)

    if not network_range:
        network_range = get_local_network_range()
        if not network_range:
            print("[ERROR] Could not auto-detect a usable IPv4 network. "
                  "Pass --range/-r explicitly.")
            sys.exit(1)
        if not quiet:
            print(f"[AUTO] Detected network range: {network_range}")

    if not quiet:
        print(f"\n[DISCOVERY] Scanning {network_range} (mode: {mode})...")

    devices = discover_devices(network_range, mode, interface_idx, max_devices, verbose)

    if not devices:
        print("[INFO] No devices discovered.")
        return []

    if not quiet:
        print(f"\n[SCAN] Found {len(devices)} device(s). Enumerating...")

    results = []
    for i, dev in enumerate(devices, 1):
        ip = dev["ip"]
        if not is_valid_ipv4(ip):
            results.append({"ip": clean_text(ip, 64), "hostname": "", "status": "error",
                            "error": "Refusing non-IPv4 target"})
            continue
        mac = dev.get("mac", "N/A")
        hostname = dev.get("hostname", ip)
        timestamp = datetime.now(timezone.utc).isoformat()

        if not quiet:
            print(f"\n  [{i}/{len(devices)}] {clean_text(hostname, 128)} ({ip})...")

        try:
            enum_result = enumerate_device(ip, port, user, auth_args, timeout, verbose)

            report = build_device_json(dev, enum_result, ip, mac, timestamp)
            filepath = save_device_json(
                report, output_dir, ip, enum_result.get("hostname") or hostname
            )

            results.append({"ip": ip, "hostname": hostname, "status": "success", "file": filepath,
                            "apps": len(report["applications"]), "duration": enum_result["duration"]})

            if not quiet:
                print(f"    [+] {clean_text(enum_result.get('os_detected', 'unknown'), 32)} | "
                      f"{len(report['applications'])} apps | {enum_result['duration']}s | {filepath}")

        except Exception as e:
            results.append({"ip": ip, "hostname": hostname, "status": "error", "error": str(e)})
            if not quiet:
                print(f"    [-] Failed: {clean_text(e, 200)}")

    total_time = round(time.time() - start_time, 2)
    successful = sum(1 for r in results if r["status"] == "success")
    total_apps = sum(r.get("apps", 0) for r in results if r["status"] == "success")

    # Keep scan_index.json current, but archive the previous index so history
    # is not lost every time the scanner runs.
    secure_output_dir(output_dir)
    index_path = safe_output_path(output_dir, "scan_index.json")
    if os.path.exists(index_path):
        archive_name = (
            "scan_index_"
            + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
            + ".json"
        )
        archive_path = safe_output_path(output_dir, archive_name)
        try:
            try:
                os.replace(index_path, archive_path)
            except OSError:
                shutil.copy2(index_path, archive_path)
                os.remove(index_path)
            secure_file(archive_path)
        except OSError as exc:
            print(f"[WARN] Could not archive previous scan index: {clean_text(exc, 200)}")

    index = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "network_range": network_range,
        "mode": mode,
        "total_devices_discovered": len(devices),
        "total_devices_scanned": successful,
        "total_applications_found": total_apps,
        "total_duration_seconds": total_time,
        "devices": results,
    }
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
    secure_file(index_path)

    if not quiet:
        print("\n" + "=" * 60)
        print("  SCAN COMPLETE")
        print("=" * 60)
        print(f"  Devices discovered : {len(devices)}")
        print(f"  Devices scanned    : {successful}")
        print(f"  Total applications : {total_apps}")
        print(f"  Total duration     : {total_time}s")
        print(f"  Output directory   : {os.path.abspath(output_dir)}")
        print(f"  Scan index         : {index_path}")
        print("=" * 60 + "\n")

    return results


def main():
    network_range = None
    mode = "all"
    interface_idx = None
    max_devices = None
    port = 22
    user = "root"
    key_file = None
    password_file = None
    ask_password = False
    password_stdin = False
    hostkey = None
    insecure_hostkey = False
    output_dir = "./output/"
    timeout = 30
    verbose = False
    quiet = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("-r", "--range") and i + 1 < len(args):
            network_range = args[i + 1]
            i += 2
        elif args[i] in ("-m", "--mode") and i + 1 < len(args):
            mode = args[i + 1]
            i += 2
        elif args[i] in ("-i", "--interface") and i + 1 < len(args):
            interface_idx = parse_int_arg(args[i + 1], args[i], minimum=0)
            i += 2
        elif args[i] in ("-n", "--max-devices") and i + 1 < len(args):
            max_devices = parse_int_arg(args[i + 1], args[i], minimum=1)
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
        elif args[i] in ("-t", "--timeout") and i + 1 < len(args):
            timeout = parse_int_arg(args[i + 1], args[i], minimum=1, maximum=3600)
            i += 2
        elif args[i] == "--list-interfaces":
            try:
                tshark = resolve_tool("tshark")
                if not tshark:
                    raise FileNotFoundError("tshark not found in a trusted location")
                result = run_bounded([tshark, "-D"], timeout=10,
                                     max_stdout=1024 * 1024, max_stderr=64 * 1024)
                print("Available interfaces:")
                for line in result.stdout.strip().split("\n"):
                    print(f"  {clean_text(line, 256)}")
            except Exception as e:
                print(f"[ERROR] {clean_text(e, 200)}")
            sys.exit(0)
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

    valid_modes = ("ping", "arp", "tshark", "all")
    if mode not in valid_modes:
        sys.exit(f"[ERROR] Invalid mode {mode!r}. Choose one of: {', '.join(valid_modes)}.")
    if mode == "tshark" and interface_idx is None:
        sys.exit("[ERROR] --mode tshark requires --interface INDEX (see --list-interfaces).")

    user = validate_user(user)

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
        scan_and_populate(
            network_range=network_range, mode=mode, interface_idx=interface_idx,
            max_devices=max_devices, port=port, user=user, auth_args=auth_args,
            timeout=timeout, output_dir=output_dir, verbose=verbose, quiet=quiet
        )
    finally:
        remove_password_file(password_path)


if __name__ == "__main__":
    main()
