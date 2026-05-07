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
import ipaddress
from datetime import datetime, timezone
from collections import defaultdict


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

    -pw, --password PWD    SSH password (fallback if key not provided)

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

    Scan with password authentication:
        python device_scanner.py -r 10.0.0.0/24 -u admin -pw SecretPass

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
    """Check if tshark and plink are available."""
    tools = {}
    for tool in ("tshark", "plink"):
        try:
            result = subprocess.run(
                [tool, "--version" if tool == "tshark" else "-V"],
                capture_output=True, text=True, timeout=10
            )
            out = (result.stdout + result.stderr).strip()
            version = out.split("\n")[0] if out else "found"
            tools[tool] = {"available": True, "version": version}
            if not verbose:
                print(f"[OK] {tool}: {version}")
        except FileNotFoundError:
            tools[tool] = {"available": False, "version": None}
            print(f"[ERROR] {tool} not found in PATH.")
        except Exception as e:
            tools[tool] = {"available": False, "version": None}
            print(f"[ERROR] {tool} check failed: {e}")
    return tools


def get_local_network_range():
    """Auto-detect local network CIDR range."""
    try:
        result = subprocess.run(
            ["ipconfig" if sys.platform == "win32" else "ip", "addr" if sys.platform != "win32" else ""],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout
        ips = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})", output)
        for ip, mask in ips:
            if not ip.startswith("127.") and int(mask) <= 24:
                return f"{ip}/{mask}"
    except Exception:
        pass
    return "192.168.1.0/24"


def discover_devices_ping(network_range, max_devices=None, timeout=2, verbose=False):
    """Discover live devices via ICMP ping sweep."""
    try:
        net = ipaddress.ip_network(network_range, strict=False)
    except ValueError:
        print(f"[ERROR] Invalid network range: {network_range}")
        return []

    devices = []
    hosts = list(net.hosts())
    if max_devices:
        hosts = hosts[:max_devices]

    if verbose:
        print(f"\n[PING] Sweeping {len(hosts)} hosts in {network_range}...")

    procs = {}
    for host in hosts:
        ip = str(host)
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip] if sys.platform == "win32" \
              else ["ping", "-c", "1", "-W", str(timeout), ip]
        procs[ip] = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    for ip, proc in procs.items():
        proc.wait()
        if proc.returncode == 0:
            devices.append({"ip": ip, "mac": "N/A", "hostname": ip, "method": "ping"})
            if verbose:
                print(f"  [+] {ip} is alive")

    return devices


def discover_devices_arp(network_range, verbose=False):
    """Discover devices via ARP table and arping."""
    devices = []
    try:
        if sys.platform == "win32":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split("\n"):
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f\-]{17})", line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":")
                    devices.append({"ip": ip, "mac": mac, "hostname": ip, "method": "arp"})
        else:
            result = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split("\n"):
                parts = line.split()
                if len(parts) >= 3 and parts[2] != "FAILED" and parts[2] != "INCOMPLETE":
                    devices.append({"ip": parts[0], "mac": parts[2], "hostname": parts[0], "method": "arp"})
    except Exception as e:
        if verbose:
            print(f"[WARN] ARP discovery failed: {e}")

    return devices


def discover_devices_tshark(interface_idx=None, duration=10, verbose=False):
    """Discover devices via tshark packet capture."""
    devices = []
    try:
        cmd = ["tshark", "-a", f"duration:{duration}", "-T", "fields",
               "-e", "ip.src", "-e", "ip.dst", "-e", "eth.src", "-e", "eth.dst",
               "-e", "dhcp.options.hostname", "-e", "mdns.host_name",
               "-E", "separator=|"]
        if interface_idx is not None:
            cmd.insert(1, "-i")
            cmd.insert(2, str(interface_idx))

        if verbose:
            print(f"\n[TSHARK] Capturing {duration}s for device discovery...")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 30)
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

                if ip and not ip.startswith(("127.", "224.", "239.", "255.")) and ip not in seen_ips:
                    seen_ips[ip] = True
                    devices.append({
                        "ip": ip,
                        "mac": mac if mac != "00:00:00:00:00:00" else "N/A",
                        "hostname": hostname if hostname else ip,
                        "method": "tshark",
                    })
    except Exception as e:
        if verbose:
            print(f"[WARN] tshark discovery failed: {e}")

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
        for dev in discover_devices_tshark(interface_idx, verbose=verbose):
            if dev["ip"] not in all_devices:
                all_devices[dev["ip"]] = dev

    devices = list(all_devices.values())
    if max_devices:
        devices = devices[:max_devices]

    return devices


def run_plink(target, port, user, cmd, auth_args, timeout=30, batch=True, verbose=False):
    """Execute a single command on a remote device via plink."""
    base_cmd = ["plink"]
    if batch:
        base_cmd.append("-batch")
    base_cmd.extend(["-P", str(port), "-l", user])
    if auth_args:
        base_cmd.extend(auth_args)
    base_cmd.extend([target, cmd])

    try:
        result = subprocess.run(base_cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1
    except Exception as e:
        return "", str(e), -1


def get_device_commands(os_type):
    """Get command suite for the detected OS."""
    suites = {
        "linux": {
            "hostname": "hostname",
            "os_info": "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 || uname -s",
            "architecture": "uname -m",
            "dpkg": "dpkg-query -W -f='${Package}|${Version}|${Maintainer}|${Status}|${installed-size}\\n' 2>/dev/null",
            "rpm": "rpm -qa --queryformat '%{NAME}|%{VERSION}|%{VENDOR}|installed|%{INSTALLTIME}\\n' 2>/dev/null",
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


def parse_linux_apps(stdout_map):
    """Parse Linux application lists."""
    apps = []
    sources = {"dpkg": "dpkg", "rpm": "rpm", "snap": "snap", "pip": "pip"}

    for key, source in sources.items():
        output = stdout_map.get(key, "")
        if not output:
            continue

        if source == "pip":
            try:
                for pkg in json.loads(output):
                    apps.append({
                        "name": pkg.get("name", ""),
                        "version": pkg.get("version", ""),
                        "last_update": "",
                        "signer": "",
                        "install_location": "",
                        "url": "",
                        "publisher": "",
                        "install_date": "",
                        "architecture": "",
                        "source": "pip",
                    })
            except json.JSONDecodeError:
                pass
        else:
            for line in output.strip().split("\n"):
                if "|" not in line:
                    continue
                parts = line.split("|")
                app = {
                    "name": parts[0].strip(),
                    "version": parts[1].strip() if len(parts) > 1 else "",
                    "last_update": "",
                    "signer": parts[2].strip() if len(parts) > 2 else "",
                    "install_location": "",
                    "url": "",
                    "publisher": parts[2].strip() if len(parts) > 2 else "",
                    "install_date": "",
                    "architecture": "",
                    "source": source,
                }
                if app["name"]:
                    apps.append(app)

    return apps


def parse_windows_apps(stdout_map):
    """Parse Windows application lists."""
    apps = []

    for key in ("reg32", "reg64"):
        output = stdout_map.get(key, "")
        if not output:
            continue

        current = {}
        for line in output.strip().split("\n"):
            line = line.strip()
            if "DisplayName" in line and "REG_SZ" in line:
                match = re.search(r"REG_SZ\s+(.+)", line)
                if match:
                    current = {
                        "name": match.group(1).strip(),
                        "version": "",
                        "last_update": "",
                        "signer": "",
                        "install_location": "",
                        "url": "",
                        "publisher": "",
                        "install_date": "",
                        "architecture": "x86" if key == "reg32" else "x64",
                        "source": "registry",
                    }
            elif current:
                for field, reg_key in [("version", "DisplayVersion"), ("publisher", "Publisher"),
                                        ("signer", "Publisher"), ("install_location", "InstallLocation"),
                                        ("install_date", "InstallDate"), ("last_update", "InstallDate")]:
                    if reg_key in line and "REG_SZ" in line:
                        match = re.search(r"REG_SZ\s+(.+)", line)
                        if match:
                            current[field] = match.group(1).strip()

                if current.get("name") and current.get("version"):
                    apps.append(current)
                    current = {}

    # winget
    winget_out = stdout_map.get("winget", "")
    if winget_out:
        for line in winget_out.strip().split("\n")[3:]:
            parts = line.split()
            if len(parts) >= 3:
                apps.append({
                    "name": " ".join(parts[:-2]),
                    "version": parts[-2],
                    "last_update": "",
                    "signer": "",
                    "install_location": "",
                    "url": "",
                    "publisher": parts[-1] if len(parts) > 3 else "",
                    "install_date": "",
                    "architecture": "",
                    "source": "winget",
                })

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
                current = {
                    "name": name, "version": "", "last_update": "", "signer": "",
                    "install_location": "", "url": "", "publisher": "",
                    "install_date": "", "architecture": "", "source": "macos_apps",
                }
        elif "Version:" in line and current:
            match = re.search(r"Version:\s*(.+)", line)
            if match:
                current["version"] = match.group(1).strip()
        elif "Location:" in line and current:
            match = re.search(r"Location:\s*(.+)", line)
            if match:
                current["install_location"] = match.group(1).strip()

    if current.get("name"):
        apps.append(current)

    # brew
    brew_out = stdout_map.get("brew", "")
    if brew_out:
        for line in brew_out.strip().split("\n"):
            parts = line.split()
            if parts:
                apps.append({
                    "name": parts[0],
                    "version": parts[1] if len(parts) > 1 else "",
                    "last_update": "", "signer": "", "install_location": "",
                    "url": "", "publisher": "", "install_date": "",
                    "architecture": "", "source": "brew",
                })

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
            errors.append({"command": label, "error": stderr[:200]})

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
        "hostname": stdout_map.get("hostname", "").strip(),
        "os": stdout_map.get("os_info", "").strip()[:200],
        "architecture": stdout_map.get("architecture", "").strip(),
        "cpu": stdout_map.get("cpu", "").strip(),
        "memory": stdout_map.get("memory", "").strip(),
        "applications": unique_apps,
        "scan_methods": scan_methods,
        "os_detected": os_type,
        "duration": round(duration, 2),
        "errors": errors,
    }


def build_device_json(device_info, enum_result, ip, mac, timestamp):
    """Build the final standardized JSON structure for a device."""
    return {
        "device": {
            "hostname": enum_result.get("hostname", device_info.get("hostname", ip)),
            "ip_address": ip,
            "mac_address": mac,
            "os": enum_result.get("os", "Unknown"),
            "architecture": enum_result.get("architecture", ""),
            "scan_timestamp": timestamp,
            "scan_methods": enum_result.get("scan_methods", []),
        },
        "applications": enum_result.get("applications", []),
        "scan_summary": {
            "total_applications": len(enum_result.get("applications", [])),
            "scan_duration_seconds": enum_result.get("duration", 0),
            "errors": enum_result.get("errors", []),
        },
    }


def save_device_json(report, output_dir, ip, hostname):
    """Save device report to a JSON file."""
    os.makedirs(output_dir, exist_ok=True)
    safe_hostname = (hostname or ip).replace(" ", "_").replace("/", "_")
    safe_ip = ip.replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = f"{safe_hostname}_{safe_ip}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

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
        mac = dev.get("mac", "N/A")
        hostname = dev.get("hostname", ip)
        timestamp = datetime.now(timezone.utc).isoformat()

        if not quiet:
            print(f"\n  [{i}/{len(devices)}] {hostname} ({ip})...")

        try:
            enum_result = enumerate_device(ip, port, user, auth_args, timeout, verbose)

            report = build_device_json(dev, enum_result, ip, mac, timestamp)
            filepath = save_device_json(report, output_dir, ip, enum_result.get("hostname", hostname))

            results.append({"ip": ip, "hostname": hostname, "status": "success", "file": filepath,
                            "apps": len(report["applications"]), "duration": enum_result["duration"]})

            if not quiet:
                print(f"    [+] {enum_result.get('os_detected', 'unknown')} | "
                      f"{len(report['applications'])} apps | {enum_result['duration']}s | {filepath}")

        except Exception as e:
            results.append({"ip": ip, "hostname": hostname, "status": "error", "error": str(e)})
            if not quiet:
                print(f"    [-] Failed: {e}")

    total_time = round(time.time() - start_time, 2)
    successful = sum(1 for r in results if r["status"] == "success")
    total_apps = sum(r.get("apps", 0) for r in results if r["status"] == "success")

    # Write scan index
    os.makedirs(output_dir, exist_ok=True)
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
    index_path = os.path.join(output_dir, "scan_index.json")
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)

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
    password = None
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
            interface_idx = int(args[i + 1])
            i += 2
        elif args[i] in ("-n", "--max-devices") and i + 1 < len(args):
            max_devices = int(args[i + 1])
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
        elif args[i] in ("-t", "--timeout") and i + 1 < len(args):
            timeout = int(args[i + 1])
            i += 2
        elif args[i] == "--list-interfaces":
            try:
                result = subprocess.run(["tshark", "-D"], capture_output=True, text=True, timeout=10)
                print("Available interfaces:")
                for line in result.stdout.strip().split("\n"):
                    print(f"  {line}")
            except Exception as e:
                print(f"[ERROR] {e}")
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
            i += 1

    auth_args = []
    if key_file:
        auth_args.extend(["-i", key_file])
    if password:
        auth_args.extend(["-pw", password])

    scan_and_populate(
        network_range=network_range, mode=mode, interface_idx=interface_idx,
        max_devices=max_devices, port=port, user=user, auth_args=auth_args,
        timeout=timeout, output_dir=output_dir, verbose=verbose, quiet=quiet
    )


if __name__ == "__main__":
    main()
