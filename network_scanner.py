"""
Flash_Network — Wireshark Network Analyzer
Uses tshark (Wireshark CLI) to capture and analyze local network traffic.
Extracts: active IPs, MAC addresses, device types, protocols, and throughput.

Requirements:
  - Wireshark installed with tshark in PATH
  - Run as Administrator (Windows) or root (Linux) for packet capture
"""

import subprocess
import sys
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from collections import defaultdict


# Capture safety limits. A long scan must not grow memory without bound.
MAX_CAPTURE_PACKETS = 200_000
MAX_TIMELINE_POINTS = 20_000


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


def safe_int(value, default=0):
    """Parse an integer, returning *default* for blank or malformed input."""
    try:
        text = str(value).strip()
        if not text:
            return default
        return int(float(text)) if ("." in text or "e" in text.lower()) else int(text)
    except (TypeError, ValueError, OverflowError):
        return default


def safe_float(value, default=0.0):
    """Parse a float, returning *default* for blank or malformed input."""
    try:
        text = str(value).strip()
        return float(text) if text else default
    except (TypeError, ValueError, OverflowError):
        return default


def is_usable_mac(mac):
    """Return True for a unicast, non-empty hardware address."""
    if not mac:
        return False
    lowered = mac.strip().lower()
    if lowered in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    try:
        return not (int(lowered.split(":")[0], 16) & 1)
    except (ValueError, IndexError):
        return False


def new_device(mac):
    return {
        "mac": mac,
        "ips": set(),
        "protocols": set(),
        "bytes_sent": 0,
        "bytes_received": 0,
        "packets_sent": 0,
        "packets_received": 0,
        "hostname": "",
        "device_type": "Unknown",
        "hints": [],
    }


def print_usage():
    """Display detailed usage information and exit."""
    usage = """
Flash_Network — Wireshark Network Scanner
=========================================

DESCRIPTION:
    Captures live network traffic using tshark (Wireshark CLI) and analyzes
    active devices, protocols, throughput, and device fingerprints.
    Results are saved as structured JSON to the output/ directory.

USAGE:
    python network_scanner.py [options]

OPTIONS:
    -d, --duration SEC     Capture duration in seconds (default: 15)
                           Range: 5-300 seconds. Shorter scans may miss
                           infrequent protocols; longer scans increase
                           device discovery accuracy.

    -i, --interface NUM    Network interface index for capture.
                           Run with --list-interfaces to see available
                           interfaces and their indices.

    -o, --output DIR       Output directory for JSON reports.
                           Default: ./output/

    -f, --filter BPF       Apply a BPF capture filter (e.g. "port 80",
                           "host 192.168.1.1", "arp").
                           Overrides the default protocol-focused capture.

    --list-interfaces      List available network interfaces and exit.
                           Use the index with -i to select one.

    --protocols            Print supported protocol filters and exit.

    -v, --verbose          Enable verbose output with per-packet details.

    -q, --quiet            Suppress console output. Only write JSON report.

    --keep-pcap            Keep the temporary .pcapng capture file. By default
                           the capture is created with owner-only permissions
                           in the system temp directory and deleted after
                           analysis, so packet data is not left behind.

    -h, --help             Show this help message and exit.

EXAMPLES:
    Quick scan on auto-detected interface (15s):
        python network_scanner.py

    30-second capture on interface 3:
        python network_scanner.py -i 3 -d 30

    Capture only ARP and DNS traffic:
        python network_scanner.py -f "arp or dns" -d 20

    List available interfaces:
        python network_scanner.py --list-interfaces

    Verbose scan with custom output directory:
        python network_scanner.py -v -o ./reports/ -d 60

    Quiet mode (JSON only):
        python network_scanner.py -q -d 10

REQUIREMENTS:
    - Wireshark installed with tshark in system PATH
    - Administrator (Windows) or root (Linux/macOS) privileges
      for packet capture on network interfaces

OUTPUT:
    JSON report saved to: output/network_scan_YYYYMMDD_HHMMSS.json

    The report contains:
      - scan_metadata: interface, timestamp, duration
      - throughput: avg/peak bandwidth, total bytes/packets
      - protocol_distribution: protocol name -> packet count
      - devices: per-device MAC, IPs, hostname, type, traffic stats

SUPPORTED PROTOCOL FILTERS:
    arp, bootp, dns, mdns, ssdp, http, tcp, udp, icmp,
    dhcp, llmnr, nbns, igmp, ospf, bgp, ssh, tls

AUTHOR:
    Flash_Network Project
"""
    print(usage)


def check_tshark():
    """Check if tshark is available on the system."""
    try:
        result = subprocess.run(
            ["tshark", "--version"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            version_line = result.stdout.split("\n")[0]
            print(f"[OK] tshark found: {version_line}")
            return True
        print("[ERROR] tshark returned non-zero exit code.")
        return False
    except FileNotFoundError:
        print("[ERROR] tshark not found. Install Wireshark and add to PATH.")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def get_interfaces():
    """List available network interfaces for capture."""
    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True, text=True, timeout=10
        )
        interfaces = []
        for line in result.stdout.strip().split("\n"):
            match = re.match(r"(\d+)\.\s+([^\s]+)\s+(.*)", line)
            if match:
                interfaces.append({
                    "index": int(match.group(1)),
                    "name": match.group(2),
                    "description": match.group(3),
                })
        return interfaces
    except Exception as e:
        print(f"[ERROR] Failed to list interfaces: {e}")
        return []


def find_active_interface(interfaces):
    """Heuristic: pick the first non-loopback interface."""
    for iface in interfaces:
        if "loopback" not in iface["description"].lower() \
           and "loopback" not in iface["name"].lower():
            return iface
    return interfaces[0] if interfaces else None


def capture_traffic(interface, duration=15, bpf_filter=None):
    """
    Capture traffic using tshark and return the pcap path plus parsed packets.
    Fields extracted per packet:
      frame.time_epoch, eth.src, eth.dst, ip.src, ip.dst,
      frame.protocols, frame.len, _ws.col.Protocol

    The capture file is created in the system temp directory with a random
    name and owner-only permissions. Callers are responsible for deleting it
    unless the operator explicitly asked to keep it.
    """
    fd, pcap_file = tempfile.mkstemp(prefix="flashnet_capture_", suffix=".pcapng")
    os.close(fd)
    secure_file(pcap_file)

    fields = [
        "frame.time_epoch",
        "frame.number",
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "frame.len",
        "frame.protocols",
        "_ws.col.Protocol",
        "dhcp.options.hostname",
        "http.host",
        "http.user_agent",
        "mdns.host_name",
        "ssdp.st",
    ]

    cmd = [
        "tshark",
        "-i", str(interface["index"]),
        "-a", f"duration:{duration}",
        "-w", pcap_file,
        "-T", "fields",
        "-E", "separator=|",
        "-E", "occurrence=f",
        "-E", "header=n",
    ]
    for f in fields:
        cmd.extend(["-e", f])

    if bpf_filter:
        cmd.append(bpf_filter)

    print(f"\n[CAPTURE] Capturing {duration}s on interface {interface['name']} ({interface['description']})...")
    print(f"        Temporary capture: {pcap_file}")

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    if process.returncode != 0 and stderr.strip():
        print(f"[WARN] tshark exited {process.returncode}: {stderr.strip()[:200]}")

    packets = []
    truncated = False
    for line in stdout.splitlines():
        if not line.strip():
            continue
        if len(packets) >= MAX_CAPTURE_PACKETS:
            truncated = True
            break
        parts = line.split("|")
        pkt = {fields[i]: parts[i] if i < len(parts) else "" for i in range(len(fields))}
        packets.append(pkt)

    if truncated:
        print(f"[WARN] Capture exceeded {MAX_CAPTURE_PACKETS} packets; "
              f"analysis truncated to the first {MAX_CAPTURE_PACKETS}.")

    return pcap_file, packets


def analyze_packets(packets):
    """Analyze captured packets and produce structured network info."""
    devices = {}
    protocol_counts = defaultdict(int)
    timeline = []
    total_bytes = 0
    timeline_stride = max(1, len(packets) // MAX_TIMELINE_POINTS)

    for index, pkt in enumerate(packets):
        src_mac = (pkt.get("eth.src") or "").strip()
        dst_mac = (pkt.get("eth.dst") or "").strip()
        src_ip = (pkt.get("ip.src") or "").strip()
        dst_ip = (pkt.get("ip.dst") or "").strip()
        frame_len = safe_int(pkt.get("frame.len"), 0)
        protocols = (pkt.get("frame.protocols") or "").strip()
        col_proto = (pkt.get("_ws.col.Protocol") or "").strip()
        hostname = (pkt.get("dhcp.options.hostname") or "").strip()
        http_host = (pkt.get("http.host") or "").strip()
        user_agent = (pkt.get("http.user_agent") or "").strip()
        mdns_name = (pkt.get("mdns.host_name") or "").strip()
        epoch = safe_float(pkt.get("frame.time_epoch"), 0.0)

        if not src_mac and not src_ip:
            continue

        total_bytes += frame_len

        # Protocol stats
        if col_proto:
            protocol_counts[col_proto] += 1

        # Timeline is sampled so a long capture cannot grow without bound.
        if epoch > 0 and index % timeline_stride == 0:
            timeline.append({"time": epoch, "len": frame_len, "proto": col_proto})

        # Device tracking by MAC
        for mac, ip, direction in [
            (src_mac, src_ip, "sent"),
            (dst_mac, dst_ip, "received"),
        ]:
            if not is_usable_mac(mac):
                continue
            if mac not in devices:
                devices[mac] = new_device(mac)
            dev = devices[mac]
            if ip:
                dev["ips"].add(ip)
            dev[f"bytes_{direction}"] += frame_len
            dev[f"packets_{direction}"] += 1

            # Collect protocol hints
            for p in protocols.split(":"):
                p = p.strip()
                if p and p not in ("eth", "ethertype", "ip", "ipv6", "frame"):
                    dev["protocols"].add(p)

        # Hostname / device type hints are only attributed to a real source
        # MAC. Previously an empty eth.src created a phantom device.
        if not is_usable_mac(src_mac) or src_mac not in devices:
            continue

        dev = devices[src_mac]
        if hostname and not dev["hostname"]:
            dev["hostname"] = hostname
        if mdns_name and not dev["hostname"]:
            dev["hostname"] = mdns_name

        if user_agent:
            dev["hints"].append(f"UA: {user_agent}")
            ua_lower = user_agent.lower()
            # Check mobile platforms before desktop ones: Android UAs contain
            # "Linux" and iOS UAs contain "Macintosh".
            if "android" in ua_lower:
                dev["device_type"] = "Android"
            elif "iphone" in ua_lower or "ipad" in ua_lower:
                dev["device_type"] = "iOS"
            elif "windows" in ua_lower:
                dev["device_type"] = "Windows PC"
            elif "macintosh" in ua_lower or "darwin" in ua_lower:
                dev["device_type"] = "macOS"
            elif "linux" in ua_lower:
                dev["device_type"] = "Linux"

        if http_host:
            dev["hints"].append(f"HTTP Host: {http_host}")

    # Infer device type from MAC OUI patterns if still Unknown
    for mac, dev in devices.items():
        if dev["device_type"] == "Unknown" and is_usable_mac(mac):
            oui = mac[:8].upper()
            if oui in ("00:1A:", "00:1B:", "00:22:", "AC:DE:"):
                dev["device_type"] = "Router / Network Device"
            elif oui in ("00:0C:", "00:0D:", "00:1E:"):
                dev["device_type"] = "IoT Device"

    return devices, total_bytes, protocol_counts, timeline


def calculate_throughput(timeline, window_sec=1.0, total_bytes=None, total_packets=None):
    """Calculate throughput in bytes/sec over time windows."""
    if not timeline:
        return {"avg_bps": 0, "peak_bps": 0, "total_bytes": 0, "duration_sec": 0}

    timeline.sort(key=lambda x: x["time"])
    start = timeline[0]["time"]
    end = timeline[-1]["time"]
    duration = max(end - start, 0.001)

    if total_bytes is None:
        total_bytes = sum(p["len"] for p in timeline)
    avg_bps = (total_bytes * 8) / duration

    # Peak throughput in windows
    windows = defaultdict(int)
    for p in timeline:
        w = int((p["time"] - start) / window_sec)
        windows[w] += p["len"]

    peak_bytes = max(windows.values()) if windows else 0
    peak_bps = (peak_bytes * 8) / window_sec

    return {
        "avg_bps": round(avg_bps, 2),
        "avg_mbps": round(avg_bps / 1_000_000, 4),
        "peak_bps": round(peak_bps, 2),
        "peak_mbps": round(peak_bps / 1_000_000, 4),
        "total_bytes": total_bytes,
        "duration_sec": round(duration, 2),
        "total_packets": total_packets if total_packets is not None else len(timeline),
        "timeline_sampled": total_packets is not None and total_packets > len(timeline),
    }


def generate_report(devices, throughput, protocol_counts, interface, duration, capture_file, output_dir="output"):
    """Generate a structured report and save to JSON."""
    device_list = []
    for mac, dev in sorted(devices.items(), key=lambda x: x[1]["bytes_sent"] + x[1]["bytes_received"], reverse=True):
        device_list.append({
            "mac_address": mac,
            "ip_addresses": sorted(list(dev["ips"])),
            "hostname": dev["hostname"] if dev["hostname"] else "N/A",
            "device_type": dev["device_type"],
            "protocols_observed": sorted(list(dev["protocols"])),
            "traffic": {
                "bytes_sent": dev["bytes_sent"],
                "bytes_received": dev["bytes_received"],
                "total_bytes": dev["bytes_sent"] + dev["bytes_received"],
                "packets_sent": dev["packets_sent"],
                "packets_received": dev["packets_received"],
            },
            "hints": dev["hints"][:10],
        })

    report = {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "interface": interface["name"],
            "interface_description": interface["description"],
            "capture_duration_sec": duration,
            "capture_file": capture_file or "(not retained)",
        },
        "throughput": throughput,
        "protocol_distribution": dict(sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)),
        "devices_detected": len(device_list),
        "devices": device_list,
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    secure_output_dir(output_dir)

    json_path = os.path.join(output_dir, f"network_scan_{timestamp}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    secure_file(json_path)

    return report, json_path


def print_summary(report):
    """Print a human-readable summary to console."""
    meta = report["scan_metadata"]
    tp = report["throughput"]

    print("\n" + "=" * 60)
    print("  FLASH_NETWORK — Wireshark Scan Summary")
    print("=" * 60)
    print(f"  Interface   : {meta['interface_description']}")
    print(f"  Duration    : {meta['capture_duration_sec']}s")
    print(f"  Timestamp   : {meta['timestamp']}")
    print("-" * 60)

    print(f"\n  THROUGHPUT:")
    print(f"    Avg  : {tp['avg_mbps']:.4f} Mbps ({tp['avg_bps']:,.0f} bps)")
    print(f"    Peak : {tp['peak_mbps']:.4f} Mbps ({tp['peak_bps']:,.0f} bps)")
    print(f"    Total: {tp['total_bytes']:,} bytes over {tp['duration_sec']}s")
    print(f"    Packets: {tp['total_packets']:,}")

    print(f"\n  PROTOCOL DISTRIBUTION (Top 15):")
    for proto, count in list(report["protocol_distribution"].items())[:15]:
        bar = "#" * min(count, 50)
        print(f"    {proto:<20} {count:>6}  {bar}")

    print(f"\n  DEVICES DETECTED: {report['devices_detected']}")
    print("-" * 60)

    for i, dev in enumerate(report["devices"], 1):
        print(f"\n  [{i}] {dev['hostname']}")
        print(f"      MAC     : {dev['mac_address']}")
        print(f"      IPs     : {', '.join(dev['ip_addresses']) if dev['ip_addresses'] else 'N/A'}")
        print(f"      Type    : {dev['device_type']}")
        print(f"      Traffic : {dev['traffic']['total_bytes']:,} bytes "
              f"({dev['traffic']['packets_sent']}↑ / {dev['traffic']['packets_received']}↓)")
        if dev["protocols_observed"]:
            print(f"      Protocols: {', '.join(dev['protocols_observed'][:8])}")
        if dev["hints"]:
            for h in dev["hints"][:3]:
                print(f"      Hint    : {h}")

    print("\n" + "=" * 60)
    print(f"  Full report saved to: {report.get('_output_path', 'N/A')}")
    print("=" * 60 + "\n")


def parse_positive_int(value, option, minimum=1, maximum=86400):
    """Parse a CLI integer with a clear error instead of a traceback."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        sys.exit(f"[ERROR] {option} expects an integer, got: {value!r}")
    if number < minimum or number > maximum:
        sys.exit(f"[ERROR] {option} must be between {minimum} and {maximum}, got: {number}")
    return number


def main():
    duration = 15
    iface_index = None
    output_dir = "output"
    bpf_filter = None
    verbose = False
    quiet = False
    keep_pcap = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-d", "--duration") and i + 1 < len(args):
            duration = parse_positive_int(args[i + 1], arg, minimum=1, maximum=3600)
            i += 2
        elif arg in ("-i", "--interface") and i + 1 < len(args):
            iface_index = parse_positive_int(args[i + 1], arg, minimum=0, maximum=100000)
            i += 2
        elif arg in ("-o", "--output") and i + 1 < len(args):
            output_dir = args[i + 1]
            i += 2
        elif arg in ("-f", "--filter") and i + 1 < len(args):
            bpf_filter = args[i + 1]
            i += 2
        elif arg == "--list-interfaces":
            if not check_tshark():
                sys.exit(1)
            interfaces = get_interfaces()
            if not interfaces:
                print("[ERROR] No network interfaces found.")
                sys.exit(1)
            print("\nAvailable interfaces:")
            for iface in interfaces:
                print(f"  [{iface['index']}] {iface['name']} — {iface['description']}")
            sys.exit(0)
        elif arg == "--protocols":
            print("Supported protocols: arp, bootp, dns, mdns, ssdp, http, tcp, udp,")
            print("  icmp, dhcp, llmnr, nbns, igmp, ospf, bgp, ssh, tls")
            sys.exit(0)
        elif arg in ("-v", "--verbose"):
            verbose = True
            i += 1
        elif arg in ("-q", "--quiet"):
            quiet = True
            i += 1
        elif arg == "--keep-pcap":
            keep_pcap = True
            i += 1
        elif arg in ("-h", "--help"):
            print_usage()
            sys.exit(0)
        else:
            sys.exit(f"[ERROR] Unknown option: {arg}\n        Use --help for usage.")

    if not quiet:
        print("=" * 60)
        print("  Flash_Network — Wireshark Network Scanner")
        print("=" * 60)

    if not check_tshark():
        sys.exit(1)

    interfaces = get_interfaces()
    if not interfaces:
        print("[ERROR] No network interfaces found.")
        sys.exit(1)

    if not quiet:
        print(f"\n  Available interfaces:")
        for iface in interfaces:
            print(f"    [{iface['index']}] {iface['name']} — {iface['description']}")

    if iface_index is not None:
        selected = next((iface for iface in interfaces if iface["index"] == iface_index), None)
        if selected is None:
            sys.exit(f"[ERROR] Interface index {iface_index} not found. Use --list-interfaces.")
    else:
        selected = find_active_interface(interfaces)

    if not selected:
        print("[ERROR] No suitable interface found.")
        sys.exit(1)

    if not quiet:
        print(f"\n  Selected: [{selected['index']}] {selected['description']}")

    capture_file, packets = capture_traffic(selected, duration, bpf_filter)
    try:
        if not packets:
            print("[WARN] No packets captured. Try running as Administrator/root or check interface.")
            sys.exit(0)

        if not quiet:
            print(f"\n[ANALYSIS] Processing {len(packets)} packets...")
        devices, total_bytes, protocol_counts, timeline = analyze_packets(packets)
        throughput = calculate_throughput(
            timeline, total_bytes=total_bytes, total_packets=len(packets)
        )

        retained_file = capture_file if keep_pcap else None
        report, output_path = generate_report(
            devices, throughput, protocol_counts, selected, duration, retained_file, output_dir
        )
        report["_output_path"] = output_path

        if not quiet:
            print_summary(report)
        else:
            print(f"Report saved to: {output_path}")
    finally:
        if capture_file and not keep_pcap:
            try:
                os.remove(capture_file)
            except OSError:
                pass


if __name__ == "__main__":
    main()
