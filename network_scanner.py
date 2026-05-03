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
import time
import re
from datetime import datetime, timezone
from collections import defaultdict


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
    Capture traffic using tshark and return raw pcapng bytes.
    Fields extracted per packet:
      frame.time_epoch, eth.src, eth.dst, ip.src, ip.dst,
      frame.protocols, frame.len, _ws.col.Protocol
    """
    pcap_file = f"flash_capture_{int(time.time())}.pcapng"

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
    print(f"        Saved to: {pcap_file}")

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    packets = []
    for line in stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("|")
        pkt = {fields[i]: parts[i] if i < len(parts) else "" for i in range(len(fields))}
        packets.append(pkt)

    return pcap_file, packets


def analyze_packets(packets):
    """Analyze captured packets and produce structured network info."""
    devices = defaultdict(lambda: {
        "mac": "",
        "ips": set(),
        "protocols": set(),
        "bytes_sent": 0,
        "bytes_received": 0,
        "packets_sent": 0,
        "packets_received": 0,
        "hostname": "",
        "device_type": "Unknown",
        "hints": [],
    })

    total_bytes = 0
    protocol_counts = defaultdict(int)
    timeline = []

    for pkt in packets:
        src_mac = pkt.get("eth.src", "").strip()
        dst_mac = pkt.get("eth.dst", "").strip()
        src_ip = pkt.get("ip.src", "").strip()
        dst_ip = pkt.get("ip.dst", "").strip()
        frame_len = int(pkt.get("frame.len", "0"))
        protocols = pkt.get("frame.protocols", "").strip()
        col_proto = pkt.get("_ws.col.Protocol", "").strip()
        hostname = pkt.get("dhcp.options.hostname", "").strip()
        http_host = pkt.get("http.host", "").strip()
        user_agent = pkt.get("http.user_agent", "").strip()
        mdns_name = pkt.get("mdns.host_name", "").strip()
        epoch = pkt.get("frame.time_epoch", "").strip()

        if not src_mac and not src_ip:
            continue

        total_bytes += frame_len

        # Protocol stats
        if col_proto:
            protocol_counts[col_proto] += 1

        # Timeline
        if epoch:
            timeline.append({"time": float(epoch), "len": frame_len, "proto": col_proto})

        # Device tracking by MAC
        for mac, ip, direction in [
            (src_mac, src_ip, "sent"),
            (dst_mac, dst_ip, "received"),
        ]:
            if not mac or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "01:00:5e:00:00:00"):
                continue

            dev = devices[mac]
            dev["mac"] = mac
            if ip:
                dev["ips"].add(ip)
            dev[f"bytes_{direction}"] += frame_len
            dev[f"packets_{direction}"] += 1

            # Collect protocol hints
            proto_parts = protocols.split(":")
            for p in proto_parts:
                p = p.strip()
                if p and p not in ("eth", "ethertype", "ip", "ipv6", "frame"):
                    dev["protocols"].add(p)

        # Hostname / device type hints
        if hostname and not devices[src_mac]["hostname"]:
            devices[src_mac]["hostname"] = hostname
        if mdns_name and not devices[src_mac]["hostname"]:
            devices[src_mac]["hostname"] = mdns_name

        if user_agent:
            devices[src_mac]["hints"].append(f"UA: {user_agent}")
            if "windows" in user_agent.lower():
                devices[src_mac]["device_type"] = "Windows PC"
            elif "linux" in user_agent.lower():
                devices[src_mac]["device_type"] = "Linux"
            elif "macintosh" in user_agent.lower() or "darwin" in user_agent.lower():
                devices[src_mac]["device_type"] = "macOS"
            elif "android" in user_agent.lower():
                devices[src_mac]["device_type"] = "Android"
            elif "iphone" in user_agent.lower() or "ipad" in user_agent.lower():
                devices[src_mac]["device_type"] = "iOS"

        if http_host:
            devices[src_mac]["hints"].append(f"HTTP Host: {http_host}")

    # Infer device type from MAC OUI patterns if still Unknown
    for mac, dev in devices.items():
        if dev["device_type"] == "Unknown":
            oui = mac[:8].upper()
            if oui in ("00:1A:", "00:1B:", "00:22:", "AC:DE:"):
                dev["device_type"] = "Router / Network Device"
            elif oui in ("00:0C:", "00:0D:", "00:1E:"):
                dev["device_type"] = "IoT Device"

    return devices, total_bytes, protocol_counts, timeline


def calculate_throughput(timeline, window_sec=1.0):
    """Calculate throughput in bytes/sec over time windows."""
    if not timeline:
        return {"avg_bps": 0, "peak_bps": 0, "total_bytes": 0, "duration_sec": 0}

    timeline.sort(key=lambda x: x["time"])
    start = timeline[0]["time"]
    end = timeline[-1]["time"]
    duration = max(end - start, 0.001)

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
        "total_packets": len(timeline),
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
            "capture_file": capture_file,
        },
        "throughput": throughput,
        "protocol_distribution": dict(sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)),
        "devices_detected": len(device_list),
        "devices": device_list,
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(output_dir, exist_ok=True)

    json_path = os.path.join(output_dir, f"network_scan_{timestamp}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

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


def main():
    duration = 15
    iface_index = None
    output_dir = "output"
    bpf_filter = None
    verbose = False
    quiet = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("-d", "--duration") and i + 1 < len(args):
            duration = int(args[i + 1])
            i += 2
        elif args[i] in ("-i", "--interface") and i + 1 < len(args):
            iface_index = int(args[i + 1])
            i += 2
        elif args[i] in ("-o", "--output") and i + 1 < len(args):
            output_dir = args[i + 1]
            i += 2
        elif args[i] in ("-f", "--filter") and i + 1 < len(args):
            bpf_filter = args[i + 1]
            i += 2
        elif args[i] == "--list-interfaces":
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
        elif args[i] == "--protocols":
            print("Supported protocols: arp, bootp, dns, mdns, ssdp, http, tcp, udp,")
            print("  icmp, dhcp, llmnr, nbns, igmp, ospf, bgp, ssh, tls")
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
    else:
        selected = find_active_interface(interfaces)

    if not selected:
        print("[ERROR] No suitable interface found.")
        sys.exit(1)

    if not quiet:
        print(f"\n  Selected: [{selected['index']}] {selected['description']}")

    capture_file, packets = capture_traffic(selected, duration, bpf_filter)

    if not packets:
        print("[WARN] No packets captured. Try running as Administrator/root or check interface.")
        sys.exit(0)

    if not quiet:
        print(f"\n[ANALYSIS] Processing {len(packets)} packets...")
    devices, total_bytes, protocol_counts, timeline = analyze_packets(packets)
    throughput = calculate_throughput(timeline)

    report, output_path = generate_report(
        devices, throughput, protocol_counts, selected, duration, capture_file, output_dir
    )
    report["_output_path"] = output_path

    if not quiet:
        print_summary(report)
    else:
        print(f"Report saved to: {output_path}")


if __name__ == "__main__":
    main()
