"""
Flash_Network — Mermaid Network Diagram Builder (Python)
Reads Flash_Network scan output (JSON) and builds a Markdown network diagram
report using mermaid.js diagram syntax.

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

Requirements:
  - At least one scan JSON file in the input directory
  - A Markdown viewer with mermaid.js support to render the diagrams
    (GitHub, GitLab, VS Code, Obsidian, mkdocs-material, ...)
"""

import sys
import os
import json
import re
from datetime import datetime, timezone
from collections import defaultdict

from flashnet_common import secure_file, secure_output_dir

DEFAULT_MAX_DEVICES = 40

# Characters that are safe inside mermaid node labels ("...") and pie labels.
# Colons are included so MAC addresses keep their separators.
MERMAID_SAFE = re.compile(r"[^A-Za-z0-9 ._,@/+=%':-]")


def print_usage():
    """Display detailed usage information."""
    usage = """
Flash_Network — Mermaid Network Diagram Builder
===============================================

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
    python network_diagram.py [options]

OPTIONS:
    -i, --input DIR        Input directory with scan JSON files (default: ./output/)
    -o, --output DIR       Output directory for the Markdown file (default: ./output/)
    -s, --scan FILE        Use a specific network_scan JSON file
    -t, --title TITLE      Report title (default: Flash_Network Network Diagram)
    -n, --max-devices NUM  Max devices shown in diagrams (default: 40, 0 = unlimited)
    -v, --verbose          Enable verbose output
    -q, --quiet            Suppress console output. Only write Markdown file.
    -h, --help             Show this help message and exit.

EXAMPLES:
    Build a diagram from the newest scans in ./output/:
        python network_diagram.py

    Use a specific network scan and a custom title:
        python network_diagram.py -s output/network_scan_20260502_200000.json -t "Home Network"

    Show up to 100 devices, quiet mode:
        python network_diagram.py -n 100 -q

    Verbose with custom input/output directories:
        python network_diagram.py -v -i ./scans/ -o ./reports/

REQUIREMENTS:
    - One or more scan JSON files in the input directory:
        network_scan_*.json, device_enum_*.json, {hostname}_{ip}_*.json
    - A Markdown viewer with mermaid.js support (GitHub, VS Code, Obsidian)

OUTPUT:
    Markdown report saved to: output/network_diagram_YYYYMMDD_HHMMSS.md
"""
    print(usage)


def sanitize_mermaid(text):
    """Strip characters that would break mermaid node/pie labels."""
    text = str(text or "").replace("\\", "/")
    text = MERMAID_SAFE.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text or "unknown"


def markdown_cell(value, fallback="N/A"):
    """Escape a value for a Markdown table cell.

    Collapses newlines, escapes pipes so a hostname cannot break the table,
    and neutralises raw HTML/backticks so permissive viewers cannot render
    markup supplied by a scanned device.
    """
    text = "" if value is None else str(value)
    if not text.strip():
        text = fallback
    text = text.replace("\r", " ").replace("\n", " ")
    text = text.replace("|", "\\|")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("`", "'")
    return re.sub(r"\s+", " ", text).strip() or fallback


def human_bytes(num):
    """Format a byte count as a human-readable string."""
    num = float(num or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:,.1f} {unit}"
        num /= 1024


def classify_os(os_text):
    """Map an OS string to a coarse category for diagram grouping."""
    text = str(os_text or "").lower()
    if "windows" in text:
        return "Windows"
    if "darwin" in text or "macos" in text or "mac os" in text:
        return "macOS"
    if any(k in text for k in ("linux", "ubuntu", "debian", "centos", "rhel", "fedora")):
        return "Linux"
    if text and text != "unknown":
        return str(os_text)[:30]
    return "Unknown / Other"


def load_json(path):
    """Load a JSON file, tolerating UTF-8 BOM written by PowerShell."""
    try:
        if os.path.getsize(path) > 64 * 1024 * 1024:
            print(f"[WARN] Refusing to read oversized JSON file: {path}")
            return None
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Could not read {path}: {e}")
        return None


def find_latest_file(input_dir, prefix):
    """Return the newest file in input_dir matching prefix*.json, or None."""
    if not os.path.isdir(input_dir):
        return None
    candidates = [
        f for f in os.listdir(input_dir)
        if f.startswith(prefix) and f.endswith(".json")
    ]
    if not candidates:
        return None
    newest = max(
        candidates,
        key=lambda f: (os.path.getmtime(os.path.join(input_dir, f)), f),
    )
    return os.path.join(input_dir, newest)


def load_scan_data(input_dir, scan_file=None):
    """Load the newest network scan, device reports, and enum reports."""
    data = {
        "network_scan": None,
        "network_scan_file": None,
        "scan_index": None,
        "device_reports": [],
        "enum_reports": [],
    }

    if scan_file:
        if not os.path.isfile(scan_file):
            print(f"[ERROR] Scan file not found: {scan_file}")
            return None
        report = load_json(scan_file)
        if report is not None:
            data["network_scan"] = report
            data["network_scan_file"] = scan_file
    else:
        path = find_latest_file(input_dir, "network_scan_")
        if path:
            report = load_json(path)
            if report is not None and "devices" in report:
                data["network_scan"] = report
                data["network_scan_file"] = path

    index_path = os.path.join(input_dir, "scan_index.json")
    if os.path.isfile(index_path):
        data["scan_index"] = load_json(index_path)

    if not os.path.isdir(input_dir):
        return data

    for name in sorted(os.listdir(input_dir)):
        if not name.endswith(".json") or name.startswith(("network_scan_", "scan_index")):
            continue
        path = os.path.join(input_dir, name)
        report = load_json(path)
        if report is None:
            continue

        if isinstance(report.get("device"), dict) and report["device"].get("ip_address"):
            report["_source_file"] = name
            data["device_reports"].append(report)
        elif isinstance(report.get("scan_metadata"), dict) and report["scan_metadata"].get("target"):
            report["_source_file"] = name
            data["enum_reports"].append(report)

    return data


def build_inventory(data):
    """Merge device scanner and enumerator reports into a unified device list."""
    inventory = []

    for report in data["device_reports"]:
        dev = report.get("device", {})
        inventory.append({
            "hostname": dev.get("hostname") or dev.get("ip_address", "?"),
            "ip": dev.get("ip_address", "?"),
            "mac": dev.get("mac_address", ""),
            "os": dev.get("os", "Unknown"),
            "apps": len(report.get("applications") or []),
            "source": report.get("_source_file", ""),
        })

    for report in data["enum_reports"]:
        meta = report.get("scan_metadata", {})
        dev = report.get("device_info", {})
        inventory.append({
            "hostname": dev.get("hostname") or meta.get("target", "?"),
            "ip": meta.get("target", "?"),
            "mac": "",
            "os": meta.get("os_detected", "Unknown"),
            "apps": report.get("application_count", 0),
            "source": report.get("_source_file", ""),
        })

    # Deduplicate by IP, keeping the entry with the most applications
    by_ip = {}
    for item in inventory:
        key = item["ip"]
        if key not in by_ip or item["apps"] > by_ip[key]["apps"]:
            by_ip[key] = item

    return sorted(by_ip.values(), key=lambda d: d["hostname"].lower())


def build_topology_diagram(network_scan, max_devices):
    """Build a mermaid flowchart of the network topology."""
    devices = (network_scan or {}).get("devices") or []
    lines = ["flowchart TD"]
    lines.append('    INET["Internet"]')
    lines.append('    GW["Gateway / Router"]')
    lines.append("    INET --> GW")
    lines.append('    NET["Local Network"]')
    lines.append("    GW --> NET")

    if not devices:
        lines.append('    NODEV["No devices captured"]')
        lines.append("    NET --> NODEV")
        return "\n".join(lines)

    shown = devices[:max_devices] if max_devices > 0 else devices

    groups = defaultdict(list)
    for dev in shown:
        groups[dev.get("device_type") or "Unknown"].append(dev)

    for gi, dtype in enumerate(sorted(groups), 1):
        sub_id = f"G{gi}"
        lines.append(f'    subgraph {sub_id}["{sanitize_mermaid(dtype)} - {len(groups[dtype])} device(s)"]')
        for di, dev in enumerate(groups[dtype], 1):
            node_id = f"{sub_id}D{di}"
            ips = ", ".join(dev.get("ip_addresses") or [])
            host = dev.get("hostname") or ips or dev.get("mac_address") or "unknown"

            parts = [sanitize_mermaid(host)]
            if ips:
                parts.append(sanitize_mermaid(ips))
            if dev.get("mac_address"):
                parts.append(sanitize_mermaid(dev["mac_address"]))
            traffic = (dev.get("traffic") or {}).get("total_bytes")
            if traffic:
                parts.append(sanitize_mermaid(f"{human_bytes(traffic)} traffic"))

            label = "<br/>".join(parts)
            lines.append(f'        {node_id}["{label}"]')
            lines.append(f"        NET --> {node_id}")
        lines.append("    end")

    hidden = len(devices) - len(shown)
    if hidden > 0:
        lines.append(f'    MORE["... {hidden} more device(s) not shown - raise --max-devices"]')
        lines.append("    NET --> MORE")

    return "\n".join(lines)


def build_protocol_pie(network_scan, top_n=10):
    """Build a mermaid pie chart of the protocol distribution."""
    dist = (network_scan or {}).get("protocol_distribution") or {}
    if not dist:
        return None
    lines = ["pie title Protocol Distribution - packets captured"]
    for proto, count in list(dist.items())[:top_n]:
        lines.append(f'    "{sanitize_mermaid(proto)}" : {int(count)}')
    return "\n".join(lines)


def build_inventory_diagram(inventory, max_devices):
    """Build a mermaid flowchart of enumerated devices grouped by OS."""
    if not inventory:
        return None
    shown = inventory[:max_devices] if max_devices > 0 else inventory

    lines = ["flowchart LR"]
    lines.append('    SCAN["Flash_Network Scan"]')

    groups = defaultdict(list)
    for item in shown:
        groups[classify_os(item.get("os"))].append(item)

    for gi, os_name in enumerate(sorted(groups), 1):
        sub_id = f"OS{gi}"
        lines.append(f'    subgraph {sub_id}["{sanitize_mermaid(os_name)} - {len(groups[os_name])} device(s)"]')
        for di, item in enumerate(groups[os_name], 1):
            node_id = f"{sub_id}D{di}"
            parts = [sanitize_mermaid(item["hostname"]), sanitize_mermaid(item["ip"])]
            if item.get("mac"):
                parts.append(sanitize_mermaid(item["mac"]))
            if item.get("apps"):
                parts.append(sanitize_mermaid(f"{item['apps']} applications"))
            label = "<br/>".join(parts)
            lines.append(f'        {node_id}["{label}"]')
            lines.append(f"        SCAN --> {node_id}")
        lines.append("    end")

    hidden = len(inventory) - len(shown)
    if hidden > 0:
        lines.append(f'    MORE["... {hidden} more device(s) not shown - raise --max-devices"]')
        lines.append("    SCAN --> MORE")

    return "\n".join(lines)


def build_scan_status_pie(scan_index):
    """Build a mermaid pie chart of scan successes vs errors."""
    devices = (scan_index or {}).get("devices") or []
    if not devices:
        return None
    ok = sum(1 for d in devices if d.get("status") == "success")
    errors = len(devices) - ok
    lines = ["pie title Device Scan Results - success vs errors"]
    lines.append(f'    "Scanned OK" : {ok}')
    lines.append(f'    "Errors" : {errors}')
    return "\n".join(lines)


def build_traffic_table(network_scan, max_devices):
    """Build a Markdown table of top talkers."""
    devices = (network_scan or {}).get("devices") or []
    if not devices:
        return None
    shown = devices[:max_devices] if max_devices > 0 else devices

    rows = [
        "| # | Hostname | IP Address(es) | MAC Address | Type | Traffic |",
        "|---|----------|----------------|-------------|------|---------|",
    ]
    for i, dev in enumerate(shown, 1):
        ips = ", ".join(dev.get("ip_addresses") or []) or "N/A"
        traffic = dev.get("traffic") or {}
        rows.append(
            f"| {i} | {markdown_cell(dev.get('hostname'))} "
            f"| {markdown_cell(ips)} "
            f"| {markdown_cell(dev.get('mac_address'), 'N/A')} "
            f"| {markdown_cell(dev.get('device_type'), 'Unknown')} "
            f"| {human_bytes(traffic.get('total_bytes'))} |"
        )
    return "\n".join(rows)


def build_inventory_table(inventory):
    """Build a Markdown table of enumerated devices and application counts."""
    if not inventory:
        return None
    rows = [
        "| # | Hostname | IP Address | OS | Applications | Source File |",
        "|---|----------|------------|----|--------------|-------------|",
    ]
    for i, item in enumerate(inventory, 1):
        rows.append(
            f"| {i} | {markdown_cell(item['hostname'])} "
            f"| {markdown_cell(item['ip'])} "
            f"| {markdown_cell(str(item['os'])[:60])} "
            f"| {markdown_cell(item['apps'], '0')} "
            f"| {markdown_cell(item['source'])} |"
        )
    return "\n".join(rows)


def build_markdown(data, title, max_devices, input_dir):
    """Assemble the full Markdown report from loaded scan data."""
    network = data["network_scan"]
    inventory = build_inventory(data)
    now = datetime.now(timezone.utc)

    md = []
    md.append(f"# {title}")
    md.append("")
    md.append(f"> Generated by Flash_Network `network_diagram.py` on "
               f"{now.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    md.append(f"> Input directory: `{input_dir}`")
    md.append("")

    # --- Overview ---------------------------------------------------------
    md.append("## Network Overview")
    md.append("")
    meta = (network or {}).get("scan_metadata", {})
    tp = (network or {}).get("throughput", {})
    md.append(f"- **Devices detected:** {(network or {}).get('devices_detected', len(inventory))}")
    if meta.get("interface_description") or meta.get("interface"):
        iface = meta.get("interface_description") or meta.get("interface")
        md.append(f"- **Capture interface:** {iface}")
    if meta.get("capture_duration_sec"):
        md.append(f"- **Capture duration:** {meta['capture_duration_sec']}s")
    if tp.get("avg_mbps") is not None:
        md.append(f"- **Avg throughput:** {tp.get('avg_mbps', 0)} Mbps / "
                  f"**Peak:** {tp.get('peak_mbps', 0)} Mbps")
    if inventory:
        total_apps = sum(d["apps"] for d in inventory)
        md.append(f"- **Devices enumerated:** {len(inventory)} "
                  f"({total_apps} applications total)")
    md.append("")

    # --- Topology ---------------------------------------------------------
    md.append("## Network Topology")
    md.append("")
    md.append("```mermaid")
    md.append(build_topology_diagram(network, max_devices))
    md.append("```")
    md.append("")

    # --- Protocol distribution -------------------------------------------
    pie = build_protocol_pie(network)
    if pie:
        md.append("## Protocol Distribution")
        md.append("")
        md.append("```mermaid")
        md.append(pie)
        md.append("```")
        md.append("")

    # --- Device inventory --------------------------------------------------
    inv_diagram = build_inventory_diagram(inventory, max_devices)
    if inv_diagram:
        md.append("## Device Inventory")
        md.append("")
        md.append("Devices enumerated via SSH (`device_scanner` / `device_enumerator`), "
                   "grouped by detected OS.")
        md.append("")
        md.append("```mermaid")
        md.append(inv_diagram)
        md.append("```")
        md.append("")

    inv_table = build_inventory_table(inventory)
    if inv_table:
        md.append("### Enumerated Devices")
        md.append("")
        md.append(inv_table)
        md.append("")

    # --- Scan results ------------------------------------------------------
    status_pie = build_scan_status_pie(data["scan_index"])
    if status_pie:
        md.append("## Scan Results")
        md.append("")
        md.append("```mermaid")
        md.append(status_pie)
        md.append("```")
        md.append("")

    # --- Traffic -----------------------------------------------------------
    traffic_table = build_traffic_table(network, max_devices)
    if traffic_table:
        md.append("## Traffic Summary (Top Talkers)")
        md.append("")
        md.append(traffic_table)
        md.append("")

    # --- Notes -------------------------------------------------------------
    md.append("## Viewing")
    md.append("")
    md.append("This file uses [mermaid.js](https://mermaid.js.org) diagrams embedded in "
              "Markdown. Render it with GitHub, GitLab, VS Code (built-in Markdown "
              "preview), Obsidian, or any mermaid-aware viewer.")
    md.append("")

    return "\n".join(md), inventory


def save_markdown(md, output_dir="./output"):
    """Save the Markdown report to a timestamped file with owner-only access."""
    secure_output_dir(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"network_diagram_{timestamp}.md"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(md)
    secure_file(filepath)

    return filepath


def print_summary(filepath, data, inventory):
    """Print a human-readable summary."""
    network = data["network_scan"]

    print("\n" + "=" * 60)
    print("  FLASH_NETWORK — Network Diagram Summary")
    print("=" * 60)
    if data["network_scan_file"]:
        print(f"  Network scan : {data['network_scan_file']}")
    if network:
        print(f"  Devices      : {network.get('devices_detected', 'N/A')} detected in capture")
    print(f"  Enumerated   : {len(inventory)} device report(s)")
    print(f"  App inventory: {sum(d['apps'] for d in inventory)} applications")
    print("-" * 60)
    print("\n  Diagrams generated:")
    print("    - Network topology flowchart")
    print("    - Protocol distribution pie chart")
    print("    - Device inventory flowchart (by OS)")
    print("    - Scan results pie chart")
    print("    - Traffic and inventory tables")
    print("\n" + "=" * 60)
    print(f"  Markdown saved to: {filepath}")
    print("=" * 60 + "\n")


def main():
    input_dir = "./output"
    output_dir = "./output"
    scan_file = None
    title = "Flash_Network Network Diagram"
    max_devices = DEFAULT_MAX_DEVICES
    verbose = False
    quiet = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("-i", "--input") and i + 1 < len(args):
            input_dir = args[i + 1]
            i += 2
        elif args[i] in ("-o", "--output") and i + 1 < len(args):
            output_dir = args[i + 1]
            i += 2
        elif args[i] in ("-s", "--scan") and i + 1 < len(args):
            scan_file = args[i + 1]
            i += 2
        elif args[i] in ("-t", "--title") and i + 1 < len(args):
            title = args[i + 1]
            i += 2
        elif args[i] in ("-n", "--max-devices") and i + 1 < len(args):
            try:
                max_devices = int(args[i + 1])
            except ValueError:
                print(f"[ERROR] --max-devices must be a number, got: {args[i + 1]}")
                sys.exit(1)
            i += 2
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
            print(f"[WARN] Unknown option ignored: {args[i]}")
            i += 1

    if scan_file and input_dir == "./output":
        # Default the input dir to the scan file's directory so sibling
        # device/enum reports are picked up automatically.
        scan_dir = os.path.dirname(os.path.abspath(scan_file))
        if os.path.isdir(scan_dir):
            input_dir = scan_dir

    if not quiet:
        print("=" * 60)
        print("  Flash_Network — Mermaid Network Diagram Builder")
        print("=" * 60)

    data = load_scan_data(input_dir, scan_file)
    if data is None:
        sys.exit(1)

    if data["network_scan"] is None and not data["device_reports"] and not data["enum_reports"]:
        print(f"[ERROR] No scan JSON files found in: {input_dir}")
        print("        Run network_scanner.py, device_scanner.py, or device_enumerator.py first,")
        print("        or point -i/--input at a directory containing their output.")
        sys.exit(1)

    if verbose and not quiet:
        print(f"[INPUT] Network scan : {data['network_scan_file'] or 'none found'}")
        print(f"[INPUT] Device reports: {len(data['device_reports'])}")
        print(f"[INPUT] Enum reports : {len(data['enum_reports'])}")
        print(f"[INPUT] Scan index   : {'found' if data['scan_index'] else 'none found'}")

    md, inventory = build_markdown(data, title, max_devices, input_dir)
    filepath = save_markdown(md, output_dir)

    if not quiet:
        print_summary(filepath, data, inventory)
    else:
        print(f"Markdown diagram saved to: {filepath}")


if __name__ == "__main__":
    main()
