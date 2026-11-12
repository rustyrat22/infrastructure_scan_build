# infrastructure_scan_build — Application Outline

## Overview

Flash_Network is a network scanning and device auditing application that leverages **Wireshark**, **PuTTY**, **PowerShell**, and **Python** to discover devices on a local network, enumerate installed applications, and produce structured JSON audit files per device.  Builds a diagram showing all devices.  There is also a widget for the container homepage.

---

## High-Level Architecture

```mermaid
flowchart TD
    subgraph User
        U[User / CLI / UI]
    end

    subgraph Flash_Network
        CM[Core Manager]
        NS[Network Scanner]
        DE[Device Enumerator]
        AE[Application Extractor]
        JR[JSON Reporter]
    end

    subgraph External_Tools
        WS[Wireshark / tshark]
        PT[PuTTY / plink]
        PS[PowerShell]
        PY[Python]
    end

    subgraph Output
        NETDISC[Network Discovery Data]
        DEVJSON[Device JSON Files]
    end

    U --> CM
    CM --> NS
    NS --> WS
    NS --> PS
    NS --> PY
    NS --> NETDISC
    NS --> DE
    DE --> PT
    DE --> PS
    DE --> PY
    DE --> AE
    AE --> PS
    AE --> PY
    AE --> JR
    JR --> DEVJSON
```

---

## Module Breakdown

### 1. Core Manager

Coordinates the entire workflow: configuration loading, module orchestration, error handling, and logging.

```mermaid
flowchart LR
    CM[Core Manager]
    CFG[Config Loader]
    LOG[Logger]
    VAL[Validator]

    CFG --> CM
    LOG --> CM
    CM --> VAL
```

**Responsibilities:**
- Load `config.yaml` / `config.json` for scan parameters
- Initialize logging and output directory
- Dispatch pipeline stages sequentially or in parallel
- Handle retries, timeouts, and error reporting

---

### 2. Network Scanner

Discovers live devices on the local network using Wireshark (tshark) and native PowerShell/Python scans.

```mermaid
flowchart TD
    NS[Network Scanner]
    WS[Capture via tshark]
    ARP[ARP Scan]
    PING[ICMP Sweep]
    SYN[Port Probe]
    PARSE[Packet Parser]
    DEVLIST[Device List]

    NS --> WS
    NS --> ARP
    NS --> PING
    NS --> SYN
    WS --> PARSE
    ARP --> PARSE
    PING --> PARSE
    SYN --> PARSE
    PARSE --> DEVLIST
```

**Wireshark Integration:**
- Uses `tshark` CLI to capture traffic on local interface
- Filters for ARP, DHCP, DNS, and broadcast packets
- Extracts MAC addresses, IPs, and hostnames

**PowerShell Integration:**
- `Get-NetNeighbor` for ARP table
- `Test-Connection` for ICMP sweeps
- Custom port scanning via `Test-NetConnection`

**Python Integration:**
- `scapy` for raw packet crafting and ARP sweeps
- `socket` for TCP/UDP port probes
- `netifaces` or `psutil` for interface enumeration

---

### 3. Device Enumerator

Connects to discovered devices via PuTTY/plink (SSH) or PowerShell remoting (WinRM) to gather device-level information.

```mermaid
flowchart TD
    DE[Device Enumerator]
    SSH[SSH via plink]
    WINRM[PowerShell Remoting]
    WMI[WMI Queries]
    GATHER[Info Collector]

    DE --> SSH
    DE --> WINRM
    SSH --> GATHER
    WINRM --> GATHER
    WINRM --> WMI
    WMI --> GATHER
```

**PuTTY Integration:**
- Uses `plink.exe` for non-interactive SSH/serial connections
- Executes remote commands to gather OS info, hostname, and installed packages
- Supports credential management via config

**PowerShell Integration:**
- `Invoke-Command` for remote script execution
- WMI/CIM queries for hardware and OS inventory
- Registry queries for installed applications on Windows

---

### 4. Application Extractor

Enumerates all installed applications on each device using PowerShell and Python fallbacks.

```mermaid
flowchart TD
    AE[Application Extractor]
    PSREG[PowerShell: Registry Scan]
    PSPKG[PowerShell: Package Managers]
    PYLNX[Python: Linux Package DBs]
    PYMAC[Python: macOS App Bundles]
    PYWIN[Python: Windows Uninstall Keys]
    NORM[Normalizer]

    AE --> PSREG
    AE --> PSPKG
    AE --> PYLNX
    AE --> PYMAC
    AE --> PYWIN
    PSREG --> NORM
    PSPKG --> NORM
    PYLNX --> NORM
    PYMAC --> NORM
    PYWIN --> NORM
```

**PowerShell Sources:**
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKLM:\SOFTWARE\WOW6432Node\...\Uninstall` (32-bit on 64-bit)
- Winget: `winget list`
- Chocolatey: `choco list --local-only`
- MSI inventory via `Get-WmiObject Win32_Product`

**Python Sources:**
- Windows: `_winreg` / `winreg` module for uninstall keys
- Linux: `dpkg -l`, `rpm -qa`, `pacman -Q`, `snap list`
- macOS: `system_profiler SPApplicationsDataType`, `/Applications` scanning

---

### 5. JSON Reporter

Generates one JSON file per device with a standardized schema.

```mermaid
flowchart TD
    JR[JSON Reporter]
    VALID[Schema Validator]
    FMT[Formatter]
    WRITE[File Writer]
    INDEX[Index Builder]

    JR --> VALID
    VALID --> FMT
    FMT --> WRITE
    WRITE --> INDEX
```

---

## JSON Output Schema

Each device gets its own file: `{hostname}_{ip_address}.json`

```json
{
  "device": {
    "hostname": "WORKSTATION-01",
    "ip_address": "192.168.1.50",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "os": "Windows 10 Pro 22H2",
    "architecture": "x64",
    "scan_timestamp": "2026-05-02T20:00:00Z",
    "scan_methods": ["tshark", "plink", "powershell", "python"]
  },
  "applications": [
    {
      "name": "Wireshark",
      "version": "4.2.5",
      "last_update": "2026-03-15",
      "signer": "Gerald Combs / Wireshark Foundation",
      "install_location": "C:\\Program Files\\Wireshark",
      "url": "",
      "publisher": "Wireshark Foundation",
      "install_date": "2026-03-15",
      "architecture": "x64",
      "source": "registry"
    },
    {
      "name": "PuTTY",
      "version": "0.81",
      "last_update": "2026-01-10",
      "signer": "Simon Tatham",
      "install_location": "C:\\Program Files\\PuTTY",
      "url": "",
      "publisher": "Simon Tatham",
      "install_date": "2026-01-10",
      "architecture": "x64",
      "source": "winget"
    }
  ],
  "scan_summary": {
    "total_applications": 47,
    "scan_duration_seconds": 32.4,
    "errors": []
  }
}
```

---

## Data Flow

```mermaid
flowchart LR
    A[Start Scan] --> B[Discover Network]
    B --> C[Build Device List]
    C --> D{Device Reachable?}
    D -->|Yes| E[Connect via SSH/WinRM]
    D -->|No| F[Mark Offline]
    E --> G[Enumerate Applications]
    G --> H[Collect Metadata]
    H --> I[Build JSON Record]
    I --> J[Validate Schema]
    J --> K[Write JSON File]
    K --> L{More Devices?}
    L -->|Yes| D
    L -->|No| M[Build Index]
    F --> L
    M --> N[End]
```

---

## Directory Structure

```
Flash_Network/
├── config/
│   ├── network_ranges.yaml       # CIDR ranges to scan
│   ├── credentials.yaml          # Encrypted creds for remote access
│   └── scanner_settings.yaml     # Timeouts, retries, threads
├── modules/
│   ├── network_scanner.py        # Wireshark/ARP/ICMP discovery
│   ├── network_scanner.ps1       # PowerShell network sweep
│   ├── device_enumerator.py      # SSH/PuTTY remote connection
│   ├── device_enumerator.ps1     # PowerShell remoting
│   ├── app_extractor.py          # Python application enumeration
│   ├── app_extractor.ps1         # PowerShell application enumeration
│   └── json_reporter.py          # JSON schema + file generation
├── output/
│   └── scans/
│       └── {date}/
│           ├── {hostname}_{ip}.json   # One per device
│           └── scan_index.json        # Master index of all scans
├── logs/
│   └── flash_network.log
├── requirements.txt              # Python dependencies
├── Flash_Network.ps1             # PowerShell entry point
├── main.py                       # Python entry point
└── README.md
```

---

## Tool Integration Details

### Wireshark (tshark)

```mermaid
flowchart TD
    TSH[tshark CLI]
    CAP[Capture Live Traffic]
    FIL[Apply BPF Filters]
    EXT[Extract: IP, MAC, Hostname, Proto]
    OUT[Device Discovery Output]

    TSH --> CAP
    CAP --> FIL
    FIL --> EXT
    EXT --> OUT
```

| Parameter | Value |
|---|---|
| Interface | Auto-detect or user-specified |
| Capture Duration | 10–30 seconds |
| Filters | `arp`, `bootp`, `dns`, `mdns`, `ssdp` |
| Output | Parsed device table (IP, MAC, hostname) |

### PuTTY (plink)

```mermaid
flowchart TD
    PLINK[plink.exe]
    AUTH[Auth: Password/Key]
    EXEC[Execute Remote Commands]
    PARSE[Parse Output]
    APPS[Application List]

    PLINK --> AUTH
    AUTH --> EXEC
    EXEC --> PARSE
    PARSE --> APPS
```

| Parameter | Value |
|---|---|
| Protocol | SSH-2 |
| Auth | SSH key or password |
| Commands | `dpkg -l`, `rpm -qa`, `ls /Applications`, `reg query` |
| Fallback | PowerShell remoting if SSH unavailable |

---

## Processing Pipeline

```mermaid
sequenceDiagram
    participant U as User
    participant CM as Core Manager
    participant NS as Network Scanner
    participant DE as Device Enumerator
    participant AE as App Extractor
    participant JR as JSON Reporter
    participant FS as File System

    U->>CM: Start scan <range>
    CM->>NS: Discover devices
    NS->>NS: Run tshark capture
    NS->>NS: Run PS/Python sweep
    NS-->>CM: Return device list
    CM->>DE: Enumerate each device
    loop Per Device
        DE->>DE: Connect via SSH/WinRM
        DE->>AE: Extract applications
        AE->>AE: Run PS/Python scripts
        AE-->>DE: App list + metadata
        DE->>JR: Build device record
        JR->>JR: Validate against schema
        JR->>FS: Write {hostname}_{ip}.json
    end
    CM->>JR: Build scan index
    JR->>FS: Write scan_index.json
    CM-->>U: Scan complete summary
```

---

## Key Features

1. **Dual Engine** — Both PowerShell and Python implementations for cross-platform support
2. **Wireshark Integration** — Passive network discovery via tshark capture
3. **PuTTY Integration** — Active device probing via SSH/plink
4. **Per-Device JSON** — Standardized schema with versioning
5. **Signer Tracking** — Captures code signer/publisher for each application
6. **URL Placeholder** — Editable URL field for documentation links
7. **Scalable** — Threaded/async scanning for large networks
8. **Resume Support** — Index tracks completed devices for interrupted scans
9. **Logging** — Full audit trail in structured log files