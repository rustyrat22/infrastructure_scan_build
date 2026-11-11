# Security Review — Flash_Network

**Scope:** all files in this repository (`device_scanner`, `device_enumerator`,
`network_scanner`, `network_diagram`, in both Python and PowerShell).
**Date:** 2026-11-10
**Status:** audit findings 1–4, 9, 11, 13–16, 20 and 21 are fixed, and the
four "What I'd tackle next" items are complete. A small set of lower-priority
follow-ups remains (section 2).

This document is an operator-facing summary. It intentionally avoids
publishing working exploit payloads.

---

## 1. Fixed in this change

| # | Finding | Severity | Where |
|---|---------|----------|-------|
| 1 | SSH passwords exposed on the process command line | Critical | both scanners + both enumerators |
| 2 | No SSH host-key verification (MITM) | Critical | both scanners + both enumerators |
| 3 | Remote hostname used in output filenames (path traversal) | Critical | `save_device_json`, `save_report`, `Save-DeviceJson`, `Save-Report` |
| 4 | Discovery not scoped to the requested CIDR | Critical | ARP and tshark discovery |
| 9 | `.ps1` files fail to parse on Windows PowerShell 5.1 | High | all `.ps1` files |
| 11 | `Measure-Object -Property apps` aborts before `scan_index.json` | Medium | `device_scanner.ps1` |

### #1 — Passwords are no longer placed on the command line

Passwords are now written to a randomly named temporary file with
owner-only permissions, passed to plink with `-pwfile`, and overwritten with
zeroes before deletion. The file is removed in a `finally` block even if the
scan fails or exits early.

New input methods:

| Python | PowerShell | Behaviour |
|--------|-----------|-----------|
| `-pw` / `--ask-password` | `-AskPassword` | Prompt with a non-echoing prompt |
| `--password-file FILE` | `-PasswordFile FILE` | Read the first line of FILE |
| `--password-stdin` | *(not provided)* | Read one line from stdin |

> **Breaking change:** `-pw SecretPass` / `-Password SecretPass` are rejected.
> The previous form left the secret visible in the process list, shell
> history, transcription logs, and EDR telemetry. The script exits with a
> message describing the supported alternatives. Key-based authentication is
> still the recommended option.

### #2 — Host-key verification is required (fail closed)

Every connection now requires one of:

- `--hostkey` / `-HostKey` with a pinned fingerprint (recommended), which is
  forwarded to plink as `-hostkey`, or
- `--insecure-host-key` / `-InsecureHostKey`, which prints a warning and
  restores the old accept-any-key behaviour.

Without either option the tools refuse to connect. This prevents a hostile
LAN host from impersonating a target and harvesting credentials/inventory.

> **Breaking change:** existing unattended jobs must add a pinned fingerprint
> or explicitly opt in to the insecure mode. Obtain the fingerprint from the
> device console (`ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub`) or from a
> trusted first connection, then store it in the job configuration.

### #3 — Filename sanitisation and output-directory containment

Hostnames, IPs, and targets are reduced to `[A-Za-z0-9._-]`, stripped of
leading/trailing dots and dashes, length-capped, and protected against
Windows reserved device names (`CON`, `NUL`, `COM1`, …). Before writing, the
resolved path is checked to make sure it remains inside the requested output
directory. A value such as `..\..\Users\Public\evil` can no longer escape
`output/`.

### #4 — Discovery is scoped to the requested CIDR

- ARP/neighbour results are filtered against the requested network.
- tshark now receives a capture filter (`-f "net <cidr>"`) and results are
  filtered again in code (defence in depth).
- Hosts outside the requested range are never added to the scan list, so
  credentials and enumeration commands are never sent to unrelated devices.

### #9 — PowerShell 5.1 compatibility

All `.ps1` files are now saved as UTF-8 **with BOM**. Previously the em-dashes
in comments were decoded as CP1252 smart quotes by Windows PowerShell 5.1,
which produced a parser error before any code ran.

While validating the parse, two pre-existing syntax errors were also fixed:
PowerShell has no `?:` (Elvis) operator. The affected expressions in
`device_scanner.ps1` and `device_enumerator.ps1` were rewritten as explicit
`if`/assignment logic. All four scripts now pass
`[System.Management.Automation.Language.Parser]::ParseFile` under 5.1.

### #11 — Application count no longer crashes the PowerShell scanner

`Measure-Object -Property apps` cannot read hashtable keys as properties on
PowerShell 5.1. It threw before the index was written. The summary now
accumulates `[int]$result.apps` in a loop, so `scan_index.json` is produced
reliably.

---

## 2. Second wave (fixed in this change)

The four "What I'd tackle next" items are complete, together with the
additional findings from the same review.

| # | Finding | Fix |
|---|---------|-----|
| 13 | Packet captures were written to the current directory with predictable names and never deleted | `python`: temp directory, `mkstemp` name, `0600`, deleted unless `--keep-pcap`; PowerShell: GUID-named temp file, owner-only ACL, deleted unless `-KeepPcap`. Analysis is capped at 200,000 packets and the timeline is sampled to 20,000 points to bound memory. |
| 14 | No `.gitignore` protection for generated inventories, captures, temp files, or secrets | Repo-root `.gitignore` covers `output/`, `*.pcapng`/`*.pcap`, capture/temp names, password files, and Python caches. |
| 15 | `Start-Process -ArgumentList` joined arguments without quoting | `ConvertTo-ProcessArgument` / `Join-ProcessArguments` implement the Windows `CommandLineToArgvW` quoting rules (spaces, quotes, trailing backslashes) in every PowerShell tool. |
| 16 | `-Timeout` was accepted but not enforced around `Start-Process -Wait` | `Invoke-ProcessWithTimeout` waits with a real deadline, kills the child on expiry, and reports the timeout to the caller. |
| 20 | Windows registry parser flushed each app on the `DisplayName` line, losing version/publisher/location | The parser now accumulates fields until the next `DisplayName` or blank line; `REG_SZ`/`REG_EXPAND_SZ` values with empty data are preserved as empty strings. |
| 21 | Auto-range passed an empty argument to `ipconfig` and always fell back to `192.168.1.0/24` | Windows parsing pairs each `IPv4 Address` with its following `Subnet Mask` and derives the network base; POSIX uses `ip -4 addr`. Both return `None`/`$null` and fail loudly instead of guessing a range. |

Additional hardening delivered alongside those items:

- **Phantom devices eliminated.** Device hints are only applied when the source
  MAC already exists in the map, in Python and PowerShell. Empty or
  destination-only MACs can no longer create a device.
- **PowerShell adapter filter corrected.** Only loopback/pseudo interfaces are
  skipped; real `\Device\NPF_{GUID}` adapters are selectable.
- **Ping sweeps bounded.** Python uses a `ThreadPoolExecutor` of 64 workers;
  PowerShell sends asynchronous batches of 64. Both reject sweeps larger than
  65,536 hosts.
- **Numeric parsing hardened.** CLI integers use `parse_int_arg` /
  `parse_positive_int`; packet fields use `safe_int` / `safe_float` and
  `[int]::TryParse` / `[double]::TryParse`. Malformed values no longer crash a
  scan.
- **CLI validation.** Invalid modes and unknown options are rejected with a
  message on both the Python and PowerShell paths; `--mode tshark` requires an
  interface.
- **Diagram output escaped.** Hostnames, OS strings, and inventory values have
  `|`, newlines, raw HTML, and backticks escaped before entering Markdown
  tables. These edits are present in `network_diagram.py` / `network_diagram.ps1`
  in the working tree but are intentionally left out of this commit because
  those files also contain unrelated uncommitted user work.
- **StrictMode enabled.** All four PowerShell tools run with
  `Set-StrictMode -Version Latest`, surfacing undefined variables and properties
  during development rather than at an operator's console.
- **Generate files are private.** Output directories are created owner-only and
  reports get owner-only permissions (`chmod` on POSIX, ACL replacement on
  Windows).
- **Windows `head` usage removed** from the enumerator command suite.

---

## 3. Follow-up work (not fixed here)

These lower-priority issues remain outside the current change.

| Severity | Finding |
|----------|---------|
| Medium | Some application parsers still assume `|`-separated output. Debian/RPM and winget paths are handled, but `snap list`, `pacman -Qi`, and chocolatey output are not normalized, so those inventories can be empty or partial. |
| Low | `device_enumerator.ps1` still declares `#Requires -RunAsAdministrator`, although it only invokes plink. |
| Low | `scan_index.json` is still overwritten on every run, so scan history is lost. |
| Low | Auto-range picks the first usable IPv4 adapter and may select a VPN or virtual adapter when several are active. Pass an explicit range for deterministic results. |

---

## 4. Operator guidance

1. **Prefer keys over passwords.** Use `-k`/`-Key` with a passphrase-protected
   key where possible.
2. **Pin host keys.** Add `-HostKey`/`--hostkey` to every scheduled job. Use
   `--insecure-host-key` only on a trusted, isolated lab network.
3. **Never put secrets in argv.** Put the password in a file readable only by
   the service account and use `-PasswordFile`/`--password-file`, or use
   `-AskPassword`/`--ask-password` interactively.
4. **Protect output.** Reports contain a full software inventory. The tools now
   create output files owner-only, but keep the output directory out of version
   control and review its ACL on shared systems.
5. **Scope scans tightly.** Pass an explicit `-Range`/`--range`. Auto-detection
   now fails loudly instead of guessing, but it still selects the first usable
   adapter and may pick a VPN interface.

---

## 5. Verification performed

- `python -m py_compile network_scanner.py device_scanner.py device_enumerator.py network_diagram.py`
- Direct unit checks of the sanitiser, output-path guard, password-file
  create/read/zero/delete cycle, and CIDR membership helpers.
- `device_scanner.py -pw SecretPass` and `device_enumerator.py -pw SecretPass`
  are rejected with the migration message.
- Both Python tools refuse to run without a host-key decision.
- `[System.Management.Automation.Language.Parser]::ParseFile` returns no
  errors for all four `.ps1` files under Windows PowerShell 5.1.
- `ConvertTo-SafeFileName`, `Join-SafeOutputPath`, `Test-IPInRange`, and
  `New-PasswordFile`/`Remove-PasswordFile` were executed directly and produce
  the expected results (traversal blocked, `CON` prefixed, CIDR membership
  enforced for /24, /25, /31, and /32, password file removed and zeroed).
- Phantom-device, Android User-Agent ordering, malformed packet numerics,
  bounded ping, registry parsing, Windows auto-range, and Markdown escaping
  probes pass.
- PowerShell quoting was round-tripped through a child process with paths
  containing spaces, embedded quotes, and trailing backslashes.
- `ConvertTo-NetworkAddress` returns the expected bases (`192.168.1.0/24`,
  `192.168.1.128/25`, `10.20.0.0/16`, `192.168.1.2/31`).
- `-Help` and unknown-option handling were smoke-tested for all four
  PowerShell scripts under `Set-StrictMode -Version Latest`; invalid modes,
  durations, and unknown arguments exit non-zero with a clear message.
- `Calculate-Throughput` handles a single timeline sample without dividing by
  zero and reports true totals when the timeline is sampled.
