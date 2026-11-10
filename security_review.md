# Security Review — Flash_Network

**Scope:** all files in this repository (`device_scanner`, `device_enumerator`,
`network_scanner`, `network_diagram`, in both Python and PowerShell).
**Date:** 2026-11-10
**Status:** findings 1–4, 9 and 11 are fixed in this change. The remaining
items are tracked below as follow-up work.

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

## 2. Follow-up work (not fixed here)

These are real issues from the audit that are intentionally out of scope for
this change.

| Severity | Finding |
|----------|---------|
| High | Packet captures (`flash_capture_*.pcapng`) are written to the current directory, have predictable names, and are never deleted; they contain DHCP hostnames, HTTP hosts, and User-Agents. |
| High | `network_scanner` has no `.gitignore` protection for `output/`, captures, or temp files; generated inventories can be committed accidentally. |
| High | `Start-Process -ArgumentList` joins arguments with spaces without quoting, so paths/commands containing spaces or quotes can break or shift arguments. |
| High | The PowerShell `-Timeout` parameters are accepted but not applied to `Start-Process -Wait`; a stalled SSH session blocks the scan indefinitely. |
| High | The Python ping sweep starts one process per host before waiting; a large CIDR can exhaust the process table. |
| Medium | Windows registry parsing in `device_enumerator.py` flushes each app on the `DisplayName` line, so version/publisher/install-location are always empty. |
| Medium | `get_local_network_range()` on Windows passes an empty argument to `ipconfig` and looks for CIDR text that `ipconfig` never prints, so it always falls back to `192.168.1.0/24`. |
| Medium | Unguarded `int()`/`float()` conversions on CLI arguments and tshark fields crash on malformed input. |
| Medium | `network_scanner.ps1` excludes interfaces whose name matches `NPF_`, which is every real tshark adapter; it also dereferences `$devices[$srcMac]` without a key check. |
| Medium | `device_enumerator.py` runs `head` in the Windows command suite, where it does not exist. |
| Medium | Several package parsers (snap, winget, choco) split on `|` even though those tools emit column/whitespace output, so results are silently empty. |
| Medium | `device_scanner.py` treats an empty enumerated hostname as present, so the discovered hostname fallback never applies. |
| Low | Markdown tables in the diagram builders do not escape `|` or newlines from hostnames/OS strings. |
| Low | `device_enumerator.ps1` requires Administrator even though it only invokes plink. |
| Low | `scan_index.json` is overwritten on every run, losing history. |

---

## 3. Operator guidance

1. **Prefer keys over passwords.** Use `-k`/`-Key` with a passphrase-protected
   key where possible.
2. **Pin host keys.** Add `-HostKey`/`--hostkey` to every scheduled job. Use
   `--insecure-host-key` only on a trusted, isolated lab network.
3. **Never put secrets in argv.** Put the password in a file readable only by
   the service account and use `-PasswordFile`/`--password-file`, or use
   `-AskPassword`/`--ask-password` interactively.
4. **Protect output.** Reports contain a full software inventory. Restrict the
   output directory ACL/umask and keep it out of version control.
5. **Scope scans tightly.** Pass an explicit `-Range`/`--range`; do not rely on
   auto-detection, which is still unreliable on Windows (see follow-up table).

---

## 4. Verification performed

- `python -m py_compile device_scanner.py device_enumerator.py`
- Direct unit checks of the sanitiser, output-path guard, password-file
  create/read/zero/delete cycle, and CIDR membership helpers.
- `device_scanner.py -pw SecretPass` and `device_enumerator.py -pw SecretPass`
  are rejected with the migration message.
- Both Python tools refuse to run without a host-key decision.
- `[System.Management.Automation.Language.Parser]::ParseFile` returns no
  errors for all four `.ps1` files under Windows PowerShell 5.1.
- `ConvertTo-SafeFileName`, `Join-SafeOutputPath`, `Test-IPInRange`, and
  `New-PasswordFile`/`Remove-PasswordFile` were executed directly and produce
  the expected results (traversal blocked, `CON` prefixed, /24 membership
  enforced, password file removed and zeroed).
