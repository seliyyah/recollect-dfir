# Recollect: Windows DFIR Live-Response Collector

```text
      ____    ______  ______  ____    __      __      ______  ______  ______
     / __ \  / ____/ / ____/ / __ \  / /     / /     / ____/ / ____/ /_  __/
    / /_/ / / __/   / /     / / / / / /     / /     / __/   / /       / /
   / _, _/ / /___  / /___  / /_/ / / /___  / /___  / /___  / /___    / /
  /_/ |_| /_____/  \____/  \____/ /_____/ /_____/ /_____/  \____/   /_/
```

A single PowerShell script that collects forensic evidence from a live Windows machine, in order of volatility. It drives the standard free DFIR toolset (Sysinternals, Eric Zimmerman's tools, KAPE, Velociraptor, WinPmem / Magnet RAM Capture / DumpIt, RawCopy) and writes a hashed, self-documenting collection: a manifest, per-step results, and SHA-256 hashes of every file.

![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-blue) ![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-informational) ![Version](https://img.shields.io/badge/version-4.0.1-green) ![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)

> 🛡️ **A blue-team tool** for incident responders, forensic analysts and researchers. Use it only on systems you own or are authorized to examine. See [Purpose and responsible use](#purpose-and-responsible-use).

---

## Quick start

1. Set up the toolkit drive as described in [Tools/README.md](Tools/README.md).
2. On the target machine, open a Command Prompt on the toolkit drive and type **`recollect`**. In Windows Explorer you can double-click `recollect.cmd` instead.

```bat
X:
cd \Toolkit
recollect
```

From PowerShell, type `.\recollect`, or run `X:\Toolkit\recollect.cmd` from any folder in either window. [User guide section 1.1](docs/USER_GUIDE.md#11-how-to-launch-recollectcmd) covers PowerShell, Command Prompt and File Explorer step by step.

`recollect` asks Windows for administrator rights, shows the license terms, then asks how to set up the collection: **1 Guided setup** or **2 Manual mode**. **Guided setup** takes you through five short steps: case ID, profile, memory capture, output folder and options. Enter accepts the suggested value. A summary with time and space estimates comes last, and nothing is collected until you confirm. The summary also prints the equivalent manual command.

**Manual mode:** choose **2** and type the parameters at the prompt (`?` lists them; you confirm before anything starts). Or give them on the command line, where no questions are asked except the license (`-AcceptLicense` skips that too). For the command line, use a terminal opened with *Run as administrator*:

```bat
recollect -CaseId IR-001 -CollectionProfile Full -Memory -OutputPath X:\Collections
```

`recollect /?` shows more examples. `recollect.cmd` starts Windows PowerShell with `-NoProfile`, and with the execution policy bypassed for that one process. The full `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\recollect.ps1 ...` form still works.

Results go to `X:\Toolkit\Collections\<CaseId>_<COMPUTER>_<UTC time>\`. Use `-OutputPath` to send them elsewhere. **Never write output to the suspect machine's internal disks.**

| Profile | Collects | Typical time |
|---|---|---|
| `Quick` | Volatile state: processes, network, sessions, services, persistence, event-log channel and ETW tampering checks | 2–3 min |
| `Standard` | + shadow copy, registry hives, all event logs, Prefetch, system and security config, Autoruns, driver hashes and loaded kernel modules, WFP filters, Sysmon config, SSH keys, PowerShell transcripts, Mark-of-the-Web, command-line histories | ~10 min |
| `Deep` | + `$MFT`, USN journal, SRUM, LNK / Jump Lists, browser artifacts, all Zimmerman parsers, extra internal drives, RMM tools, IIS, exfiltration-tool search | 30–60 min |
| `Full` | + KAPE, Velociraptor, pagefile / hiberfil, full Recycle Bin, Sigcheck of System32 | 1–2 hours |
| `MemoryOnly` | RAM image, plus the clock and time zone. Nothing else | ~5 min for 32 GB |
| `-Memory` | RAM image first (any profile) | ~5 min for 32 GB |

Opt-in extras: `-NetworkCapture` (records network traffic while collecting, `.pcapng` for Wireshark), `-YaraRules <file.yar>` (process-memory YARA scan, Full), `-LolDriversCsv <file>` (match driver hashes against a local LOLDrivers export) and `-DefenderQuarantine` (copies quarantined **malware samples**; see below). Guided setup offers each one only when it applies to the chosen profile. It finds YARA rules in `Tools\YARA\` and a LOLDrivers export anywhere under `Tools\`.

📖 **The full instructions** (every parameter, what every output folder contains and how to analyze it, and a Timeline Explorer refresher) are in **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)**.

---

## Features

- **Guided or manual:** type `recollect` for a guided setup with clear questions, sensible defaults and a summary to confirm. Give parameters for manual mode, or add `-NonInteractive` to script it. Both modes record the same manifest, and guided runs also log the equivalent manual command.
- **Order of volatility:** memory → network → processes → configuration → disk artifacts → parsers.
- **Forensically careful:** refuses to write to the system drive or other internal disks unless explicitly allowed; calls Windows binaries by full path; timestamps in UTC; removes the shadow copy and temporary link it creates, even on Ctrl+C.
- **Chain of custody:** `manifest.json` (script hash, parameters, host, timing, tool inventory, per-step results) and `FileHashes.csv` (SHA-256 of every collected file).
- **Resilient:** each step is isolated and recorded as OK / WARN / FAIL / SKIPPED, so a missing tool or failed step never stops the run.
- **Drive-letter independent:** finds its tools relative to its own location, collects whatever drive Windows is on, and auto-detects extra **internal** disks (USB and virtual disks are excluded).
- **Tamper and BYOVD awareness:** records whether logging was interfered with (disabled or shrunk event-log channels, stopped ETW/AutoLogger sessions, WFP filters blocking security tools) and hashes every driver, including ones loaded with no service entry, ready for LOLDrivers matching.
- **Careful with credentials:** Recollect's own collectors record configs that can hold secrets (rclone, ngrok, WinSCP, FileZilla, RMM agents, AnyDesk) as presence and hash only, and never copy SSH private keys or browser cookies, saved passwords and autofill. See the caution below.
- **Command lines in one place:** `System\command_history.csv` lists every command from every PowerShell history file (for every account, including SYSTEM and the service accounts, which attackers using PsExec or services leave behind), plus bash, Python and Windows Terminal; at Deep, `EventLogs\command_events.csv` adds the command lines from the event logs (script blocks, PowerShell starts, process creation, WMI consumers) in time order, with the collector's own activity marked. [Section 7.15](docs/USER_GUIDE.md#715-command-line-activity-where-commands-are-recorded) maps where else commands are recorded, including CMD, which keeps no history file.
- **Hidden data streams:** `Disk\ads_unusual.csv` lists NTFS alternate data streams (`file.txt:payload.exe`) on files and folders where attackers hide tools. Routine streams such as Mark-of-the-Web are only counted. Each stream gets its size, SHA-256, first bytes and a content hint ("PE executable", "script"...), and streams up to 1 MB are copied for analysis.
- **Network forensics:** live connections joined to processes, DNS cache, ARP, routes, proxies, SMB sessions, firewall and WFP filters, and SRUM's per-app traffic, plus `EventLogs\network_events.csv` (Deep): one time-ordered table of who connected to this machine and from where (network and RDP logons with source IP, failed logons, RDP sessions, share access, WinRM, SSH), outgoing RDP, BITS downloads, DNS queries, firewall rule changes and Wi-Fi. **Opt-in packet capture** (`-NetworkCapture`) records traffic with Windows' built-in pktmon while the collection runs and saves a `.pcapng` for Wireshark.
- **Sysmon in one table:** when Sysmon is installed, `EventLogs\sysmon_events.csv` (Deep) turns every Sysmon event (process creation, network, DNS, registry, file, process access, drivers, WMI, tampering) into one readable, time-ordered table, with the collector's own activity marked.
- **Self-explaining output:** every output folder, and every artifact folder under `Disk\`, gets an `ANALYSIS_README.txt`: what the files are, why they matter, how to analyze them, and links to the tools' official pages. Written for new analysts, researchers and students; `-NoAnalysisReadme` turns it off.
- **Smart tool handling:** finds tools by file name anywhere under `Tools\`; picks the runnable build (skips .NET builds whose runtime is missing and falls back to KAPE's bundled copies; prefers x64 over x86 and ARM64).

> ⚠ **Caution: a collection can still contain working credentials.** The memory image, the pagefile and hibernation file, the SAM and SECURITY registry hives, any Windows Setup answer file (`unattend.xml`) and, in the Full profile, **KAPE's browser targets (saved passwords, cookies and the DPAPI keys that decrypt them)** hold passwords, hashes or tokens by their nature, and command histories, logs and notes can hold them by accident. **Treat every collection as sensitive and archive it with a password.** KAPE's browser targets can be left out with `-KapeSkipBrowserData`, or by answering No in guided setup, which explains what they copy before asking. The full list is in [section 7.14 of the user guide](docs/USER_GUIDE.md#714-outputs-that-can-contain-passwords-and-other-secrets).

## Requirements

- Windows 10 / 11 / Server 2016+, **Windows PowerShell 5.1**, Administrator rights.
- An external drive with enough free space (Full + Memory on a 32 GB RAM laptop is about 72 GB).
- The third-party tools, which you download yourself (they are **not** included in this repository: several of their licenses don't allow redistribution, and they're large). See [Tools/README.md](Tools/README.md).

## Repository layout

```text
.
├── recollect.cmd         # launcher: guided setup, or manual mode with parameters
├── recollect.ps1         # the collector (must stay next to the Tools folder)
├── README.md
├── CHANGELOG.md
├── LICENSE               # BSD 3-Clause
├── docs/
│   ├── USER_GUIDE.md     # full operator guide and output reference
│   └── DEVELOPMENT.md    # architecture, coding rules, testing, known issues
└── Tools/
    └── README.md         # what to download and where to put it (binaries are git-ignored)
```

`Tools/*` (except its README) and `Collections/` are excluded by `.gitignore`, so tool binaries and evidence are never committed.

## Analysis tools

The collection is designed to be opened with **Timeline Explorer** and the other Zimmerman GUI tools, **Volatility 3** / **MemProcFS** for memory, and a **Velociraptor** server for the Velociraptor zips. Section 7 of the [user guide](docs/USER_GUIDE.md) opens with a quick-reference table of which tool to use for each output folder, including the less common outputs: WMI repository, WebCache, thumbcache, Notepad tabs and Defender quarantine. Section 2.4 lists where to get each tool.

**bulk_extractor** makes a good second pass over the raw files: point it at the memory image and the pagefile (not the whole case folder) to carve URLs, domains, emails, IPs and packet fragments that Volatility's plugins don't parse. Section 10 of the user guide explains where to point it, what to read first, and how it fits with Volatility. Its feature files are often too large for Notepad or Excel; the companion script [bulk-extractor-to-csv](https://github.com/seliyyah/bulk-extractor-to-csv) converts them to CSV for Timeline Explorer.

## Purpose and responsible use

Recollect is built **for defenders**: incident responders, forensic examiners, SOC analysts, students and researchers who need a fast, repeatable and well-documented way to preserve evidence from a Windows machine before it changes or disappears.

**Nothing in it is new offensive capability.** Every technique it uses (memory acquisition, shadow copies, copying locked files such as the registry hives, `$MFT` and event logs) is long-established, publicly documented forensic practice. It is taught in DFIR courses and performed by the freely available tools credited below. The script's contribution is **orchestration and rigor**: running those tools in order of volatility, keeping its footprint on the evidence small, and recording a manifest, hashes and per-step results so the collection holds up to review.

Collecting credential-bearing artifacts such as the SAM and SECURITY hives is a normal and necessary part of an investigation: it's how analysts find rogue accounts, password-change times and evidence of credential theft. Attackers already have far simpler and stealthier ways to get the same data. Withholding these capabilities from defenders protects no one.

**Please use it responsibly:**

- **Authorization:** run it only on systems you own or have written authorization to examine (for example an incident-response engagement, internal investigation, lab or training environment).
- **Coordination:** shadow-copy creation, memory-driver loading and hive copying look like attacker activity to EDR and antivirus products. Tell your SOC before collecting, so the alerts don't trigger a second incident.
- **Handling:** a collection can contain password hashes, personal data, browsing history and full memory contents. Store, transfer and destroy it according to your organization's evidence-handling and privacy policies, and the law in your jurisdiction.
- **`-DefenderQuarantine`:** this opt-in switch copies Defender's quarantine, which means **real malware samples** (RC4-obfuscated with a well-known key, so not directly runnable, but trivially restored). It is never enabled by any profile. Use it only when you need the samples, archive the collection with `-Archive -ArchivePassword`, and store it as malware. The detection metadata is collected without it.
- **`-YaraRules`:** scanning process memory is slow and can trigger EDR alerts. Coordinate with the SOC first.
- **Testing:** test changes on a lab VM before using them on a real case.

## Credits

This project stands on the shoulders of the people who build and maintain the free DFIR tools it orchestrates. **None of these tools are included in this repository.** Download each from its official source and follow its license. If they help you, star their repositories, cite them in your reports and support their work.

| Tool | Created and maintained by | What Recollect uses it for | Official source |
|---|---|---|---|
| **EZ Tools** (EvtxECmd, RECmd, MFTECmd, PECmd, AmcacheParser, AppCompatCacheParser, LECmd, JLECmd, SBECmd, RBCmd, SrumECmd, WxTCmd, SQLECmd, Timeline Explorer) | **Eric Zimmerman** | Parsing every collected artifact into analysis-ready CSV, and viewing it | https://ericzimmerman.github.io |
| **KAPE** (Kroll Artifact Parser and Extractor) | **Eric Zimmerman / Kroll**, with community-maintained Targets and Modules ([KapeFiles](https://github.com/EricZimmerman/KapeFiles)) | Full-profile triage collection and `!EZParser` processing | https://www.kroll.com/kape |
| **Sysinternals Suite** (Autoruns, Handle, ListDlls, LogonSessions, Sigcheck, TCPView) | **Mark Russinovich** and **Bryce Cogswell** (Sysinternals founders), now **Microsoft** | Persistence, open handles, loaded DLLs, logon sessions, signature checks, network connections | https://learn.microsoft.com/sysinternals |
| **Velociraptor** | **Mike Cohen** and the **Velocidex** team (now part of **Rapid7**), with the open-source community | Built-in forensic artifacts collected offline | https://github.com/Velocidex/velociraptor |
| **WinPmem** | **Velocidex** (originally from the Rekall / Google memory-forensics projects) | Memory acquisition (1st choice) | https://github.com/Velocidex/WinPmem |
| **Magnet RAM Capture** | **Magnet Forensics** | Memory acquisition (2nd choice) | https://www.magnetforensics.com/resources/magnet-ram-capture/ |
| **DumpIt** (Comae Toolkit) | **Matt Suiche** (MoonSols, then **Comae Technologies**, founded 2016 and acquired by **Magnet Forensics** in 2022) | Memory acquisition (3rd choice); Hibr2Bin for hibernation files | Magnet Forensics |
| **RawCopy** | **Joakim Schicht** | Copying locked NTFS files (`$MFT`, `$LogFile`, pagefile, hiberfil) | https://github.com/jschicht/RawCopy |
| **7-Zip** | **Igor Pavlov** | Optional encrypted archive of the collection | https://www.7-zip.org |

The user guide also recommends these analysis tools, credited to their authors: **Volatility 3** (The Volatility Foundation), **MemProcFS** (Ulf Frisk), **Hayabusa** (Yamato Security), **Chainsaw** (WithSecure), **bulk_extractor** (Simson Garfinkel), **DB Browser for SQLite** (the sqlitebrowser project), **Wireshark** (the Wireshark project), **klogg** (the klogg project), **Thumbcache Viewer** (Eric Kutcher), **BrowsingHistoryView** and **ESEDatabaseView** (Nir Sofer, NirSoft), **PyWMIPersistenceFinder** (David Pany), **notepad_parser** (AbdulRhman Alfaifi), **maldump** (NÚKIB) and **defender-dump** (knez). Thanks also to **AboutDFIR** (aboutdfir.com) for its Timeline Explorer guide, which section 9 of the user guide draws on.

All product names and trademarks belong to their respective owners. Their mention here doesn't imply endorsement of this project.

## License

Recollect is released under the **[BSD 3-Clause License](LICENSE)**. Copyright (c) 2026, seliyyah-dfir.

The license covers only this repository's own files (the script and its documentation). The third-party tools credited above are not part of it: each keeps its own license, and some (Sysinternals, KAPE) don't allow redistribution at all.

**Every run asks you to agree to the license terms first.** The script shows the license and an authorized-use notice and asks "Do you agree to these terms? [y/N]"; any answer but yes ends the run before anything is collected. `-AcceptLicense` records agreement without the prompt and is required with `-NonInteractive`. The acceptance is written to `Collection.log` and the manifest.

### Sharing and redistributing

You may use, copy, modify and share Recollect, including commercially and inside your organization, under these conditions:

- **Sharing a link** to this repository needs nothing more: the license travels with it.
- **Copying it** (a fork, a toolkit drive handed to a colleague, a zip on a file share, a script inside your own toolkit): keep the [LICENSE](LICENSE) file with it, and keep the copyright and license lines in the script's header. If you change the script, keep those notices; please also say that your copy is modified, so problems aren't reported against the original.
- **Distributing it in another form** (compiled, packaged or bundled into another product): reproduce the copyright notice, the license conditions and the disclaimer in the documentation or other materials that ship with it.
- **No endorsement:** don't use the author's or contributors' names to promote anything derived from it without written permission.
- **A prepared toolkit drive** that also holds the third-party tools is a redistribution of those tools too. Include each tool's own license, and leave out the tools whose licenses forbid redistribution (Sysinternals, KAPE): the recipient downloads those from the official source.

## Disclaimer

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.** As the license states in full, the copyright holder and contributors are not liable for any damages, including data loss, business interruption or legal consequences, arising in any way from its use or from anyone's redistribution of it. You alone are responsible for having the legal authority to collect data from any system you run it on, for how you use it, and for handling what it collects lawfully.
