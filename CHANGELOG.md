# Changelog

All notable changes to Recollect (`recollect.ps1`, called `Collect_v3.ps1` before 4.0.0). Format based on [Keep a Changelog](https://keepachangelog.com/); versions follow [Semantic Versioning](https://semver.org/).

## [4.0.2]

### Changed
- **Deep's typical time is now 60 to 90 minutes (was 30 to 60)**, in guided setup's profile menu, the README and the user guide. On the lab laptop, the Sigcheck scan of user-writable folders alone takes about 44 minutes (two Deep runs: 43 and 44 min), and a Deep run with memory and the packet capture took 74 minutes. Memory capture time is still shown separately.

### Verified
- **A live elevated Deep run with memory and `-NetworkCapture`:** 107 OK, 5 expected skips (shadow-copy fallbacks not needed), 2 WARNs caused by the USB output drive dropping out once (324 disk errors in one minute, during the `$MFT` parse).
- **`network_events.csv` live:** 2,414 rows in 12 seconds, sorted by time: firewall rule changes, BITS jobs and downloads, network and Wi-Fi connections, outgoing RDP.
- **Unusual alternate data streams from a real shadow copy:** 505,636 files and folders scanned in 1.9 minutes; routine streams counted in the summary row.
- **The real `pktmon list` layout:** component Id, MAC and name on one line, as the lookup expects. The Wi-Fi adapter was matched by MAC, not by the fallback. 38,033 packets over 64 minutes, no events lost; `capture_wifi.pcapng` decodes in tshark (IPv4 and IPv6, TCP, TLS, HTTP, DNS, ARP); the driver was unloaded and the PktMon service ended stopped.

## [4.0.1]

### Added
- **`EventLogs\network_events.csv` (Deep and up): network activity from the collected event logs in one time-ordered table.** No tool needed.
  - **Inbound:** network and Remote Desktop logons with the source IP (Security 4624 types 3, 8, 10) and failed ones (4625), logons with explicit credentials to another server (4648), RDP session reconnects and disconnects (4778/4779), share access (5140), RDP authentication and remote sessions (Terminal Services 1149, 21, 22, 24, 25), WinRM sessions (6, 91, 169), OpenSSH logons accepted or failed, and SMB client logon failures (31001).
  - **Outbound:** outgoing RDP connections (RDP client 1024/1102), BITS jobs and downloads with their URL (3, 59, 60), and DNS queries (DNS Client 3008, when that log is enabled).
  - **Changes:** firewall rules added, changed or deleted (2004-2006, 2052, 2097, 2099), and Wi-Fi and network connections (WLAN 8001/8003, NetworkProfile 10000/10001).
  - **Columns:** `TimeUtc`, `Area`, `EventId`, `Event`, `Account`, `RemoteAddress`, `Target`, `Detail`, `RecordId`, `LogFile`.
  - **Left out:** local-only noise, such as logons without a remote address, console sessions and the "Identifying..." network placeholder. An event without a specific layout lists its fields in `Detail`.
- **`-NetworkCapture` (opt-in): packet capture while the collection runs.**
  - **How:** Windows' built-in pktmon (nothing is installed) records traffic from right after the memory capture until the live steps end, at the network adapters only (each packet once), full packets, in a circular file capped by **`-NetworkCaptureMaxMB`** (default 512).
  - **Output:** when it stops, the `.etl` is converted to `Network\capture.pcapng` for Wireshark, and the packet-capture driver is unloaded again.
  - **Wi-Fi:** a Wi-Fi adapter hands pktmon raw 802.11 frames, but pktmon's converter labels the whole file Ethernet, so Wireshark can't decode them (found in the first live test: 1,648 of 1,654 packets showed as undecoded data). Each Wi-Fi adapter's packets are now also converted on their own to **`Network\capture_wifi.pcapng`**, labeled IEEE 802.11. The adapter's pktmon component is found by MAC address in a `pktmon list` taken at start. If it can't be found, the file is a relabeled copy of the whole capture, with a note. Windows leaves the *Protected* bit set on these already-decrypted frames, so Wireshark needs *Ignore the Protection bit = Yes - without IV*; the guide and the folder README say so.
  - **Safeguards:** it is always stopped, even when the run is aborted. If another pktmon capture is already running, it's left alone and the step fails with a note. It needs Windows 10 version 2004 or later, and isn't available with Memory Only.
  - **Guided setup** offers it for every profile except Memory Only, default No, with a disclaimer: unencrypted traffic is recorded in full and can contain passwords.
  - **Footprint:** the space check adds twice the cap, and the start-of-run log says the capture is on and sensitive.

### Documentation
- README: a "Network forensics" feature; `-NetworkCapture` among the opt-in extras.
- User guide:
  - Sections 1.2 (the guided option), 4 (Deep row) and 5 (`-NetworkCapture`, `-NetworkCaptureMaxMB`).
  - 7.3: the capture files, first steps in Wireshark, and what only network-side sources (firewall and proxy logs, NetFlow, Zeek, Suricata) can provide.
  - 7.7: `network_events.csv`.
  - 7.14: what a capture can hold.
  - The quick-reference table.
- `ANALYSIS_README.txt` for `Network\` and `EventLogs\` describe the new files.

### Verified
- **`network_events.csv` against a real collection's logs:** 2,346 rows in about 9 seconds, sorted by time. That's Wi-Fi and network connections, outgoing RDP (server name and address), BITS jobs and downloads with URLs, and firewall rule changes with the account and program behind them. The field names were read from the real events.
- **Event types not in the lab's logs, built from Microsoft's schemas:** RDP and network logons with a source IP, a logon without one (skipped), a failed logon, RDP reconnect, share access to `C$`, RDP authentication, a remote session, WinRM, SSH accepted and failed (invalid user), DNS, SMB client failure, and an unknown event (fields listed).
- **The capture start and stop logic, with a stand-in pktmon:** the exact commands (`status`; `start --capture --comp nics --pkt-size 0 --file-name ... --file-size ... --log-mode circular`; `stop`; `etl2pcap ... --out ...`; `unload`); refusal when another capture is running; stop when nothing was started; and the abort-path stop.
- **Guided setup:** the question appears for every profile except Memory Only, and reaches the summary and the manual command.
- **A live elevated Quick run with the capture:** 30 OK, 1 expected skip. pktmon started 0.4 s after the memory step, and the idle status text was confirmed ("Packet Monitor is not running."). It captured 1,654 packets over 1.8 minutes with no events lost, stopped and converted in 3.6 s, unloaded its driver (the PktMon service was stopped afterwards), and both files were hashed.
- **The Wi-Fi fix, on that capture:** relabeled as 802.11 with the Protection-bit setting, all 1,654 frames decode (IPv4 and IPv6, TCP, TLS, DNS, QUIC, ARP), against 6 before. The export was tested with a stand-in pktmon for both the found-by-MAC and fallback paths.
- **Not yet verified:**
  - The real `pktmon list` layout that the component lookup reads; the fallback covers a mismatch.
  - The WinRM, SMB client, 4625, 4778/4779, 5140 and DNS rows against real events.

## [4.0.0]

The Recollect rename is complete: the script, the launcher and the repository now carry the name too. Nothing about what is collected, or how, has changed.

### Changed (breaking)
- **Script:** `Collect_v3.ps1` is now **`recollect.ps1`**.
- **Launcher:** `collect.cmd` is now **`recollect.cmd`**: type `recollect` in Command Prompt, `.\recollect` in PowerShell, or double-click it. It looks for `recollect.ps1` next to itself or one folder below, as before.
- **Repository:** `seliyyah/windows-dfir-collector` is now **`seliyyah/recollect-dfir`**. GitHub redirects the old address for the web page and for `git clone`, pull and push. To point an existing clone at the new address: `git remote set-url origin https://github.com/seliyyah/recollect-dfir.git`.
- **What to update:**
  - Saved launch commands and scheduled tasks: replace `collect` with `recollect`, and `Collect_v3.ps1` with `recollect.ps1`.
  - Toolkit drives: copy the new `recollect.cmd` and `recollect.ps1`, and delete the old `collect.cmd` and `Collect_v3.ps1`, so two versions aren't side by side.
  - Every parameter is unchanged.
- In the collection, `manifest.json` `Script.Name` is now `recollect.ps1`, and the manual-mode command shown in guided setup and recorded in `Collection.log` starts with `recollect`.
- The links in the docs, the banner panel and every `ANALYSIS_README.txt` point to the new repository address.

### Verified
- `recollect.cmd`: `/?`; finding `recollect.ps1` beside it and one folder down; the non-elevated manual-mode message; argument pass-through.
- Guided setup and manual mode at the prompt, with scripted answers, through to the point where the collection folder would be created. The equivalent command and the typed line both start with `recollect`.
- No reference to `Collect_v3.ps1`, `collect.cmd` or the old repository address remains outside this changelog's history.

## [3.9.0]

### Added
- **Unusual alternate data streams, `Disk\ads_unusual.csv` (Standard and up).** Lists hidden NTFS streams (`file.txt:payload.exe`) on files **and folders** where attackers hide tools and staged data:
  - **Where it looks:** recursively under Users, ProgramData, Program Files (both), `Windows\Temp`, the task folders, `$Recycle.Bin` and PerfLogs; at the top level only for the drive root, `Windows` and `System32`. It reads from the shadow copy, with a live fallback.
  - **What it skips:** routine streams are counted in a summary row, not listed. Those are Zone.Identifier (already in `zone_identifier.csv`), SmartScreen, Office and thumbnail properties, OLE property sets, macOS and Dropbox metadata, and Malwarebytes' marks.
  - **What it records:** for every other stream, its size, SHA-256 (up to 512 MB), first 16 bytes and a content hint (PE executable, ZIP, OLE, script or text...).
  - **Copies:** streams up to 1 MB are copied to `Disk\ADS\` as `.bin` files.
  - **How:** the same native `FindFirstStreamW` walker as Mark-of-the-Web, junctions skipped, capped at 1.5 million entries per area.
- **Sysmon events in one table, `EventLogs\sysmon_events.csv` (Deep and up).** Every event from the collected Sysmon log becomes one readable row, in log order, using the event's own `UtcTime`. Each row has the event name, account, process, a `Target` column for what the event is about, and a `Detail` column with the fields that matter for that event type. All 29 event types are mapped, and unknown ones list their fields. Collect_v3 and every process it started are followed through Sysmon's own process-creation events and marked "from this collection run". It stops at 300,000 events with a WARN, and the file is empty when Sysmon isn't installed. No tool needed.
- **KAPE browser data: disclaimer and opt-out.** Full runs still include KAPE's browser targets by default.
  - **Guided setup** explains what they copy for Full: saved passwords, cookies, autofill and the DPAPI keys that decrypt them. It asks "Include KAPE's browser data? (Y/n)", and the summary and manual command reflect the answer.
  - **`-KapeSkipBrowserData`** (new) runs `!SANS_Triage` without its `WebBrowsers` target. KAPE has no exclude option, so the compound is expanded into its other targets, read from the KAPE install's own `.tkape` file; entries are deduplicated and unknown compounds are flagged.
  - **Every Full run logs** whether browser data is included.
  - **The disclaimer is honest about what remains:** KAPE's Dropbox metadata target still copies the DPAPI key folder, and its mRemoteNG target saved connection credentials.

### Changed
- **Guided or manual, chosen after the license.** Started without parameters, Recollect now asks "How do you want to set up this collection?" with two choices: **1 Guided setup** (Enter, as before) or **2 Manual mode**.
  - **What manual mode offers:** a prompt where parameters are typed as after `collect`. It shows examples, `?` lists every parameter with its type or allowed values, **B** goes back and **Q** quits. Unambiguous short names work (`-Coll`), and switches can be turned off with `-Memory:$false`.
  - **Confirmation:** the typed line is shown back for confirmation. With `-Archive`, the password is asked for afterwards, hidden and twice.
  - **Safe parsing:** the line is read with PowerShell's own parser, but only plain values are accepted. Variables, `$(...)`, `;` and pipes are refused, so nothing typed is ever run.
  - **Logging:** `Collection.log` records the typed line, and `Script.LaunchMode` says `manual (typed at the prompt)`.
- **New name: Recollect.** A new startup banner with large slanted RECOLLECT letters, drawn in a different color on each launch (picked at random from seven bright console colors), and a framed panel (name, version, credit, tagline, repository). The console screens, `Collection.log`, `manifest.txt`, the folder READMEs and the docs now say Recollect. **Unchanged:** the launcher `collect.cmd`, the script file `Collect_v3.ps1`, the repository address and every parameter, so existing launch commands and scripts keep working. Log and manifest lines that said "Collect_v3" now say "Recollect" (for example the `Recollect log | started ...` header and "from this collection run (Recollect itself)"): update any filters that matched the old text.
- `ANALYSIS_README.txt` for `Disk\` and `EventLogs\` describe the new files and how to read them.
- Standard runs take about 2 minutes longer (the stream scan); Deep runs about 2 ms per Sysmon event longer.

### Documentation
- README: features for hidden streams and Sysmon; the credentials caution mentions `-KapeSkipBrowserData`.
- User guide:
  - Section 1.2 (guided options): the KAPE browser data question.
  - Section 4: Standard and Deep rows.
  - Section 5: the `-KapeSkipBrowserData` row.
  - Section 7 quick reference, 7.7 (`sysmon_events.csv`) and 7.8 (`ads_unusual.csv`, `Disk\ADS\`).
  - 7.13 and 7.14: the opt-out and what it does and doesn't remove.

### Verified
- **The guided or manual choice:** the real script was run to the point where the collection folder would be created, with scripted answers and the admin check stubbed.
  - A full typed line, including a comma list, reached the settings, the manifest parameters and the log.
  - `?` listed the parameters.
  - Refused, each with a clear message: an unknown parameter, `$(calc)`, a bare command, `; calc`, a value outside the allowed set, a missing value, an ambiguous short name, and a typed `-ArchivePassword`. No process was started.
  - `-Coll quick -Case X -Memory:$false -Archive` worked, with the hidden password prompt after it.
  - B went back to the choice; declining the confirmation allowed retyping; a missing profile brought up the menu.
- **Stream scan:**
  - A test folder: an executable hidden in a text file's stream (flagged as a PE), a PowerShell command in a folder's stream, a 3 MB stream (hashed, not copied), an empty stream, and routine Zone.Identifier and OLE property streams (counted, not listed). Copies and hashes matched.
  - The live system drive, not elevated: 445,000 files and folders in about 2¼ minutes; only Malwarebytes' marks turned up, and they are now on the routine list.
- **KAPE:**
  - The expansion against the lab KAPE's `!SANS_Triage`: 17 targets, `WebBrowsers` removed. An explicit `WebBrowsers` entry is removed, duplicates collapsed, and an unknown compound flagged.
  - Guided setup asks for Full, and the answer reaches the summary and the manual command.
- **Sysmon:**
  - The row conversion for events built from Sysmon's published schema (1, 2, 3, 10, 13, 15, 22, 25 and an unknown ID).
  - The reader loop and its cap against a real collected event log.
- **Not yet verified:**
  - `sysmon_events.csv` against a real Sysmon log, including the own-run marking (Sysmon isn't installed on the lab laptop).
  - The stream scan from a real shadow copy in an elevated run.
  - A Full run with `-KapeSkipBrowserData`.

## [3.8.0]

### Added
- **`collect.cmd`, a launcher.** Type `collect` on the toolkit drive, or double-click it. It starts Windows PowerShell 5.1 by full path (64-bit even from a 32-bit prompt), with `-NoProfile` so the profile scripts of the computer being collected never run, and with the execution policy bypassed for that one process only; no setting changes. It can sit next to `Collect_v3.ps1` or at the drive root with the toolkit one folder below. `collect /?` prints usage and examples.
- **Guided setup.** Started with no parameters (through `collect` or directly), the script shows a banner and the unchanged license prompt, then five short steps:
  1. Case ID (validated) and examiner.
  2. Profile, with a description, typical time and space for each.
  3. Memory capture, with this computer's RAM size, the time it takes and the space it needs.
  4. Output folder, with the drive's type and free space. It warns before writing to this computer's own disks or when space is short.
  5. Only the options that apply to the chosen profile.

  Enter accepts the suggested value, Q quits at any prompt, and a summary with estimated time and space must be confirmed before anything is collected or written. The summary shows the equivalent manual-mode command, which `Collection.log` also records. Guided choices are recorded in `manifest.json` (`Script.Parameters`) as if they had been typed; the archive password never is.
  - When not elevated, guided setup asks Windows for administrator rights (the UAC prompt) and opens the collection in a new window, which stays open at the end so the summary can be read.
  - The options it can offer: YARA rules come from `Tools\YARA\` (rules inside other tools aren't offered). A LOLDrivers export is found by name (`loldrivers*.csv/json`) or at the repository's `loldrivers.io\content\api\drivers.csv`. The archive password is typed twice, hidden, with a note that 7-Zip receives it on its command line.
- **`MemoryOnly` profile:** a RAM image plus `System\time.txt` (clock, time zone, time sync), nothing else. It implies `-Memory`, and stops with an error before collecting if no memory tool is in the toolkit. The memory and clock steps are now level 0, so every profile still runs them as before.
- `manifest.json` records `Script.LaunchMode` (`guided setup` or `manual (parameters)`), and the log says which mode was used.

### Changed
- **Manual mode is unchanged**: any parameter means no questions apart from the license (none with `-AcceptLicense`) and the existing warnings. Without `-CollectionProfile`, the profile menu is now the same five-option menu guided setup uses.
- New look for the console: a banner at the start, and an end-of-run summary showing case, profile, output folder, results (in yellow when a step failed or warned), duration and the FileHashes.csv hash.
- Top-level output folders a profile leaves empty (for example `KAPE\` and `Velociraptor\` in a Standard run) are removed at the end, before the READMEs are written and the files hashed.
- **QuickEdit (a click in the window pausing the run) is now turned off as soon as setup ends.** It used to be turned off only after the drive and free-space checks, which can take half a minute. A click right after confirming the guided summary paused the first live guided run for 2 minutes, until Escape was pressed. A "Preparing the collection" line now shows during those checks. QuickEdit stays on during the questions, so the summary's command can be copied, and the console gets it back if the run stops before collecting.
- The "needs administrator rights" error now says how to start it: `collect` with no parameters, or an elevated terminal.
- Typical times in the README and user guide updated from lab-laptop runs: Deep 30–60 min (was 30–40), Full 1–2 hours (was 60–100 min).
- `.gitattributes` keeps `.cmd` and `.bat` files CRLF.

### Documentation
- README: Quick start rewritten around `collect` (guided and manual), the Memory Only row, the "Guided or manual" feature, `collect.cmd` in the repository layout.
- User guide: section 1 now explains how to launch `collect.cmd` from PowerShell, Command Prompt or File Explorer, including how to switch to the toolkit drive in each (1.1), then both modes (1.2 Guided setup, 1.3 Manual mode); Memory Only in sections 1, 4 and 5; `collect.cmd`, `Tools\YARA\` and the LOLDrivers repository in the section 3 layout; new troubleshooting rows (administrator rights, `.\collect` in PowerShell, a declined UAC prompt, launcher not finding the script, Memory Only without a tool, options not offered).
- Tools README: the `YARA\` and `LOLDrivers-main\` folders and where to get LOLDrivers.

### Verified
- Guided setup driven by scripted answers in six scenarios:
  - Full with memory, LOLDrivers and a password-protected archive.
  - Invalid case IDs, profile numbers, relative and malformed paths, and yes/no answers re-asked with a clear message, then Memory Only.
  - Quitting with Q, and declining at the summary (both exit without collecting).
  - A toolkit without a memory tool (Memory Only refused, the memory step explains why), with two YARA files in `Tools\YARA\`, one elsewhere that isn't offered, and a mismatched then matching password.
  - The system drive as output, accepted, with `-AllowSystemDrive` in the command.
- The real script up to the point where the collection folder would be created, with the admin check stubbed and answers scripted:
  - In guided mode, the choices became the script's settings and `Script.Parameters`, and the log held the license line, launch mode and equivalent command.
  - A declined license still exits.
  - Manual mode works with `-CollectionProfile MemoryOnly` and with the new profile menu.
- `collect.cmd`:
  - `/?`.
  - Finding the script beside it, or one folder down even with a space in the folder name; "not found" and "more than one copy" messages.
  - The non-elevated manual-mode message.
  - Arguments with spaces passed through, with `-NoProfile`.
- Guided setup takes about 3 seconds of its own: drive types come from `Win32_DiskDrive` because the storage provider's first `Get-Disk` call took 18 seconds on the lab laptop.
- **A live guided run** started from a non-elevated PowerShell window on the lab laptop: the Windows permission prompt, the new elevated window, then guided setup choosing Quick, a custom examiner name and an archive. Result: 28 OK, 1 expected skip (memory not chosen). The log and `manifest.json` show the guided launch mode, the equivalent command and the choices as parameters. The six empty top-level folders were removed; all 40 files were hashed; the archive's SHA-256 matched; the password is in neither the log nor the manifest.
- **Not yet verified:** a full Memory Only collection, and the earlier QuickEdit switch-off in a live run.

## [3.7.0]

### Added
- **`System\command_history.csv` (Standard and up):** every command from every collected command-history file, one row per command, with the account, source, line number, the file it came from and that file's last-modified time. Multi-line PowerShell commands are joined into one row; bash times are read when `HISTTIMEFORMAT` was set; from Windows Terminal screen text only the PowerShell and CMD prompt lines are taken. Built from the copies under `Disk\`, so it works with or without the shadow copy.
- **More command-history files are collected:**
  - PSReadLine history for **SYSTEM** (`Windows\System32\config\systemprofile` and `SysWOW64`) and the **service accounts** (`Windows\ServiceProfiles\*`). PowerShell run through PsExec `-s`, a service or a scheduled task writes there, and it wasn't collected before.
  - Every PSReadLine host file (`*_history.txt`), not only `ConsoleHost_history.txt`: for example `Visual Studio Code Host_history.txt`.
  - `.bash_history` (Git Bash, MSYS2, Cygwin) and `.python_history` from each profile.
  - Windows Terminal's saved tab text (`buffer_*.txt`), when Terminal restores previous sessions: the only place on disk where CMD commands can survive.
  - The no-snapshot fallback copies the same files live.
- **`EventLogs\command_events.csv` (Deep and up):** command lines from the collected event logs, sorted by time: PowerShell script blocks (4104, Windows PowerShell and PowerShell 7), the command line of every PowerShell start (Windows PowerShell 400), process creation (Security 4688, Sysmon 1) and WMI permanent event consumers (WMI-Activity 5861). Read from the collection's copies, never the live logs, with no tool needed. Rows caused by the collection itself (its own script blocks, which PowerShell logs automatically as "suspicious", and its own start) are kept but marked "from this collection run". 4104 account SIDs are translated to names.
- `ANALYSIS_README.txt` entries for the SYSTEM and service-account PSReadLine folders and Windows Terminal's folder; the System, EventLogs, user-profile and PSReadLine entries describe the new files.

### Changed
- The "user hives + PowerShell history" step is now "user hives"; the histories have their own step.

### Fixed
- **A stuck ListDlls could write hundreds of MB.** In a live run ListDlls kept retrying a process that had exited and wrote the same 4-line error 4.4 million times (315 MB) until the 15-minute timeout. It normally finishes in seconds, so its timeout is now 5 minutes, and `Invoke-External` has a new output cap (`-MaxOutputMB`, 50 MB for ListDlls) that stops a tool once its output passes that size. Whenever a tool is stopped (timeout or cap), repeated blocks of 1 to 8 lines that appear at least 3 times in a row are collapsed to one copy and a note with the repeat count, so the partial output stays readable; the step still reports FAIL, with the reason and the number of lines collapsed.

### Documentation
- User guide: new section 7.15, "Command-line activity: where commands are recorded" (including CMD, which keeps no history file, only `conhost.exe` memory); sections 4, 7.2, 7.7, 7.8, the quick reference and 7.14 list the new files.

### Verified
- Both CSVs built from a real Full collection's copies: 198 history lines gave 190 commands (5 multi-line commands joined); 524 event rows (450 script blocks, 74 PowerShell starts), of which 434 were correctly marked as the collector's own.
- The copy step and `command_history.csv` against a constructed snapshot: SYSTEM, 32-bit SYSTEM and NetworkService histories attributed to the right account, a VS Code host file included and an unrelated file in the PSReadLine folder skipped, bash `HISTTIMEFORMAT` times attached to the right commands, Python history, and only the PowerShell and CMD prompt lines taken from Windows Terminal screen text.
- A live elevated Deep run: 101 OK, 6 expected skips, 1 FAIL (the ListDlls hang fixed above). `command_history.csv` had 257 commands from 276 history lines (7 multi-line commands joined); `command_events.csv` had 518 rows sorted by time (406 script blocks, all marked as the collector's own; 111 PowerShell starts, the operator's own launch command correctly unmarked; and one WMI 5861 row, the "SCM Event Log Consumer" registration that ships with Windows). Both files were hashed and described in their folders' READMEs.
- The ListDlls fix with a stand-in tool that loops on the same 4-line error: the 5 MB cap and a 6-second timeout each stopped it and collapsed about 95,000 and 29,000 repeats to one note line; a tool that finishes normally is untouched; collapsing 50 MB of the real 315 MB output took 3 seconds and removed only the loop.
- **Not yet verified:** the 4688 and Sysmon 1 rows (the lab machine has no process auditing and no Sysmon; the field names follow the published event schemas), the Windows Terminal `buffer_*.txt` file name (Terminal isn't installed on the lab machine), and the ListDlls fix against a real ListDlls hang.

## [3.6.1]

### Fixed
- `Collection.log` started with the license-acceptance line instead of the `Collect_v3 log | started` header (the acceptance is logged before the collection folder exists). The header is now always the first line.
- `Collection.log` ended with an empty line: the final flush passed `$null`, which a `[string]` parameter turns into an empty string that was then written. Flushing no longer adds a line.

### Verified
- The 3.6.0 license prompt in a live elevated Quick run: typed `y`, and the acceptance (method and UTC time) was in `Collection.log`, `manifest.txt` and `manifest.json`; 28 OK, 1 expected skip.
- Both fixes with the script's own logging functions against a temporary log folder.

## [3.6.0]

### Changed
- **License changed from MIT to BSD 3-Clause.** Both licenses let anyone use, copy, modify and share the script; BSD 3-Clause states the redistribution conditions (keep the copyright notice, conditions and disclaimer with source copies, reproduce them in the documentation of other forms) and adds that the author's name may not be used to endorse derived products. The license text is also embedded in the script, and the script header carries the copyright and SPDX lines.
- **Every run now asks you to agree to the license terms first.** The script shows the BSD 3-Clause license and an authorized-use notice and asks "Do you agree to these terms? [y/N]"; any answer but yes ends the run before anything is collected or written. **`-AcceptLicense`** (new) records agreement without the prompt. **A `-NonInteractive` run now needs `-AcceptLicense`**, or it stops at once: add it to existing launch commands and scripts. The acceptance (method and UTC time) is recorded in `Collection.log`, `manifest.json` (`Script.LicenseAccepted`) and `manifest.txt`.

### Documentation
- README: new License, "Sharing and redistributing" and Disclaimer sections covering links, copies (forks, toolkit drives, zips), other forms, the no-endorsement condition, and prepared toolkit drives that also hold third-party tools. The note that third-party tools aren't included now says that several, not all, of their licenses forbid redistribution.
- User guide: the launch commands add `-AcceptLicense`; section 1 explains the prompt; section 5 lists the parameter.

## [3.5.1]

### Documentation
- **New user guide section 7.14, "Outputs that can contain passwords and other secrets",** with a bold caution and two tables: outputs that hold credential material by design (memory image; pagefile, hibernation file and swapfile; the SAM, SECURITY, SYSTEM and SOFTWARE hives; Windows Setup answer files in `Panther`; KAPE's Full-profile copy; the opt-in Defender quarantine) and outputs that can hold secrets depending on what users and attackers did (PowerShell history and transcripts, command lines in event logs and process lists, URLs and session files, Notepad tabs and Sticky Notes, notifications, screen and thumbnail caches, bulk_extractor output).
- **Corrected: KAPE's `!SANS_Triage` in the Full profile copies browser password stores.** Its browser targets take Chrome, Edge and Brave `Login Data`, `Cookies` and `Web Data`, Firefox `logins.json`, `signons.sqlite` and `cookies.sqlite`, and each user's DPAPI master keys; its remote-admin targets take AnyDesk `*.conf` and mRemoteNG `confCons.xml`. Confirmed in a real Full collection. The README's "never collected" line was only true of Collect_v3's own collectors; it now says so, with a caution box linking to section 7.14, and the browser section notes the difference.
- `ANALYSIS_README.txt` files for the collection root, `Memory\`, `Disk\SystemFiles\`, `Disk\Windows\Panther\` and `KAPE\` now carry a one-line caution about the credentials they can hold. Windows Setup answer files are still collected, since they can matter to the investigation.

## [3.5.0]

### Added
- **`ANALYSIS_README.txt` guidance files.** At the end of a run, the collection root, each top-level output folder and each artifact folder under `Disk\` get a short plain-text file: what the files are (for example, that the `.sys` files in `Disk\SystemFiles` are the pagefile, hibernation file and swapfile, not drivers, or that the `.log` files in the BITS `Downloader` folder are database transaction files, not text logs), why they matter, how to analyze them, and links to the tools' official pages and to the user guide. 60 entries cover every folder the script can produce. They're aimed at new analysts, researchers and students who open a folder without the guide. Only folders that exist and aren't empty get a file; an existing file of the same name is never overwritten; the files are written before hashing, so they're in `FileHashes.csv`. Collect_v3 doesn't run or include any of the tools named.
- `-NoAnalysisReadme` skips them.
- **Output drive check.** A new last row in `CollectorResults.csv` (phase 9) reads the System and Partition event logs for disk errors on, and reconnects of, the output disk during the run. It's WARN only when there's evidence of a dropout, never on a healthy drive.

### Fixed
- **A USB output drive that dropped out for a few seconds broke the log and crashed PowerShell.** On the lab laptop the output drive disconnected and reconnected twice during test runs (disk event 51, then Partition event 1006). `Collection.log` was a `Start-Transcript` file, so it stopped at the moment of the dropout and never recovered, and powershell.exe crashed on exit with an IOException. One run also marked six steps FAIL while the drive was gone, the other none at all, though the dropout overlapped a step. Now:
  - `Collection.log` is written line by line, and lines that can't be written are kept and written once the drive is back.
  - Before each step, an unreachable output folder gets up to 2 minutes to come back; if it doesn't, the remaining steps are marked FAIL ("output drive unavailable") instead of each failing on its own.
  - After each step, a reconnect (the volume's device name changes) marks that step WARN: "the output drive was disconnected and reconnected during this step; check its output".
  - There is no transcript any more, so nothing is left to crash on exit.

### Verified
- READMEs: against an empty copy of a real Full collection's folder tree plus the folders that collection didn't have (69 files written, every entry matched, every tool named has a link, a second run changed nothing), and in a live Standard run (29 files, all in `FileHashes.csv`).
- Logging and the drive watch: with a simulated dropout (a `subst` drive removed and re-created during a run of the functions) and against the real event logs of the run where the drive dropped out. A live Standard run with no dropout (70 OK, 6 expected SKIPs) gave a complete `Collection.log`, an OK drive check and no crash on exit. A second live run with the output drive pulled for about 20 seconds during the Mark-of-the-Web step: that step was marked WARN (its output was complete), the drive check was WARN ("reconnected 1 time"), `Collection.log` was complete and PowerShell didn't crash.

## [3.4.2]

Fixes and verification from an elevated Full + Memory run with `-YaraRules`, `-LolDriversCsv` and `-VelociraptorArtifactArgs` on the lab laptop (104 OK, 1 WARN, 5 expected SKIPs, no FAILs; the WARN is fixed below).

### Fixed
- **A click in the console window could pause the whole run.** With the console's QuickEdit mode on (the Windows default), one click starts a text selection, and Windows blocks every write to that console until it is cleared. A lab run sat for 6.5 hours after a finished step, waiting to print one line. The script now turns QuickEdit off for its own console window at start (logged) and restores the previous mode at the end, or straight away if collection is aborted. No registry or system setting is changed.
- **SQLECmd parsed nothing with current EZ Tools builds.** SQLECmd 2026.10.3 loads `SQLite.Interop.dll` from `runtimes\<platform>\native` next to the exe, and the script's clean working copy left that folder out, so SQLECmd exited at once (the step was correctly marked WARN). The `runtimes` folder is now copied too; the same collection then parsed 27 databases.

### Changed
- `-LolDriversCsv`: the log now says how many unique hashes were loaded and how many drivers matched (a match is logged in yellow). A file with no hashes in it marks the step WARN, because an empty list would otherwise look exactly like a clean host.

### Verified
- `-YaraRules` end to end with real Velociraptor 0.77.3: a benign test rule matched a marker typed into Notepad (1 hit, with a 48-byte context upload). The artifact's `YaraRule` and `ProcessRegex` parameters are confirmed in the saved definition.
- LOLDrivers matching against a local file merged from the project's 713 YAML files (19,184 unique hashes): 455 drivers checked, 0 hits on the clean laptop.
- On a USB 3 port, the I/O-bound steps are back at the baseline (memory image 252 s, RawCopy 283 s).
- `-DefenderQuarantine` and `-Archive -ArchivePassword` on a Standard run (70 OK, no WARNs, about 7 minutes): an EICAR test file quarantined by Defender was copied, and the 7-Zip archive can't even be listed without the password. Pass the password with `-Command`, not `-File` (a SecureString can't pass through `-File`).

### Documentation
- New user guide section 10, **bulk_extractor**: where to point it (memory image, pagefile and swapfile, Recycle Bin `$R`, `$LogFile`, converted hiberfil) and where not to (the whole case folder, parsed output, logs and hives), practical notes, and how it complements Volatility. The README links to it and credits Simson Garfinkel.
- `-VelociraptorArtifactArgs` takes a hashtable, which `powershell.exe -File` can't pass. The parameters table now shows the `-Command "& .\Collect_v3.ps1 ..."` form.
- Troubleshooting entry for a run that looks frozen (QuickEdit).

## [3.4.1]

Fixes from the first elevated Full + Memory run of 3.4.0 on the lab laptop (104 OK, 1 WARN, 5 expected SKIPs, no FAILs).

### Fixed
- **ETW check reported a false finding.** `logman query -ets` can fail as a whole ("The GUID passed was not recognized as valid by a WMI data provider") when one session can't be queried. The expected-session check then reported EventLog-System, EventLog-Security, DefenderApiLogger and the others as **NOT running**. Session names are now also read directly with `QueryAllTracesW`. If no session list can be read, each check says `UNKNOWN` and the step is marked WARN, instead of claiming the sessions are stopped.
- **False WARN in the network extras collector** on hosts with a disconnected adapter: "No MSFT_NetConnectionProfile objects found…" from `Get-NetIPConfiguration` is now treated like the other harmless "no matching object" records.

### Verified
- WFP: the real `netsh wfp show filters` XML matches the parser (922 filters, 20 BLOCK filters with an application path, all Windows Service Hardening rules on a clean host).
- `Get-SmbOpenFile`, Velociraptor with `Windows.EventLogs.RDPAuth` (23 artifacts, 0 failed).
- The 3.4.0 collectors add about 4.5 minutes to a Full run.

## [3.4.0]

Collector additions from a review of 3.3.1. 20 new collectors (110 in total, up from 90), plus new sections in the existing SMB and Velociraptor collectors.

### Added
- **Kernel drivers** (`System\drivers_hashed.csv`, Standard): every driver with SHA-256/SHA-1/MD5, signer, issuer, certificate expiry and version info.
  - Merges the service list with the modules actually loaded in the kernel (`EnumDeviceDrivers`), so drivers whose service key was deleted after loading are still listed (`LoadedNoService`).
  - A `Triage` column separates the ones worth reviewing from normal Windows library modules and crash-dump copies.
  - New `-LolDriversCsv` parameter matches the hashes against a local LOLDrivers export, with no network access.
- **Code integrity** (`Security\code_integrity.txt`): vulnerable driver blocklist setting, Device Guard registry, `Win32_DeviceGuard` (VBS / HVCI).
- **Logging tampering:**
  - `EventLogs\channel_config.csv` (every profile): enabled state, max size, retention and fill state of every event log channel.
  - `Security\etw_sessions.txt` (every profile): running ETW sessions, expected-session check, AutoLogger sessions with `Start=0`, full AutoLogger registry.
  - `Security\wfp_filters.xml` + `wfp_block_summary.csv`: all WFP filters (always written with `file=`), and a summary of BLOCK filters keyed on an application path (the EDRSilencer pattern). Deep+ also writes `wfp_state.xml`.
  - `Security\sysmon_config.txt`: Sysmon found by version info (works when renamed), decoded config (only a valid Microsoft-signed binary is run), driver registry parameters.
- **More remote-access tools** (Deep):
  - ScreenConnect, Atera and LogMeIn logs, with paths from KAPE 1.3.0.2 targets.
  - MeshAgent, NetSupport, SimpleHelp, Action1 and ScreenConnect agents discovered through their services.
  - Secret-bearing configs are presence + hash only, in `Disk\remote_access_presence.csv`. NetSupport `client32.ini` gives only its gateway address and port; MeshAgent `.msh` only its server URL.
  - Files pushed through ScreenConnect are listed and hashed, not copied.
- **SSH** (Standard): `authorized_keys`, `administrators_authorized_keys`, `known_hosts`, `config`, `sshd_config`, public host keys, sshd logs. Private keys are never copied.
- **Mark-of-the-Web** (`Disk\zone_identifier.csv`, Standard): Zone.Identifier for user Downloads, Desktop, Documents, Temp and the Outlook cache.
  - Read from the snapshot; a fast native stream scan handles about 26,000 hits in about 75 s.
  - Risky file types up to 50 MB are hashed at Deep+.
- **IIS** (Deep, IIS hosts only): `applicationHost.config` and other configs (module registrations), `Disk\iis_webroot_listing.csv` with hashes for script and binary types, and each site's `web.config`.
- **Virtual machines and disk images**: Hyper-V VMs, mounted VHD and ISO files (`System\virtual_disks.txt`); VHD/VHDX/VMDK/VDI/ISO/IMG file search (`System\virtual_disk_files.csv`, Deep, list only).
- **SMB open files** (`Get-SmbOpenFile`) in `Network\smb.txt`.
- **Service failure actions** (`Persistence\service_failure_actions.csv`, Standard): services that run a program on failure.
- **Notepad TabState / WindowState and Sticky Notes** (Deep).
- **PowerShell transcripts** (Standard): policy `OutputDirectory` folders (UNC paths recorded, not followed) and the default `Documents` locations.
- **Exfiltration and tunneling tools** (`Security\exfil_tools.csv`, Deep): rclone, restic, MEGA, WinSCP, FileZilla, PuTTY tools, ngrok, cloudflared, chisel, Syncthing, S3 Browser and Cyberduck, matched by name and by version info.
  - `rclone.conf` gives only its remote names and types (or `encrypted`).
  - Other configs are presence + hash only.
  - MEGAsync logs are copied.
- **Velociraptor:**
  - `Windows.EventLogs.RDPAuth` added to the defaults (23 artifacts).
  - New `-VelociraptorArtifactArgs` for per-artifact arguments; `-VelociraptorArgs` still applies to all.
  - New opt-in `-YaraRules`: runs `Windows.Detection.Yara.Process`, reads the rule parameter name from the build's artifact definition, and copies and hashes the rules file.
- **New opt-in `-DefenderQuarantine`:** copies Defender's quarantine (malware samples). Never enabled by any profile, with a console warning and a loud warning when archiving without a password.

### Changed
- `ProgramData\AnyDesk\*.conf` is no longer copied. `service.conf` can hold the unattended-access password hash and salt; it is now recorded as presence + hash only.
- `logman` added to the table of system binaries called by full path.

## [3.3.1]

### Added
- Velociraptor browser artifacts in the default Full-profile list: `Windows.Applications.Chrome.History`, `Edge.History`, `Chrome.Extensions`, `Firefox.History` and `Firefox.Downloads` (22 artifacts in total). They give a second, independently parsed source of browser history with **UTC** timestamps. `Chrome.Cookies` is deliberately left out.
- User guide section 7.13 **Browser artifacts**: where parsed and raw browser data lands (SQLECmd CSVs, raw profile files, KAPE copies including shadow-copy versions, Velociraptor zips), what each file holds, how to view it, and what is deliberately not collected.

### Fixed
- **Documentation said every timestamp in `Parsed\` is UTC.** The SQLECmd browser CSVs (`ChromiumBrowser_*`, columns ending in `(Local)`) are in the local time of the machine that ran SQLECmd, which is the suspect machine. Sections 7.10, 7.13 and 9.3 now say so, so analysts convert before correlating with UTC artifacts.

## [3.3.0]

### Added
- **Extra internal drives:** automatic discovery of internal disks besides the system drive (bus type SATA, NVMe, SAS, RAID, SCSI, ATA, Storage Spaces or Fibre Channel; USB, SD/MMC, iSCSI and virtual disks excluded; output and toolkit drives excluded; BitLocker-locked volumes skipped).
  - Deep: raw `$MFT`, `$LogFile` and `$Boot`, USN journal, root listing, Recycle Bin `$I` files.
  - Full: deleted-file content (`$R`) and KAPE (`-KapeVolumeTargets`, default `FileSystem,RecycleBin`).
- Parameters `-Volumes`, `-SystemDriveOnly`, `-KapeVolumeTargets`.
- A drive table at the start of the log, and a `Volumes` section in `manifest.json`.
- A warning and prompt when the output folder is on another internal disk.

### Changed
- MFTECmd output now includes the drive letter (`MFT_C.csv`, `Boot_C.csv`).
- RBCmd output is split per drive (`Parsed\RBCmd\<drive>\`).

## [3.2.2]

### Added
- USN journal via `fsutil usn readjournal <drive> csv` (Deep). Timestamps in that CSV are in host local time.

### Fixed
- **SQLECmd parsed nothing:** KAPE's `Maps` folder held old maps with duplicate IDs. It now runs from a de-duplicated working copy and retries without any map it rejects.
- **pagefile, hiberfil and swapfile reported "not present":** `Test-Path` returns False for in-use paging files.
- **Sigcheck CSVs unreadable:** UTF-16 without a byte-order mark is now converted to UTF-8.
- **Sigcheck WARN:** its exit code is the count of matches, not an error.
- **Network collector WARN:** "No matching MSFT_Net…" records from `Get-NetIPConfiguration` are no longer counted as errors.
- **Processes WARN:** `GetOwner` "Not found" for processes that exit mid-collection is no longer counted.
- **Defender WARN:** when the WinDefend service is stopped (0x800106ba), this is recorded as expected.

### Removed
- The RawCopy `$J` target. RawCopy cannot address the `$UsnJrnl:$J` stream.

## [3.2.1]

### Fixed
- **Manifest build failed** ("Argument types do not match"). The manifest is now built field by field, and any field that fails records its own error.
- **Velociraptor failed:** `Windows.KapeFiles.Targets` is no longer built in. It now collects 17 built-in artifacts, one zip each.

## [3.2.0]

### Added
- **About 40 new artifacts:**
  - network extras: port proxies, NetBIOS, neighbors, Wi-Fi profiles
  - IFEO and SilentProcessExit, startup commands, shadow-copy list
  - security settings, certificate stores, stored credential names, Kerberos tickets, local groups, AppX packages, PnP devices
  - WER, Panther, minidumps, Defender detection history, IIS logs, thumbcache, WebCache, notifications, OneDrive logs
  - remote-access tool logs, browser artifacts (no cookies, passwords or autofill)
  - pagefile, hiberfil and swapfile, full Recycle Bin, Windows Search database, MEMORY.DMP, Sigcheck of System32
- **New parsers:** AppCompatCacheParser, SBECmd, RBCmd, WxTCmd, SQLECmd.
- **KAPE:** `!EZParser` modules by default; new `-KapeVss` switch.
- **Tool discovery:** detects .NET builds that can't run and falls back to KAPE's bundled copies; ignores ARM64 builds and prefers x64 over x86.

### Fixed
- **WinPmem command line:** corrected for go-winpmem (`acquire --nosparse`).
- **Shadow copy:** removed before KAPE runs, so it isn't collected twice.
- **Copy notes:** no longer fill up with "0 copied" lines.

## [3.1.0] and earlier

- **3.1.0:**
  - shadow-copy event logs go to `EventLogs\All`, plus a live `wevtutil` export
  - ported the remaining items from the original batch collector
- **3.0.2:** defensive reading of CIM properties, and a try/catch around the manifest build.
- **3.0.1:**
  - the shadow-copy ID is recorded right after creation, so a failed mount no longer leaks a snapshot
  - scheduled-task COM-handler actions are guarded
- **3.0.0:** complete rewrite of v2 as a collector framework.
  - fixed a variable-name collision: PowerShell names are case-insensitive, and `$N` / `$n` clashed
