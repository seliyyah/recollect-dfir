# Development notes

For anyone (human or AI assistant) changing `Collect_v3.ps1`.

## Architecture

- **Collectors.** Every artifact is registered with `Add-Collector`:
  - `-Phase`: 1–8, order of volatility
  - `-Level`: Quick=1, Standard=2, Deep=3, Full=4
  - `-Name`
  - `-Out` (relative output path) and `-Format`: `Text`, `Csv`, `Json` or `None`
  - optional `-Needs <tool keys>`, `-NeedsVss`, `-OnlyWithoutVss`
- **`Invoke-Collector`** runs each one with timing and error capture, and records OK / WARN / FAIL / SKIPPED:
  - **FAIL** when the action throws.
  - **WARN** for a non-zero exit code or anything left in `$Error`.
  - Expected, harmless errors should be removed from `$Error` inside the collector (see the Processes and Defender collectors) rather than hidden globally.
- **Phases:**

  | Phase | Contents |
  |---|---|
  | 1 | Memory |
  | 2 | Time and network |
  | 3 | Processes, sessions, services, persistence |
  | 4 | System configuration |
  | 5 | Shadow copy and disk copies (plus live fallbacks) |
  | 6 | Slow live tools |
  | 7 | Parsers (run only against collected **copies**) |
  | 8 | KAPE and Velociraptor (the shadow copy is removed first) |

- **External tools** run through `Invoke-External`, which captures stdout/stderr, enforces a hard timeout, converts UTF-16 output to UTF-8 and stores the exit code in `$script:LastExit`. An optional `-MaxOutputMB` stops a tool whose output passes that size (a tool stuck repeating an error); after any stop, `Compress-RepeatedLines` collapses repeated blocks in the partial output and the step throws, so it reports FAIL.
- **Launch and guided setup (3.8.0):**
  - `collect.cmd` only finds the script, checks elevation (`fltmc`), self-elevates with `/elevated` for guided setup, and runs `powershell.exe -NoProfile -ExecutionPolicy Bypass -File`. Keep it ASCII and CRLF.
  - `$GuidedMode` is true when `$PSBoundParameters` is empty. The order is: banner, then license, then admin and architecture checks, then `Invoke-GuidedSetup`, which returns a hashtable and writes nothing. The script then assigns the choices to the parameter variables and adds them to `$PSBoundParameters`, so the manifest records them. Nothing is created before the summary is confirmed.
  - The console UI helpers (`Write-Ui*`, `Read-Ui*`, `Show-ProfileMenu`, `$ProfileInfo`) are plain ASCII. `Read-UiAnswer` handles Q by calling `Stop-GuidedSetup`, which exits 0.
  - Drive types come from `Win32_DiskDrive`, not `Get-Disk`, whose first call took 18 s on the lab laptop.
  - The profile times in `$ProfileInfo` must match the README and user guide section 4.
- **Collector levels:** 0 = Memory Only and up (memory, clock), 1 = Quick, 2 = Standard, 3 = Deep, 4 = Full.
- **Windows binaries** are called by full path through the `$Exe` table (System32). `PATH` is reset to system directories at start.
- **Tool discovery:** `Find-Tool` searches `Tools\` recursively by file name. It:
  - skips `\arm64\` paths
  - ranks x86 paths last on 64-bit systems
  - uses `Test-ToolRunnable` to skip framework-dependent .NET apps whose runtime major version isn't installed
- **Shadow copy:** created in phase 5 and mounted through a directory symlink under `%SystemRoot%\Temp`, so hashing never walks it. `Copy-VssArtifact` copies from it. `Remove-Vss` is idempotent and runs before phase 8 and in a `finally` block.
- **Extra volumes:** `Get-InternalVolume` uses `Get-Partition` / `Get-Disk` (BusType allowlist), with a `Win32_LogicalDisk` fallback. `$Ctx.ExtraVolumes` holds the drives selected. `Get-NtfsVolumeList` returns the system drive plus the extra NTFS drives.
- **Logging (3.5.0):** `Write-Log` prints to the console and appends the same line to `Collection.log` with `Add-LogLine` (open, append, close). There is no `Start-Transcript`: a transcript keeps one handle open, so a USB output drive that drops for a few seconds kills it for the rest of the run, and powershell.exe then crashes on exit. Lines that can't be written are held in `$script:LogPending` and written with the next line that succeeds.
- **Output drive watch (3.5.0):** `Get-DosDevice` reads the NT device behind the output drive letter. `Wait-OutputDrive` (before each step) waits up to 120 s for an unreachable output folder; `Get-OutputDropNote` (after each step) marks the step WARN if the device name changed, which happens on every disconnect and reconnect. `Get-OutputDriveCheck` adds a phase 9 row from the System log (source `disk`, matched by `\HarddiskN\`) and the Partition log (event 1006, matched by the output disk's serial number).
- **After collection:**
  1. output drive check, then `CollectorResults.csv`
  2. `manifest.json` (built field by field with `Set-ManifestField`) and `manifest.txt`
  3. `ANALYSIS_README.txt` files, then the last flush of `Collection.log`
  4. SHA-256 of every file into `FileHashes.csv`
  5. optional archive

## Rules

1. **Forensic soundness first:**
   - never write to the system drive or another internal disk unless `-AllowSystemDrive` is given
   - call host binaries by full path
   - keep all timestamps UTC (or label them clearly, as with the fsutil USN CSV)
   - hash after the last write to `Collection.log`
   - remove only what the script itself created
2. **Windows PowerShell 5.1 compatibility:**
   - no ternary, `??`, `?.` or `&&`
   - `-Encoding UTF8` writes a BOM
   - `Start-Process` needs `$null = $p.Handle` before `ExitCode` can be read
3. **`Set-StrictMode -Version Latest` is on.** Reading a missing property throws; guard with `PSObject.Properties`.
4. **Variable names are case-insensitive.** `$ToolkitRoot` and `$toolkitRoot` are the same variable. Check for clashes with every new variable. This has caused two bugs.
5. **Large `[ordered]@{}` literals** with many computed values have thrown "Argument types do not match" on PS 5.1. Build dictionaries one statement at a time.
6. **Keep the collector pattern.** Add new artifacts with `Add-Collector`, not as loose top-level code.
7. **Privacy:** don't collect cookies, saved passwords or autofill data.

## Testing

Only on a lab VM or a dedicated test machine. Snapshot the VM first.

1. Parse check:
   ```powershell
   [void][System.Management.Automation.Language.Parser]::ParseFile('.\Collect_v3.ps1',[ref]$null,[ref]$e); $e
   ```
2. Run `Quick`, then `Standard`, `Deep`, and `Full -Memory`.
3. After each run, read `CollectorResults.csv` (filter Status ≠ OK), then `manifest.json`, and spot-check the output files themselves: a step marked OK can still produce empty output.
4. Check that the shadow copy was removed: `vssadmin list shadows`.

## Verification status of third-party command lines

| Tool | Status |
|---|---|
| KAPE 1.3.0.2 (`--tsource --tdest --target --tflush --vss --module --mdest --mflush`) | Verified (full run) |
| Velociraptor 0.77.3 (`artifacts list`, `artifacts collect <name> --output <zip>`) | Verified (24 artifacts including the 5 browser artifacts and `Windows.Detection.Yara.Process`, 0 failed) |
| go-winpmem (`acquire --nosparse <file>`) | Verified (33.5 GB image) |
| RawCopy 1.0.0.22 (`/FileNamePath:C:0`, `C:2`, `C:7`, file paths for paging files) | Verified. `$UsnJrnl:$J` is **not** supported. |
| `fsutil usn queryjournal` / `readjournal <drive> csv` | Verified |
| EZ tools (KAPE-bundled .NET Framework builds) | Verified, including the SQLECmd map de-duplication. SQLECmd 2026.10.3 also needs its `runtimes\` folder in the working copy (fixed in 3.4.2; 27 databases parsed). |
| Magnet RAM Capture, DumpIt command lines | **Unverified** (WinPmem is used first) |
| Extra-internal-volume collection | **Unverified**: no test machine with a second internal disk yet |
| `-Archive -ArchivePassword` / 7-Zip 23.01 | Verified (Standard run: 1,088 files, 782 MB → 58 MB; listing without the password fails, so headers are encrypted; `.sha256` matches). The password has to be passed with `-Command`, since a SecureString can't pass through `-File`. |
| `-NtpServer` | **Unverified** |
| `ANALYSIS_README.txt` writer (3.5.0) | Verified on a skeleton of a real Full collection's folder tree (69 files, all 60 entries matched, idempotent) and in a live Standard run (29 files, all in `FileHashes.csv`). |
| Line-by-line `Collection.log`, output drive watch and check (3.5.0) | Verified with a simulated dropout (a `subst` drive removed and re-created: held-back lines written in order, the wait logged, a reconnect flags only its own step) and against the real event logs of a run where the USB output drive dropped (1 disk error and 2 reconnects found; WARN), and of a quiet minute (OK). Live Standard run with no dropout: `Collection.log` complete from the first line to "Collection finished", check row OK, no PowerShell crash on exit. Live Standard run with the USB output drive pulled for about 20 s during the Zone.Identifier step: that step WARN, its output complete (25,909 rows), the check row WARN, `Collection.log` complete, no crash. Windows logs a pull as two Partition 1006 events (Capacity 0, then the real capacity); only the second is counted. The "drive never comes back" path is tested by simulation only. |

### 3.4.0 additions

First tested **without admin rights** through a harness that loads the script's real functions and collector definitions, against a fake system drive with fixtures and traps (private SSH keys, secrets in `client32.ini`, Atera, AnyDesk and `rclone.conf`). No trap secret reached any output. Then one elevated `Full -Memory -KapeVss` run on the lab laptop (3.4.0: 104 OK, 1 WARN, 5 expected SKIPs, 0 FAIL; the WARN and the ETW false finding were fixed in 3.4.1).

| Item | Status |
|---|---|
| Driver hashes, `EnumDeviceDrivers`, path normalization, `Triage`, LOLDrivers matching | Verified live (455 drivers; works even unelevated). Matched against a local file merged from the 713 LOLDrivers YAMLs (19,184 unique hashes): 0 hits on the clean laptop, case-insensitive lookup confirmed. |
| Event log channel config, code integrity / `Win32_DeviceGuard`, Sysmon "not installed" path, virtual disks, service failure actions | Verified live |
| Zone.Identifier native scan | Verified (fixtures + a real profile: 25,909 hits in 77 s from the snapshot) |
| SSH, transcripts (default locations), Notepad/Sticky, MEGAsync, RMM presence + secret filtering | Verified on fixtures |
| `-DefenderQuarantine` | Verified real (3.4.2): an EICAR test file quarantined by an active Defender was copied (Entries, ResourceData, Resources; 3 files, 0 failed). The Defender status collector was also run against an active Defender for the first time (detection listed). |
| WFP: `netsh wfp show filters/state file=` and the summary parser | Verified elevated (922 filters, 20 BLOCK-by-app, app paths decoded from `asString`) |
| `Get-SmbOpenFile` | Verified elevated (no open files) |
| `logman query -ets` | Elevated, it **failed as a whole** on the lab laptop ("The GUID passed was not recognized as valid by a WMI data provider"). 3.4.1 adds `QueryAllTracesW` (`Get-EtwSessionName`) and `UNKNOWN` instead of a false "NOT running". The native enumeration is verified elevated (27 sessions, matching logman; unelevated it correctly returns 0). |
| Velociraptor per-artifact args, `Windows.EventLogs.RDPAuth` | Verified real (23 artifacts, 0 failed, 388 s) |
| Velociraptor YARA (rule text with newlines and quotes) | Verified real: a test rule matching a marker typed into Notepad, with `-VelociraptorArtifactArgs @{'Windows.Detection.Yara.Process'=@('ProcessRegex=(?i)notepad')}`, gave 1 hit in notepad.exe (rule, offset and a 48-byte context upload). `YaraRule` and `ProcessRegex` confirmed in the saved artifact definition. |
| Sysmon `-c` with Sysmon installed, IIS (`appcmd list vdir`), transcription policy folders, MeshAgent/NetSupport/SimpleHelp/Action1 discovery, ScreenConnect transfer folder | **Unverified**: not installed on the lab laptop |
| Exfil tools: version-info match on a renamed real rclone | **Unverified** (name match and `rclone.conf` parsing verified) |
| MEGAsync log folder path | **Unverified** (community-documented) |
| Run time with the 3.4 additions | The new collectors total ≈ 4.5 min. The 3.4.0 Full + Memory run took 130 min and 73 GB against a 92 min baseline, but the extra time was all I/O-bound steps (memory image 255 → 1012 s, RawCopy 298 → 689 s, KAPE 2325 → 3066 s): the output drive ran at USB 2.0 speed (~33 MB/s). Re-measured on a USB 3 port (3.4.2): memory 252 s, RawCopy 283 s, USN 372 s, Velociraptor 376 s (24 artifacts), Sigcheck 519 + 256 s, all back at the baseline. KAPE took 2752 s because the host now has one more shadow copy (4 vs 3, 15.8 vs 12.6 GB). |
| License prompt (3.6.0) | Verified non-elevated (the run stops at the admin check right after the prompt): `n` and an empty answer exit 1 with "Terms not accepted" and nothing written; `y` logs the acceptance; `-NonInteractive` without `-AcceptLicense` prints the terms and exits 1; `-NonInteractive -AcceptLicense` logs the acceptance without showing the terms. Live elevated Quick run (interactive `y`): acceptance recorded in `Collection.log`, `manifest.txt` and `manifest.json`. `-AcceptLicense` not yet run elevated. |
| Command history (3.7.0): copy step and `command_history.csv` | Verified against a real Full collection's PSReadLine file (198 lines, 190 commands) and a constructed snapshot (SYSTEM, SysWOW64, ServiceProfiles, VS Code host, bash with `HISTTIMEFORMAT`, Python, Windows Terminal prompt lines), and live in an elevated Deep run (257 commands from 276 lines). Windows Terminal's `buffer_*.txt` name is from its session-restore feature (1.21+) and **unverified** (Terminal not installed on the lab laptop). |
| Command events (3.7.0): `command_events.csv` | 4104 and 400 verified against a real Full collection's logs (524 rows; 434 marked as the collector's own by PID and script path; SIDs translated). Live elevated Deep run: 518 rows, all 406 script blocks marked as the collector's own, and one 5861 row (the built-in "SCM Event Log Consumer"), so 5861 parsing is verified. 4688 and Sysmon 1 **unverified**: no process auditing or Sysmon on the lab laptop; field names follow the event schemas. |
| Tool output cap and repeat collapsing (3.7.0) | Verified with a stand-in tool looping on a 4-line error: the `-MaxOutputMB` cap and the timeout each stopped it and collapsed the repeats to one note line; a normally finishing tool is untouched; edge cases (paired blank lines kept, blocks seen only twice kept, partial trailing copy kept, UTF-16 input, Latin-1 bytes) checked; 50 MB of a real ListDlls loop collapsed in 3 s. Not yet seen against a real ListDlls hang. |
| Unusual alternate data streams (3.9.0) | `Find-AdsStream` (C# via Add-Type) verified on planted streams (PE in a file's stream, script in a folder's stream, 3 MB, empty, routine ones) and on the live system drive, not elevated (445,000 entries, about 2¼ minutes). **Unverified:** an elevated run reading from the shadow copy. |
| Sysmon events CSV (3.9.0) | `ConvertTo-SysmonRow` verified with events built from the Sysmon schema; the `Get-SysmonEventRows` reader loop and its cap verified against a real collected log of another channel. **Unverified:** a real Sysmon log and the own-run marking (no Sysmon on the lab laptop). |
| `-KapeSkipBrowserData` (3.9.0) | `Get-KapeTargetList` verified against the lab KAPE's `!SANS_Triage.tkape` (17 targets without `WebBrowsers`); guided question verified with scripted answers. **Unverified:** a Full run with the switch. |
| Guided setup and `collect.cmd` (3.8.0) | Guided setup verified with scripted answers (a fake `Read-Host`) in six scenarios: invalid input re-asked, Q and "no" at the summary exit cleanly, no memory tool, the YARA folder rule, a password mismatch, the system drive accepted. The real script was run to the point where the collection folder would be created, with the admin check stubbed: choices reach the parameter variables, the manifest parameters and the log; a declined license exits; manual `MemoryOnly` and the new menu work. `collect.cmd` verified for `/?`, script discovery (beside it, one level down, a space in the path, none, two), the non-elevated manual message, and argument pass-through. Live guided run (Quick, with an archive) verified on the lab laptop: the UAC prompt, the elevated window, the manifest and log entries, the empty-folder cleanup and the archive hash. **Unverified:** a full Memory Only collection, and the earlier QuickEdit switch-off live. |

Fixtures still to build on the lab laptop (from the 3.4.0 handoff): load a benign signed test driver through a service and delete the service key; add a WFP block filter for a dummy app; shrink and disable test event-log channels; `sc failure <testsvc> actions= run/60000 command= ...`; a real renamed rclone; a Notepad unsaved tab on Windows 11; a YARA rule matching a known running process (done in 3.4.2).

## Known benign output

- `<tool>.err` files containing only a Sysinternals copyright banner.
- `Skipped ...: needs .NET 10.0.0 runtime` during tool discovery, when a KAPE-bundled fallback is found.
- `wfp_block_summary.csv` rows with provider `FWPM_PROVIDER_MPSSVC_WSH` (Windows Service Hardening: SearchFilterHost, dmcertinst, omadmclient and similar). A clean Windows 10 host has about 20 of them.
- SQLECmd console: `SQL logic error` for the maps *Edge Browser History Screenshots* and *Windows Your Phone Settings DB*. The map queries don't match every database version; SQLECmd exits 0 and parses the rest.
- `Velociraptor\Windows.Applications.Edge.History_console.log.err`: `Symbol Source not found`. One query in Velociraptor 0.77.3's own Edge.History artifact; the zip still holds the history rows and the step is OK.
- Velociraptor YARA log: `yara: Warning unknown shorthand directive //`. A rules file that starts with a comment; the rule is still compiled and used.
