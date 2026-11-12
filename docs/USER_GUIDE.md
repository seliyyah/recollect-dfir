# Recollect — Windows DFIR Collection Script: User Guide

**Script version:** 4.0.1  **Runs on:** Windows 10 / 11 / Server 2016+ with Windows PowerShell 5.1  **Needs:** Administrator rights

> 🛡️ Recollect is a **blue-team** tool for incident responders, forensic analysts and researchers. It orchestrates freely available forensic tools, and their authors are credited in the [README](../README.md#credits). Please read [Purpose and responsible use](../README.md#purpose-and-responsible-use) before using it on a real case.

---

## 1. Quick start: launch commands

> **Before you start:** only run this on a machine you are **authorized** to examine. Plug in your toolkit drive.

There are two ways to start a collection:

| | Guided setup | Manual mode |
|---|---|---|
| **Start it with** | `recollect` (no parameters) or a double-click on `recollect.cmd`, then choose **1** after the license | Choose **2** after the license and type the parameters at the prompt, or start with `recollect` followed by parameters |
| **Administrator rights** | Asked for automatically (a Windows permission prompt; the collection opens in a new window) | Run it from a terminal opened with *Run as administrator* |
| **Questions** | License, then five short steps and a summary to confirm | Only the license (none with `-AcceptLicense`); at the prompt, a confirmation of what you typed |
| **Best for** | Most collections, and anyone new to the tool | Experienced users, scripts, repeatable procedures |

### 1.1 How to launch `recollect.cmd`

Replace `X:` with your toolkit drive's letter: File Explorer → **This PC** shows it. Use whichever of these suits you; they all do the same thing.

**Which window am I in?** Windows Terminal can open either PowerShell or Command Prompt. Look at the prompt:
- `PS C:\Users\you>` means **PowerShell**.
- `C:\Users\you>` (no `PS`) means **Command Prompt**.

**Easiest: one line, from any folder, in either window**

```powershell
X:\Toolkit\recollect.cmd
```

**File Explorer, no typing:** open `X:\Toolkit` and double-click **`recollect.cmd`**.

**PowerShell, from the toolkit folder**

```powershell
X:                # switch to the toolkit drive; the prompt becomes PS X:\>
cd \Toolkit       # go into the toolkit folder; the prompt becomes PS X:\Toolkit>
.\recollect         # PowerShell needs .\ to run a file from the current folder
```

`cd X:\Toolkit` does the first two steps at once. Typing plain `recollect` in PowerShell gives *"The command recollect was not found, but does exist in the current location"*. That's PowerShell's safety rule; add the `.\`.

**Command Prompt, from the toolkit folder**

```bat
X:                &rem switch to the toolkit drive; the prompt becomes X:\>
cd \Toolkit       &rem go into the toolkit folder; the prompt becomes X:\Toolkit>
recollect           &rem no .\ needed in Command Prompt
```

In Command Prompt, `cd X:\Toolkit` on its own does **not** change drives. Type `X:` first, or use `cd /d X:\Toolkit`.

**Then:** started without parameters, `recollect` asks Windows for permission (choose **Yes**), and the guided setup opens in a new window. For manual mode, open the window with *Run as administrator* first (right-click PowerShell, Command Prompt or Windows Terminal → *Run as administrator*) and add parameters to any of the commands above, for example `X:\Toolkit\recollect.cmd -CaseId IR-001 -CollectionProfile Standard`.

**Shorter still:** `recollect.cmd` also works at the root of the drive, with the toolkit in a folder one level below it (`X:\recollect.cmd` next to `X:\Toolkit\`). Then `X:\recollect` from anywhere, or a double-click on the drive itself, is all it takes.

### 1.2 Guided setup (recommended)

Started without parameters, Recollect shows the license terms and then asks how to set up the collection:

```
  HOW DO YOU WANT TO SET UP THIS COLLECTION?
   1  Guided setup   Five short questions with suggested answers. Recommended.
   2  Manual mode    Type the parameters yourself, as on the command line.
```

Press Enter (or **1**) for guided setup, or **2** for manual mode (section 1.3). Guided setup then asks:

| Step | Question | Default (press Enter) |
|---|---|---|
| 1. Case details | Case ID (letters, numbers, dots, dashes, underscores), then examiner name | Case ID must be typed; examiner = the signed-in user |
| 2. Collection profile | Quick, Standard, Deep, Full or Memory Only (section 4), each with typical time and space | Standard |
| 3. Memory capture | Capture RAM first? Shows this computer's RAM size, the time and the space it needs | Yes for Deep and Full, No for Quick and Standard; always included in Memory Only |
| 4. Output location | The folder for the collection. Shows the drive's type and free space; warns before writing to this computer's own disks or when space is short | `<toolkit>\Collections` |
| 5. Options | Only the options that apply: Defender quarantine (Standard and up), LOLDrivers matching (when a LOLDrivers export is in `Tools\`), YARA scan (Full, when rules are in `Tools\YARA\`), **KAPE browser data** (Full, when KAPE is in `Tools\`: a disclaimer explains what it copies, and you include or leave it out), **network capture** (every profile but Memory Only: records traffic while the collection runs, with a disclaimer), archive with a password | Off, except LOLDrivers matching and KAPE browser data (included unless you say no). Network capture is off unless you say yes |

A summary follows: case, examiner, computer, profile, memory, output drive, options, estimated time and space. It also shows the **same collection as a manual-mode command**, which `Collection.log` records too. The collection starts only when you confirm. Type **Q** at any prompt to quit; nothing has been collected or written up to that point.

Guided runs record their choices in `manifest.json` (`Script.Parameters`) as if they had been typed, and `Script.LaunchMode` says which mode was used. The archive password is never displayed, logged or recorded.

### 1.3 Manual mode

There are two ways in.

**At the prompt:** start `recollect` with no parameters, accept the license and choose **2**. Then type the parameters exactly as you would after `recollect` on the command line, for example `-CaseId IR-001 -CollectionProfile Full -Memory -OutputPath F:\Collections`, and press Enter:

- Recollect lists what it will run with and asks you to confirm. Without `-CollectionProfile` it shows the profile menu next; without `-CaseId` the case ID is `NOCASE`.
- Type **?** for the list of parameters, **B** to go back to the choice, or **Q** to quit.
- Parameter names can be shortened as long as they stay unambiguous (`-Coll` for `-CollectionProfile`). Switches can be turned off explicitly: `-Memory:$false`.
- Only plain values are accepted (words, paths, quoted text, comma lists such as `-Volumes D:,F:`). Anything else is refused and nothing you type is ever run: no variables, `$(...)`, `;` or pipes.
- `-ArchivePassword` isn't typed on the line. With `-Archive`, Recollect asks for the password afterwards, hidden and twice. `-VelociraptorArtifactArgs` (a hashtable) works only on the command line.
- `Collection.log` records the typed line (`Parameters typed: recollect ...`), and `manifest.json` records `Script.LaunchMode` as `manual (typed at the prompt)`.

**On the command line:** give `recollect` (or `recollect.ps1`) any parameter and it asks no questions apart from the license and the warnings below. Open a terminal with *Run as administrator* and go to the toolkit folder:

```powershell
cd X:\Toolkit
```

Then run **one** of these, changing `-CaseId` to your own case number. The `recollect` form and the long `powershell.exe` form below are equivalent: `recollect.cmd` adds `-NoProfile -ExecutionPolicy Bypass` for you.

```bat
recollect -CaseId IR-001 -CollectionProfile Full -Memory -OutputPath X:\Collections
recollect -CaseId IR-001 -CollectionProfile MemoryOnly
```

> **License terms.** Every run starts by showing the license (BSD 3-Clause, including its "as is" warranty disclaimer) and an authorized-use notice, and asks **"Do you agree to these terms? [y/N]"**. Type `y` to continue. Any other answer ends the run before anything is collected or written. The commands below add `-AcceptLicense`, which records your agreement without the prompt; it's required with `-NonInteractive`, and a `-NonInteractive` run without it stops at once. Either way, the acceptance (how and when, in UTC) is recorded in `Collection.log`, `manifest.json` and `manifest.txt`. Read the terms once in [LICENSE](../LICENSE) or by running the script without `-AcceptLicense`.

**Full collection with memory (recommended, collects everything):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\recollect.ps1 -CollectionProfile Full -Memory -CaseId IR-001 -NonInteractive -AcceptLicense
```

**Full, plus everything KAPE can find in older shadow copies (slower, much bigger):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\recollect.ps1 -CollectionProfile Full -Memory -KapeVss -CaseId IR-001 -NonInteractive -AcceptLicense
```

**Memory only (RAM image plus the clock and time zone; about 5 minutes for 32 GB):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\recollect.ps1 -CollectionProfile MemoryOnly -CaseId IR-001 -NonInteractive -AcceptLicense
```

**Deep (no KAPE or Velociraptor; about 30–60 minutes):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\recollect.ps1 -CollectionProfile Deep -Memory -CaseId IR-001 -NonInteractive -AcceptLicense
```

**Standard (registry, event logs, Prefetch and the core live tools; about 10 minutes):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\recollect.ps1 -CollectionProfile Standard -CaseId IR-001 -NonInteractive -AcceptLicense
```

**Quick (volatile state only; 2–3 minutes):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\recollect.ps1 -CollectionProfile Quick -CaseId IR-001 -NonInteractive -AcceptLicense
```

**Manual, but asked for the profile** (any parameter except `-CollectionProfile`: the script shows the profile menu):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\recollect.ps1 -CaseId IR-001
```

Started with **no** parameters at all, `recollect.ps1` runs the guided setup, exactly like `recollect`.

The results land in `X:\Toolkit\Collections\<CaseId>_<ComputerName>_<UTC time>\`. To send them somewhere else, add `-OutputPath Y:\Evidence`.

> **Never save the output to the C: drive** (or to any other internal disk of the suspect machine). Doing so overwrites deleted data that might be evidence. The script warns you and stops unless you add `-AllowSystemDrive`.

---

## 2. Software requirements

### 2.1 On the machine being collected

| Requirement | Notes |
|---|---|
| Windows 10 / 11 / Server 2016 or newer, 64-bit preferred | 32-bit works, with 32-bit tool builds |
| Windows PowerShell 5.1 | Built into Windows 10/11. Launch with `powershell.exe`, not `pwsh`. |
| Administrator rights | The script exits if it isn't elevated |
| Nothing to install | Every tool runs from the toolkit drive |

### 2.2 Toolkit drive

Use an **external USB drive** (or a network share) with enough free space. The script checks free space before it starts:

| Profile | Minimum free space | Add for `-Memory` |
|---|---|---|
| Quick | 1 GB | + RAM × 1.1 |
| Standard | 5 GB | + RAM × 1.1 |
| Deep | 15 GB | + RAM × 1.1 |
| Full | 100 GB | + RAM × 1.1 |

*Real example:* a Full run with `-Memory` on a laptop with 32 GB of RAM produced about **72 GB** in **about 92 minutes**: a 33.5 GB memory image, 18 GB of paging and hibernation files, 13 GB from KAPE and about 6 GB of disk artifacts.

### 2.3 Third-party tools

The script finds each tool by its **file name**, searching every folder under `Toolkit\Tools\`. **Folder names don't matter.** Any tool that is missing is skipped and recorded as `SKIPPED` in the results, and the rest of the collection still runs.

| Tool | Required? | File(s) the script looks for | Used for | Profile | Where to get it |
|---|---|---|---|---|---|
| **Sysinternals Suite** | Strongly recommended | `autorunsc64.exe`, `handle64.exe`, `tcpvcon64.exe`, `Listdlls64.exe`, `logonsessions64.exe`, `sigcheck64.exe` (or the 32-bit names without `64`) | Autoruns persistence, open handles, connections, DLLs, logon sessions, unsigned-file scan | Quick+ | learn.microsoft.com/sysinternals (download the **Sysinternals Suite** zip) |
| **Eric Zimmerman tools** | Strongly recommended | `EvtxECmd.exe`, `RECmd.exe` (+ `BatchExamples\Kroll_Batch.reb`), `MFTECmd.exe`, `AmcacheParser.exe`, `PECmd.exe`, `LECmd.exe`, `JLECmd.exe`, `SrumECmd.exe`, `SBECmd.exe`, `RBCmd.exe`, `WxTCmd.exe`, `SQLECmd.exe`, `AppCompatCacheParser.exe` | Turn raw artifacts into CSVs | Deep+ | ericzimmerman.github.io (run `Get-ZimmermanTools.ps1`) |
| **KAPE** | Recommended | `kape.exe` (with its `Targets\`, `Modules\` and `Modules\bin\` folders) | Full triage collection plus the `!EZParser` modules. Its bundled Zimmerman tools are also the fallback (see note) | Full | kroll.com/kape (free; registration required) |
| **Velociraptor** | Recommended | `velociraptor*.exe` (for example `velociraptor-v0.77.3-windows-amd64.exe`) | 17 built-in forensic artifacts, each zipped | Full | github.com/Velocidex/velociraptor/releases |
| **WinPmem** | One memory tool needed for `-Memory` | `go-winpmem*.exe` or `winpmem*.exe` | RAM image (1st choice) | any + `-Memory` | github.com/Velocidex/WinPmem/releases |
| **Magnet RAM Capture** | Optional | `MRCv*.exe` or `MagnetRAMCapture*.exe` | RAM image (2nd choice) | any + `-Memory` | magnetforensics.com (free tools) |
| **Comae DumpIt** | Optional | `DumpIt.exe` (the x64 build is picked automatically) | RAM image (3rd choice) | any + `-Memory` | Comae Toolkit (Magnet Forensics) |
| **RawCopy** | Recommended | `RawCopy64.exe` / `RawCopy.exe` | Locked NTFS files: `$MFT`, `$LogFile`, `$Boot`, pagefile, hiberfil, swapfile | Deep+ / Full | github.com/jschicht/RawCopy |
| **7-Zip** | Optional | `7z.exe` **and** `7z.dll` (or `7za.exe`) | Only with `-Archive` (encrypted .7z) | any | 7-zip.org. Copy the two files from `C:\Program Files\7-Zip\`; **the installer alone won't work** |

> **Note on .NET and the Zimmerman tools:** the newest Zimmerman builds in `Get-ZimmermanTools\net\` need the **.NET 10 runtime**, which suspect machines usually don't have. If a tool can't run, the log shows a harmless warning like `Skipped ...\EvtxECmd.exe: needs .NET 10.0.0 runtime` and the script **automatically uses the copy bundled with KAPE** (in `kape\KAPE\Modules\bin\`), which only needs the .NET Framework built into Windows. That's why **keeping KAPE in the toolkit matters even if you never run Full.** You can also run `Get-ZimmermanTools.ps1 -NetVersion 0`, which downloads the .NET 4.7.2 builds alongside the .NET 10 ones; the script picks whichever can run. AmcacheParser, SQLECmd and WxTCmd are only published for .NET 10, so for those three the KAPE copies are still the fallback (as of the October 2026 release notes on ericzimmerman.github.io).

### 2.4 On your analysis workstation (not the suspect machine)

| Tool | For |
|---|---|
| **Timeline Explorer** (Zimmerman; in `Get-ZimmermanTools\net\TimelineExplorer\`) | Opening all the CSVs. See section 9 |
| **.NET Desktop Runtime 10** | Needed by the current Zimmerman GUI tools (Timeline Explorer, Registry Explorer and the others) |
| Registry Explorer, MFTExplorer, ShellBags Explorer, JumpList Explorer, EZViewer | Interactive viewing of the raw artifacts (all in `Get-ZimmermanTools\net\`) |
| Volatility 3 and/or MemProcFS | Memory image analysis |
| DB Browser for SQLite | Browsing browser and app databases by hand |
| Hayabusa or Chainsaw (optional) | Quick Sigma-rule hunting across `EventLogs\All\*.evtx` |
| bulk_extractor (optional) | Carving URLs, domains, emails, IPs and packets from the memory image and pagefile. See section 10 |
| bulk-extractor-to-csv (optional; [github.com/seliyyah/bulk-extractor-to-csv](https://github.com/seliyyah/bulk-extractor-to-csv)) | Converting bulk_extractor output to CSV for Timeline Explorer |
| Velociraptor (the same `velociraptor.exe` as in the toolkit) | Running a local server to import the `Velociraptor\` zips. See 7.12 |
| Wireshark ([wireshark.org](https://www.wireshark.org)) | bulk_extractor's `packets.pcap` |
| Notepad++ and klogg ([github.com/variar/klogg](https://github.com/variar/klogg)) | Text output; klogg opens multi-GB text files that other editors can't |
| Thumbcache Viewer ([thumbcacheviewer.github.io](https://thumbcacheviewer.github.io)) | `thumbcache_*.db` thumbnails |
| NirSoft BrowsingHistoryView and ESEDatabaseView ([nirsoft.net](https://www.nirsoft.net)) | The legacy IE/Edge `WebCacheV01.dat` ESE database |
| PyWMIPersistenceFinder ([github.com/davidpany/WMI_Forensics](https://github.com/davidpany/WMI_Forensics); Python) | WMI consumers in the collected `OBJECTS.DATA` |
| notepad_parser ([github.com/AbdulRhmanAlfaifi/notepad_parser](https://github.com/AbdulRhmanAlfaifi/notepad_parser)) | Unsaved Windows 11 Notepad tabs (`TabState\`) |
| maldump ([github.com/NUKIB/maldump](https://github.com/NUKIB/maldump)) or defender-dump ([github.com/knez/defender-dump](https://github.com/knez/defender-dump)) | Decoding `Security\DefenderQuarantine\`. ⚠ **Only in an isolated malware-analysis VM:** the output is live malware |

---

## 3. Where to put the files (folder setup)

**In plain terms:** make one folder called `Toolkit` on your USB drive. Put `recollect.ps1` directly inside it. Make a `Tools` folder next to the script and unzip every tool into its own subfolder of `Tools`. **Extract whole folders**, not just the `.exe` files: several tools need the files that ship beside them (Maps, batch files, DLLs).

```text
X:\Toolkit\                              <- any drive letter works
├── recollect.cmd                        <- the launcher (may also go one level up, at X:\)
├── recollect.ps1                        <- the script
├── docs\USER_GUIDE.md                   <- this guide
├── Tools\                               <- every tool goes in here (subfolder names don't matter)
│   ├── SysinternalsSuite\               <- unzipped Sysinternals Suite (autorunsc64.exe, sigcheck64.exe, ...)
│   ├── Get-ZimmermanTools\              <- output of Get-ZimmermanTools.ps1
│   │   └── net\
│   │       ├── EvtxeCmd\  (EvtxECmd.exe + Maps\)
│   │       ├── RECmd\     (RECmd.exe + BatchExamples\Kroll_Batch.reb)
│   │       ├── SQLECmd\   (SQLECmd.exe + Maps\)
│   │       ├── TimelineExplorer\
│   │       └── MFTECmd.exe, PECmd.exe, LECmd.exe, JLECmd.exe, AmcacheParser.exe, ...
│   ├── kape\
│   │   └── KAPE\                        <- kape.exe, Targets\, Modules\, Modules\bin\
│   ├── velociraptor\                    <- velociraptor-vX.Y.Z-windows-amd64.exe
│   ├── WinPmem\                         <- go-winpmem_amd64_..._signed.exe
│   ├── Magnet\                          <- MRCv120.exe
│   ├── Comae\                           <- x64\DumpIt.exe (x86\ and ARM64\ can stay; x64 is preferred)
│   ├── RawCopy\                         <- RawCopy64.exe, RawCopy.exe
│   ├── 7zip\                            <- 7z.exe + 7z.dll
│   ├── YARA\                            <- optional: .yar/.yara rules for the process scan (guided setup offers them)
│   └── LOLDrivers-main\                 <- optional: the LOLDrivers repository (guided setup finds its drivers.csv)
└── Collections\                         <- created automatically; each run gets its own subfolder
```

**One-time preparation on your own (internet-connected) machine:**

1. Download and unzip the tools as shown above.
2. Update KAPE's targets and modules: `X:\Toolkit\Tools\kape\KAPE\kape.exe --sync`
3. Remove the "downloaded from the internet" mark from everything, so Windows doesn't block or prompt for the tools in the field:
   ```powershell
   Get-ChildItem X:\Toolkit -Recurse -File | Unblock-File
   ```
4. Optional: do a test run on a lab VM or test PC (with the **Quick** profile first) and check `CollectorResults.csv`.

**Drive letters don't matter.** The script finds its tools relative to its own location and collects whatever drive Windows is installed on (`%SystemDrive%`), even if that isn't C:.

---

## 4. Collection profiles

Each of Quick, Standard, Deep and Full includes everything in the profiles above it. Memory Only stands apart.

| Profile | Adds | Typical time |
|---|---|---|
| **Memory Only** (0) | A RAM image only, plus `System\time.txt` (clock, time zone and time-sync status, which memory analysis needs to read timestamps correctly). No shadow copy and no live tools. Use it when time is short or when memory is all you need now; you can run another profile afterwards. Needs WinPmem, Magnet RAM Capture or DumpIt in the toolkit; without one, the run stops with an error before collecting. | about 5 min for 32 GB |
| **Quick** (1) | System time and clock, network connections (joined to processes), TCPView, DNS cache, ARP and routes, SMB sessions, named pipes, port proxies, processes (with hash, signature and owner), logon sessions, services, scheduled tasks, Run keys, WMI subscriptions, BITS, startup commands, IFEO debuggers, shadow-copy list, OS identity, local accounts, disks and BitLocker, **event log channel configuration**, **ETW sessions and AutoLogger settings**, SMB open files | 2–3 min |
| **Standard** (2) | Creates a **shadow copy (VSS snapshot)** and copies from it: all registry hives (system, user and service accounts), Amcache, **all event logs**, Prefetch, scheduled-task XML, setupapi logs, Defender logs, BITS queue, PCA, GPO scripts, Startup folders, **command-line histories** (PowerShell for every account, including SYSTEM and the service accounts, plus bash, Python and Windows Terminal), laid out in `System\command_history.csv`. Also: systeminfo, installed software, hotfixes, drivers (and their signatures), USB storage history, PnP devices, AppX packages, Defender, firewall and audit config, gpresult, security settings (LSA, WDigest, RDP, UAC, PowerShell logging), certificate stores, stored credential *names*, Kerberos tickets, local groups, accessibility binaries (sticky-keys check), live export of key event logs, Autoruns, Handle, ListDlls, LogonSessions. New in 3.4: **driver hashes and loaded kernel modules** (LOLDrivers-ready), code integrity / vulnerable-driver blocklist / VBS, **WFP filters**, Sysmon config, VMs and mounted disk images, service failure actions, SSH keys and configs, PowerShell transcripts, **Mark-of-the-Web**. New in 3.9: **unusual alternate data streams** (hidden NTFS streams) in `Disk\ads_unusual.csv`, about 2 minutes | ~10 min |
| **Deep** (3) | SRUM, WMI repository, LNK files and Jump Lists, ActivitiesCache (Timeline), RDP bitmap cache, WER reports, Panther and debug logs, thumbcache, iconcache, WebCache, notifications, OneDrive logs, remote-access tool logs (AnyDesk, TeamViewer, RustDesk, Splashtop), browser artifacts (history, bookmarks, sessions, extensions; **not** cookies, passwords or autofill), raw `$MFT`, `$LogFile` and `$Boot`, the USN journal, Sigcheck of user-writable folders, **all Zimmerman parsers**, extra internal drives (section 5.1). New in 3.4: ScreenConnect, Atera, LogMeIn and discovered RMM agents (logs copied, configs presence-only), IIS config and web-root listing, Notepad TabState and Sticky Notes, MEGAsync logs, WFP full state, disk-image file search, **exfiltration-tool search** (rclone, MEGA, ngrok …). New in 3.7: `EventLogs\command_events.csv`, every command line from the event logs (PowerShell 4104 and 400, 4688, Sysmon 1, WMI-Activity 5861) in time order. New in 3.9: `EventLogs\sysmon_events.csv`, every Sysmon event in one readable table (when Sysmon is installed). New in 4.0.1: `EventLogs\network_events.csv`, network activity from the logs | 30–60 min |
| **Full** (4) | pagefile, hiberfil and swapfile, the full Recycle Bin, the Windows Search database, MEMORY.DMP, Sigcheck of System32, **KAPE** (`!SANS_Triage` + `!EZParser`), **Velociraptor** (23 artifacts, including browser history and RDP logon chains) | 1–2 hours |
| `-Memory` (any profile) | RAM image, taken **first**, before anything else changes memory | 4–5 min for 32 GB |
| `-YaraRules` (Full, opt-in) | YARA scan of process memory with your rules (Velociraptor `Windows.Detection.Yara.Process`) | slow; depends on rules and process count |
| `-DefenderQuarantine` (opt-in) | Copy of Defender's quarantine: **malware samples** | depends on quarantine size |

Times are from the lab laptop writing to a USB 3 drive: Quick 2 minutes, Deep 60 minutes and Full 60 minutes to 2 hours in recent runs. Standard hasn't been timed since 3.4 added steps, so allow extra time beyond the 10 minutes shown. Slower disks, more data and busy hosts take longer. Guided setup shows the same figures. Top-level output folders that a profile leaves empty (for example `KAPE\` in a Standard run) are removed at the end, so the collection shows only what was collected.

---

## 5. All parameters

| Parameter | What it does | Default |
|---|---|---|
| `-CollectionProfile` | `Quick`, `Standard`, `Deep`, `Full` or `MemoryOnly` (implies `-Memory`) | Asks you (fails if `-NonInteractive`) |
| `-CaseId` | Case number; used in the folder name and manifest | `NOCASE` |
| `-Operator` | Your name; recorded in the manifest | `DOMAIN\user` |
| `-OutputPath` | Where results go | `<toolkit>\Collections` |
| `-ToolsPath` | Where to look for tools | `<toolkit>\Tools` |
| `-Memory` | Take a RAM image first | off |
| `-NonInteractive` | Never prompt (stops instead of asking) | off |
| `-AcceptLicense` | Agree to the license terms and authorized-use notice without the prompt. **Required with `-NonInteractive`.** Recorded in the log and manifest | off (you're asked) |
| `-AllowSystemDrive` | Allow output on C: or another internal disk (**not recommended**) | off |
| `-Volumes D:,F:` | Collect exactly these extra drives | auto-detect internal drives |
| `-SystemDriveOnly` | Don't collect extra internal drives | off |
| `-KapeTargets` | KAPE targets for Full | `!SANS_Triage` |
| `-KapeModules` | KAPE modules to run after the targets (`''` = none) | `!EZParser` |
| `-KapeVss` | KAPE also collects every existing shadow copy | off |
| `-KapeSkipBrowserData` | Full only. Leave KAPE's `WebBrowsers` target out of `!SANS_Triage`: no browser saved-password, cookie or autofill databases and no DPAPI keys from it. KAPE has no exclude option, so the script runs the triage set's other targets by name, read from your KAPE's own `!SANS_Triage.tkape`. Browser **history** is still collected by Recollect (Deep) and Velociraptor. KAPE's Dropbox metadata target can still copy DPAPI keys, and its mRemoteNG target saved connection credentials (section 7.14). With your own `-KapeTargets`, only `!SANS_Triage` and `WebBrowsers` entries are changed, and the log says so. Guided setup asks this question for Full. | off (browser data included) |
| `-KapeVolumeTargets` | KAPE targets for extra internal drives | `FileSystem,RecycleBin` |
| `-VelociraptorArtifact` | List of Velociraptor artifacts | 23 built-ins (section 7.12) |
| `-VelociraptorArgs` | `Name=Value` parameters passed to **every** artifact | none |
| `-VelociraptorArtifactArgs` | Parameters for **one** artifact: `@{ 'Windows.EventLogs.RDPAuth' = @('DateAfter=2026-01-01') }`. A hashtable can't be passed through `powershell.exe -File`; launch with `-Command "& .\recollect.ps1 ... -VelociraptorArtifactArgs @{...}"` or run the script directly from an elevated PowerShell prompt. | none |
| `-YaraRules C:\path\rules.yar` | **Opt-in, Full only.** Scans process memory with these rules through Velociraptor. The rules file is copied into `Velociraptor\` and hashed. ⚠ Slow, and memory scanning can trigger EDR alerts. The rule text is passed on the command line, so files over ~30,000 characters must be split. To scan only some processes, add `-VelociraptorArtifactArgs @{'Windows.Detection.Yara.Process'=@('ProcessRegex=(?i)notepad')}` (the `-Command` form, see that row). Hits are in `Windows.Detection.Yara.Process.zip` → `results\*.json`. Guided setup offers the rule files in `Tools\YARA\`. | off |
| `-LolDriversCsv C:\path\drivers.csv` | Local copy of the LOLDrivers export (CSV or JSON from loldrivers.io). Every MD5/SHA-1/SHA-256 in it is matched against `System\drivers_hashed.csv`. Any text file works, so the YAML files from the LOLDrivers repository can simply be concatenated into one file. The log shows how many hashes were loaded and how many drivers matched (column `LolDriversMatch`). No network access. | off |
| `-NetworkCapture` | **Opt-in.** Records all network traffic with Windows' built-in **pktmon** (nothing is installed) from right after the memory capture until the live steps finish, at the network adapters, full packets. Saved as `Network\capture.etl` and converted to `Network\capture.pcapng` for Wireshark. Needs Windows 10 version 2004 or later; not available with `MemoryOnly`. If another pktmon capture is already running, it's left alone and the step fails with a note. The capture is always stopped, even on Ctrl+C. ⚠ **Unencrypted traffic is recorded in full and can contain passwords** (section 7.14). Guided setup asks about it, default No. | off |
| `-NetworkCaptureMaxMB` | Size cap for the capture, 16 to 8192 MB. When full, the oldest packets are overwritten, so the capture ends with the most recent traffic. The space check adds twice this (the `.etl` and the `.pcapng`). | 512 |
| `-DefenderQuarantine` | **Opt-in.** Copy Defender's quarantine to `Security\DefenderQuarantine\`. ⚠ These are **malware samples**. Never enabled by any profile. Use with `-Archive -ArchivePassword`; the script warns loudly if you archive without a password. | off |
| `-NtpServer` | Compare the clock against an NTP server (needs network) | off |
| `-Archive` | Zip or 7-Zip the finished collection into `<case folder>.7z`, with a `.7z.sha256` and a `.7z.log` beside it. The case folder itself is kept, unencrypted. | off |
| `-ArchivePassword` | Encrypt the .7z with AES-256, file names included (pass a SecureString: `(Read-Host 'Archive password' -AsSecureString)`). A SecureString can't pass through `powershell.exe -File`, so use the `-Command "& .\recollect.ps1 ... -ArchivePassword (Read-Host 'Archive password' -AsSecureString)"` form, or run the script directly. The password is given to 7-Zip on its command line, so hosts that log process command lines (Sysmon, event 4688, EDR) record it: use a password unique to the case. | none |
| `-NoAnalysisReadme` | Don't write the `ANALYSIS_README.txt` guidance files (see section 7). | off (files are written) |

### 5.1 Extra internal drives

The script automatically collects **other internal disks** too (a second SSD or HDD, for example), on top of the Windows drive. A drive counts as internal when it's connected by SATA, NVMe, SAS, RAID, SCSI, ATA, Storage Spaces or Fibre Channel. **USB drives, SD cards and virtual disks are never collected automatically**, and neither are the output drive and the toolkit drive. BitLocker-locked drives are skipped with a warning. The start of the log prints a table of every drive and what will happen to it.

For each extra internal drive: Deep collects the raw `$MFT`, `$LogFile` and `$Boot` (NTFS only), the USN journal, a listing of the top-level folder and the Recycle Bin metadata. Full also collects the deleted files themselves and runs KAPE against the drive.

---

## 6. What to expect while it runs, and its footprint

- Each step prints a line like `[P5] Copy: ALL event logs (snapshot)` followed by `OK`, `WARN`, `FAIL` or `SKIPPED`.
- **The script changes the machine as little as it can.** It creates **one** shadow copy and a temporary link under `C:\Windows\Temp`, and **deletes both** when it finishes, even if you press Ctrl+C. Nothing is installed.
- `-Memory` loads a **kernel driver** (WinPmem, Magnet or DumpIt) for a few minutes.
- **Expect security alerts:** copying the SAM and SECURITY hives, creating a shadow copy and loading a memory driver all look like attacker behavior to EDR and antivirus. Tell the SOC before you start.
- Everything is written to the output drive. Timestamps in the script's own files are **UTC**.
- At the end, every collected file gets a SHA-256 hash (`FileHashes.csv`).

---

## 7. The output, folder by folder

Every run creates `Collections\<CaseId>_<COMPUTER>_<yyyyMMddTHHmmssZ>\`, for example `IR-001_WORKSTATION01_20261105T024807Z`. Empty folders are deleted at the end, so a Quick run has fewer folders.

**`ANALYSIS_README.txt` in every folder (from 3.5.0):** the collection root, each top-level folder and each artifact folder under `Disk\` (for example `Disk\SystemFiles`, `Disk\NTFS`, `Disk\ProgramData\Microsoft\Network\Downloader`, each user's browser and Recent folders) get a short plain-text file. It says what the files in that folder are, why they matter, how to analyze them, and links to the tools' official pages and to the matching section of this guide. It's a quick pointer for anyone who opens the folder without this guide, such as a new analyst or a student. Recollect doesn't run or include any of those tools. Only folders that exist and aren't empty get a file, a collected file of the same name is never overwritten, and the files are written before hashing, so they're listed in `FileHashes.csv`. `-NoAnalysisReadme` turns them off. Some command-line parsers given a whole folder may report the extra `.txt` file as unrecognized, which is harmless.

### Quick reference: which tool opens which output

Do all analysis on your workstation, never on the suspect machine. The sections in the last column have the details. Where to get each tool is in section 2.4.

| Output | Start with | Then, for depth | Section |
|---|---|---|---|
| `CollectorResults.csv`, `manifest.txt`, `Collection.log` | Timeline Explorer (CSV), any text editor | | 7.0 |
| `Memory\*.raw` | **Volatility 3** | **MemProcFS**; **bulk_extractor**, then **bulk-extractor-to-csv** to read its output | 7.1, 10 |
| `Disk\ads_unusual.csv` | Timeline Explorer | A hex editor for the copies in `Disk\ADS\`; VirusTotal for the hashes | 7.8 |
| `EventLogs\network_events.csv` | Timeline Explorer | `Parsed\EvtxECmd\evtx_all.csv` (the same events, generic layout) | 7.7 |
| `Network\capture.pcapng` (opt-in) | **Wireshark** | `connections.csv` to tie addresses to processes | 7.3 |
| `EventLogs\sysmon_events.csv` | Timeline Explorer | `Parsed\EvtxECmd\evtx_all.csv` (same events, generic layout) | 7.7 |
| `System\command_history.csv`, `EventLogs\command_events.csv` | Timeline Explorer | The raw history files and `.evtx` logs they came from; section 7.15 for the other places commands are recorded | 7.15 |
| `System\`, `Network\`, `Processes\`, `Persistence\`, `Security\` | Timeline Explorer for the CSVs; a text editor (Notepad++) for the TXT files | Hash, IP and domain lookups (see the note below the table) | 7.2–7.6 |
| `Security\DefenderQuarantine\` | **Only in an isolated malware-analysis VM:** **maldump** or **defender-dump** to decode the samples | Your usual malware-analysis tools | 7.6 |
| `EventLogs\All\` | `Parsed\EvtxECmd\evtx_all.csv` in Timeline Explorer | **Hayabusa** or **Chainsaw** for Sigma-rule hunting; Event Viewer for a single log | 7.7 |
| `Disk\...\config\`, `NTUSER.DAT`, `UsrClass.dat` | `Parsed\RECmd_*`, `Parsed\SBECmd` | **Registry Explorer**, **ShellBags Explorer** | 7.8, 7.10 |
| `Disk\NTFS\` | `Parsed\MFTECmd` | **MFTExplorer**; `KAPE\Modules\...\MFTECmd_$J_Output.csv` for the USN journal in UTC | 7.8, 7.11 |
| Prefetch, Amcache, ShimCache, LNK, Jump Lists, SRUM, Timeline, Recycle Bin | The matching `Parsed\` folder in Timeline Explorer | **JumpList Explorer**, **EZViewer** | 7.10 |
| Browser databases | `Parsed\SQLECmd` (⚠ local time) | **DB Browser for SQLite**; the Velociraptor browser artifacts (UTC) | 7.13 |
| `WebCache\` (ESE database) | NirSoft **BrowsingHistoryView** | NirSoft **ESEDatabaseView** for every table | 7.8 |
| `thumbcache_*.db` | **Thumbcache Viewer** | | 7.8 |
| `wbem\Repository\` | `Persistence\wmi_subscriptions.txt` and Velociraptor's `PermanentWMIEvents` | **PyWMIPersistenceFinder** on `OBJECTS.DATA`, for consumers no longer registered | 7.5, 7.8 |
| Notepad `TabState\` (Deep+) | **notepad_parser** | A hex editor | 7.8 |
| `SystemFiles\hiberfil_C.sys` | Comae **Hibr2Bin** (in the toolkit), then Volatility 3 | bulk_extractor on the converted file | 7.8, 10 |
| `SystemFiles\pagefile_C.sys` | **bulk_extractor** | MemProcFS (load it beside the memory image); YARA | 7.8, 10 |
| `Tools\` (Sysinternals) | Timeline Explorer (`autoruns.csv`, `sigcheck_*.csv`), a text editor for the rest | | 7.9 |
| `KAPE\` | `Modules\` CSVs in Timeline Explorer | The Zimmerman GUI tools on `Targets\` | 7.11 |
| `Velociraptor\*.zip` | A local **Velociraptor** server (`velociraptor.exe gui`) with `Server.Utils.ImportCollection` | The JSON inside each zip | 7.12 |
| bulk_extractor output | **bulk-extractor-to-csv**, then Timeline Explorer | **klogg** for huge text files; **Wireshark** for `packets.pcap` | 10 |

**Hash, IP and domain lookups:** look up SHA-256 or SHA-1 values, IP addresses and domains on VirusTotal, AbuseIPDB or your own threat-intelligence platform. **Search by hash; don't upload files from a case.** Files uploaded to public services are shared with other users and researchers, and an attacker watching for their own malware will see that it has been found.

### 7.0 Files at the top level (read these first)

| File | Contents | How to use it |
|---|---|---|
| `CollectorResults.csv` | One row per step: Phase, Name, **Status** (OK / WARN / FAIL / SKIPPED), exit code, seconds, rows, note | **Open this first.** Filter Status ≠ OK. The Note column explains each issue. SKIPPED with "tool not found" means the tool isn't in the toolkit. |
| `manifest.json` / `manifest.txt` | Chain of custody: script version and its SHA-256, the parameters used, case, operator, host, OS, last boot, start and end time (UTC), time zone, shadow-copy ID (and whether it was deleted), the drive table, the tool inventory and every step's result | Attach to your case notes. `manifest.txt` is the readable summary. |
| `FileHashes.csv` | SHA-256, size, last-write time and relative path of every collected file | Proves integrity. To re-check a file later: `Get-FileHash <file> -Algorithm SHA256` and compare. |
| `ToolInventory.csv` | Every tool the script looked for: found or missing, path, version, SHA-256, signature status | Shows exactly which tool binaries produced the evidence |
| `Collection.log` | Every line the script printed, with UTC timestamps. Written line by line, so it stays complete even if the output drive drops out for a moment | Troubleshooting. Search it for `WARN` and `ERROR`. |

### 7.1 `Memory\`

| File | Contents |
|---|---|
| `<COMPUTER>_<stamp>.raw` | Full physical memory image (about the size of the RAM) |
| `acquisition.log` | Output from the memory tool |

**How to analyze:** **Volatility 3**, for example `vol -f image.raw windows.pslist`, then `windows.pstree`, `windows.cmdline`, `windows.netscan`, `windows.malfind`, `windows.svcscan`, `windows.dlllist`. **MemProcFS** mounts the image as a drive letter, so you can browse processes, handles and network connections as folders and files, and it can produce a timeline. Look for processes with odd parents (for example Word spawning PowerShell), injected code (`malfind`), and connections to unknown IP addresses. For a second pass that finds URLs, domains, emails and packet fragments the plugins don't parse, run **bulk_extractor** on the image (section 10).

### 7.2 `System\`

| File | Contents / what to look for |
|---|---|
| `identity.txt`, `systeminfo.txt` | Host name, OS build, domain, install date, uptime, patches |
| `time.txt` | Local and UTC time, time zone, `w32tm` status. **Check clock skew before you correlate times.** |
| `accounts.txt`, `local_groups.txt` | Local users and group members. Look for unexpected members of Administrators or Remote Desktop Users. |
| `sessions.txt` | Who is logged on right now (`quser` / `qwinsta`) |
| `installed_software.csv`, `appx_packages.csv`, `hotfixes.csv` | What's installed and when. Look for remote-access tools or recently installed unknown software. |
| `drivers.csv`, `drivers_signed.txt` | Loaded drivers and whether they're signed. Unsigned drivers deserve a close look. |
| `drivers_hashed.csv` | **Every driver with SHA-256, SHA-1 and MD5**, signer, issuer, certificate expiry, version info. It merges the service list with the modules **actually loaded in the kernel**. BYOVD "EDR killer" drivers are *validly signed*, so match the hashes against **LOLDrivers** (loldrivers.io); `-LolDriversCsv` does it for you (`LolDriversMatch`). Filter **`Triage` = `review…`**: drivers loaded with **no service entry** that aren't part of Windows (EDR killers often load a driver and then delete its service key), or LOLDrivers hits. `LoadedNoService` alone also lists normal Windows library modules and `dump_*` crash-dump copies. |
| `virtual_disks.txt` | Hyper-V VMs, mounted VHD/VHDX disks and mounted ISO images, with their image file paths. Some ransomware runs inside a VM to get past EDR. |
| `virtual_disk_files.csv` (Deep+) | VHD, VHDX, VMDK, VDI, ISO and IMG files under Users, ProgramData, PerfLogs, Windows\Temp and drive roots. **Listed, never copied.** ISO and VHD files are common initial-access containers. |
| `pnp_devices.csv`, `usbstor.txt` | Devices, including USB storage ever connected (vendor, product, serial) |
| `disks_bitlocker.txt` | Disks, volumes, BitLocker status |
| `shadow_copies.txt` | Existing shadow copies. Attackers often delete them; missing copies can be a ransomware sign. |
| `prefetch_listing.csv` | Prefetch file names with timestamps (quick view of what ran) |
| `command_history.csv` (Standard+) | **Every command from every collected command-history file**, one row per command: `Account` (a user, `SYSTEM`, `LocalService` or `NetworkService`), `Source` (which PowerShell host, bash, Python, or Windows Terminal prompt lines), `Line`, `Command`, the `File` it came from and that file's `FileModifiedUtc`. Multi-line PowerShell commands are joined into one row. History files have no per-command times (bash has them only when `HISTTIMEFORMAT` was set): `FileModifiedUtc` dates the file's last command. **Filter `Account` for `SYSTEM`**: PowerShell run as SYSTEM usually means PsExec `-s`, a service or a scheduled task. See section 7.15. |

**Tools:** Notepad++ or any text editor; CSVs in Timeline Explorer.

### 7.3 `Network\`

| File | Contents / what to look for |
|---|---|
| `connections.csv` | TCP connections **joined to the owning process** (name, path, PID). Start here. |
| `netstat_ano.txt`, `netstat_anob.txt`, `tcpvcon.csv` | The same picture from different tools, to cross-check |
| `dns_cache.csv` | Recently resolved host names. Look for C2-looking domains. |
| `netconfig.txt` | IP config, ARP table, routes, `hosts` file, proxy settings. A modified hosts file or proxy is a red flag. |
| `net_extra.txt` | Port proxies (a pivoting technique), NetBIOS cache and sessions, neighbors, Wi-Fi profiles |
| `smb.txt` | SMB sessions, shares, mapped drives, and **files remote clients currently have open on this host** (`Get-SmbOpenFile`: client, user, path). Look for lateral movement and staging. |
| `named_pipes.txt` | Named pipes. Some C2 frameworks use recognizable pipe names. |
| `capture.pcapng`, `capture_wifi.pcapng`, `capture.etl`, `pktmon.log`, `pktmon_components.txt` | **Only with `-NetworkCapture`:** every packet sent or received while the collection ran, captured with pktmon at the network adapters. Open the `.pcapng` in **Wireshark** on an analysis machine. Good first steps: *Statistics > Conversations* and *Endpoints* (who talked to whom, and how much), the `dns` filter (names looked up), `http.request` and `tls.handshake.extensions_server_name` (where HTTP and HTTPS went). Match addresses against `connections.csv` to find the process. **On Wi-Fi, open `capture_wifi.pcapng`:** a Wi-Fi adapter hands pktmon raw 802.11 frames, which `capture.pcapng` (labeled Ethernet) can't decode, so Recollect converts each Wi-Fi adapter's packets on their own and labels them 802.11. Windows has already decrypted those frames but leaves their *Protected* bit set, so first set *Edit > Preferences > Protocols > IEEE 802.11 > Ignore the Protection bit* to **Yes - without IV**. Wired adapters' packets decode normally in `capture.pcapng`. The `.etl` is pktmon's original file; `pktmon.log` and `pktmon_components.txt` are pktmon's own output. ⚠ Can contain passwords from unencrypted traffic. |

**Tools:** Timeline Explorer for the CSVs. Check IPs and domains against threat intelligence (VirusTotal, AbuseIPDB).

**What a host collector can't give you:** the capture covers only the minutes the collection ran, and only this machine. Traffic from before the incident was noticed, and traffic between other machines, comes from the network: firewall and proxy logs, NetFlow, and network sensors (Zeek, Suricata, a full packet-capture appliance). Ask the network team for those for the same time window, and line them up with `EventLogs\network_events.csv`.

### 7.4 `Processes\`

| File | Contents / what to look for |
|---|---|
| `processes.csv` | Every process: PID, parent PID, name, **path**, **command line**, user, start time (UTC), **SHA-256**, **signature status** |
| `tasklist.txt` | `tasklist /v`, the services inside each svchost, loaded modules |

**What to look for:** Unsigned or "NotSigned" executables; programs running from `AppData`, `Temp`, `ProgramData` or `Users\Public`; encoded PowerShell (`-enc`); odd parent/child pairs; misspelled system names (`scvhost.exe`). Look up SHA-256 values on VirusTotal.

### 7.5 `Persistence\`

| File | Contents |
|---|---|
| `run_keys.txt` | Run/RunOnce, Winlogon, AppInit_DLLs, Explorer policy Run keys (machine and every loaded user) |
| `services.csv`, `sc_netstart.txt` | All services with binary path and start mode |
| `schtasks.csv`, `scheduled_task_actions.csv` | Scheduled tasks and **what each one runs** |
| `wmi_subscriptions.txt` | WMI event filters and consumers (fileless persistence) |
| `startup_commands.csv`, `startup_folders.csv` | Startup items and Startup-folder contents |
| `bits.txt` | BITS jobs (used for stealthy downloads) |
| `ifeo.csv` | Image File Execution Options "Debugger" and SilentProcessExit entries (hijacks) |
| `accessibility_binaries.csv` | Hash and signature of sethc, utilman, osk and friends (the "sticky keys" backdoor) |
| `service_failure_actions.csv` (Standard+) | Services with a **"run a program on failure" command** (`FailureCommand`), plus the `sc qfailure` output. Persistence that `services.csv` doesn't show. Some vendors (NVIDIA, for example) use it legitimately, so check what the command runs. |

**What to look for:** Anything pointing at user-writable paths, script hosts (`powershell`, `wscript`, `mshta`, `rundll32`) with unusual arguments, recently created tasks or services, and **any** IFEO debugger or WMI consumer (both are rare on clean machines). Compare against `Tools\autoruns.csv`.

### 7.6 `Security\`

| File | Contents |
|---|---|
| `defender.txt` | Defender service status, settings, **exclusions** (attackers add their own), detection history |
| `firewall.txt` | Firewall profiles and every rule. Look for new "allow" rules. |
| `auditpol.txt`, `gpresult.txt` | Audit policy (tells you which events *could* exist) and the applied Group Policy |
| `security_settings.txt` | LSA protection, **WDigest** (`UseLogonCredential=1` means cleartext passwords in memory), RDP settings, UAC, PowerShell logging, execution policy |
| `security_products.txt` | Registered antivirus and firewall products |
| `credential_metadata.txt` | Stored credential **names** (`cmdkey`) and Kerberos tickets (`klist`). No secrets are collected. |
| `certificates.csv` | Root, CA and TrustedPublisher certificates. Unknown roots can enable interception. |
| `etw_sessions.txt` (all profiles) | Running ETW trace sessions (`logman query -ets`, plus a list read directly with `QueryAllTracesW`, which still works when logman fails with "The GUID passed was not recognized"), a check for expected ones (EventLog-*, DefenderApiLogger, DefenderAuditLogger; `UNKNOWN` means no session list could be read, not that they are stopped), AutoLogger sessions disabled at boot (`Start=0`), and the full AutoLogger registry. **Missing Defender or EventLog sessions, or `Start=0` / `Enabled=0` on providers, suggest telemetry tampering.** |
| `code_integrity.txt` | The **vulnerable driver blocklist** setting (`VulnerableDriverBlocklistEnable`: 0 = disabled), the Device Guard registry, and `Win32_DeviceGuard` (VBS and HVCI/memory integrity configured and running). |
| `wfp_filters.xml`, `wfp_block_summary.csv` | All **Windows Filtering Platform** filters, which `firewall.txt` doesn't show. The summary lists **BLOCK filters keyed on an application path**, the pattern EDRSilencer-style tools use to cut an EDR off from its cloud. Any block on `MsMpEng.exe`, `MsSense.exe` or another security product's process is a strong red flag. `wfp_state.xml` (Deep+) is the full WFP state and can be tens of MB. |
| `sysmon_config.txt` | Whether **Sysmon** is installed (found by version info, so a renamed copy is still detected) and its decoded configuration (`<sysmon> -c`, run only for a valid Microsoft-signed binary) plus the driver's registry parameters. Check what the config excludes. |
| `exfil_tools.csv` (Deep+) | **Exfiltration and tunneling tools** (rclone, restic, MEGA, WinSCP, FileZilla, PuTTY tools, ngrok, cloudflared, chisel, Syncthing, S3 Browser, Cyberduck), matched by file name **and** by version info, so a renamed `rclone` is still found. Hash and signature. **Configs, presence only:** for `rclone.conf` only the remote names and types are recorded (or `encrypted`); `ngrok.yml`, `WinSCP.ini` and FileZilla's server lists are listed with hash, never copied (they hold credentials). |
| `DefenderQuarantine\` (opt-in) | Only with `-DefenderQuarantine`: a copy of Defender's quarantine. ⚠ **Live malware samples** (RC4-obfuscated with a well-known key, not directly runnable). Handle and store as malware. To decode the samples, run **maldump** or **defender-dump** in an isolated malware-analysis VM, never on your everyday workstation. |

### 7.7 `EventLogs\`

| Folder | Contents |
|---|---|
| `All\` | **Every** `.evtx` file, copied from the shadow copy (about 350+ files) |
| `Live\` | Live exports of Security, System, Application, PowerShell and Sysmon (a backup copy) |
| `command_events.csv` (Deep+) | **Command lines from the event logs, sorted by time:** PowerShell script blocks (4104, Windows PowerShell and PowerShell 7), the command line of each PowerShell start (Windows PowerShell 400: shows `-enc` encoded commands even with no other logging), process creation with command line (Security 4688, Sysmon 1), and WMI permanent event consumers (WMI-Activity 5861). Columns: `TimeUtc`, `Source`, `EventId`, `Account`, `Process`, `ParentProcess`, `Command`, `Detail`, `RecordId`, `LogFile`. A long script block spans several 4104 events: group them by the `ScriptBlockId` in `Detail`. **Rows caused by the collection itself** (Recollect's own script blocks, which PowerShell logs automatically as "suspicious", and its own start) are kept but marked "from this collection run" in `Detail`: filter them out. No 4688 rows, or rows without a command line, mean process auditing or its command-line option was off. |
| `network_events.csv` (Deep+) | **Network activity from the event logs, sorted by time:** network and Remote Desktop logons with the source IP (Security 4624 types 3, 8 and 10) and failed ones (4625), logons with explicit credentials to another server (4648), RDP session reconnects and disconnects (4778/4779), share access (5140, when audited), RDP authentication and sessions (Terminal Services 1149, 21-25), **outgoing** RDP connections (RDP client 1024/1102), WinRM sessions, OpenSSH logons, SMB client logon failures, BITS jobs and downloads with their URL, DNS queries (DNS Client 3008, only when that log is enabled), firewall rule changes (2004-2006, 2052, 2097, 2099) and Wi-Fi and network connections. Columns: `TimeUtc`, `Area`, `EventId`, `Event`, `Account`, `RemoteAddress`, `Target`, `Detail`, `RecordId`, `LogFile`. Local-only noise (logons without a remote address, console sessions) is left out. Filter `RemoteAddress` for addresses outside your network, `Event` for "Logon: Remote Desktop" and "Failed logon", and `Target` for admin shares (`C$`, `ADMIN$`). |
| `sysmon_events.csv` (Deep+) | **Every Sysmon event in one readable table**, when Sysmon is installed (the file is empty otherwise). One row per event in log order, with the event's own `UtcTime`: `TimeUtc`, `EventId`, `Event` (its name), `Account`, `ProcessId`, `Image`, `Target` (what the event is about: the command line, `proto src -> dst (host)`, file, registry key, DNS name, pipe, accessed process ...), `Detail` (parent process, signature, granted access, registry value, DNS results ...), `Hashes`, `RuleName`, `RecordId`, `LogFile`. Good starting points: 1 process created, 3 network connection, 22 DNS query, 10 process accessed (`Target` lsass.exe: credential theft), 13 registry value set (Run keys), 2 file creation time changed (timestomping), 15 file stream created (hidden ADS), 25 process tampering. **Rows from Recollect and every process it started** (followed through Sysmon's own process-creation events) are marked "from this collection run" in `Detail`. Stops at 300,000 events with a WARN; the rest are in the `.evtx` and in `evtx_all.csv`. Parsing takes about 2 ms per event (a 64 MB log of 100,000 events: about 3 to 4 minutes). |
| `channel_config.csv` (all profiles) | Every event log channel: enabled or not, retention mode, **maximum size**, current size, record count, whether it's full, oldest record, last write. **A disabled channel, or a Security log shrunk to a tiny maximum size, is evidence of anti-forensics** even when the log itself looks clean. |

**How to analyze:** Start with the parsed version, `Parsed\EvtxECmd\evtx_all.csv`, in **Timeline Explorer** (section 7.10). For a single log, double-click the `.evtx` to open it in Windows Event Viewer. For fast threat hunting, run **Hayabusa** or **Chainsaw** against the `All\` folder, for example `hayabusa csv-timeline -d "<case folder>\EventLogs\All" -o hayabusa_timeline.csv`, and open the result in Timeline Explorer.

**Key event IDs:**

| Log | ID | Meaning |
|---|---|---|
| Security | 4624 / 4625 | Logon success / failure (check *LogonType*: 2 interactive, 3 network, 10 RDP) |
| Security | 4672 | Admin-level logon |
| Security | 4688 | Process created (if auditing is on) |
| Security | 4720 / 4732 | User created / added to a group |
| Security | 4698 | Scheduled task created |
| Security | 1102 | **Audit log cleared** |
| System | 7045 | **Service installed** |
| System | 104 | Log cleared |
| PowerShell Operational | 4104 | Script block logging (the actual code that ran) |
| TerminalServices-RemoteConnectionManager | 1149 | RDP authentication succeeded |
| TerminalServices-LocalSessionManager | 21 / 24 / 25 | RDP session logon / disconnect / reconnect |
| Sysmon (if installed) | 1 / 3 / 11 / 13 | Process / network / file created / registry |

### 7.8 `Disk\`: raw artifacts copied from the shadow copy

The folder tree **mirrors the original paths** (`Disk\Windows\...` = `C:\Windows\...`).

| Subfolder / file | Contents | Analyze with |
|---|---|---|
| `Windows\System32\config\` | SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT hives + transaction logs | **Registry Explorer**; parsed in `Parsed\RECmd_System` |
| `Users\<name>\NTUSER.DAT`, `...\UsrClass.dat` | Each user's hives | Registry Explorer, ShellBags Explorer; parsed in `Parsed\RECmd_Users`, `SBECmd` |
| `Windows\appcompat\Programs\Amcache.hve` | Program-execution and installation history with **SHA-1 hashes** | Parsed in `Parsed\Amcache` |
| `Windows\Prefetch\` | `.pf` files: what ran, how often, the last 8 run times | Parsed in `Parsed\PECmd` |
| `Windows\System32\Tasks\` | Scheduled-task XML (including deleted-but-still-present files) | Text editor |
| `Windows\System32\sru\` | SRUM database: per-app network bytes and resource use for about 30 days | Parsed in `Parsed\SrumECmd` |
| `Windows\System32\wbem\Repository\` | WMI repository (WMI persistence) | **PyWMIPersistenceFinder** on `OBJECTS.DATA`; it can find consumers that are no longer registered. Compare with `Persistence\wmi_subscriptions.txt` |
| `Users\...\Recent\`, `...\AutomaticDestinations` | LNK files and Jump Lists: files and folders the user opened, including on USB and network drives | Parsed in `Parsed\LECmd`, `JLECmd`; JumpList Explorer |
| `Users\...\ConnectedDevicesPlatform\` | ActivitiesCache.db (Windows Timeline) | Parsed in `Parsed\WxTCmd` |
| `Users\...\Google\Chrome\...`, `...\Edge\...`, Firefox | Browser history, downloads, sessions, extensions | Parsed in `Parsed\SQLECmd`; DB Browser for SQLite |
| `Users\...\Explorer\thumbcache_*.db` | Thumbnails of pictures and videos viewed, even after deletion | Thumbcache Viewer |
| `Users\...\WebCache\` | IE/Edge legacy cache and history (ESE database) | NirSoft **BrowsingHistoryView** (history) or **ESEDatabaseView** (every table) |
| `ProgramData\Microsoft\Windows\WER\` | Crash reports (can show malware crashes) | Text editor |
| `$Recycle.Bin\` | Deleted files: `$I` = metadata, `$R` = content (content only in Full) | Parsed in `Parsed\RBCmd` |
| `NTFS\MFT_C.bin`, `LogFile_C.bin`, `Boot_C.bin` | Raw NTFS metadata: **every file** on the drive with its timestamps | Parsed in `Parsed\MFTECmd`; MFTExplorer |
| `NTFS\UsnJrnl_fsutil_C.csv` | USN change journal: file create, rename and delete events. ⚠ **Timestamps are in local time, not UTC.** | Timeline Explorer |
| `SystemFiles\` (Full) | `pagefile_C.sys`, `hiberfil_C.sys`, `swapfile_C.sys` | **hiberfil:** convert with Comae `Hibr2Bin.exe` (in the toolkit) and analyze with Volatility. **pagefile:** `strings`, YARA, bulk_extractor (section 10), or load beside the memory image in MemProcFS |
| `Accessibility_Binaries\` | Copies of sethc.exe / utilman.exe | Compare hashes with known-good |
| `Volume_D\` (and so on) | Extra internal drives: `root_listing.csv`, `recyclebin_listing.csv`, `$Recycle.Bin\` | Timeline Explorer; RBCmd output |
| `ProgramData\ssh\`, `Users\<u>\.ssh\` (Standard+) | OpenSSH `authorized_keys`, `administrators_authorized_keys`, `known_hosts`, `config`, `sshd_config`, public host keys and sshd logs. **Private keys are never copied.** A planted key is quiet persistence that Autoruns doesn't check. | Text editor: look for keys nobody recognizes |
| `PSReadLine\*_history.txt` under `Users\<u>\AppData\Roaming\Microsoft\Windows\PowerShell\`, `Windows\System32\config\systemprofile\...` (SYSTEM), `Windows\SysWOW64\config\systemprofile\...` (SYSTEM, 32-bit PowerShell) and `Windows\ServiceProfiles\<account>\...` (Standard+) | PowerShell command history, one file per host: `ConsoleHost_history.txt` (console and Windows Terminal), `Visual Studio Code Host_history.txt` and others. The last 4096 commands by default, no timestamps. | `System\command_history.csv`; a text editor |
| `Users\<u>\.bash_history`, `.python_history`, Windows Terminal `buffer_*.txt` (Standard+) | Git Bash, MSYS2 or Cygwin history; the Python prompt's history; Windows Terminal tab screen text (commands **and output**, saved when Terminal restores previous sessions) | `System\command_history.csv`; a text editor for the output around each command |
| `Users\<u>\Documents\PowerShell_transcript.*.txt` (Standard+) | PowerShell transcripts from the default locations (`Documents\` and `Documents\<yyyyMMdd>\`), plus any local folder set by transcription policy. A policy folder on a network share is noted, not followed. | Text editor: full command input **and output** |
| `ads_unusual.csv` (Standard+) | **Hidden NTFS alternate data streams** (`file.txt:payload.exe`) that Explorer and `dir` don't show, on files **and folders** under Users, ProgramData, Program Files, `Windows\Temp`, the task folders, `$Recycle.Bin` and PerfLogs, plus the top level of the drive, `Windows` and `System32`. Read from the snapshot. Routine streams are counted in the last row, not listed: Zone.Identifier (see `zone_identifier.csv`), SmartScreen, Office and thumbnail properties, macOS and Dropbox metadata, Malwarebytes' own marks. Every other stream gets a row: `Path`, `IsFolder`, `Stream`, `Size`, the host file's `LastWriteTimeUtc`, `SHA256` (streams up to 512 MB), `FirstBytes` (hex), `ContentHint` (PE executable, ZIP, script or text, ...) and `CopiedTo`. Streams up to 1 MB are copied to `Disk\ADS\` as `.bin` files: ⚠ **they can be malware**, so open them only in a hex editor on an analysis machine. About 2 minutes on the lab laptop (445,000 files and folders). For other drives, use MFTECmd's `HasAds` / `IsAds` columns in `Parsed\`. | Timeline Explorer: sort by `ContentHint`; VirusTotal for `SHA256` |
| `zone_identifier.csv` (Standard+) | **Mark-of-the-Web** for files in each user's Downloads, Desktop, Documents, Temp and Outlook attachment cache: `ZoneId` (3 = internet), `HostUrl` (where it was downloaded from), `ReferrerUrl`. Read from the snapshot. At Deep+ risky file types up to 50 MB are hashed. Extracting a downloaded zip copies MOTW onto every file inside, so expect thousands of rows. | Timeline Explorer: filter `HostUrl` |
| `remote_access_presence.csv` (Deep+) | Remote-access / RMM tool configs and files **recorded but not copied** (presence, size, UTC times, SHA-256): ScreenConnect `User.xml` and client `user.config`, files pushed through ScreenConnect (`Temp\ScreenConnect\<ver>\Files\`), Atera configs, AnyDesk `*.conf`, NetSupport `client32.ini` (only `GatewayAddress` / port are read out: the C2 or gateway address), MeshAgent `.msh` (only the server URL), and configs next to any MeshAgent, NetSupport, SimpleHelp, Action1 or ScreenConnect service. | Timeline Explorer |
| `Program Files\ScreenConnect\`, `...\ATERA Networks\`, `ProgramData\LogMeIn\` (Deep+) | Remote-access logs: ScreenConnect `Session.db`, Atera and LogMeIn logs, and `*.log` / `*.txt` next to discovered RMM services. Paths follow KAPE's `RemoteAdmin` targets. | Text editor; DB Browser for SQLite |
| `iis_webroot_listing.csv`, `Windows\System32\inetsrv\config\` (Deep+, IIS only) | `applicationHost.config` (lists **native and managed modules**: malicious IIS modules are a known backdoor), every file in every site root with SHA-256 for script and binary types (`.aspx .ashx .asmx .php .jsp .config .dll` …), and each site's `web.config`. Exchange servers have their own web-shell locations, which aren't covered. | Timeline Explorer: sort by `ModifiedUtc`, look for new scripts |
| `Users\<u>\...\Microsoft.WindowsNotepad_*\LocalState\TabState\` and `...StickyNotes_*\plum.sqlite` (Deep+) | **Unsaved Notepad tabs** (Windows 11) and Sticky Notes. | No parser is bundled: use **notepad_parser** for `TabState\`; `plum.sqlite` opens in DB Browser for SQLite |
| `Users\<u>\AppData\Local\Mega Limited\MEGAsync\logs\` (Deep+) | MEGAsync logs (exfiltration to MEGA). Logs only, no credentials. | Text editor |
| `_CopyLog.csv` | Every file copied from the shadow copy, with original timestamps (UTC) | Proof of where each file came from |

### 7.9 `Tools\`: output of the live Sysinternals tools

| File | Contents / what to look for |
|---|---|
| `autoruns.csv` | **Every** auto-start location with hashes and signatures. Filter *Signer* for "(Not verified)" and *Image Path* for user-writable folders. |
| `sigcheck_Users.csv`, `sigcheck_ProgramData.csv`, `sigcheck_WinTemp.csv`, `sigcheck_System32.csv` | **Unsigned** executables only, with hashes. Malware usually lands in Users or ProgramData. |
| `handle.txt` | Open handles per process (which process has which file or registry key open) |
| `listdlls.txt` | DLLs loaded by each process. Look for DLLs loaded from odd paths. If the step shows FAIL, ListDlls was stopped (5-minute limit, or its output passed 50 MB because it was stuck repeating an error); the partial output is kept, and repeated lines are collapsed to one copy followed by a `[Recollect: ... repeated N more times ...]` note. |
| `logonsessions.txt` | Logon sessions and the processes in each |
| `rawcopy_*.log` | RawCopy status messages |
| `*.err` | The tool's stderr. Usually just its copyright banner, which is normal. |

### 7.10 `Parsed\`: Zimmerman tool output (open with Timeline Explorer)

Timestamps are **UTC**, with one important exception: ⚠️ the **SQLECmd browser CSVs** (`ChromiumBrowser_*`, columns ending in `(Local)`) are in the **local time of the machine that ran SQLECmd**. For these collections that's the suspect machine itself (its time zone is in `manifest.json` → `Time.TimeZone`). Convert them before you line them up with the other CSVs. See section 7.13. Each tool also leaves a `<Tool>.log` with its console output.

| Folder | What it is | Key columns / what to look for |
|---|---|---|
| `EvtxECmd\evtx_all.csv` | **All event logs in one CSV**, normalized | `TimeCreated`, `EventId`, `Channel`, `MapDescription`, `UserName`, `RemoteHost`, `PayloadData1-6`, `ExecutableInfo`. Filter by EventId (see the table in 7.7). |
| `MFTECmd\MFT_C.csv` | Every file and folder on C: | `ParentPath`, `FileName`, `Created0x10` (SI) vs `Created0x30` (FN), `LastModified0x10`, `FileSize`, `InUse` (False = deleted). **`SI<FN` = True suggests timestomping.** `ZoneIdContents` shows internet downloads. |
| `PECmd\..._PECmd_Output.csv` / `_Timeline.csv` | Prefetch: program execution | `ExecutableName`, `RunCount`, `LastRun`, `PreviousRun0-6`, `FilesLoaded`. The Timeline file has one row per run. |
| `Amcache\...` | Programs present or run, with **SHA-1** | `UnassociatedFileEntries`: `FullPath`, `SHA1`, `FileKeyLastWriteTimestamp`. Look up the SHA-1 on VirusTotal. |
| `AppCompatCache\...` | ShimCache | `Path`, `LastModifiedTimeUTC`, `CacheEntryPosition` (0 = most recent). Shows a file **existed**; on Windows 10+ it doesn't prove it ran. |
| `RECmd_System\`, `RECmd_Users\` | Kroll batch registry parse: one big CSV plus one CSV per plugin | `UserAssist` (GUI programs run, with counts), `BamDam` (last execution per user), `RecentDocs`, `RunMRU`, `TypedURLs`, `WordWheelQuery` (Explorer searches), `OpenSavePidlMRU`, `Services`, `USB`, `USBSTOR`, `MountedDevices`, `KnownNetworks`, `TaskCache`, `UserAccounts`, `ProfileList` |
| `SBECmd\` | ShellBags: folders the user browsed, including deleted, USB and network folders | `AbsolutePath`, `FirstInteracted`, `LastInteracted` |
| `LECmd\`, `JLECmd\` | LNK files and Jump Lists: files opened | `TargetPath` (or `LocalPath`), target created/modified/accessed times, `DriveType`, `VolumeSerialNumber`, `MachineID`, `MacAddress` |
| `SrumECmd\` | SRUM | `NetworkUsages`: bytes sent and received **per app per hour** (great for spotting exfiltration). `AppResourceUseInfo`: CPU and disk I/O per app. |
| `WxTCmd\<user>\` | Windows Timeline | `Activity`: app, file or URL, start and end time |
| `SQLECmd\` | Browser and app databases (⚠️ browser times are **local**, not UTC) | `ChromiumBrowser_HistoryVisits`, `_Downloads`, `_KeywordSearches`, `_OmniboxShortcuts`, `_NetworkActionPredictor`, `_Favicons`; Windows `ActivitiesCache`; `NotificationsDB`. The `SourceFile` column shows which browser and profile each row came from. Full details in section 7.13. |
| `RBCmd\<drive>\` | Recycle Bin | `FileName` (original path), `DeletedOn`, `FileSize` |

### 7.11 `KAPE\` (Full)

| Subfolder | Contents |
|---|---|
| `Targets\C\` | KAPE's own raw triage copy (`!SANS_Triage`), mirroring the original paths. Includes the raw `$MFT`, `$LogFile` and **`$Extend\$J`** (USN journal, which our own step collects only as fsutil CSV). With `-KapeVss`, `Targets\VSS<n>\` folders hold copies from older shadow copies (great for "before vs after"). |
| `Targets_D\` and so on | Extra internal drives (`FileSystem`, `RecycleBin`) |
| `Modules\<Category>\` | `!EZParser` output, already sorted by category (EventLogs, FileSystem, Registry, ProgramExecution, FileFolderAccess, ...). Includes `MFTECmd_$J_Output.csv`, the USN journal **in UTC with full paths**, which is better than the fsutil CSV. |
| `kape_console.log` | Full KAPE log |

**Tip:** `Modules\` and `Parsed\` overlap. Use `Parsed\` for the live drive and `KAPE\Modules\` for the `$J` and the shadow-copy versions.

### 7.12 `Velociraptor\` (Full)

One zip per artifact: Pslist, NetstatEnriched, Services, StartupItems, TaskScheduler, PermanentWMIEvents, Amcache (Detection.Amcache), AppCompatCache, UserAssist, Shellbags, Prefetch, Lnk, SRUM, Timeline, RecycleBin, Usn, NTFS.MFT, plus the browser artifacts Chrome.History, Edge.History, Chrome.Extensions, Firefox.History and Firefox.Downloads (times in UTC; a browser that isn't installed simply returns no rows), and **Windows.EventLogs.RDPAuth** (RDP logon chains reconstructed from the event logs). With `-YaraRules`, also `Windows.Detection.Yara.Process.zip` (YARA hits in process memory), with the exact rules used in `yara_rules_<name>.yar` and the artifact definition in `Windows.Detection.Yara.Process.definition.yaml`. Each zip holds the results as JSON (one row per line) plus any uploaded files. `<artifact>_console.log` holds that run's output. `artifacts_list.txt` lists every artifact in that Velociraptor build.

**How to analyze:** The easiest route is to import the zips into a Velociraptor server. A local test server works: `velociraptor.exe gui` starts one on your workstation. Then run the server artifact **`Server.Utils.ImportCollection`** to load each zip and browse or query it in the web GUI. You can also unzip a collection and read the JSON results directly.

### 7.13 Browser artifacts: where everything is

Browser evidence lands in up to four places. **Start with the parsed CSVs, then go to the raw files for anything they don't cover.**

**1. Parsed CSVs (Deep and Full):** `Parsed\SQLECmd\`. Open them in Timeline Explorer. File names start with a timestamp.

| File | What's in it |
|---|---|
| `*_ChromiumBrowser_HistoryVisits_*.csv` | Every page visit: `URL`, `URLTitle`, `VisitTime (Local)`, `VisitCount`, `TypedCount` (typed into the address bar), `VisitDurationInSeconds`, and `FromVisitID` (which visit led to this one) |
| `*_ChromiumBrowser_Downloads_*.csv` | Downloads: file name, save path, source URL, start and end time, size |
| `*_ChromiumBrowser_KeywordSearches_*.csv` | Search terms entered in the address bar or search engines |
| `*_ChromiumBrowser_OmniboxShortcuts_*.csv` | Text typed in the address bar and the suggestion the user chose |
| `*_ChromiumBrowser_NetworkActionPredictor_*.csv` | What the user typed and which URL they went to (type-ahead history) |
| `*_ChromiumBrowser_Favicons_*.csv` | Site icons. These can reveal sites even after history was cleared. |
| `*_Windows_ActivitiesCacheDB_*.csv` | Windows Timeline, which can include browser activity |

- **"Chromium"** covers Chrome, Edge, Brave, Vivaldi and Opera. When more than one is installed you get one file per browser of the same type.
- **The `SourceFile` column** (the last column) shows the browser and profile each row came from, for example `...\Microsoft\Edge\User Data\Default\History`. Filter on it.
- ⚠️ **Time zone:** columns named `... (Local)` are in the local time of the machine that ran SQLECmd. For these collections that's the **suspect machine** (see `manifest.json` → `Time.TimeZone`). Event logs, MFT and Prefetch CSVs are UTC, so convert before you correlate. The Velociraptor browser artifacts (point 4) are in UTC and make a good cross-check.

**2. Raw browser files (Deep and Full):** `Disk\Users\<user>\AppData\...`, copied from the shadow copy

| Browser | Folder | Key files |
|---|---|---|
| Chrome | `Local\Google\Chrome\User Data\<profile>\` (usually `Default`, `Profile 1`, ...) | `History` (SQLite: visits, URLs, downloads, searches), `Favicons`, `Shortcuts`, `Top Sites`, `Network Action Predictor`, `Visited Links`, `Bookmarks` (JSON), `Preferences` / `Secure Preferences` (JSON: settings, download folder, extensions), `Sessions\` (open tabs), `Extensions\*\*\manifest.json` |
| Edge | `Local\Microsoft\Edge\User Data\<profile>\` | Same set as Chrome |
| Brave, Vivaldi, Opera | Their own `User Data\` folders | Same set, when installed |
| Firefox | `Roaming\Mozilla\Firefox\Profiles\<profile>\` | `places.sqlite` (history and bookmarks), `downloads.sqlite` / `places.sqlite` downloads, `sessionstore*` (open tabs), `extensions.json` |
| IE / legacy Edge | `Local\Microsoft\Windows\WebCache\` | `WebCacheV01.dat` (ESE database: history, cache, cookies index) |

**Not collected by Recollect's own browser step, on purpose:** `Cookies`, `Login Data` (saved passwords), `Web Data` (autofill and cards), Firefox `key4.db`, `logins.json` and `formhistory.sqlite`. KAPE's copy in the Full profile does include most of them (point 3 and section 7.14).

How to view them:
- **SQLite files** (`History`, `places.sqlite`, `Favicons`, ...): **DB Browser for SQLite**, opened read-only (tick *Read Only* in the open dialog). Chrome times are microseconds since 1601-01-01 UTC. Firefox times are microseconds since 1970-01-01 UTC.
- **JSON files** (`Bookmarks`, `Preferences`, `manifest.json`): any text editor. Check `Preferences` for the download folder and the extensions that are turned on.
- **`WebCacheV01.dat`:** NirSoft BrowsingHistoryView, or an ESE database viewer. Nothing in the script parses this file.
- **Recovering cleared history:** a cleared `History` database often still holds deleted records in free pages. Specialist SQLite carving tools can recover them, and so can the shadow-copy versions from KAPE (point 3).

**3. KAPE's copy (Full):** `KAPE\Targets\C\Users\<user>\AppData\Local\Google\Chrome\User Data\` and `...\Microsoft\Edge\User Data\`. This is KAPE's own raw copy. ⚠ **Unlike Recollect's own copy, it includes `Login Data`, `Cookies`, `Web Data` and the user's DPAPI master keys: see section 7.14.** `-KapeSkipBrowserData` (or answering No in guided setup) leaves KAPE's browser targets out. With `-KapeVss`, older versions from each shadow copy are in `KAPE\Targets\VSS<n>\Users\...`, which is the best way to see history that was later cleared. `KAPE\Modules\SQLDatabases\` may be empty; use `Parsed\SQLECmd\` for parsed output.

**4. Velociraptor (Full):** `Velociraptor\Windows.Applications.Chrome.History.zip`, `...Edge.History.zip`, `...Chrome.Extensions.zip`, `...Firefox.History.zip` and `...Firefox.Downloads.zip`. These are parsed independently of SQLECmd, with times in **UTC**. Import them with `Server.Utils.ImportCollection` (section 7.12).

### 7.14 Outputs that can contain passwords and other secrets

> ⚠ **CAUTION: a collection can contain working credentials.** Recollect's own collectors don't copy browser passwords, cookies, autofill, SSH private keys or the secret-bearing configs of remote-access and transfer tools (those are recorded as presence and hash only). **But several outputs hold, or can hold, passwords, password hashes, keys or session tokens by their nature, and the Full profile's KAPE triage copies browser password stores outright.** Anyone with a copy of the collection may be able to log in as the machine's users, its service accounts or, through shared passwords, other machines. **Treat every collection as sensitive:** use `-Archive -ArchivePassword`, keep it on access-controlled storage, share it only with people working the case, never upload it or files from it to public services, and dispose of it under your organization's evidence policy.

**Contain credential material by design:**

| Output | What it can hold | Collected by | Profile |
|---|---|---|---|
| `Memory\*.raw` | **Everything in RAM:** LSASS password hashes and Kerberos tickets, clear-text passwords when WDigest is on, browser session tokens, decrypted data, keys | `-Memory` | any, opt-in |
| `Disk\SystemFiles\` (`hiberfil_C.sys`, `pagefile_C.sys`, `swapfile_C.sys`) | **The same as memory**, from earlier points in time | RawCopy | Full |
| `Disk\Windows\System32\config\` (`SAM`, `SECURITY`, `SYSTEM`, `SOFTWARE`) | **Local account password hashes (NTLM), LSA secrets** (service-account passwords, the auto-logon password), **cached domain logon hashes**. SAM and SECURITY are decrypted with the boot key in SYSTEM, which is collected with them. Some machines also keep an auto-logon `DefaultPassword` in clear text in the SOFTWARE hive. | shadow-copy copy (or `reg save` fallback) | Standard and up |
| `Disk\Windows\Panther\` | **Windows Setup answer files** (`unattend.xml`, if one was left behind): the local administrator or domain-join password, in clear text or Base64. The same image usually means the same password on every machine. | shadow-copy copy | Deep and up |
| `KAPE\Targets\` | **KAPE's `!SANS_Triage` browser targets copy what Recollect's own collectors skip:** Chrome, Edge and Brave `Login Data` (saved passwords), `Cookies` and `Web Data` (autofill, saved cards); Firefox `logins.json`, `signons.sqlite` and `cookies.sqlite`; and each user's **DPAPI master keys** (`AppData\Roaming\Microsoft\Protect\`), which with the user's password or the collected hives can decrypt those saved passwords. Its remote-admin targets copy AnyDesk `*.conf` (unattended-access password hash) and mRemoteNG `confCons.xml` (saved connection passwords, often encrypted with a publicly known default key). Also the same SAM and SECURITY hives. Verified in a real Full collection. **`-KapeSkipBrowserData`** (or No to the guided-setup question) drops the `WebBrowsers` target, and with it every browser database above and the DPAPI keys it copies. The Dropbox metadata target still copies the DPAPI key folder, and the remote-admin targets still copy AnyDesk and mRemoteNG configs. | KAPE | Full |
| `Network\capture.pcapng`, `capture.etl` | **Unencrypted traffic in full:** passwords and session cookies sent over HTTP, FTP, Telnet, POP3/IMAP without TLS, LDAP simple binds, and NTLM challenge-responses (crackable offline) | `-NetworkCapture` | Opt-in |
| `Security\DefenderQuarantine\` | Quarantined files, which can include **credential dumps** (for example an LSASS dump Defender caught) | `-DefenderQuarantine` | opt-in |

**Can contain secrets, depending on what users and attackers did:**

| Output | What it can hold | Profile |
|---|---|---|
| `System\command_history.csv`, the `PSReadLine\*_history.txt` files, `.bash_history`, `.python_history`, Windows Terminal `buffer_*.txt`, PowerShell transcripts | Passwords typed into commands (`net user … <password>`, `ConvertTo-SecureString -AsPlainText`, connection strings) | Standard and up |
| `EventLogs\` (including `command_events.csv`), `Processes\processes.csv`, `Processes\tasklist.txt`, Velociraptor `Pslist` | Command lines and PowerShell script blocks (event 4104) that include passwords or tokens | Quick and up (event log copies: Standard and up; Velociraptor: Full) |
| Browser `History`, `Sessions\`, Firefox `sessionstore`, `WebCache\` | Session tokens and credentials embedded in URLs; Firefox session files can include session cookies and form contents for restoring tabs | Deep and up |
| Notepad `TabState\`, Sticky Notes `plum.sqlite` | Whatever the user typed, including passwords kept "temporarily" | Deep and up |
| `Notifications\wpndatabase.db` | Message previews, including one-time sign-in codes | Deep and up |
| RDP bitmap cache, `thumbcache_*.db` | Pictures of screens and images, which can show passwords | Deep and up |
| bulk_extractor output (section 10) | Carved URLs, emails, JSON and packets from memory: session tokens and credentials in URLs | your own runs |

`Security\credential_metadata.txt` lists stored credential **names** (`cmdkey /list`) and Kerberos ticket **metadata** (`klist`) only, never the secrets, and `Network\net_extra.txt` lists Wi-Fi profile names without keys.

---

### 7.15 Command-line activity: where commands are recorded

Commands run on a Windows machine end up in several places, and none of them is complete on its own. Start with the two CSVs; the table says where else to look.

| Where | What it records | In the collection |
|---|---|---|
| PSReadLine history (PowerShell) | Typed commands, per account and per host; no times | `System\command_history.csv`; raw files under `Disk\` (section 7.8) |
| PowerShell script block logging (4104) | The code that actually ran, including scripts and decoded `-enc` commands. Logged for "suspicious" code even when the policy is off | `EventLogs\command_events.csv` (Deep+); `Parsed\EvtxECmd\evtx_all.csv` |
| Windows PowerShell 400 | The command line of every PowerShell start (`HostApplication`); on by default | `EventLogs\command_events.csv` |
| PowerShell transcripts | Commands **and output**, when transcription is enabled | `Disk\Users\<u>\Documents\` (section 7.8) |
| Security 4688, Sysmon 1 | Every process with its command line, **only** if process auditing with command lines, or Sysmon, was on. This is where `cmd.exe /c …`, `wmic …` and other non-PowerShell commands show up | `EventLogs\command_events.csv` |
| WMI-Activity 5861 | WMI permanent event consumers (persistence) as they're registered, with the command they run | `EventLogs\command_events.csv`; also `Persistence\wmi_subscriptions.txt` and the WMI repository |
| **CMD (`cmd.exe`)** | **Keeps no history file.** Its history (doskey) lives only in the memory of the `conhost.exe` process behind each console window | `Memory\*.raw` (`-Memory`): use Volatility's console plugins (check which ones your Volatility 3 version includes) or search the image for the commands. Windows Terminal's `buffer_*.txt`, when present, holds CMD prompt lines too |
| bash, Python | Typed commands; bash adds times when `HISTTIMEFORMAT` was set | `System\command_history.csv` |
| Registry | `RunMRU` (the Win+R box), `TypedPaths` (Explorer's address bar) | `Parsed\RECmd_Users\` |
| Prefetch, Amcache, ShimCache | That a program ran (not its arguments) | `Parsed\PECmd`, `Parsed\Amcache`, `Parsed\AppCompatCache` |

Not collected: WSL shells keep their `.bash_history` inside the distribution's virtual disk (`ext4.vhdx`), which would have to be mounted and read separately.

> ⚠ Commands can contain passwords (section 7.14).

## 8. Troubleshooting

| Message | Meaning / fix |
|---|---|
| `Recollect needs administrator rights` | Start it with `recollect` and no parameters (guided setup asks Windows for permission), or open the terminal with *Run as administrator* for manual mode |
| `'recollect' is not recognized` in PowerShell | Type `.\recollect`: PowerShell doesn't run files from the current folder without `.\` |
| `Administrator permission was not given` | The Windows permission (UAC) prompt was declined or closed. Run `recollect` again and choose **Yes** |
| `recollect.ps1 was not found` / `More than one copy` | `recollect.cmd` looks next to itself, then one folder down. Keep it beside `recollect.ps1`, or at the drive root with a single toolkit folder below it |
| `Memory Only needs WinPmem, Magnet RAM Capture or DumpIt` | Put a memory tool under `Tools\` (section 3), or choose another profile |
| Guided setup doesn't offer the YARA scan or LOLDrivers matching | It offers YARA only for Full and only with rule files in `Tools\YARA\`; LOLDrivers only for Standard and up, and only with `loldrivers*.csv/json` or the repository's `loldrivers.io\content\api\drivers.csv` under `Tools\`. Use `-YaraRules` / `-LolDriversCsv` in manual mode for files elsewhere |
| `Skipped ...\<Tool>.exe: needs .NET 10.0.0 runtime` | Harmless. KAPE's bundled copy is used instead (check that a `FOUND` line follows). |
| `SKIPPED - tool not found: X` | Put that tool under `Tools\` (section 3) |
| `Output is on the SYSTEM drive` / `INTERNAL disk` | Use `-OutputPath` on an external drive |
| `Only N GB free` | Use a bigger drive, or a smaller profile, or drop `-Memory` |
| WFP collector: "XML layout not recognised" | The BLOCK summary couldn't find filters in `wfp_filters.xml`. The XML is still collected; review it by hand. |
| YARA scan skipped | `-YaraRules` only runs in Full. Also check the rules file is under ~30,000 characters, and that `Windows.Detection.Yara.Process.definition.yaml` shows a `YaraRule` parameter. |
| `zone_identifier.csv` is very large | Normal when users extracted downloaded zips: Windows copies Mark-of-the-Web onto every extracted file. Filter on `HostUrl`. |
| Defender section shows `0x800106ba` | The Defender service isn't running. Expected on machines with another antivirus product; recorded in `defender.txt`. |
| A collector shows WARN | Read its Note in `CollectorResults.csv`; usually one item failed and the rest succeeded |
| Interrupted with Ctrl+C | The shadow copy and temp link are still removed. Check with `vssadmin list shadows`. |
| Several steps FAIL with "Could not find a part of the path 'E:\Collections\…'" or "A device which does not exist was specified", or the last row of `CollectorResults.csv`, **Output drive check**, is WARN | The **output drive dropped out** during the run: a USB drive briefly disconnected and reconnected. Windows records it as disk event 51 ("An error was detected on device … during a paging operation") and Partition event 1006. From 3.5.0 the script waits up to 2 minutes for the drive to come back, keeps every log line, marks each step that overlapped the dropout WARN ("the output drive was disconnected and reconnected during this step"), and stops running steps if the drive doesn't return. Re-collect anything the WARN steps produced if it matters. The usual cause is a bus-powered drive that doesn't get enough power, or a loose cable or port: use a powered hub, a different port or cable, or another drive (an SSD draws far less power), and don't use a drive that has dropped out for real cases. |
| The run seems frozen: no new lines for a long time, little CPU, title bar starts with **Select** | The console window was clicked while **QuickEdit** was on, and Windows pauses any program writing to a console with an active selection. Click the window and press **Esc** or **Enter**; it resumes at once with nothing lost. From 3.4.2 the script turns QuickEdit off for its own window during the run (log line `Console QuickEdit turned off`) and restores it at the end. A host run with an older version, or a console where that can't be changed, can still freeze this way. |

---

## 9. Timeline Explorer refresher

**Timeline Explorer** (TLE), by Eric Zimmerman, is a free, read-only replacement for Excel, built for forensic CSV output: instant filtering, grouping, tagging and color coding, even on files with millions of rows. Everything in `Parsed\` and `KAPE\Modules\`, plus most CSVs in the other folders, opens in it. Unlike Excel it **doesn't change the data or reformat timestamps**. The only thing you can edit is the Tag column.

**Further reading:** the illustrated walkthrough at aboutdfir.com/toolsandartifacts/windows/timeline-explorer/ (with GIFs of each feature, and the main source for this section); SANS 3MinMax *Episode 87: Introducing and Using Timeline Explorer* (YouTube); the Security Noob overview at thesecuritynoob.com (links to further videos); and, inside the tool, **Help → Quick Help** for shortcuts.

### 9.1 Getting it running

1. Run it on your **analysis workstation**, not on the suspect machine.
2. It's in `Tools\Get-ZimmermanTools\net\TimelineExplorer\TimelineExplorer.exe`. Run `Get-ZimmermanTools.ps1` now and then to stay on the latest version.
3. If it won't start, install the **.NET Desktop Runtime** version it was built for (currently .NET 10) from Microsoft.
4. **Work on a copy** of the collection, never on the original evidence drive.
5. Optional: **Tools → Skins** to choose a theme, including dark mode (for example *Office 2019 Black*).

### 9.2 Opening files and managing tabs

- **File → Open**, or **drag and drop** CSV files onto the window. You can drop many at once. Each file opens in its **own tab**.
- **One window per computer** keeps things tidy. Drop all of one host's CSVs into the same window (for example the whole `KAPE\Modules\FileFolderAccess\` folder: JLECmd, LECmd and SBECmd output). The **file path in the bottom-left corner** tells you which file and host you're looking at. Double-click that path to copy it.
- The **tab search box** filters the tab list as you type (a "contains" match), so typing `MFT` finds the MFTECmd tab. **Ctrl+W** closes the current tab and **Ctrl+Q** closes them all.
- For Excel files, only the **first worksheet** is opened.
- Large files (the MFT CSV is about 450 MB, `evtx_all.csv` about 350 MB) take a minute to load and need plenty of RAM (16 GB+ recommended).
- **Good files to start with:** `Parsed\EvtxECmd\evtx_all.csv`, `Parsed\PECmd\*_Timeline.csv`, `Parsed\MFTECmd\MFT_C.csv`, `Parsed\Amcache\*UnassociatedFileEntries.csv`, `Parsed\RECmd_Users\*_Kroll_Batch_Output.csv`, `Processes\processes.csv`, `Tools\autoruns.csv`.

### 9.3 Reading the screen

- The first two columns are added by TLE: **Line** (the original row number) and **Tag** (a checkbox for marking rows).
- **Bottom-left:** the current file path and the active **filter expression**. **Bottom-right:** total lines and **Visible Lines**. Watch Visible Lines so you always know whether a filter is hiding rows.
- Timestamps are shown as `yyyy-MM-dd HH:mm:ss`. To change that, use **Tools → Datetime Format** (it's saved in `TimelineExplorer\Settings\TLE_settings.xml`).
- Timestamps from the Zimmerman tools are **UTC**. Note the host's time zone from `manifest.json` → `Time.TimeZone`. Two exceptions are in **local** time: `Disk\NTFS\UsnJrnl_fsutil_*.csv`, and the SQLECmd browser CSVs (`Parsed\SQLECmd\*ChromiumBrowser_*`, columns ending in `(Local)`).

### 9.4 Sorting and column layout

- Click a **column header** to sort; click again to reverse. Or **right-click the header → Sort Ascending / Descending**. Sort on a timestamp column to read events in order.
- **Right-click a header** for more options, including **Best Fit (all columns)**. **Ctrl+R** resets all column widths when they get messy.
- **Column Chooser** (right-click a header): drag columns you don't need into it to hide them. **Double-click** a column in the chooser to put it back where it was, or drag it to a new position.
- **Drag headers** to reorder columns. Put the important ones (timestamp, path, event ID) at the front.
- **First Scrollable Column** freezes every column to its left, so the timestamp and file name stay on screen while you scroll right (like Excel's freeze panes, but for columns).

### 9.5 Filtering (the main skill)

- **Filter row:** the empty row directly under the headers. Type in the box under a column to show only rows that **contain** that text. Results update **as you type**. Examples: `4624` under *EventId*, `\AppData\` under *ParentPath*, `powershell` under *ExecutableInfo*.
- **Value filter:** click the **funnel icon** on a header to tick values from a list. The view updates instantly, with no OK button. Tip: **drag across several consecutive values and press Space** to tick them all at once.
- **Combining filters:** filters on different columns combine with **AND**.
- **Edit Filter** (bottom-left, where the active filter is shown): build complex expressions, and switch between **AND** and **OR**. For example, to see `.docx` **OR** `.pptx` **OR** `.pdf`, use OR, because AND would match nothing since no row holds all three. You can also type the expression by hand. Edit Filter offers more operators than the header filter: *begins with*, *between* (for time windows), *greater / less than* and so on.
- **Temporarily disable a filter:** untick the checkbox beside the filter expression at the bottom. **Clear it** with the X: one element, or the whole filter.
- **Context around a finding:** TLE **keeps your position** when you remove a filter. Filter down to the suspicious row, select it, then clear or disable the filter (with the grid sorted by time). You land on the same row, now surrounded by **everything that happened just before and after it**. This is one of the most useful moves in an investigation.

### 9.6 Searching (the search bar, top right)

- Type a term in the **search bar** in the top-right corner to search across **all columns**. Use it for IOCs: file names, IP addresses, user names, hashes.
- **Search Options** (next to the bar) controls how the search behaves: highlight matches only, or hide rows that don't match.
- Click the **blue "?"** in Search Options for the **power-search syntax** (for example limiting a term to one column, or combining terms). This syntax works **only in the search bar**, not in the column filter row.

### 9.7 Grouping

- **Drag a column header** into the grouping pane above the grid to group by that column. You can stack several. For example, group `evtx_all.csv` by **EventId** (counts per event type), then by **TimeCreated** (how many of each per date).
- Expand or collapse the groups to drill in.
- To undo: right-click a grouped header → **Ungroup**, or right-click an empty part of the grouping pane → **Clear Grouping**. Columns go back to where they were.

### 9.8 Tagging, color, copying

- **Tag:** tick the **Tag** checkbox on rows of interest as you work. Later, filter the Tag column to *checked* to see only your findings, which become your evidence list.
- **Conditional formatting:** right-click a header → **Conditional Formatting → Highlight Cell Rules → Text That Contains…** to color matching cells. For example, green for `.exe`, red for `\Temp\`, yellow for your suspect user name.
- **Plaso super timelines** open with automatic color coding. The legend is in the **Help** menu.
- **Copying:** select rows and press **Ctrl+C** to paste them into your report or notes. Depending on the setting, the **column headers are copied too**, so check the first time you paste.

### 9.9 Saving your work

- **File → Save Session** saves every open tab with your filters and tags. Reopen it with **File → Open** (select the session file), even after a reboot.
- To build a session from a whole KAPE output folder automatically, Phill Moore (This Week in 4n6) published a PowerShell script for exactly that. The aboutdfir page links to it.
- For things TLE doesn't do, such as **pivot tables** (for example "earliest entry per event log" to see how far back the logs go), copy the data into Excel. **Never edit the original CSVs.**

### 9.10 Example workflow: "What happened around 14:32 UTC?"

1. Open `evtx_all.csv`. Filter *EventId* to `4624` and look for logons near 14:32. Check *PayloadData* for the logon type (3 = network, 10 = RDP) and *RemoteHost* for the source.
2. Open `PECmd\*_Timeline.csv`. In **Edit Filter**, set *RunTime* **between** 14:20 and 14:50. What ran?
3. Open `MFT_C.csv`. Filter *Created0x10* to the same window and *ParentPath* to `\Users\` or `\ProgramData\`. What files appeared? Check `SI<FN` for timestomping.
4. Search the new executable's name in the **search bar** of the `Amcache\*UnassociatedFileEntries.csv` tab. Copy its **SHA-1** and check it on VirusTotal.
5. Check `SrumECmd\*NetworkUsages*.csv` for that program's bytes sent (possible exfiltration).
6. Check `Persistence\` and `Tools\autoruns.csv` for anything it set up to survive a reboot.
7. On each finding, **clear the filter while the row is selected** to see what happened around it.
8. **Tag** every relevant row, **File → Save Session**, then filter Tag = checked and **Ctrl+C** the rows into your report.

---

## 10. bulk_extractor: carving the raw files

**bulk_extractor** (Simson Garfinkel; [github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)) ignores file systems and file formats. It reads raw bytes and pulls out *features*: URLs, domains, email addresses, IP addresses, network packets, JSON, and the contents of compressed or base64-encoded data. That makes it a good second pass over the raw, unstructured files Recollect collects, and a poor one over everything else.

Run it **afterwards, on your analysis workstation, against a copy** of the collection, never on the suspect machine. It is CPU-heavy, and Recollect deliberately stops at collection.

**Getting it:** use a tested build from the project's [releases page](https://github.com/simsong/bulk_extractor/releases); the main branch is a development tree. If the release you want has no Windows build, run it in WSL or a Linux forensic VM (the SANS SIFT Workstation includes it) and point it at the collection over a read-only share.

### 10.1 Where to point it, and why

| Target | Why |
|---|---|
| **Memory image:** `Memory\<COMPUTER>_<stamp>.raw` | **The best target.** It recovers URLs, domains, emails and IPs from RAM, including from processes that have already exited and data no Volatility plugin parses. Its network scanner rebuilds packet fragments left in memory into a `.pcap`, which is valuable when there was no network capture. The domain and URL histograms make a fast IOC list. |
| **`Disk\SystemFiles\pagefile_C.sys`, `swapfile_C.sys`** (Full) | Memory that Windows pushed out to disk. It often holds older activity that is no longer in the RAM image. |
| **`Disk\$Recycle.Bin\...\$R*`** (Full) and **`Disk\NTFS\LogFile_C.bin`** | Fragments of deleted or recently changed content. |
| **`Disk\SystemFiles\hiberfil_C.sys`** (Full) | **Only after converting it** with Comae `Hibr2Bin.exe` or Volatility. From Windows 8 on, the hibernation file is compressed in a format bulk_extractor can't read directly, so the raw file gives little. Treat the converted file like a second memory image. |

**Not worth scanning:**

- **The whole case folder.** `Parsed\`, `KAPE\`, `Velociraptor\` and the CSVs are already structured. Scanning them returns the same URLs from several sources and buries the useful hits.
- **Event logs and registry hives.** The EZ tools, Timeline Explorer and Registry Explorer read these properly. Carving them adds noise, not information.

### 10.2 Practical notes

- **The output folder must not exist yet;** bulk_extractor creates it. One folder per input keeps results apart:

  ```powershell
  bulk_extractor -o E:\Analysis\IR-001_mem "E:\Collections\<case folder>\Memory\<COMPUTER>_<stamp>.raw"
  bulk_extractor -o E:\Analysis\IR-001_pagefile "E:\Collections\<case folder>\Disk\SystemFiles\pagefile_C.sys"
  ```

- **Start with the histograms:** `domain_histogram.txt`, `url_histogram.txt` and `email_histogram.txt`, ranked by count. Rare entries near the bottom are often more interesting than the top ones, which are usually Microsoft, Google and CDN domains.
- **Then open the matching feature files** (`domain.txt`, `url.txt`, `email.txt`, `ip.txt`). Each hit has its **byte offset** in the image and a little surrounding context, which you use to tie it back to a process (see 10.3).
- **Large files:** feature files such as `domain.txt` and `url.txt` can run to millions of lines, too many for Notepad or Excel. [bulk-extractor-to-csv](https://github.com/seliyyah/bulk-extractor-to-csv) converts the whole output folder to CSV for Timeline Explorer, removes the `\000` padding from UTF-16 context, and its user guide covers quick `grep` and `Select-String` searches.
- **Network output:** `packets.pcap` (open in Wireshark) and `ip.txt`. Expect fragments, not whole conversations.
- **Time:** roughly 30–60 minutes for a 32 GB image, depending on the CPU. It uses every core.
- **Handle the output as evidence.** It contains whatever was in memory, which can include session tokens, credentials in URLs and personal data.

### 10.3 How it complements Volatility

They answer different questions, so use both:

| | Volatility 3 / MemProcFS | bulk_extractor |
|---|---|---|
| **Approach** | Rebuilds Windows' own structures: process list, threads, handles, sockets, loaded modules | Ignores structure; scans every byte for patterns |
| **Strength** | **Context:** which process, which user, when it started, what it had open | **Coverage:** finds strings in freed memory, exited processes and data structures no plugin parses |
| **Weakness** | Sees only what its plugins understand; misses data that has been freed | No context: a hit is just bytes at an offset |

**Typical workflow:**

1. Run bulk_extractor on the memory image and read the domain and URL histograms for anything unexpected.
2. Note the offset of an interesting hit from the feature file.
3. In Volatility, find what owns that region: `windows.pslist` / `windows.vadinfo` to map process memory, or `windows.netscan` for a matching connection. In MemProcFS, search the mounted process folders for the same string.
4. Feed new indicators back: hunt the domain in the parsed browser history (section 7.13) and the IP in `Network\` and the event logs.

Volatility tells you *who* and *when*; bulk_extractor tells you *what else is in there*.

---

*Questions or failures: send `CollectorResults.csv`, `manifest.txt` and `Collection.log` from the run.*
