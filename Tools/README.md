# Tools folder

Put the third-party tools here. They are **not** stored in this repository (their licenses don't allow redistribution, and they're large), so everything in this folder except this README is git-ignored.

The script searches this folder **recursively by file name**, so subfolder names don't matter. **Extract each tool's whole folder**, not just the `.exe`: several tools need the files that ship beside them (Maps, batch files, DLLs).

## Suggested layout

```text
Tools\
├── SysinternalsSuite\        autorunsc64.exe, handle64.exe, tcpvcon64.exe, Listdlls64.exe,
│                             logonsessions64.exe, sigcheck64.exe (+ the rest of the suite)
├── Get-ZimmermanTools\       output of Get-ZimmermanTools.ps1
│   └── net\                  EvtxeCmd\ (with Maps\), RECmd\ (with BatchExamples\Kroll_Batch.reb),
│                             SQLECmd\ (with Maps\), TimelineExplorer\, MFTECmd.exe, PECmd.exe, ...
├── kape\KAPE\                kape.exe, Targets\, Modules\, Modules\bin\
├── velociraptor\             velociraptor-vX.Y.Z-windows-amd64.exe
├── WinPmem\                  go-winpmem_amd64_..._signed.exe
├── Magnet\                   MRCv*.exe
├── Comae\                    x64\DumpIt.exe
├── RawCopy\                  RawCopy64.exe, RawCopy.exe
└── 7zip\                     7z.exe + 7z.dll   (copy from C:\Program Files\7-Zip; the installer alone won't work)
```

## Where to get them

| Tool | Source | Needed for |
|---|---|---|
| Sysinternals Suite | https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite | Autoruns, Handle, ListDlls, LogonSessions, Sigcheck, TCPView |
| Eric Zimmerman tools | https://ericzimmerman.github.io (`Get-ZimmermanTools.ps1`; add `-NetVersion 0` to get both the .NET 4.7.2 and .NET 10 builds) | Parsers (Deep+), Timeline Explorer |
| KAPE | https://www.kroll.com/kape (free, registration) | Full profile; its bundled EZ tools are also the fallback when .NET 10 is missing |
| Velociraptor | https://github.com/Velocidex/velociraptor/releases | Full profile |
| WinPmem | https://github.com/Velocidex/WinPmem/releases | `-Memory` (1st choice) |
| Magnet RAM Capture | https://www.magnetforensics.com/resources/magnet-ram-capture/ | `-Memory` (2nd choice) |
| Comae DumpIt | Magnet Forensics / Comae Toolkit | `-Memory` (3rd choice) |
| RawCopy | https://github.com/jschicht/RawCopy | Raw `$MFT`, `$LogFile`, pagefile, hiberfil (Deep / Full) |
| 7-Zip | https://www.7-zip.org | `-Archive` only |

Missing tools are reported as `SKIPPED` and the rest of the collection still runs.

## After downloading

```powershell
# Update KAPE targets and modules
.\kape\KAPE\kape.exe --sync

# Remove the "downloaded from the internet" mark so Windows doesn't block the tools in the field
Get-ChildItem .. -Recurse -File | Unblock-File
```

See [docs/USER_GUIDE.md](../docs/USER_GUIDE.md) section 2 for the exact file names the script looks for and the .NET runtime notes.
