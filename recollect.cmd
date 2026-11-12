@echo off
rem ==========================================================================
rem  recollect.cmd - launcher for Recollect (Windows DFIR triage collector)
rem
rem    recollect                 Guided setup: answer a few questions, then collect.
rem    recollect -CaseId ...     Manual mode: the parameters go straight to
rem                            recollect.ps1 (see docs\USER_GUIDE.md).
rem    recollect /?              Usage and examples.
rem
rem  Starts Windows PowerShell 5.1 by full path with -NoProfile (the profile
rem  scripts of the computer being collected never run) and with the execution
rem  policy bypassed for this one process only; no setting is changed.
rem  Guided setup asks Windows for administrator rights when needed.
rem  Keep this file next to recollect.ps1, or at the root of the drive with
rem  the toolkit in a folder one level below it.
rem
rem  BSD 3-Clause License. Copyright (c) 2026, seliyyah-dfir. See LICENSE.
rem ==========================================================================
setlocal EnableExtensions DisableDelayedExpansion
title Recollect

rem 64-bit PowerShell even when this runs in a 32-bit cmd.exe.
set "PSEXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PSEXE=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"

rem Find recollect.ps1: next to this file, or in exactly one folder below it.
set "COLLECT_SCRIPT="
if exist "%~dp0recollect.ps1" set "COLLECT_SCRIPT=%~dp0recollect.ps1"
if defined COLLECT_SCRIPT goto :found
set "FOUND_COUNT=0"
for /d %%D in ("%~dp0*") do if exist "%%~fD\recollect.ps1" (
    set "COLLECT_SCRIPT=%%~fD\recollect.ps1"
    set /a FOUND_COUNT+=1
)
if "%FOUND_COUNT%"=="1" goto :found
echo.
if "%FOUND_COUNT%"=="0" (
    echo   recollect.ps1 was not found next to recollect.cmd or in a folder below it.
) else (
    echo   More than one copy of recollect.ps1 was found below %~dp0.
    echo   Run the recollect.cmd inside the toolkit folder you want to use.
)
echo.
exit /b 1

:found
if /i "%~1"=="/?"     goto :usage
if /i "%~1"=="-?"     goto :usage
if /i "%~1"=="-help"  goto :usage
if /i "%~1"=="--help" goto :usage
if /i "%~1"=="/elevated" goto :elevated

rem Administrator? (fltmc only succeeds in an elevated process.)
"%SystemRoot%\System32\fltmc.exe" >nul 2>&1
if errorlevel 1 goto :not_admin

"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%COLLECT_SCRIPT%" %*
exit /b %errorlevel%

:not_admin
if not "%~1"=="" (
    echo.
    echo   Recollect needs administrator rights.
    echo   Manual mode: open a terminal with "Run as administrator" and run recollect again.
    echo   Guided setup: run recollect with no parameters and Windows will ask for permission.
    echo.
    exit /b 1
)
echo.
echo   Recollect needs administrator rights. Windows will ask for permission;
echo   the collection then opens in a new window.
set "COLLECT_SELF=%~f0"
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath $env:COLLECT_SELF -ArgumentList '/elevated' -Verb RunAs -ErrorAction Stop } catch { exit 1 }"
if errorlevel 1 (
    echo.
    echo   Administrator permission was not given. Nothing was collected.
    echo.
    exit /b 1
)
exit /b 0

:elevated
rem The new elevated window opened by guided setup: keep it open at the end so the summary can be read.
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%COLLECT_SCRIPT%"
set "RC=%errorlevel%"
echo.
pause
exit /b %RC%

:usage
echo.
echo   Recollect - Windows DFIR triage collector
echo.
echo   GUIDED SETUP (recommended)
echo     recollect
echo       Answers a few questions (case ID, profile, memory, output folder,
echo       options), shows a summary, then collects. Asks Windows for
echo       administrator rights if needed.
echo.
echo   MANUAL MODE (parameters, for experienced users and scripts)
echo     Run from a terminal opened with "Run as administrator":
echo     recollect -CaseId IR-2026-001 -CollectionProfile Standard
echo     recollect -CaseId IR-2026-001 -CollectionProfile Full -Memory -OutputPath X:\Collections
echo     recollect -CaseId IR-2026-001 -CollectionProfile MemoryOnly
echo     recollect -CaseId IR-2026-001 -CollectionProfile Deep -NonInteractive -AcceptLicense
echo.
echo   Profiles: Quick, Standard, Deep, Full, MemoryOnly.
echo   Every parameter is described in docs\USER_GUIDE.md, section 5.
echo   In PowerShell, type .\recollect (PowerShell does not run files from the
echo   current folder without .\).
echo.
exit /b 0
