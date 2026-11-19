@echo off
rem RecoveryKit launcher. Pure cmd.exe: works in WinRE, WinPE and Shift+F10 (no PowerShell needed).
rem
rem Usage in WinRE / Windows Setup:
rem   1. Boot the broken PC into WinRE: Troubleshoot > Advanced options > Command Prompt
rem      (or press Shift+F10 in Windows Setup).
rem   2. Find the USB letter. It is NOT fixed. Try:  dir D:\ITWORK   then  dir E:\ITWORK  ...
rem      or run  diskpart  then  list volume  then  exit.
rem   3. Run  LETTER:\ITWORK\RecoveryKit\run.cmd   (extra switches are passed on, e.g. --scan).
rem
rem Everything is relative to this file; the USB letter is never assumed.
rem Python: python\python.exe next to this file; else py -3; else python on PATH.
setlocal
cd /d "%~dp0"

if /i not "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    echo RecoveryKit runs on 64-bit Windows only. Detected: %PROCESSOR_ARCHITECTURE%
    exit /b 1
)

rem No .pyc files on the USB.
set PYTHONDONTWRITEBYTECODE=1

if exist "%~dp0python\python.exe" goto bundled
goto trypy

:bundled
echo Using bundled Python: %~dp0python\python.exe
"%~dp0python\python.exe" -m recoverykit %*
exit /b %ERRORLEVEL%

:trypy
py -3 --version >nul 2>&1
if errorlevel 1 goto trypython
echo Bundled Python not found, using: py -3
py -3 -m recoverykit %*
exit /b %ERRORLEVEL%

:trypython
python --version >nul 2>&1
if errorlevel 1 goto nopython
echo Bundled Python not found, using: python
python -m recoverykit %*
exit /b %ERRORLEVEL%

:nopython
echo No Python found.
echo The bundled python folder is missing from this kit. On a normal Windows PC run
echo   Install-ToUsb.ps1
echo from the RecoveryKit project folder to copy the kit with its Python to the USB.
exit /b 1
