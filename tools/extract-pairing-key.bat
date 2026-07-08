@echo off
REM Recover the Windows OWNER host-pairing key (DPAPI) so Linux can present the owner
REM identity. Self-elevates (needs admin to run the LOCAL SERVICE decrypt task + ACL the
REM work dir). Output: C:\ProgramData\verimark-extract\pairing-fields.json  (holds the OWNER
REM private key - keep it out of git; move/delete after copying to Linux). See findings/42.
setlocal

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0' %*"
    exit /b
)

cd /d "%~dp0.."

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] python not found on PATH. Install Python 3.
    pause
    exit /b 1
)

python tools\extract-pairing-key.py %*
echo.
pause
