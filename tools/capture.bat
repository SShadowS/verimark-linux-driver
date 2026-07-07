@echo off
REM One-click VeriMark capture. Double-click this, approve the UAC prompt, then
REM follow the on-screen steps (enroll + verify a finger). Self-elevates to admin.
setlocal

REM --- self-elevate if not already admin ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0' %*"
    exit /b
)

cd /d "%~dp0.."

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [X] python not found on PATH. Install Python 3 and 'pip install frida-tools'.
    pause
    exit /b 1
)

REM ensure frida is importable; install on first run if missing
python -c "import frida" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installing frida-tools ^(first run only^)...
    python -m pip install --quiet frida-tools
)

python tools\win-capture.py %*
echo.
pause
