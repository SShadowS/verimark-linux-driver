@echo off
REM One-click PAIRING capture. Run tools\win-unpair-verimark.ps1 FIRST (removes stored
REM pairing), then double-click THIS. It starts USBPcap + the Frida CNG hook, then tells
REM you to replug the reader and run fingerprint "Set up" so the 0x93 pairing + host
REM authorization is recorded. Self-elevates via capture.bat.
setlocal
cd /d "%~dp0"
call capture.bat --pairing
