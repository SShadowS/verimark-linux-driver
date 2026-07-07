#!/usr/bin/env python3
"""win-capture.py - attach Frida to the VeriMark WUDFHost and dump CNG key
material + plaintext protocol during an enroll/verify session (Windows only).

Pairs with tools/frida-hook-cng.js. Run this ELEVATED (admin) - attaching to
WUDFHost.exe requires it.

    python tools/win-capture.py                 # attach, log until Ctrl-C, then enroll
    python tools/win-capture.py --selftest      # attach, confirm hooks install, detach (no finger)
    python tools/win-capture.py --pid 16844     # force a specific WUDFHost PID

The VeriMark (047d:00f2) biometric interface is driven by synaWudfBioUsb, hosted
in one of several WUDFHost.exe instances. We auto-pick the instance whose module
lives under ...\\drivers\\umdf\\ (the oem90/synawudfbiousb.inf package) to avoid
grabbing the *built-in* laptop reader (06cb:0126), which uses the UWP package.
"""
import argparse
import os
import subprocess
import sys
import time

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida-hook-cng.js")
CAPDIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "captures")

# PowerShell: list WUDFHost PIDs loading a synawudfbiousb*.dll, with the module path,
# so we can tell the external VeriMark (\drivers\umdf\) from the built-in (FileRepository).
_PS_FIND = r"""
Get-Process WUDFHost -ErrorAction SilentlyContinue | ForEach-Object {
  $p = $_
  try {
    $p.Modules | Where-Object { $_.ModuleName -match 'synawudfbiousb' } |
      ForEach-Object { '{0}|{1}' -f $p.Id, $_.FileName }
  } catch {}
}
"""


def find_pids():
    """Return (verimark_pids, all_candidates) as lists of (pid, path)."""
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command", _PS_FIND],
        capture_output=True, text=True,
    ).stdout
    cands = []
    for line in out.splitlines():
        line = line.strip()
        if "|" in line:
            pid, path = line.split("|", 1)
            cands.append((int(pid), path))
    # VeriMark = oem90 package, installed under \drivers\umdf\ ; built-in = FileRepository UWP pkg.
    verimark = [(p, path) for (p, path) in cands if "\\umdf\\" in path.lower()]
    return verimark, cands


def resolve_pid(forced):
    if forced:
        return forced
    verimark, cands = find_pids()
    if not cands:
        sys.exit("No WUDFHost is hosting synaWudfBioUsb. Is the VeriMark plugged in "
                 "and the Synaptics driver loaded?")
    if len(verimark) == 1:
        print(f"[*] VeriMark WUDFHost PID {verimark[0][0]}  ({verimark[0][1]})")
        return verimark[0][0]
    print("[!] Could not uniquely identify the VeriMark WUDFHost. Candidates:")
    for pid, path in cands:
        print(f"      PID {pid}: {path}")
    sys.exit("Re-run with --pid <PID> (pick the external dongle's synawudfbiousb, "
             "not the built-in 06cb:0126 reader).")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pid", type=int, help="force a specific WUDFHost PID")
    ap.add_argument("--selftest", action="store_true",
                    help="attach, confirm hooks install, then detach (no enroll needed)")
    ap.add_argument("--out", help="log file (default: captures/win-cng-<pid>.log)")
    args = ap.parse_args()

    try:
        import frida
    except ImportError:
        sys.exit("frida not installed. Run: python -m pip install frida-tools")

    pid = resolve_pid(args.pid)
    os.makedirs(CAPDIR, exist_ok=True)
    logpath = args.out or os.path.join(CAPDIR, f"win-cng-{pid}.log")
    logf = open(logpath, "a", encoding="utf-8", buffering=1)

    def emit(line):
        print(line)
        logf.write(line + "\n")

    installed = {"n": 0}

    def on_message(msg, data):
        if msg.get("type") == "send":
            emit("[send] " + str(msg["payload"]))
        elif msg.get("type") == "log":
            text = msg.get("payload", "")
            if text.startswith("hooked "):
                installed["n"] += 1
            emit(text)
        elif msg.get("type") == "error":
            emit("[frida-error] " + str(msg.get("stack") or msg))

    emit(f"=== win-capture attaching to PID {pid} ===  log={logpath}")
    session = frida.attach(pid)
    with open(HOOK, "r", encoding="utf-8") as f:
        script = session.create_script(f.read())
    script.on("message", on_message)
    script.load()

    if args.selftest:
        time.sleep(1.5)
        emit(f"[selftest] {installed['n']} hooks installed. Detaching.")
        session.detach()
        emit("[selftest] OK" if installed["n"] > 0 else "[selftest] FAILED - no hooks installed")
        logf.close()
        return 0 if installed["n"] > 0 else 1

    emit("[*] Hooks live. Now ENROLL and VERIFY a finger (Settings > Sign-in options "
         ">\n    Fingerprint recognition). Run USBPcap in parallel for the wire bytes.")
    emit("[*] Press Ctrl-C here when the session is done.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except Exception:
            pass
        emit("[*] Detached. Log saved to " + logpath)
        logf.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
