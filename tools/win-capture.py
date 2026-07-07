#!/usr/bin/env python3
r"""win-capture.py - one-command VeriMark working-session capture (Windows only).

Does the whole capture in one shot:
  1. finds the VeriMark WUDFHost and confirms Frida can inject it (pre-check),
  2. starts USBPcap capturing the wire bytes (all root hubs, filtered later on Linux),
  3. attaches the CNG hook that dumps the TLS session key + plaintext protocol,
  4. waits while you enroll + verify a finger, then stops everything and lists artifacts.

Run it ELEVATED (admin) - attaching WUDFHost and USBPcap both need it. Easiest is to
double-click tools\capture.bat (it self-elevates). Or:

    python tools\win-capture.py                 # full capture (frida + USBPcap)
    python tools\win-capture.py --selftest      # just confirm injection works (no finger)
    python tools\win-capture.py --no-usb        # frida key/plaintext only, skip USBPcap
    python tools\win-capture.py --pid 16844     # force a specific WUDFHost PID

The VeriMark (047d:00f2) biometric interface is driven by synaWudfBioUsb, hosted in one
of several WUDFHost.exe instances. We auto-pick the one whose module lives under
...\drivers\umdf\ (the oem90/synawudfbiousb.inf package) so we don't grab the *built-in*
laptop reader (06cb:0126), which uses the UWP package.
"""
import argparse
import ctypes
import glob
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(ROOT, "tools", "frida-hook-cng.js")
CAPDIR = os.path.join(ROOT, "captures")

_PS_FIND = r"""
Get-Process WUDFHost -ErrorAction SilentlyContinue | ForEach-Object {
  $p = $_
  try {
    $p.Modules | Where-Object { $_.ModuleName -match 'synawudfbiousb' } |
      ForEach-Object { '{0}|{1}' -f $p.Id, $_.FileName }
  } catch {}
}
"""

USBPCAP_CANDIDATES = [
    r"C:\Program Files\USBPcap\USBPcapCMD.exe",
    r"C:\Program Files (x86)\USBPcap\USBPcapCMD.exe",
]


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


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
    verimark = [(p, path) for (p, path) in cands if "\\umdf\\" in path.lower()]
    return verimark, cands


def resolve_pid(forced):
    if forced:
        return forced
    verimark, cands = find_pids()
    if not cands:
        sys.exit("No WUDFHost is hosting synaWudfBioUsb. Is the VeriMark plugged in and "
                 "the Synaptics driver loaded?")
    if len(verimark) == 1:
        print(f"[*] VeriMark WUDFHost PID {verimark[0][0]}  ({verimark[0][1]})")
        return verimark[0][0]
    print("[!] Could not uniquely identify the VeriMark WUDFHost. Candidates:")
    for pid, path in cands:
        print(f"      PID {pid}: {path}")
    sys.exit("Re-run with --pid <PID> (the external dongle's synawudfbiousb, not the "
             "built-in 06cb:0126 reader).")


def find_usbpcap():
    for c in USBPCAP_CANDIDATES:
        if os.path.exists(c):
            return c
    return None


def start_usbpcap(cmd, tag):
    r"""Shotgun-start a capture on every real USBPcap root hub (\\.\USBPcap1..8).

    We don't identify which hub the dongle is on - we capture them all and filter
    to 047d:00f2 later with tools/extract-usb-payloads.py. Invalid control devices
    make USBPcapCMD exit immediately, so we keep only the ones still alive.
    """
    procs = []
    for n in range(1, 9):
        dev = rf"\\.\USBPcap{n}"
        out = os.path.join(CAPDIR, f"win-usb-{tag}-hub{n}.pcap")
        try:
            p = subprocess.Popen(
                [cmd, "-d", dev, "-o", out, "-A"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            procs.append((n, out, p))
        except Exception as e:
            print(f"    (USBPcap{n} launch failed: {e})")
    time.sleep(1.5)
    alive = []
    for n, out, p in procs:
        if p.poll() is None:
            alive.append((n, out, p))
            print(f"    capturing \\.\\USBPcap{n} -> {os.path.basename(out)}")
        else:
            try:
                os.remove(out)
            except OSError:
                pass
    if not alive:
        print("    [!] No USBPcap root hubs captured. Is USBPcap installed / are you elevated?")
    return alive


def stop_usbpcap(alive):
    for n, out, p in alive:
        try:
            p.terminate()
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=int, help="force a specific WUDFHost PID")
    ap.add_argument("--selftest", action="store_true",
                    help="attach, confirm hooks install, then detach (no enroll needed)")
    ap.add_argument("--no-usb", action="store_true", help="skip USBPcap; frida hook only")
    ap.add_argument("--out", help="frida log path (default: captures/win-cng-<pid>.log)")
    args = ap.parse_args()

    if not is_admin():
        print("[!] Not elevated. Attaching WUDFHost and USBPcap need admin.\n"
              "    Easiest: run tools\\capture.bat (it self-elevates), or open an\n"
              "    'Administrator: PowerShell' and re-run this.")
        return 2

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

    # --- attach (this is the step that fails on VBS/protected-host machines) ---
    emit(f"=== win-capture attaching to PID {pid} ===  log={logpath}")
    try:
        session = frida.attach(pid)
        with open(HOOK, "r", encoding="utf-8") as f:
            script = session.create_script(f.read())
        script.on("message", on_message)
        script.load()
    except frida.ProcessNotRespondingError:
        emit("[X] Frida could not inject the biometric WUDFHost.")
        emit("    This box protects the fingerprint host (Core Isolation / VBS is ON).")
        emit("    FIX: Windows Security > Device security > Core isolation >")
        emit("         turn OFF 'Memory integrity', reboot, and re-run.")
        emit("    (Turning off antivirus does NOT help - it's Core Isolation that blocks this.)")
        logf.close()
        return 3

    if args.selftest:
        time.sleep(1.5)
        ok = installed["n"] > 0
        emit(f"[selftest] {installed['n']} hooks installed -> {'OK' if ok else 'FAILED'}")
        session.detach()
        logf.close()
        return 0 if ok else 1

    emit(f"[+] Injection OK ({installed['n']} CNG hooks live).")

    # --- USBPcap wire capture ---
    tag = time.strftime("%Y%m%d-%H%M%S")
    alive = []
    if not args.no_usb:
        cmd = find_usbpcap()
        if cmd:
            emit("[*] Starting USBPcap wire capture...")
            alive = start_usbpcap(cmd, tag)
        else:
            emit("[!] USBPcapCMD.exe not found - capturing key/plaintext only "
                 "(install USBPcap for the wire bytes).")

    emit("")
    emit("  ==================================================================")
    emit("  NOW: enroll and then verify a finger.")
    emit("   - Settings > Accounts > Sign-in options > Fingerprint recognition")
    emit("   - Add / set up, swipe to enroll, then remove+verify a few times.")
    emit("  When done, come back here and press ENTER to stop and save.")
    emit("  ==================================================================")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass

    stop_usbpcap(alive)
    try:
        session.detach()
    except Exception:
        pass

    emit("")
    emit("[*] Done. Artifacts in captures\\:")
    emit(f"      {os.path.basename(logpath)}   (session key: symKeySecret/derivedKey; "
         f"plaintext: PLAINTEXT-OUT/-IN)")
    for n, out, p in alive:
        try:
            sz = os.path.getsize(out)
        except OSError:
            sz = 0
        emit(f"      {os.path.basename(out)}   ({sz:,} bytes)")
    emit("[*] Copy the captures\\ folder back to Linux, then:")
    emit("      ./tools/extract-usb-payloads.py captures/win-usb-*.pcap --min-len 8")
    logf.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
