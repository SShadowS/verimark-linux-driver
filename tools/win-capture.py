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


def is_system():
    r"""True if we're running as the SYSTEM account (S-1-5-18).

    Spawn-gating injects into a freshly-spawned WUDFHost that runs as LOCAL SERVICE
    in Session 0. A plain elevated (admin) token usually still injects here thanks to
    SeDebugPrivilege (the existing attach path proves it works on this box), but if
    gating silently misses the service-launched host, re-run as SYSTEM via
    `psexec -s -i python tools\win-capture.py --spawn-gate`.
    """
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
            capture_output=True, text=True,
        ).stdout.strip()
        return out == "S-1-5-18"
    except Exception:
        return False


def prepare_agent_tmp():
    r"""Relocate the frida-agent drop dir so a LOCAL SERVICE target can load it.

    Frida injects by writing frida-agent-<arch>.dll into %TEMP% and having the
    target LoadLibrary it. Our %TEMP% is C:\Users\<me>\AppData\Local\Temp, which
    the biometric WUDFHost (running as LOCAL SERVICE, S-1-5-19) cannot read - so
    injection dies with 'refused to load frida-agent'. That, NOT Core Isolation,
    is the usual blocker on this box.

    Fix: point TMP/TEMP at a dir the service accounts can read+execute. We grant
    RX (inheritable) to LOCAL SERVICE and NETWORK SERVICE and Full only to
    Administrators - no standard-user write, so nobody can plant a DLL that a
    privileged host would load. Must run before `import frida` (GLib caches the
    tmp dir on first use).
    """
    d = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "verimark-frida")
    os.makedirs(d, exist_ok=True)
    acls = [
        ["icacls", d, "/inheritance:r"],
        ["icacls", d, "/grant", "*S-1-5-32-544:(OI)(CI)F"],   # Administrators: full
        ["icacls", d, "/grant", "*S-1-5-19:(OI)(CI)(RX)"],    # LOCAL SERVICE: read+exec
        ["icacls", d, "/grant", "*S-1-5-20:(OI)(CI)(RX)"],    # NETWORK SERVICE: read+exec
    ]
    for cmd in acls:
        subprocess.run(cmd, capture_output=True, text=True)
    for var in ("TMP", "TEMP", "TMPDIR"):
        os.environ[var] = d
    return d


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


def make_on_message(emit, installed, tag=""):
    """Build a frida script message handler. `installed['n']` counts 'hooked ' lines
    across all scripts; `tag` prefixes lines so spawn-gate can tell hosts apart."""
    pfx = ("[%s] " % tag) if tag else ""

    def on_message(msg, data):
        t = msg.get("type")
        if t == "send":
            text = msg.get("payload")
            if isinstance(text, str):
                if text.startswith("hooked "):
                    installed["n"] += 1
                emit(pfx + text)
            else:
                emit(pfx + "[send] " + str(text))
        elif t == "log":
            text = msg.get("payload", "")
            if text.startswith("hooked "):
                installed["n"] += 1
            emit(pfx + text)
        elif t == "error":
            emit(pfx + "[frida-error] " + str(msg.get("stack") or msg))

    return on_message


def run_early_attach(args, frida, hook_src, emit, logf, installed):
    r"""Best-effort t=0 capture WITHOUT spawn-gating (which frida does NOT support on
    Windows: `enable_spawn_gating` -> "not yet supported on this OS", verified on
    frida 17.15.3). Instead we poll `enumerate_processes` on a tight loop and attach to
    every WUDFHost the instant it appears, existing and freshly-spawned.

    Why this shape: the provisioning/ownership handshake runs once at driver-LOAD init
    in a *freshly spawned* host. A one-shot `frida.attach(pid)` is always one process
    behind — the replug that triggers init also kills the attached PID (that is why the
    earlier --pairing run logged zero crypto). Polling re-attaches to the NEW host as
    fast as inject latency allows; the self-selecting hook installs its LdrLoadDll
    watcher on landing, so it arms as soon as synaWudfBioUsb + bcrypt map in.

    NOT a hard guarantee: if the driver finishes all its crypto within ~inject-latency
    (~100-300ms) of the host spawning, we still miss it. If the selftest shows misses,
    the deterministic fallback is IFEO `Debugger` -> a relauncher that frida-`spawn()`s
    WUDFHost (spawn IS supported on Windows) + frida-gadget; see findings notes.

    No process is ever suspended here, so there is zero risk of freezing the box.
    """
    import threading

    device = frida.get_local_device()
    sessions = {}
    seen = {"pids": set(), "bio": False}
    stop = threading.Event()
    lock = threading.Lock()

    def attach_pid(pid):
        try:
            emit("[early] WUDFHost pid=%d appeared — attaching ASAP" % pid)
            s = device.attach(pid)
            scr = s.create_script(hook_src)
            base = make_on_message(emit, installed, tag="pid%d" % pid)

            def wrap(msg, data, _base=base):
                p = msg.get("payload")
                if isinstance(p, str) and "BIOMETRIC-HOST" in p:
                    seen["bio"] = True
                _base(msg, data)

            scr.on("message", wrap)
            scr.load()   # installs the LdrLoadDll self-select watcher immediately
            sessions[pid] = s
        except Exception as e:
            emit("[early] pid=%d attach failed: %s" % (pid, e))

    def poller():
        while not stop.is_set():
            try:
                for p in device.enumerate_processes():
                    if p.name and p.name.lower() == "wudfhost.exe":
                        with lock:
                            fresh = p.pid not in seen["pids"]
                            if fresh:
                                seen["pids"].add(p.pid)
                        if fresh:
                            attach_pid(p.pid)
            except Exception:
                pass
            stop.wait(0.015)   # ~15ms poll; dominant latency is frida inject, not this

    tag = time.strftime("%Y%m%d-%H%M%S")
    alive = []
    th = threading.Thread(target=poller, daemon=True)
    try:
        th.start()
        emit("[*] early-attach poller running (attaching to every WUDFHost as it appears).")

        if not args.no_usb:
            cmd = find_usbpcap()
            if cmd:
                emit("[*] Starting USBPcap wire capture...")
                alive = start_usbpcap(cmd, tag)
            else:
                emit("[!] USBPcapCMD.exe not found - key/plaintext only.")

        emit("")
        emit("  ==================================================================")
        if args.early_selftest:
            emit("  EARLY-ATTACH SELFTEST — no enroll needed. Do this:")
            emit("   1. Trigger a fresh driver load: UNPLUG the VeriMark, wait 3s,")
            emit("      PLUG it back in  (or Device Manager > VeriMark > Disable/Enable).")
            emit("   2. Watch for '[early] WUDFHost pid=... attaching' then a")
            emit("      'BIOMETRIC-HOST ... arming' line — that means we re-attached to the")
            emit("      fresh host and self-selected the biometric one before/at its crypto.")
            emit("      If CNG lines (symKeySecret/PLAINTEXT) appear too, we caught init.")
            emit("   Press ENTER once you've replugged and watched the lines.")
        else:
            emit("  T=0 PAIRING CAPTURE — capture is RUNNING (polling for the fresh host). Do this:")
            emit("   1. You should have ALREADY run win-unpair-verimark.ps1 (no stored pairing).")
            emit("   2. Trigger a FRESH driver load so provisioning runs ON CAMERA:")
            emit("        UNPLUG the VeriMark, wait 3s, PLUG it back in.")
            emit("      The poller re-attaches to the NEW WUDFHost as fast as it can.")
            emit("   3. Settings > Accounts > Sign-in options > Fingerprint > Set up, enroll.")
            emit("   4. Look for 'BIOMETRIC-HOST ... arming' + symKeySecret/PLAINTEXT lines.")
            emit("   Keep this window open the WHOLE time. Press ENTER when fully done.")
        emit("  ==================================================================")
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            pass
    finally:
        stop.set()
        th.join(timeout=2)
        stop_usbpcap(alive)
        for pid, s in list(sessions.items()):
            try:
                s.detach()
            except Exception:
                pass

    emit("")
    emit("[*] Early-attach summary: WUDFHosts attached=%d, biometric self-select=%s, "
         "total CNG hooks armed=%d" % (len(sessions), seen["bio"], installed["n"]))
    if args.early_selftest:
        ok = seen["bio"] and installed["n"] > 0
        emit("[selftest] %s — %s" % (
            "OK" if ok else "FAILED",
            "re-attached to the biometric host and armed hooks on replug" if ok else
            "did NOT arm; if attached=0 the poller couldn't inject (try SYSTEM via "
            "psexec -s -i); if attached>0 but no BIOMETRIC-HOST, the driver didn't load "
            "synaWudfBioUsb (replug didn't respawn) or init finished before inject"))
        return 0 if ok else 1

    emit("[*] Artifacts in captures\\:")
    for n, out_path, p in alive:
        try:
            sz = os.path.getsize(out_path)
        except OSError:
            sz = 0
        emit("      %s   (%d bytes)" % (os.path.basename(out_path), sz))
    emit("[*] If no symKeySecret/PLAINTEXT lines appeared, inject lost the race — see the")
    emit("    IFEO+frida-gadget fallback in the function docstring.")
    emit("[*] Copy captures\\ back to Linux, then:")
    emit("      ./tools/extract-usb-payloads.py captures/win-usb-*.pcap --min-len 8")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=int, help="force a specific WUDFHost PID")
    ap.add_argument("--selftest", action="store_true",
                    help="attach, confirm hooks install, then detach (no enroll needed)")
    ap.add_argument("--no-usb", action="store_true", help="skip USBPcap; frida hook only")
    ap.add_argument("--pairing", action="store_true",
                    help="pairing-capture mode: on-screen steps for a FRESH pairing "
                         "(run win-unpair-verimark.ps1 first, then replug to trigger 0x93)")
    ap.add_argument("--early-attach", action="store_true",
                    help="best-effort t=0 capture for the driver-LOAD provisioning/ownership "
                         "crypto: poll and re-attach to the WUDFHost the instant it (re)spawns "
                         "on replug, instead of a one-shot attach that the respawn orphans. "
                         "(frida spawn-gating is unsupported on Windows.) Use for pairing/ownership.")
    ap.add_argument("--early-selftest", action="store_true",
                    help="validate early-attach: replug once, confirm we re-attach to the fresh "
                         "biometric host and arm hooks — no enroll needed.")
    ap.add_argument("--out", help="frida log path (default: captures/win-cng-<pid>.log)")
    args = ap.parse_args()

    if not is_admin():
        print("[!] Not elevated. Attaching WUDFHost and USBPcap need admin.\n"
              "    Easiest: run tools\\capture.bat (it self-elevates), or open an\n"
              "    'Administrator: PowerShell' and re-run this.")
        return 2

    agent_tmp = prepare_agent_tmp()
    print(f"[*] frida-agent tmp: {agent_tmp} (RX granted to LOCAL/NETWORK SERVICE so "
          f"the biometric WUDFHost can load it)")

    try:
        import frida
    except ImportError:
        sys.exit("frida not installed. Run: python -m pip install frida-tools")

    os.makedirs(CAPDIR, exist_ok=True)

    # --- early-attach / selftest: poll+attach the (re)spawned host, no pre-existing PID ---
    if args.early_attach or args.early_selftest:
        tag = time.strftime("%Y%m%d-%H%M%S")
        logpath = args.out or os.path.join(CAPDIR, f"win-cng-early-{tag}.log")
        logf = open(logpath, "a", encoding="utf-8", buffering=1)

        def emit(line):
            print(line)
            logf.write(line + "\n")

        installed = {"n": 0}
        with open(HOOK, "r", encoding="utf-8") as f:
            hook_src = f.read()
        if not is_system():
            emit("[!] Not SYSTEM. Attaching a Session-0 LOCAL SERVICE host usually still "
                 "works from an admin token (SeDebugPrivilege), but if 'attached=0', "
                 "re-run via:  psexec -s -i python tools\\win-capture.py " +
                 ("--early-selftest" if args.early_selftest else "--early-attach"))
        emit(f"=== win-capture early-attach ===  log={logpath}")
        try:
            rc = run_early_attach(args, frida, hook_src, emit, logf, installed)
        finally:
            logf.close()
        return rc

    pid = resolve_pid(args.pid)
    logpath = args.out or os.path.join(CAPDIR, f"win-cng-{pid}.log")
    logf = open(logpath, "a", encoding="utf-8", buffering=1)

    def emit(line):
        print(line)
        logf.write(line + "\n")

    installed = {"n": 0}
    on_message = make_on_message(emit, installed)

    # --- attach (this is the step that fails on VBS/protected-host machines) ---
    emit(f"=== win-capture attaching to PID {pid} ===  log={logpath}")
    try:
        session = frida.attach(pid)
        with open(HOOK, "r", encoding="utf-8") as f:
            script = session.create_script(f.read())
        script.on("message", on_message)
        script.load()
    except frida.ProcessNotRespondingError as e:
        emit(f"[X] Frida could not inject the biometric WUDFHost (PID {pid}): {e}")
        emit("    Ranked likely causes (agent-tmp perms already handled above):")
        emit("    1) HVCI / 'Memory integrity' ON - blocks the unsigned agent load.")
        emit("       Check: Windows Security > Device security > Core isolation.")
        emit("       Verify: powershell \"(Get-CimInstance -Namespace root/Microsoft/Windows/"
             "DeviceGuard Win32_DeviceGuard).SecurityServicesRunning\"  (a '2' means HVCI is on).")
        emit("    2) Target is a Protected Process (PPL) - injection is impossible; pick the")
        emit("       right WUDFHost with --pid (the umdf\\synawudfbiousb one, not 06cb:0126).")
        emit("    3) AV/EDR blocking CreateRemoteThread/LoadLibrary in the host.")
        emit("    (Agent-load perms for the LOCAL SERVICE host are pre-fixed via prepare_agent_tmp;")
        emit("     if you still see 'refused to load frida-agent', it's #1 above.)")
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
    if args.pairing:
        emit("  PAIRING CAPTURE MODE - the capture is now RUNNING. Do this, in order:")
        emit("   1. You should have ALREADY run win-unpair-verimark.ps1 (no stored pairing).")
        emit("   2. NOW trigger a fresh device init so 0x93 pairing happens ON CAMERA:")
        emit("        - UNPLUG the VeriMark, wait 3s, PLUG it back in.   (best)")
        emit("        - or: Device Manager > the VeriMark > Disable then Enable.")
        emit("   3. Settings > Accounts > Sign-in options > Fingerprint > Set up,")
        emit("      and enroll a finger. The FIRST setup after unpair re-runs pairing +")
        emit("      the host-authorization we need. Swipe until enrolled.")
        emit("   4. (optional) remove + verify once to catch steady-state too.")
        emit("   Keep this window open the WHOLE time - pairing fires on replug/first-init,")
        emit("   which is why capture is started BEFORE you replug.")
        emit("  When fully done, come back here and press ENTER to stop and save.")
    else:
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
