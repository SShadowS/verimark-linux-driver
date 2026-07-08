#!/usr/bin/env python3
r"""extract-pairing-key.py - recover the Windows OWNER host-pairing key (Windows only).

Why: the VeriMark sensor is single-owner; Windows owns it. A Linux host that pairs second is a
non-owner (cert_type=2) and gets 0x0405 on MOC enroll/verify. But the owner identity is just the
host EC keypair (no TPM - findings/DECISION), which Windows persists DPAPI-wrapped in the registry.
If we decrypt it and load it into rev's SensorPairingData on Linux, Linux presents the OWNER key and
gets an authorized (cert_type=0) session. Non-destructive; Windows Hello keeps working.

The DPAPI blob is user-scoped under NT AUTHORITY\LOCAL SERVICE (S-1-5-19), NO optional entropy, NO
local-machine flag (findings/42). So the decrypt must run *as* LOCAL SERVICE. We do that with a
one-shot scheduled task that runs POWERSHELL (system-wide, unlike a per-user python) executing a
decrypt script staged in C:\ProgramData (LOCAL SERVICE-readable). Requires admin.

    tools\extract-pairing-key.bat            # self-elevates, runs this

Output: C:\ProgramData\verimark-extract\ -> plain.bin (decrypted TagVal) + pairing-fields.json
(the TLV entries: tag/len/hex). Copy pairing-fields.json to Linux; findings/42 step 5 reformats it
into rev's .pdata (68 priv | 400 host_cert | 400 sensor_cert) for the enroll test.
"""
import ctypes
import json
import os
import re
import subprocess
import sys
import time

WORKDIR = r"C:\ProgramData\verimark-extract"
SENSOR_ID = "F7007AD929C60000"
DPAPI_MAGIC = bytes.fromhex("01000000d08c9ddf0115d1118c7a00c04fc297eb")  # blob[16:] must start here
BACKUP_REG = os.path.join(os.environ.get("USERPROFILE", r"C:\Users\Default"),
                          "Desktop", "verimark-unpair-backup",
                          "HKEY_USERS_S-1-5-19_Software_Synaptics_PairingData.reg")
TASK = "VeriMarkExtractKey"
PWSH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

# Decrypt script run AS LOCAL SERVICE by the scheduled task. Prefers the LIVE current owner key
# from LOCAL SERVICE's own HKCU; falls back to the staged backup blob (dpapi.bin).
PS_DECRYPT = r'''
$ErrorActionPreference = 'Stop'
$work = 'C:\ProgramData\verimark-extract'
$out  = Join-Path $work 'plain.bin'
$err  = Join-Path $work 'plain.bin.err'
$srcf = Join-Path $work 'plain.bin.src'
try {
  Add-Type -AssemblyName System.Security
  $sid = 'F7007AD929C60000'
  $dpapi = $null; $src = 'backup-file'
  try {
    $v = (Get-ItemProperty -Path 'HKCU:\Software\Synaptics\PairingData' -Name $sid -ErrorAction Stop).$sid
    if ($v -and $v.Length -gt 24) {
      $magic = [byte[]](0x01,0x00,0x00,0x00,0xd0,0x8c,0x9d,0xdf)
      $ok = $true; for ($i=0; $i -lt 8; $i++) { if ($v[16+$i] -ne $magic[$i]) { $ok=$false; break } }
      if ($ok) { $dpapi = $v[16..($v.Length-1)]; $src = 'live-registry' }
    }
  } catch { }
  if ($null -eq $dpapi) { $dpapi = [IO.File]::ReadAllBytes((Join-Path $work 'dpapi.bin')) }
  $plain = [Security.Cryptography.ProtectedData]::Unprotect($dpapi, $null, 'CurrentUser')
  [IO.File]::WriteAllBytes($out, $plain)
  Set-Content -Path $srcf -Value $src -NoNewline
} catch {
  Set-Content -Path $err -Value $_.Exception.Message -NoNewline
}
'''


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def blob_from_reg(path: str) -> bytes:
    """Parse the .reg export: value "F7007AD929C60000"=hex:01,00,.. with '\\' continuations."""
    raw = open(path, "rb").read()
    text = raw.decode("utf-16-le", "ignore") if raw[:2] == b"\xff\xfe" else raw.decode("utf-8", "ignore")
    text = text.replace("\r", "")
    m = re.search(r'"%s"\s*=\s*hex[^:]*:(.*?)(?=\n[^ \t]|\Z)' % SENSOR_ID, text, re.S | re.I)
    if not m:
        raise SystemExit("value %s not found in %s" % (SENSOR_ID, path))
    return bytes(int(h, 16) for h in re.findall(r"[0-9a-fA-F]{2}", m.group(1)))


def strip_header(value: bytes) -> bytes:
    dpapi = value[16:]
    if dpapi[:len(DPAPI_MAGIC)] != DPAPI_MAGIC:
        raise SystemExit("blob[16:] does not start with the DPAPI magic (got %s) - header size wrong?"
                         % dpapi[:20].hex())
    return dpapi


def parse_tagval(plain: bytes):
    """TagVal TLV: [tag u16 BE][len u32 BE][data] * N."""
    entries, i = [], 0
    while i + 6 <= len(plain):
        tag = int.from_bytes(plain[i:i + 2], "big")
        ln = int.from_bytes(plain[i + 2:i + 6], "big")
        if ln > len(plain) - (i + 6):
            break
        entries.append({"tag": tag, "len": ln, "hex": plain[i + 6:i + 6 + ln].hex()})
        i += 6 + ln
    return entries


def sc(*args):
    return subprocess.run(list(args), capture_output=True, text=True)


def main():
    if not is_admin():
        sys.exit("[!] Not elevated. Run tools\\extract-pairing-key.bat (self-elevates).")

    os.makedirs(WORKDIR, exist_ok=True)
    sc("icacls", WORKDIR, "/grant", "*S-1-5-19:(OI)(CI)M")  # LOCAL SERVICE read+write

    if not os.path.exists(BACKUP_REG):
        sys.exit("[!] backup .reg not found: %s\n    Run tools\\win-unpair-verimark.ps1 once (it "
                 "exports PairingData) - though the LIVE registry is preferred if present." % BACKUP_REG)
    value = blob_from_reg(BACKUP_REG)
    print("[*] PairingData value: %d bytes" % len(value))
    dpapi = strip_header(value)

    inb = os.path.join(WORKDIR, "dpapi.bin")
    outb = os.path.join(WORKDIR, "plain.bin")
    ps = os.path.join(WORKDIR, "decrypt.ps1")
    for stale in (outb, outb + ".err", outb + ".src"):
        try:
            os.remove(stale)
        except OSError:
            pass
    open(inb, "wb").write(dpapi)
    open(ps, "w", encoding="utf-8").write(PS_DECRYPT)
    sc("icacls", WORKDIR, "/grant", "*S-1-5-19:(OI)(CI)M")  # re-apply so new files inherit
    print("[*] DPAPI blob (%d B) + decrypt.ps1 staged in %s" % (len(dpapi), WORKDIR))

    # decrypt AS LOCAL SERVICE via a one-shot task running system-wide PowerShell
    cmd = '"%s" -NoProfile -ExecutionPolicy Bypass -File "%s"' % (PWSH, ps)
    sc("schtasks", "/create", "/tn", TASK, "/tr", cmd, "/sc", "once", "/st", "23:59",
       "/ru", "LOCAL SERVICE", "/rl", "LIMITED", "/f")
    sc("schtasks", "/run", "/tn", TASK)
    print("[*] decrypt task running as LOCAL SERVICE; waiting...")

    plain = None
    for _ in range(60):
        if os.path.exists(outb):
            plain = open(outb, "rb").read()
            break
        if os.path.exists(outb + ".err"):
            err = open(outb + ".err", encoding="utf-8").read()
            sc("schtasks", "/delete", "/tn", TASK, "/f")
            sys.exit("[X] decrypt (LOCAL SERVICE) failed: %s" % err)
        time.sleep(0.5)

    if plain is None:
        info = sc("schtasks", "/query", "/tn", TASK, "/v", "/fo", "LIST").stdout
        last = "\n".join(l for l in info.splitlines() if "Result" in l or "Last Run" in l)
        sc("schtasks", "/delete", "/tn", TASK, "/f")
        sys.exit("[X] timed out (no plain.bin/.err). Task status:\n%s\n"
                 "    A non-zero 'Last Result' means PowerShell couldn't run the script." % last)
    sc("schtasks", "/delete", "/tn", TASK, "/f")

    src = "backup-file"
    try:
        src = open(outb + ".src", encoding="utf-8").read().strip() or src
    except OSError:
        pass
    print("[+] decrypted plaintext: %d bytes (owner key source: %s)" % (len(plain), src))

    entries = parse_tagval(plain)
    fields = os.path.join(WORKDIR, "pairing-fields.json")
    with open(fields, "w", encoding="utf-8") as f:
        json.dump({"sensor_id": SENSOR_ID, "plain_len": len(plain), "entries": entries}, f, indent=2)
    print("[+] %d TagVal entries -> %s" % (len(entries), fields))
    for e in entries:
        note = "  <- 400-B cert (host or sensor)" if e["len"] == 400 else (
               "  <- ~68-B EC private key?" if 60 <= e["len"] <= 80 else "")
        print("    tag=0x%04x len=%-4d%s" % (e["tag"], e["len"], note))
    print("\n[*] Next: copy %s to Linux; findings/42 step 5 reformats -> rev .pdata, retry 0x96/0x99." % fields)
    print("[*] SECURITY: plain.bin / pairing-fields.json hold the OWNER PRIVATE KEY. Outside the repo,\n"
          "    never committed - move to Linux securely and delete the Windows copies after.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
