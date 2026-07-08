#!/usr/bin/env python3
r"""extract-pairing-key.py - recover the Windows OWNER host-pairing key (Windows only).

Why: the VeriMark sensor is single-owner; Windows owns it. A Linux host that pairs second is a
non-owner (cert_type=2) and gets 0x0405 on MOC enroll/verify. But the owner identity is just the
host EC keypair (no TPM - findings/DECISION), which Windows persists DPAPI-wrapped in the registry.
If we decrypt it and load it into rev's SensorPairingData on Linux, Linux presents the OWNER key and
gets an authorized (cert_type=0) session. Non-destructive; Windows Hello keeps working.

The DPAPI blob is user-scoped under NT AUTHORITY\LOCAL SERVICE (S-1-5-19) with NO optional entropy
and NO local-machine flag (findings/42). So the decrypt must run *as* LOCAL SERVICE - we do that via
a one-shot scheduled task. Requires admin (to create the task + ACL the work dir).

    tools\extract-pairing-key.bat            # self-elevates, runs 'orchestrate'
    python tools\extract-pairing-key.py      # orchestrate (needs admin)
    python tools\extract-pairing-key.py decrypt <in.bin> <out.bin>   # internal (run by the task)

Output: C:\ProgramData\verimark-extract\  ->  plain.bin (decrypted TagVal) + pairing-fields.json
(the 6 TLV entries: tag/len/hex). Copy pairing-fields.json to the Linux box; findings/42 step 5
reformats it into rev's .pdata (68 priv | 400 host_cert | 400 sensor_cert) for the enroll test.
"""
import ctypes
import ctypes.wintypes as wt
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


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> DATA_BLOB:
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def crypt_unprotect(data: bytes) -> bytes:
    """CryptUnprotectData(data, entropy=NULL, flags=0). Runs in the caller's account context."""
    inb, _keep = _blob(data)
    out = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(out))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


# ---- .reg parsing: value "F7007AD929C60000"=hex:01,00,.. with '\' line continuations ----
def blob_from_reg(path: str) -> bytes:
    raw = open(path, "rb").read()
    text = raw.decode("utf-16-le", "ignore") if raw[:2] == b"\xff\xfe" else raw.decode("utf-8", "ignore")
    text = text.replace("\r", "")
    m = re.search(r'"%s"\s*=\s*hex[^:]*:(.*?)(?=\n[^ \t]|\Z)' % SENSOR_ID, text, re.S | re.I)
    if not m:
        raise SystemExit("value %s not found in %s" % (SENSOR_ID, path))
    hexes = re.findall(r"[0-9a-fA-F]{2}", m.group(1))
    return bytes(int(h, 16) for h in hexes)


def strip_header(value: bytes) -> bytes:
    """Drop the 16-byte Synaptics wrapper; return the DPAPI blob (must start with DPAPI magic)."""
    dpapi = value[16:]
    if dpapi[:len(DPAPI_MAGIC)] != DPAPI_MAGIC:
        raise SystemExit("blob[16:] does not start with the DPAPI magic - header size wrong?\n"
                         "  got: " + dpapi[:20].hex())
    return dpapi


# ---- TagVal TLV: [tag u16 BE][len u32 BE][data] * N ----
def parse_tagval(plain: bytes):
    entries, i = [], 0
    while i + 6 <= len(plain):
        tag = int.from_bytes(plain[i:i + 2], "big")
        ln = int.from_bytes(plain[i + 2:i + 6], "big")
        if ln > len(plain) - (i + 6):
            break
        entries.append({"tag": tag, "len": ln, "hex": plain[i + 6:i + 6 + ln].hex()})
        i += 6 + ln
    return entries


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def grant_localservice(d: str):
    subprocess.run(["icacls", d, "/grant", "*S-1-5-19:(OI)(CI)M"], capture_output=True, text=True)


def do_decrypt(infile: str, outfile: str):
    """Runs as LOCAL SERVICE (via the scheduled task). Decrypts to outfile.

    Prefers the LIVE current owner key from LOCAL SERVICE's own HKCU (freshest, matches the
    current master key); falls back to the backup blob the orchestrator passed in `infile`.
    """
    errf = outfile + ".err"
    try:
        dpapi = None
        src = "backup-file"
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Synaptics\PairingData") as k:
                val = bytes(winreg.QueryValueEx(k, SENSOR_ID)[0])
            if len(val) > 16 and val[16:16 + len(DPAPI_MAGIC)] == DPAPI_MAGIC:
                dpapi, src = val[16:], "live-registry"
        except Exception:
            dpapi = None
        if dpapi is None:
            dpapi = open(infile, "rb").read()  # fallback: backup blob from orchestrator
        plain = crypt_unprotect(dpapi)
        with open(outfile, "wb") as f:
            f.write(plain)
        with open(outfile + ".src", "w", encoding="utf-8") as f:
            f.write(src)
    except Exception as e:  # surface to the orchestrator
        with open(errf, "w", encoding="utf-8") as f:
            f.write("%s: %s" % (type(e).__name__, e))
        return 1
    return 0


def orchestrate():
    if not is_admin():
        sys.exit("[!] Not elevated. Run tools\\extract-pairing-key.bat (self-elevates), or use an "
                 "Administrator shell.")
    ctypes.windll.kernel32.SetLastError(0)
    os.makedirs(WORKDIR, exist_ok=True)
    grant_localservice(WORKDIR)

    # 1. source the stored value (backup .reg is the known-good, always-readable copy)
    if not os.path.exists(BACKUP_REG):
        sys.exit("[!] backup .reg not found: %s\n    Run tools\\win-unpair-verimark.ps1 once (it "
                 "exports PairingData), or point BACKUP_REG at your export." % BACKUP_REG)
    value = blob_from_reg(BACKUP_REG)
    print("[*] PairingData value: %d bytes" % len(value))
    dpapi = strip_header(value)
    inb = os.path.join(WORKDIR, "dpapi.bin")
    outb = os.path.join(WORKDIR, "plain.bin")
    for stale in (outb, outb + ".err"):
        try:
            os.remove(stale)
        except OSError:
            pass
    open(inb, "wb").write(dpapi)
    print("[*] DPAPI blob (%d B) -> %s" % (len(dpapi), inb))

    # 2. decrypt AS LOCAL SERVICE via a one-shot scheduled task (its DPAPI master key)
    cmd = '"%s" "%s" decrypt "%s" "%s"' % (sys.executable, os.path.abspath(__file__), inb, outb)
    subprocess.run(["schtasks", "/create", "/tn", TASK, "/tr", cmd, "/sc", "once",
                    "/st", "23:59", "/ru", "LOCAL SERVICE", "/rl", "LIMITED", "/f"],
                   capture_output=True, text=True)
    subprocess.run(["schtasks", "/run", "/tn", TASK], capture_output=True, text=True)
    print("[*] decrypt task running as LOCAL SERVICE; waiting...")

    plain = None
    for _ in range(60):
        if os.path.exists(outb):
            plain = open(outb, "rb").read()
            break
        if os.path.exists(outb + ".err"):
            err = open(outb + ".err", encoding="utf-8").read()
            subprocess.run(["schtasks", "/delete", "/tn", TASK, "/f"], capture_output=True, text=True)
            sys.exit("[X] decrypt (LOCAL SERVICE) failed: %s\n"
                     "    If it's a key/decrypt error, the LOCAL SERVICE master key may have rotated; "
                     "try re-exporting the LIVE PairingData while paired." % err)
        time.sleep(0.5)
    subprocess.run(["schtasks", "/delete", "/tn", TASK, "/f"], capture_output=True, text=True)
    if plain is None:
        sys.exit("[X] timed out waiting for the decrypt task (no plain.bin / .err).")

    src = "backup-file"
    try:
        src = open(outb + ".src", encoding="utf-8").read().strip() or src
    except OSError:
        pass
    print("[+] decrypted plaintext: %d bytes (owner key source: %s)" % (len(plain), src))

    # 3. parse TagVal + dump
    entries = parse_tagval(plain)
    fields = os.path.join(WORKDIR, "pairing-fields.json")
    with open(fields, "w", encoding="utf-8") as f:
        json.dump({"sensor_id": SENSOR_ID, "plain_len": len(plain), "entries": entries}, f, indent=2)
    print("[+] %d TagVal entries -> %s" % (len(entries), fields))
    for e in entries:
        note = ""
        if e["len"] == 400:
            note = "  <- 400-B cert (host or sensor)"
        elif 60 <= e["len"] <= 80:
            note = "  <- ~68-B EC private key?"
        print("    tag=0x%04x len=%-4d%s" % (e["tag"], e["len"], note))
    print("\n[*] Next: copy %s to the Linux box; findings/42 step 5 reformats it into rev's .pdata\n"
          "    (68 priv | 400 host_cert | 400 sensor_cert), then retry 0x96/0x99.\n"
          "[*] SECURITY: %s holds the OWNER private key - do not commit it (captures/ is git-ignored;\n"
          "    this dir is NOT - move the JSON out of the repo or delete after transfer)." %
          (fields, WORKDIR))


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "decrypt":
        return do_decrypt(sys.argv[2], sys.argv[3])
    orchestrate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
