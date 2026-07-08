#!/usr/bin/env python3
r"""verify-gcm.py - cross-check the VeriMark AES-256-GCM secure channel.

Two independent proofs that the Frida key/nonce dump is correct and the channel is
really AES-256-GCM (see findings/22-live-secure-channel.md):

  A) self-consistency (default): for every record in a win-cng-<pid>.log, AES-256-GCM
     decrypt the captured CIPHERTEXT with the captured key+nonce and confirm it
     reproduces the captured PLAINTEXT. Needs nothing but the log.

  B) wire match (--pcap): pull the 17 03 03 application-data records for the VeriMark
     out of a USBPcap capture (via tshark), decrypt them with the session key +
     (salt||explicit-nonce), and confirm they equal the Frida plaintext. Proves the
     bytes on the wire == what the driver encrypted/decrypted.

GCM with a 96-bit IV is AES-CTR with the counter starting at (nonce || 0x00000002),
so we can recover the plaintext without the AAD (which the hook doesn't capture) -
a plaintext match is itself proof the key+nonce are right.

Usage:
  python tools\verify-gcm.py captures\win-cng-4868.log
  python tools\verify-gcm.py captures\win-cng-4868.log --pcap captures\win-usb-*.pcap
"""
import argparse
import glob
import re
import subprocess
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.exit("need cryptography:  python -m pip install cryptography")

TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "tshark",
]

_DUMP = re.compile(r"^\s*([A-Za-z.\-]+) \((\d+)\): ([0-9a-fA-F]*)\s*$")
_MARK = re.compile(r"^\[(BCryptEncrypt|BCryptDecrypt|BCryptGenerateSymmetricKey)\]")

ONENTER = {"PLAINTEXT-OUT", "gcm.nonce.out", "CIPHERTEXT-IN", "gcm.nonce.in", "gcm.tag.in"}
ONLEAVE = {"CIPHERTEXT-OUT", "gcm.tag.out", "PLAINTEXT-IN"}


def ctr_decrypt(key, nonce12, ct):
    """AES-256-GCM plaintext recovery via CTR from counter nonce||0x00000002."""
    init = nonce12 + (2).to_bytes(4, "big")
    dec = Cipher(algorithms.AES(key), modes.CTR(init)).decryptor()
    return dec.update(ct) + dec.finalize()


def parse_ops(path):
    """Walk the log and rebuild per-op records: {type, key, nonce, ct, pt}.

    Dump lines emitted in onEnter appear *before* the op's ret marker; onLeave dumps
    after it. We route each dump to the pending (previous) or new op purely by label,
    and complete an op when the next marker arrives.
    """
    recs = []
    pending = None
    key = None
    accum = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            d = _DUMP.match(line)
            if d:
                lab, ln, hx = d.group(1), int(d.group(2)), d.group(3)
                try:
                    accum.append((lab, bytes.fromhex(hx)))
                except ValueError:
                    pass
                continue
            mk = _MARK.match(line)
            if not mk:
                continue
            # onLeave dumps in `accum` belong to the pending op; symKeySecret updates key
            for lab, val in accum:
                if lab == "symKeySecret":
                    key = val
                elif pending is not None and lab in ONLEAVE:
                    if lab == "CIPHERTEXT-OUT":
                        pending["ct"] = val
                    elif lab == "PLAINTEXT-IN":
                        pending["pt"] = val
            if pending is not None:
                recs.append(pending)
                pending = None
            kind = mk.group(1)
            if kind in ("BCryptEncrypt", "BCryptDecrypt"):
                op = {"type": "enc" if kind == "BCryptEncrypt" else "dec", "key": key}
                for lab, val in accum:
                    if lab == "PLAINTEXT-OUT":
                        op["pt"] = val
                    elif lab == "CIPHERTEXT-IN":
                        op["ct"] = val
                    elif lab in ("gcm.nonce.out", "gcm.nonce.in"):
                        op["nonce"] = val
                pending = op
            accum = []
    # trailing onLeave dumps for the final pending op
    for lab, val in accum:
        if pending is not None and lab in ONLEAVE:
            if lab == "CIPHERTEXT-OUT":
                pending["ct"] = val
            elif lab == "PLAINTEXT-IN":
                pending["pt"] = val
    if pending is not None:
        recs.append(pending)
    return recs


def level_a(recs):
    print("=== A) self-consistency (Frida ciphertext -> plaintext) ===")
    keys = {}
    ok = bad = skip = 0
    for r in recs:
        if not all(r.get(k) for k in ("key", "nonce", "ct", "pt")):
            skip += 1
            continue
        if len(r["key"]) != 32 or len(r["nonce"]) != 12:
            skip += 1
            continue
        got = ctr_decrypt(r["key"], r["nonce"], r["ct"])
        if got == r["pt"]:
            ok += 1
            keys.setdefault(r["type"], set()).add(r["key"].hex())
        else:
            bad += 1
            if bad <= 3:
                print(f"  MISMATCH {r['type']} nonce={r['nonce'].hex()} "
                      f"ct={r['ct'][:12].hex()}.. got={got[:12].hex()}.. want={r['pt'][:12].hex()}..")
    print(f"  verified {ok}  mismatch {bad}  skipped(incomplete) {skip}")
    for t, ks in sorted(keys.items()):
        for k in ks:
            print(f"    {t}: key {k[:16]}..")
    return ok, bad


def load_wire_records(pcap_globs):
    """Return {explicit_nonce_hex: record_body} for every 17 03 03 record in the pcaps.

    The VeriMark rides control-out / interrupt-in, so the TLS records don't show up as
    tshark 'usb.capdata'. But each small app-data record sits contiguous inside one USB
    transfer, so we scan the raw pcap bytes for the `17 03 03 len16` framing directly -
    simpler and dissector-independent. False positives (170303 inside ciphertext) are
    harmless: level B only uses records whose explicit nonce matches a captured one.
    """
    files = []
    for g in pcap_globs:
        files.extend(glob.glob(g))
    recs = {}
    for fp in files:
        data = open(fp, "rb").read()
        i = 0
        while True:
            j = data.find(b"\x17\x03\x03", i)
            if j < 0:
                break
            rlen = (data[j + 3] << 8) | data[j + 4] if j + 5 <= len(data) else 0
            if 24 <= rlen <= 2048 and j + 5 + rlen <= len(data):
                body = data[j + 5:j + 5 + rlen]
                recs.setdefault(body[:8].hex(), body)
            i = j + 3
    return recs


def level_b(recs, wire, salts):
    print("\n=== B) wire match (USBPcap 17 03 03 -> Frida plaintext) ===")
    if not wire:
        print("  no 17 03 03 records found in the pcap(s) - "
              "check the capture actually holds the secure session.")
        return
    print(f"  {len(wire)} distinct wire records (by explicit nonce)")
    matched = unmatched = 0
    for r in recs:
        if not all(r.get(k) for k in ("key", "nonce", "pt")):
            continue
        expl = r["nonce"][4:].hex()          # last 8 bytes = TLS explicit nonce
        body = wire.get(expl)
        if body is None:
            continue
        salt = salts.get(r["type"])
        if not salt:
            continue
        # wire body = explicit_nonce[8] || ciphertext || tag[16]
        ct = body[8:-16] if len(body) > 24 else body[8:]
        got = ctr_decrypt(r["key"], salt + r["nonce"][4:], ct)
        if got[:len(r["pt"])] == r["pt"]:
            matched += 1
        else:
            unmatched += 1
            if unmatched <= 3:
                print(f"  wire mismatch nonce8={expl} got={got[:12].hex()}.. want={r['pt'][:12].hex()}..")
    print(f"  matched {matched}  unmatched {unmatched}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log")
    ap.add_argument("--pcap", nargs="+", help="USBPcap file(s)/glob for the wire match")
    args = ap.parse_args()

    recs = parse_ops(args.log)
    print(f"parsed {len(recs)} crypto ops "
          f"({sum(r['type'] == 'enc' for r in recs)} enc / {sum(r['type'] == 'dec' for r in recs)} dec)\n")
    ok, bad = level_a(recs)

    # derive per-direction salt (first 4 bytes of that direction's nonce)
    salts = {}
    for r in recs:
        if r.get("nonce") and len(r["nonce"]) == 12:
            salts.setdefault(r["type"], r["nonce"][:4])

    if args.pcap:
        wire = load_wire_records(args.pcap)
        level_b(recs, wire, salts)

    sys.exit(0 if bad == 0 else 1)


if __name__ == "__main__":
    main()
