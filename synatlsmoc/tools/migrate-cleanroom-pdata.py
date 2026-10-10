#!/usr/bin/env python3
"""Migrate the clean-room driver's pairing credential to the synatlsmoc driver.

If a VeriMark Desktop (047d:00f2) was paired and enrolled with the clean-room
driver in ../driver/, this machine OWNS the key via an 868-byte
/var/lib/fprint/verimark/<sid>.pdata file. synatlsmoc keeps the same objects (the
host and sensor certificates, 400 bytes each, and a P-256 private key) in a
different container, libfprint's persistent-data file. Converting the old file
lets synatlsmoc open the key as the existing owner, instead of generating new
credentials and pairing a second time (which, on an already-owned key, only joins
as a non-owner; see findings/35).

Old file : [0:68] little-endian private scalar | [68:468] host cert | [468:868] sensor cert
New file : GVariant "(issv)" = (1, "synatlsmoc", "0",
                                variant "(ayays)" (host_cert, sensor_cert, privkey PKCS#8 PEM))
           device_id is "0" because synatlsmoc defines no probe vfunc.

Safety: the private key is checked against the public key inside the host
certificate before anything is written, the result is re-parsed and compared, an
existing output file is never overwritten, and the output is created mode 0600.
Nothing is printed except PASS/FAIL lines (never key material). The input file
is only read.

Usage:
  sudo python3 -I migrate-cleanroom-pdata.py IN.pdata OUT.bin
  python3 -I migrate-cleanroom-pdata.py --self-test

Typical paths:
  IN  = /var/lib/fprint/verimark/<sid>.pdata
  OUT = /var/lib/fprint/verimark/047d-00f2/libfprint-persistent.bin  (what install.sh sets
        SYNA_TLSMOC_PERSISTENT_DATA_FILE to; the directory must be root:root 0700)

Requires: python3-gi (GLib) and python3-cryptography.
"""
import os
import sys
import tempfile

import gi
gi.require_version("GLib", "2.0")
from gi.repository import GLib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

CERT_LEN = 400
SCALAR_FIELD = 0x44          # 68-byte little-endian field
PDATA_LEN = SCALAR_FIELD + 2 * CERT_LEN   # 868
# Order n of the NIST P-256 (secp256r1) group: a valid private scalar is 1 <= d < n.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
DRIVER_ID = "synatlsmoc"
DEVICE_ID = "0"


class Fail(Exception):
    pass


def le_int(b):
    return int.from_bytes(b, "little")


def convert(buf):
    """Return the serialized persistent-data bytes for an 868-byte old pdata blob."""
    if len(buf) != PDATA_LEN:
        raise Fail(f"input is {len(buf)} bytes, expected {PDATA_LEN}")

    host_cert = buf[SCALAR_FIELD:SCALAR_FIELD + CERT_LEN]
    sensor_cert = buf[SCALAR_FIELD + CERT_LEN:]

    for name, c in (("host", host_cert), ("sensor", sensor_cert)):
        magic, curve = le_int(c[0:2]), le_int(c[2:4])
        if magic != 0x5F3F or curve != 23:
            raise Fail(f"{name} cert has bad magic/curve ({magic:#x}/{curve})")
    print("PASS: both certs have the expected magic (0x5f3f) and curve (23 = P-256)")

    scalar = le_int(buf[0:SCALAR_FIELD])
    if not 0 < scalar < P256_ORDER:
        raise Fail("private scalar is not a valid P-256 key (must be 1 <= d < the curve order)")
    try:
        key = ec.derive_private_key(scalar, ec.SECP256R1())
    except ValueError as e:      # belt and braces: never let a library error become a traceback
        raise Fail(f"private scalar rejected by the crypto library: {e}")

    pub = key.public_key().public_numbers()
    if (pub.x, pub.y) != (le_int(host_cert[4:72]), le_int(host_cert[72:140])):
        raise Fail("private key does NOT match the public key in the host certificate")
    print("PASS: private key derives exactly the public key inside the host certificate")

    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode("ascii")

    inner = GLib.Variant.new_tuple(GLib.Variant("ay", host_cert),
                                   GLib.Variant("ay", sensor_cert),
                                   GLib.Variant("s", pem))
    outer = GLib.Variant.new_tuple(GLib.Variant("i", 1),
                                   GLib.Variant("s", DRIVER_ID),
                                   GLib.Variant("s", DEVICE_ID),
                                   GLib.Variant("v", inner))
    data = outer.get_data_as_bytes().get_data()

    back = GLib.Variant.new_from_bytes(GLib.VariantType("(issv)"), GLib.Bytes.new(data), False)
    ver, drv, dev, v = back.unpack()
    c1, c2, p = v
    if (ver, drv, dev) != (1, DRIVER_ID, DEVICE_ID):
        raise Fail(f"envelope mismatch after round-trip: {(ver, drv, dev)}")
    if bytes(c1) != host_cert or bytes(c2) != sensor_cert or p != pem:
        raise Fail("payload mismatch after round-trip")
    print(f"PASS: output round-trips as (1, '{DRIVER_ID}', '{DEVICE_ID}', (host_cert, sensor_cert, pem))")
    return data


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # never overwrite
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)
    print(f"WROTE: {path} ({len(data)} bytes, mode 0600)")


def synth_pdata(key=None, mismatch=False):
    """Build a synthetic old-format blob (random key, fake cert bodies) for the self-test."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    nums = key.private_numbers()
    pub = (key if not mismatch else ec.generate_private_key(ec.SECP256R1())).public_key().public_numbers()

    def cert(px, py):
        c = bytearray(CERT_LEN)
        c[0:2] = (0x5F3F).to_bytes(2, "little")
        c[2:4] = (23).to_bytes(2, "little")
        c[4:72] = px.to_bytes(68, "little")
        c[72:140] = py.to_bytes(68, "little")
        return bytes(c)

    buf = bytearray(PDATA_LEN)
    buf[0:SCALAR_FIELD] = nums.private_value.to_bytes(SCALAR_FIELD, "little")
    buf[SCALAR_FIELD:SCALAR_FIELD + CERT_LEN] = cert(pub.x, pub.y)
    other = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    buf[SCALAR_FIELD + CERT_LEN:] = cert(other.x, other.y)
    return bytes(buf)


def self_test():
    print("== self-test: good input ==")
    assert convert(synth_pdata())
    print("== self-test: key/cert mismatch must be rejected ==")
    try:
        convert(synth_pdata(mismatch=True))
    except Fail as e:
        print("PASS: rejected:", e)
    else:
        raise SystemExit("FAIL: mismatched key was accepted")
    print("== self-test: out-of-range scalars (0, n, 2**256-1) must be rejected ==")
    for bad in (0, P256_ORDER, 2 ** 256 - 1):
        blob = bytearray(synth_pdata())
        blob[0:SCALAR_FIELD] = bad.to_bytes(SCALAR_FIELD, "little")
        try:
            convert(bytes(blob))
        except Fail as e:
            print(f"PASS: scalar {'0' if bad == 0 else hex(bad)[:12] + '...'} rejected: {e}")
        else:
            raise SystemExit(f"FAIL: out-of-range scalar {bad:#x} was accepted")
    print("== self-test: wrong length must be rejected ==")
    try:
        convert(b"\0" * 10)
    except Fail as e:
        print("PASS: rejected:", e)
    else:
        raise SystemExit("FAIL: short input was accepted")
    print("== self-test: refuses to overwrite ==")
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "out.bin")
        write_new(out, convert(synth_pdata()))
        try:
            write_new(out, b"x")
        except FileExistsError:
            print("PASS: existing output was not overwritten")
        else:
            raise SystemExit("FAIL: overwrote an existing file")
    print("self-test OK")


def main(argv):
    if argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if len(argv) != 3 or argv[1].startswith("-"):
        print(__doc__)
        return 2
    try:
        with open(argv[1], "rb") as f:
            data = convert(f.read())
        write_new(argv[2], data)
    except (Fail, OSError) as e:
        print("FAIL:", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
