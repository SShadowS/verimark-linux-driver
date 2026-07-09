#!/usr/bin/env python3
"""
Build a rev `SensorPairingData` .pdata from Windows' extracted OWNER pairing fields
(findings/42), so `rev` can present the OWNER host keypair to the sensor and (hypothesis)
get an authorized cert_type=0 session that unblocks MOC (findings/38).

Input:  ../pairing-fields.json  (decrypted Synaptics TagVal container from the Windows box)
Output: pdata/<sensorid>.owner.pdata   (68-B priv LE ‖ 400 host_cert ‖ 400 sensor_cert)

This is OFFLINE and non-destructive: it does not touch the device and does NOT overwrite the
existing P1 non-owner pdata (<sensorid>.pdata). It cryptographically identifies which 400-B blob
is the sensor cert (verifies against this sensor's 10.1-kf pubkey) vs the owner host cert, and
checks that the tag-2 private scalar derives to the host cert's public key.

⚠ The output holds the OWNER private key — pdata/ is git-ignored; keep it there.
"""
import os, sys, io, json, struct

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "re", "synaTudor-rev", "pydrv"))

import cryptography.hazmat.primitives.asymmetric.ec as ecc
import cryptography.hazmat.primitives.hashes as hashes
from tudor.sensor.pair import SensorCertificate, SensorPairingData
from tudor.sensor.sensor import load_sensor_key

PDATA_DIR = os.path.join(HERE, "pdata")
INPUT = os.path.join(REPO, "pairing-fields.json")

# This sensor (findings/28): FW 10.1, key_flag set -> sensor pubkey "10.1-kf".
FW_MAJOR, FW_MINOR, KEY_FLAG = 10, 1, True


def verifies_against(cert, pubkey):
    try:
        pubkey.verify(cert.signature, cert.signbytes(), ecc.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def main():
    with open(INPUT) as f:
        doc = json.load(f)
    sid = doc["sensor_id"].lower()
    ents = {e["tag"]: bytes.fromhex(e["hex"]) for e in doc["entries"]}

    print("sensor_id = %s" % sid)
    print("tags present: %s" % sorted(ents))

    # 1. private scalar (tag 2) + the two 400-B certs (tags 1, 3)
    priv_raw = ents[2]
    assert len(priv_raw) == 32, "tag-2 priv scalar is %d B, expected 32" % len(priv_raw)
    d = int.from_bytes(priv_raw, "little")           # Synaptics TagVal scalar is little-endian
    priv_key = ecc.derive_private_key(d, ecc.SECP256R1())
    derived_pub = priv_key.public_key().public_numbers()
    print("\ntag-2 owner private scalar loaded (LE), pubkey derived.")

    cert1 = SensorCertificate.frombytes(ents[1])
    cert3 = SensorCertificate.frombytes(ents[3])
    for tag, c in ((1, cert1), (3, cert3)):
        print("  cert tag=%d: cert_type=%d  sign_size=%d" % (tag, c.cert_type, len(c.signature)))

    # 2. identify sensor cert = the one whose sig verifies against this sensor's 10.1-kf pubkey
    sensor_pub = load_sensor_key(FW_MAJOR, FW_MINOR, KEY_FLAG)
    v1 = verifies_against(cert1, sensor_pub)
    v3 = verifies_against(cert3, sensor_pub)
    print("\nverify vs sensor 10.1-kf pubkey:  tag1=%s  tag3=%s" % (v1, v3))

    if v1 == v3:
        print("!!! ambiguous: exactly one cert must verify as the sensor cert (got tag1=%s tag3=%s)"
              % (v1, v3))
        return 4
    if v3:
        sensor_cert, host_cert, host_tag = cert3, cert1, 1
    else:
        sensor_cert, host_cert, host_tag = cert1, cert3, 3
    print("=> tag%d = SENSOR cert; tag%d = owner HOST cert"
          % (3 if v3 else 1, host_tag))

    # 3. sanity: the owner private scalar must derive to the HOST cert's pubkey
    hp = host_cert.pub_key.public_numbers()
    if (hp.x, hp.y) == (derived_pub.x, derived_pub.y):
        print("=> owner private key MATCHES host cert pubkey  ✓")
    else:
        print("!!! owner private key does NOT match host cert pubkey.")
        sp = sensor_cert.pub_key.public_numbers()
        if (sp.x, sp.y) == (derived_pub.x, derived_pub.y):
            print("    (it matches the SENSOR cert pubkey instead — identification likely inverted)")
        return 5

    # 4. build + persist SensorPairingData (rev format). Do NOT overwrite the P1 non-owner pdata.
    pdata = SensorPairingData(priv_key, host_cert, sensor_cert)
    os.makedirs(PDATA_DIR, exist_ok=True)
    out = os.path.join(PDATA_DIR, "%s.owner.pdata" % sid)
    if os.path.exists(out):
        print("\n!!! %s already exists — refusing to overwrite. Remove it first if rebuilding." % out)
        return 3
    buf = io.BytesIO()
    pdata.save(buf)
    raw = buf.getvalue()
    assert len(raw) == 0x44 + 400 + 400, len(raw)

    # round-trip check: reload and confirm equality of the crypto material
    rt = SensorPairingData.load(io.BytesIO(raw))
    assert rt.priv_key.private_numbers().private_value == d
    assert rt.host_cert.tobytes() == host_cert.tobytes()
    assert rt.sensor_cert.tobytes() == sensor_cert.tobytes()

    with open(out, "wb") as f:
        f.write(raw)
    print("\n=== wrote %d bytes -> %s ===" % (len(raw), out))
    print("Next: run p2_moc.py with VERIMARK_PDATA=%s to present the OWNER identity." % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
