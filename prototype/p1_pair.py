#!/usr/bin/env python3
"""
P1 — pair a Linux host identity and bring up the TLS session on the VeriMark.

⚠ THIS IS THE FIRST WRITE TO THE SENSOR. It sends 0x93 PAIR, which mints a host
certificate in the sensor's flash (multi-slot; the Windows enrollment should survive).
The returned pairing data is persisted IMMEDIATELY, before anything else, so a crash
mid-init can never lose the freshly minted identity.

Sequence:
  1. construct Sensor (read-only reset: GET_VERSION + IOTAs + load sensor key)
  2. guard: prov==3, key_flag, advanced_security
  3. sensor.pair()            -> SensorPairingData  [SENSOR WRITE: 0x93]
  4. pdata.save(<sensorid>.pdata)  [persist immediately]
  5. sensor.initialize(pdata) -> verifies sensor cert, establishes TLS 1.2 session
  6. confirm remote_tls_status() and a WRAPPED GET_START_INFO (0x19) round-trip

Run as root (claims iface1). Reuses rev's tudor.tls / tudor.sensor unchanged.
"""
import os, sys, io, logging, struct

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)                                   # control_comm
sys.path.insert(0, os.path.join(REPO, "re", "synaTudor-rev", "pydrv"))  # tudor

import usb.core
import tudor
import tudor.sensor
from tudor.comm import LogCommunicationProxy
from control_comm import ControlComm

VID, PID = 0x047d, 0x00f2
PDATA_DIR = os.path.join(HERE, "pdata")


def main():
    logging.basicConfig(level=tudor.LOG_COMM, format="%(message)s")

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("device not found"); return 2
    print("found %04x:%04x  bus=%d addr=%d\n" % (VID, PID, dev.bus, dev.address))

    comm = ControlComm(dev)
    comm = LogCommunicationProxy(comm)
    sensor = None
    try:
        print(">>> constructing Sensor (read-only reset + IOTAs + load key)\n")
        sensor = tudor.sensor.Sensor(comm)
        sid = sensor.id.hex()
        print("\n>>> Sensor: id=%s  FW=%d.%d.%d  prov=%s  key_flag=%s  adv_sec=%s"
              % (sid, sensor.fw_major, sensor.fw_minor, sensor.fw_build_num,
                 sensor.prov_state, sensor.key_flag, sensor.advanced_security))

        # --- guards before the write ---
        assert sensor.prov_state == 3, "prov_state != 3 (unexpected)"
        assert sensor.key_flag, "key_flag not set (unexpected)"
        assert sensor.advanced_security, "advanced_security not present (unexpected)"

        outfile = os.path.join(PDATA_DIR, "%s.pdata" % sid)
        if os.path.exists(outfile):
            print("!!! %s already exists — refusing to overwrite. Move it aside first." % outfile)
            return 3

        # ============ SENSOR WRITE: 0x93 PAIR ============
        print("\n>>> sensor.pair()  [SENSOR WRITE 0x93] ...")
        pdata = sensor.pair()
        print(">>> pair() returned. Persisting IMMEDIATELY...")

        # persist first, before anything can fail
        os.makedirs(PDATA_DIR, exist_ok=True)
        buf = io.BytesIO()
        pdata.save(buf)
        raw = buf.getvalue()
        with open(outfile, "wb") as f:
            f.write(raw)
        print(">>> saved %d bytes -> %s" % (len(raw), outfile))

        # describe what we got (offline sanity)
        hc, dc = pdata.host_cert, pdata.sensor_cert
        print("    host_cert  : type=%d  sign_size=%d" % (hc.cert_type, len(hc.signature)))
        print("    sensor_cert: type=%d  sign_size=%d" % (dc.cert_type, len(dc.signature)))

        # verify the device cert against THIS sensor's loaded pubkey (interop proof)
        import cryptography.hazmat.primitives.asymmetric.ec as ecc
        import cryptography.hazmat.primitives.hashes as hashes
        try:
            sensor.pub_key.verify(dc.signature, dc.signbytes(), ecc.ECDSA(hashes.SHA256()))
            print("    sensor_cert signature VERIFIES against 10.1-kf pubkey ✓")
        except Exception as e:
            print("    !!! sensor_cert verify FAILED: %r" % e)
            print("    (pairing data is saved; stopping before TLS)")
            return 4

        # ============ bring up TLS ============
        print("\n>>> sensor.initialize(pdata)  — establish TLS 1.2 session ...")
        sensor.initialize(pdata)
        print(">>> initialize() OK — sensor.initialized=%s" % sensor.initialized)

        # confirm the secure channel
        raw_comm = comm.proxied
        print("\n>>> remote_tls_status(): %s" % raw_comm.remote_tls_status())

        print(">>> wrapped GET_START_INFO (0x19) round-trip ...")
        resp = comm.send_command(struct.pack("<B", tudor.Command.GET_START_INFO), 0x44)
        status = struct.unpack("<H", resp[:2])[0]
        print(">>> wrapped GET_START_INFO status=0x%04x  (%d bytes)  ✓" % (status, len(resp)))

        print("\n=== P1 DONE: live TLS session from Linux; wrapped command round-trips. ===")
        print("=== pairing data: %s ===" % outfile)
        return 0
    except Exception:
        import traceback
        print("\n!!! P1 error:")
        traceback.print_exc()
        return 1
    finally:
        try:
            if sensor is not None and sensor.initialized:
                sensor.uninitialize()
        except Exception:
            pass
        try: comm.proxied.close()
        except Exception: pass


if __name__ == "__main__":
    sys.exit(main())
