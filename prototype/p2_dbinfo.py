#!/usr/bin/env python3
"""
P2a — READ-ONLY DB2 inspection over the live TLS session.

Loads the P1 pairing data, establishes the TLS 1.2 session, and reads the sensor's
template store through the encrypted channel:
  0x9e DB2_GET_DB_INFO   — capacity / usage counters (findings/25 layout)
  0x9f DB2_GET_OBJ_LIST  — best-effort probe (format uncertain; read-only, non-fatal)

No writes. This proves the encrypted MOC command path works from Linux with a *loaded*
(not freshly-paired) identity, and shows the existing Windows-side templates.

Run as root. Reuses rev's tudor.tls/tudor.sensor unchanged over the EP0 transport.
"""
import os, sys, io, struct, logging

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "re", "synaTudor-rev", "pydrv"))

import usb.core
import tudor
import tudor.sensor
from tudor.comm import LogCommunicationProxy, Command, CommandFailedException
from tudor.sensor.pair import SensorPairingData
from control_comm import ControlComm

VID, PID = 0x047d, 0x00f2
PDATA_DIR = os.path.join(HERE, "pdata")


def parse_db_info(resp: bytes) -> dict:
    """findings/25 layout of the 40-B DB2_GET_DB_INFO response."""
    d = {}
    d["status"] = struct.unpack_from("<H", resp, 0)[0]
    d["version"] = struct.unpack_from("<H", resp, 4)[0]
    d["u8"] = struct.unpack_from("<H", resp, 8)[0]
    d["u12"] = struct.unpack_from("<H", resp, 12)[0]
    d["store_size"] = struct.unpack_from("<H", resp, 14)[0]     # 0x0210 = 528 seen
    d["max_slots"] = struct.unpack_from("<H", resp, 16)[0]      # 100 seen
    d["u18"] = struct.unpack_from("<H", resp, 18)[0]
    # +22..38 live usage counters
    d["usage_words"] = [struct.unpack_from("<H", resp, o)[0] for o in range(22, 40, 2)]
    return d


def main():
    logging.basicConfig(level=tudor.LOG_COMM, format="%(message)s")

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("device not found"); return 2

    comm = ControlComm(dev)
    comm = LogCommunicationProxy(comm)
    sensor = None
    try:
        sensor = tudor.sensor.Sensor(comm)
        sid = sensor.id.hex()
        print("\n>>> sensor id=%s  FW=%d.%d.%d  prov=%s"
              % (sid, sensor.fw_major, sensor.fw_minor, sensor.fw_build_num, sensor.prov_state))

        pfile = os.path.join(PDATA_DIR, "%s.pdata" % sid)
        if not os.path.exists(pfile):
            print("!!! no pairing data at %s — run p1_pair.py first" % pfile); return 3
        with open(pfile, "rb") as f:
            pdata = SensorPairingData.load(io.BytesIO(f.read()))
        print(">>> loaded pairing data: %s" % pfile)

        print("\n>>> initialize(pdata) — establish TLS ...")
        sensor.initialize(pdata)
        print(">>> TLS up: remote_tls_status=%s\n" % comm.proxied.remote_tls_status())

        # --- 0x9e DB2_GET_DB_INFO (known-good, read-only) ---
        print(">>> DB2_GET_DB_INFO (0x9e) ...")
        resp = comm.send_command(struct.pack("<BB", Command.DB2_GET_DB_INFO, 1), 0x28)
        info = parse_db_info(resp)
        print("    raw: %s" % resp.hex())
        print("    status=0x%04x  version=%d  store_size=%d  max_slots=%d"
              % (info["status"], info["version"], info["store_size"], info["max_slots"]))
        print("    usage words (+22..): %s" % " ".join("%d" % w for w in info["usage_words"]))

        # --- 0x9f DB2_GET_OBJ_LIST (best-effort probe; format uncertain) ---
        print("\n>>> DB2_GET_OBJ_LIST (0x9f) — best-effort probe ...")
        for desc, cmd in [
            ("9f 01",            struct.pack("<BB", Command.DB2_GET_OBJ_LIST, 1)),
            ("9f 02000000",      struct.pack("<BI", Command.DB2_GET_OBJ_LIST, 2)),
        ]:
            try:
                r = comm.send_command(cmd, 0x400, raw=True)
                st = struct.unpack_from("<H", r, 0)[0]
                print("    [%s] status=0x%04x len=%d  %s" % (desc, st, len(r), r[:64].hex()))
            except CommandFailedException as e:
                print("    [%s] CommandFailed status=0x%04x" % (desc, e.status))
            except Exception as e:
                print("    [%s] %r" % (desc, e))

        print("\n=== P2a done (read-only): encrypted MOC/DB channel works from Linux. ===")
        return 0
    except Exception:
        import traceback; traceback.print_exc(); return 1
    finally:
        try:
            if sensor is not None and sensor.initialized: sensor.uninitialize()
        except Exception: pass
        try: comm.proxied.close()
        except Exception: pass


if __name__ == "__main__":
    sys.exit(main())
