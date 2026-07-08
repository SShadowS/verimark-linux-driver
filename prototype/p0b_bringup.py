#!/usr/bin/env python3
"""
P0b — bring up the synaTudor `rev` stack on the VeriMark via the EP0-control shim.
READ-ONLY: exercises Sensor init (GET_VERSION + IOTAs + sensor-key load, GET_START_INFO)
through the real reuse stack, then stops at the TLS/pairing gate (we are unpaired, so
initialize() raises "No pairing data given" BEFORE any TLS write). No sensor writes.

Requires root (claim iface1). Reuses rev's tudor.tls / tudor.sensor unchanged.
"""
import os, sys, logging, struct

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


def main():
    # show comm-level + detail logs from the tudor stack
    logging.basicConfig(level=tudor.LOG_COMM, format="%(message)s")

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("device not found"); return 2
    print("found %04x:%04x  bus=%d addr=%d\n" % (VID, PID, dev.bus, dev.address))

    comm = ControlComm(dev)
    comm = LogCommunicationProxy(comm)   # per-command tracing
    try:
        print(">>> constructing Sensor (runs reset: GET_VERSION + IOTAs + load key)\n")
        sensor = tudor.sensor.Sensor(comm)
        print("\n>>> Sensor info")
        print("    FW version    : %d.%d.%d" % (sensor.fw_major, sensor.fw_minor, sensor.fw_build_num))
        print("    product id    : %s" % sensor.product_id)
        print("    sensor id     : %s" % sensor.id.hex())
        print("    adv security  : %s" % sensor.advanced_security)
        print("    key flag      : %s" % sensor.key_flag)
        print("    provision     : %s" % sensor.prov_state)
        print("    is_paired()   : %s" % sensor.is_paired())
        print("    sensor pubkey : %s" % ("loaded" if getattr(sensor, "pub_key", None) else "NONE"))
        try:
            print("    config version: %d.%d.%d" % (sensor.cfg_ver.major, sensor.cfg_ver.minor, sensor.cfg_ver.revision))
            print("    WBF param     : 0x%x" % sensor.wbf_param_iota.param)
        except Exception as e:
            print("    (iota detail: %s)" % e)

        print("\n>>> initialize(None) — expect to reach the TLS/pairing gate and stop")
        try:
            sensor.initialize(None)
            print("!!! initialize() returned without needing pairing — UNEXPECTED (investigate)")
        except Exception as e:
            print("\n=== reached gate as expected: %r" % e)
            print("=== P0b OK: full rev stack runs over the EP0-control shim, read-only,")
            print("    up to the point where TLS establishment needs a Linux-host pair (P1).")
        return 0
    except Exception as e:
        import traceback
        print("\n!!! P0b failed:")
        traceback.print_exc()
        return 1
    finally:
        try: comm.proxied.close()
        except Exception: pass


if __name__ == "__main__":
    sys.exit(main())
