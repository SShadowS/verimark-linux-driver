#!/usr/bin/env python3
"""
p2_reset.py — CAREFUL single-shot RESET_OWNERSHIP (0x10) probe.

Goal: clear the sensor's owner slot so our Linux host can (re-)claim it as
first-pairer (findings/35 TOFU model). We do NOT have the 0x10 payload format
(rev/proto.txt names it only; no builder in the shipping DLL) — so this tries
the MINIMAL natural form and does exactly ONE attempt, observing state before
and after. No payload mutation, no retry loop (that is the reckless path).

Every malformed cmd this sensor has seen returned a graceful status code
(0x0405/0x0689/0x0401), never acted on garbage — so the expected worst case of
a bad-format 0x10 is another error status, and the expected best case is the
reset. We read provision-state (GET_VERSION) before & after to detect any change.

Safety: prints everything, asks for explicit confirmation before the write.
Run as root, PYTHONPATH set to the user site-packages.
"""
import os, sys, io, struct, logging

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "re", "synaTudor-rev", "pydrv"))

import usb.core
import tudor
import tudor.sensor
from tudor.comm import LogCommunicationProxy, Command
from tudor.sensor.pair import SensorPairingData

VID, PID = 0x047d, 0x00f2
PDATA_DIR = os.path.join(HERE, "pdata")
from control_comm import ControlComm


def u16(b, o=0):
    return struct.unpack_from("<H", b, o)[0]


def read_prov_state(comm):
    """GET_VERSION (0x01) -> provision state (& 0xf). 0/1 = UNPROVISIONED, 3 = PROVISIONED."""
    d = comm.send_command(struct.pack("<B", Command.GET_VERSION), 0x26, raw=True)
    prov = struct.unpack("<2xxxxxIBBxbxxxx6sbbxxxxxxxxxxxB", d)[-1]
    return prov & 0xf, d


def main():
    logging.basicConfig(level=tudor.LOG_INFO, format="%(message)s")

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        raise SystemExit("device not found")
    # Clear any lingering TLS session from a prior run (avoids cleartext GET_VERSION 0x0315 desync)
    try:
        dev.reset()
        dev = usb.core.find(idVendor=VID, idProduct=PID)
    except Exception as e:
        print("(usb reset skipped: %r)" % e)
    comm = LogCommunicationProxy(ControlComm(dev))
    sensor = tudor.sensor.Sensor(comm)

    # --- establish TLS from saved pairing data (read-only, proven) ---
    sid = sensor.id.hex()
    pfile = os.path.join(PDATA_DIR, "%s.pdata" % sid)
    if not os.path.exists(pfile):
        raise SystemExit("no pairing data at %s — run p1_pair.py first" % pfile)
    with open(pfile, "rb") as f:
        pdata = SensorPairingData.load(io.BytesIO(f.read()))
    sensor.initialize(pdata)
    if not comm.proxied.remote_tls_status():
        raise SystemExit("TLS did not establish")
    print("TLS up. sensor id=%s" % sid)

    # --- state BEFORE ---
    prov_before, raw_before = read_prov_state(comm)
    print("\nBEFORE:  provision_state = %d  (%s)" %
          (prov_before, "PROVISIONED" if prov_before == 3 else "UNPROVISIONED"))
    print("         GET_VERSION raw = %s" % raw_before.hex())

    # --- confirmation gate ---
    variant = sys.argv[1] if len(sys.argv) > 1 else "empty"
    payloads = {
        "empty": struct.pack("<B", 0x10),                 # 0x10 only
        "u32z":  struct.pack("<BI", 0x10, 0),             # 0x10 + u32(0)
    }
    if variant not in payloads:
        raise SystemExit("unknown variant %r (choose: %s)" % (variant, ", ".join(payloads)))
    cmd = payloads[variant]
    print("\n>>> ABOUT TO SEND RESET_OWNERSHIP 0x10  variant=%s  bytes=%s" % (variant, cmd.hex()))
    print(">>> This is a WRITE / privileged op. One attempt, no retries.")
    ans = input(">>> Type 'RESET' to proceed, anything else to abort: ").strip()
    if ans != "RESET":
        print("aborted by user."); return

    # --- the single attempt ---
    try:
        r = comm.send_command(cmd, 0x40, raw=True)
        print("\n0x10 RESET_OWNERSHIP -> status=0x%04x  len=%d  %s" % (u16(r), len(r), r.hex()))
    except Exception as e:
        print("\n0x10 RESET_OWNERSHIP raised: %r" % e)

    # --- state AFTER (re-read; may need re-init if TLS dropped) ---
    try:
        prov_after, raw_after = read_prov_state(comm)
    except Exception as e:
        print("\n(state re-read over current session failed: %r; re-opening...)" % e)
        dev2 = usb.core.find(idVendor=VID, idProduct=PID)
        comm2 = LogCommunicationProxy(ControlComm(dev2))
        prov_after, raw_after = read_prov_state(comm2)

    print("\nAFTER:   provision_state = %d  (%s)" %
          (prov_after, "PROVISIONED" if prov_after == 3 else "UNPROVISIONED"))
    print("         GET_VERSION raw = %s" % raw_after.hex())

    print("\n=== RESULT ===")
    if prov_after != prov_before:
        print("provision_state CHANGED %d -> %d  ***" % (prov_before, prov_after))
    else:
        print("provision_state unchanged (%d). If status was an error (0x04xx), the payload"
              " format is wrong / op is gated." % prov_after)


if __name__ == "__main__":
    main()
