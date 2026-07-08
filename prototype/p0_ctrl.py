#!/usr/bin/env python3
"""
P0 (real) — VeriMark (047d:00f2) Tudor transport over EP0 control. READ-ONLY.

Recovered from the 132 DLL decompiles (findings/27): the biometric channel (iface1,
no bulk pipe) tunnels the sensor's logical bulk channel over EP0 vendor control:

  command WRITE : bmRequestType=0x40, bRequest=0x16, wValue=(len & 7), wIndex=0,
                  data padded to a multiple of 8 bytes (<=4096/chunk)
  response READ : bmRequestType=0xc0, bRequest=0x17, wValue=0, wIndex=0,
                  (<=4096/chunk, retry on timeout until ready)

Sends two raw (pre-TLS) query opcodes that perform NO sensor write:
  GET_VERSION    (0x01) -> fw version, product id, provision state
  GET_START_INFO (0x19) -> start/reset info

Requires root. iface0 (FIDO) is left untouched; we only need EP0.
"""
import sys, struct, time
import usb.core, usb.util

VID, PID = 0x047d, 0x00f2
IF_BIO = 1
REQ_WRITE, REQ_READ = 0x16, 0x17
RT_WRITE, RT_READ = 0x40, 0xc0

CMD_GET_VERSION    = 0x01
CMD_GET_START_INFO = 0x19
PROV = {0: "UNPROVISIONED_A", 1: "UNPROVISIONED_B", 3: "PROVISIONED"}


def hexdump(b, width=16):
    if not b: return "    (empty)"
    return "\n".join("    %04x  %s" % (i, " ".join("%02x" % x for x in b[i:i+width]))
                     for i in range(0, len(b), width))


def cmd_write(dev, data, timeout=2000):
    pad = (-len(data)) % 8
    buf = bytes(data) + b"\x00" * pad
    wValue = len(data) & 7
    n = dev.ctrl_transfer(RT_WRITE, REQ_WRITE, wValue, 0, buf, timeout)
    return n


def cmd_read(dev, maxlen=256, timeout=2000, retries=20):
    last = None
    for _ in range(retries):
        try:
            data = dev.ctrl_transfer(RT_READ, REQ_READ, 0, 0, maxlen, timeout)
            return bytes(data)
        except usb.core.USBError as e:
            last = e
            # 110 = timeout, 19 = no-device; retry on timeout (device not ready yet)
            if getattr(e, "errno", None) in (110,):
                time.sleep(0.05); continue
            raise
    raise last


def transaction(dev, name, opc, respmax=256):
    print("== %s (0x%02x) ==" % (name, opc))
    try:
        w = cmd_write(dev, struct.pack("<B", opc))
        print("  ctrl-OUT 0x40/0x16 wValue=%d: wrote %s bytes" % (1 & 7, w))
    except usb.core.USBError as e:
        print("  ctrl-OUT FAILED: %s" % e); print(); return None
    try:
        resp = cmd_read(dev, respmax)
    except usb.core.USBError as e:
        print("  ctrl-IN FAILED: %s" % e); print(); return None
    print("  ctrl-IN 0xc0/0x17: got %d bytes" % len(resp))
    print(hexdump(resp))
    if len(resp) >= 2:
        st = struct.unpack_from("<H", resp, 0)[0]
        print("  status = 0x%04x %s" % (st, "OK" if st == 0 else "**nonzero**"))
    print()
    return resp


def main():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("device not found"); return 2
    print("found  bus=%d addr=%d" % (dev.bus, dev.address))

    detached = claimed = False
    try:
        try:
            if dev.is_kernel_driver_active(IF_BIO):
                dev.detach_kernel_driver(IF_BIO); detached = True
                print("detached kernel driver from iface %d" % IF_BIO)
        except usb.core.USBError as e:
            print("(iface %d kernel check: %s)" % (IF_BIO, e))
        try:
            usb.util.claim_interface(dev, IF_BIO); claimed = True
            print("claimed iface %d\n" % IF_BIO)
        except usb.core.USBError as e:
            print("(claim iface %d: %s -- trying control transfers anyway)\n" % (IF_BIO, e))

        v = transaction(dev, "GET_VERSION", CMD_GET_VERSION)
        if v and len(v) >= 38 and struct.unpack_from("<H", v, 0)[0] == 0:
            (fw_build, fw_major, fw_minor, product_id, sid, f1, f2, prov) = struct.unpack(
                "<2xxxxxIBBxbxxxx6sbbxxxxxxxxxxxB", v[:38])
            ps = prov & 0xf
            print("  --> FW %d.%d.%d  product=0x%02x  id=%s  prov=%d (%s)\n"
                  % (fw_major, fw_minor, fw_build, product_id & 0xff, sid.hex(), ps,
                     PROV.get(ps, "?")))
        transaction(dev, "GET_START_INFO", CMD_GET_START_INFO)
        print("done.")
        return 0
    finally:
        if claimed:
            try: usb.util.release_interface(dev, IF_BIO)
            except Exception: pass
        if detached:
            try: dev.attach_kernel_driver(IF_BIO)
            except Exception: pass
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    sys.exit(main())
