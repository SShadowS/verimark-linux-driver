#!/usr/bin/env python3
"""
P0a — VeriMark Desktop (047d:00f2) transport probe.  READ-ONLY, NO WRITES.

Purpose: empirically confirm findings/26 — that the Tudor command channel is
iface0 EP 0x01 interrupt-OUT (60 B) / 0x81 interrupt-IN (60 B), NOT EP0 control
transfers with responses on iface1 0x83.  Sends two raw (pre-TLS) commands that
perform no sensor write:

  GET_VERSION    (0x01, 38-B resp)  -> fw version, product id, PROVISION STATE
  GET_START_INFO (0x19, 68-B resp)  -> start/reset info

Neither touches pairing/provisioning.  Requires root (detach kernel HID driver +
claim interface).  On exit it releases and reattaches the kernel driver so U2F/HID
returns.

Behavioral constants (opcodes, response sizes, struct layouts) are reused from the
synaTudor `rev` reimplementation as documented facts; no vendor code.
"""
import sys, struct, time
import usb.core, usb.util

VID, PID = 0x047d, 0x00f2
EP_CMD_OUT = 0x01   # iface0 interrupt-OUT, 60 B  (WinUsb_WritePipe target per findings/26)
EP_RSP_IN  = 0x81   # iface0 interrupt-IN,  60 B  (WinUsb_ReadPipe)
IFACE_CMD  = 0                                     # HID interface, co-opted for Tudor

CMD_GET_VERSION    = 0x01
CMD_GET_START_INFO = 0x19

PROV_STATES = {0: "UNPROVISIONED_A", 1: "UNPROVISIONED_B", 3: "PROVISIONED"}
PRODUCT_IDS = {}  # informational only


def hexdump(b, width=16):
    out = []
    for i in range(0, len(b), width):
        chunk = b[i:i+width]
        hexs = " ".join("%02x" % c for c in chunk)
        out.append("  %04x  %-*s" % (i, width*3, hexs))
    return "\n".join(out)


MAXP = 60  # iface0 IN/OUT wMaxPacketSize

def clear_halts(dev):
    for ep in (EP_CMD_OUT, EP_RSP_IN):
        try:
            dev.clear_halt(ep)
        except Exception as e:
            print("  (clear_halt 0x%02x: %s)" % (ep, e))

def send_raw(dev, cmd_bytes, resp_size, timeout=2000):
    """Write a raw command to EP 0x01, read the response from EP 0x81.

    Interrupt-IN transfers must request a buffer that is a multiple of the
    endpoint max packet size (60) or libusb returns EOVERFLOW when the device
    sends a full packet. Round the request up and add one packet of slack; the
    read returns the actual byte count the device sent.
    """
    try:
        n = dev.write(EP_CMD_OUT, cmd_bytes, timeout)
        print("  write 0x%02x: %d bytes -> ok (%d)" % (EP_CMD_OUT, len(cmd_bytes), n))
    except usb.core.USBError as e:
        print("  write 0x%02x FAILED: %s" % (EP_CMD_OUT, e)); raise
    # smallest multiple of the max packet size that holds resp_size, NO slack:
    # the device pads short responses to a full 60-B packet with no terminating
    # short packet, so an over-large request would block waiting for more.
    want = max(1, (resp_size + MAXP - 1) // MAXP) * MAXP
    try:
        data = dev.read(EP_RSP_IN, want, timeout)
    except usb.core.USBError as e:
        print("  read 0x%02x FAILED (asked %d): %s" % (EP_RSP_IN, want, e))
        try:
            dev.clear_halt(EP_RSP_IN)
        except Exception:
            pass
        raise
    return bytes(data)


def find_dev():
    return usb.core.find(idVendor=VID, idProduct=PID)


def main():
    dev = find_dev()
    if dev is None:
        print("device %04x:%04x not found" % (VID, PID)); return 2
    print("found %04x:%04x  bus=%d addr=%d" % (VID, PID, dev.bus, dev.address))

    # A prior aborted transaction can wedge the sensor (reads return EIO). Do a
    # USB port reset for a clean firmware state, then re-acquire a fresh handle.
    try:
        print("resetting device for clean state ...")
        dev.reset()
    except Exception as e:
        print("  (reset: %s)" % e)
    usb.util.dispose_resources(dev)
    time.sleep(1.5)
    dev = find_dev()
    if dev is None:
        print("device vanished after reset"); return 2
    print("reacquired  bus=%d addr=%d" % (dev.bus, dev.address))

    detached = False
    claimed = False
    try:
        if dev.is_kernel_driver_active(IFACE_CMD):
            print("detaching kernel driver from iface %d ..." % IFACE_CMD)
            dev.detach_kernel_driver(IFACE_CMD)
            detached = True
        usb.util.claim_interface(dev, IFACE_CMD)
        claimed = True
        print("claimed iface %d" % IFACE_CMD)
        clear_halts(dev)
        print()

        # --- GET_VERSION (0x01) ---
        print("== GET_VERSION (0x01) ==")
        resp = send_raw(dev, struct.pack("<B", CMD_GET_VERSION), 0x26)
        print("resp %d bytes:" % len(resp)); print(hexdump(resp))
        if len(resp) >= 2:
            status = struct.unpack_from("<H", resp, 0)[0]
            print("  status = 0x%04x %s" % (status, "OK" if status == 0 else "**nonzero**"))
        if len(resp) >= 38:
            (fw_build, fw_major, fw_minor, product_id, sid, flags1, flags2,
             prov_state) = struct.unpack("<2xxxxxIBBxbxxxx6sbbxxxxxxxxxxxB", resp[:38])
            adv_sec = (flags1 & 1) != 0
            key_flag = (flags2 & 0x20) != 0
            print("  FW version : %d.%d.%d" % (fw_major, fw_minor, fw_build))
            print("  product id : 0x%02x" % (product_id & 0xff))
            print("  sensor id  : %s" % sid.hex())
            print("  adv security: %s   key_flag: %s" % (adv_sec, key_flag))
            ps = prov_state & 0xf
            print("  PROVISION STATE = %d (%s)" % (ps, PROV_STATES.get(ps, "unknown")))
        print()

        # --- GET_START_INFO (0x19) ---
        print("== GET_START_INFO (0x19) ==")
        resp = send_raw(dev, struct.pack("<B", CMD_GET_START_INFO), 0x44)
        print("resp %d bytes:" % len(resp)); print(hexdump(resp))
        if len(resp) >= 2:
            status = struct.unpack_from("<H", resp, 0)[0]
            print("  status = 0x%04x %s" % (status, "OK" if status == 0 else "**nonzero**"))
        if len(resp) >= 68:
            start_type, reset_type, start_code = struct.unpack_from("<2xBBI", resp, 0)
            print("  start_type=0x%02x reset_type=0x%02x start_code=0x%x"
                  % (start_type, reset_type, start_code))
        print("\nP0a OK — transport confirmed: cmd OUT 0x01 / resp IN 0x81 on iface0.")
        return 0

    except usb.core.USBError as e:
        print("\nUSBError: %s" % e)
        print("(errno=%s)  If BUSY on claim: hidraw/hid-generic still holds iface0." % getattr(e, "errno", "?"))
        return 1
    finally:
        if claimed:
            try: usb.util.release_interface(dev, IFACE_CMD)
            except Exception: pass
        if detached:
            try:
                dev.attach_kernel_driver(IFACE_CMD)
                print("reattached kernel driver to iface %d" % IFACE_CMD)
            except Exception as e:
                print("warn: could not reattach kernel driver: %s" % e)
        usb.util.dispose_resources(dev)


if __name__ == "__main__":
    sys.exit(main())
