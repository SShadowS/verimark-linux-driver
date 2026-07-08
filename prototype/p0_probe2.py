#!/usr/bin/env python3
"""
P0a v2 — VeriMark (047d:00f2) transport DIAGNOSTIC. READ-ONLY, NO WRITES to sensor
storage (only raw query opcodes).

Open question this resolves: after writing a bare command opcode to iface0 EP 0x01
(the device's only OUT endpoint), does the RESPONSE come back on:
   (a) iface0 EP 0x81  (60-B interrupt-IN)   -- findings/26 hypothesis, or
   (b) iface1 EP 0x83  (8-B  interrupt-IN)   -- original RESUME brief hypothesis
It writes each raw opcode then tries reading BOTH IN endpoints and reports which
delivers, with hexdumps. Also checks for spontaneous events on 0x83 before any write.

Behavioral constants reused from synaTudor `rev` as documented facts; no vendor code.
"""
import sys, struct, time
import usb.core, usb.util

VID, PID = 0x047d, 0x00f2
EP_CMD_OUT = 0x01
EP_IN_A    = 0x81   # iface0, 60 B
EP_IN_B    = 0x83   # iface1, 8 B
IF0, IF1   = 0, 1

CMD_GET_VERSION    = 0x01
CMD_GET_START_INFO = 0x19


def hexdump(b, width=16):
    out = []
    for i in range(0, len(b), width):
        c = b[i:i+width]
        out.append("    %04x  %s" % (i, " ".join("%02x" % x for x in c)))
    return "\n".join(out) if b else "    (empty)"


def find_dev():
    return usb.core.find(idVendor=VID, idProduct=PID)


def try_read(dev, ep, want, timeout, label):
    try:
        data = bytes(dev.read(ep, want, timeout))
        print("  read %s (0x%02x, asked %d): GOT %d bytes" % (label, ep, want, len(data)))
        print(hexdump(data))
        return data
    except usb.core.USBError as e:
        print("  read %s (0x%02x, asked %d): %s" % (label, ep, want, e))
        return None


def main():
    dev = find_dev()
    if dev is None:
        print("device not found"); return 2
    print("found  bus=%d addr=%d" % (dev.bus, dev.address))
    do_reset = "noreset" not in sys.argv
    if do_reset:
        try:
            dev.reset()
            print("reset ok")
        except Exception as e:
            print("(reset: %s)" % e)
        usb.util.dispose_resources(dev)
        time.sleep(2.0)
        dev = find_dev()
        if dev is None:
            print("device vanished after reset"); return 2
    else:
        print("(skipping USB reset)")

    claimed = []
    detached = []
    try:
        for i in (IF0, IF1):
            try:
                if dev.is_kernel_driver_active(i):
                    dev.detach_kernel_driver(i); detached.append(i)
            except usb.core.USBError as e:
                print("(is_kernel_driver_active/detach iface %d: %s)" % (i, e))
            try:
                usb.util.claim_interface(dev, i); claimed.append(i)
                print("claimed iface %d" % i)
            except usb.core.USBError as e:
                print("claim iface %d FAILED: %s" % (i, e))
        for ep in (EP_CMD_OUT, EP_IN_A, EP_IN_B):
            try: dev.clear_halt(ep)
            except Exception: pass
        print()

        # 0) spontaneous event on 0x83 before any command?
        print("== pre-command: poll 0x83 for spontaneous event (300ms) ==")
        try_read(dev, EP_IN_B, 8, 300, "IN_B/0x83")
        print()

        for name, opc, rsz in (("GET_VERSION", CMD_GET_VERSION, 0x26),
                               ("GET_START_INFO", CMD_GET_START_INFO, 0x44)):
            print("== %s (0x%02x) ==" % (name, opc))
            try:
                n = dev.write(EP_CMD_OUT, struct.pack("<B", opc), 1000)
                print("  write 0x01: ok (%d)" % n)
            except usb.core.USBError as e:
                print("  write 0x01 FAILED: %s" % e); print(); continue
            # try the 60-B iface0 IN first, then the 8-B iface1 IN
            a = try_read(dev, EP_IN_A, ((rsz + 59)//60)*60, 800, "IN_A/0x81")
            if not a:
                try_read(dev, EP_IN_B, ((rsz + 7)//8)*8, 800, "IN_B/0x83")
            print()
        return 0
    finally:
        for i in claimed:
            try: usb.util.release_interface(dev, i)
            except Exception: pass
        for i in detached:
            try: dev.attach_kernel_driver(i)
            except Exception: pass
        usb.util.dispose_resources(dev)
        print("cleaned up (released/reattached)")


if __name__ == "__main__":
    sys.exit(main())
