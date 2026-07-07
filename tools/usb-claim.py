#!/usr/bin/env python3
"""Talk to a raw VeriMark interface via libusb (pyusb).

Detaches the kernel driver from the chosen interface, claims it, and lets you
write/read on its endpoints. Interface 1 = vendor biometric (the driver target);
interface 0 = FIDO HID.

  sudo ./usb-claim.py --iface 1 --info
  sudo ./usb-claim.py --iface 1 --send 0a0b0c   # write hex to OUT ep, read IN
  sudo ./usb-claim.py --iface 1 --listen        # just read the IN ep

Note (see device-facts.md): interface 1 declares only an interrupt-IN endpoint
(0x83). If there is no OUT endpoint, host->device data goes via CONTROL transfers
(--ctrl), not this interface's endpoints. Confirm the real path from a capture.

Requires: pip install pyusb ; run as root (or add a udev rule for 047d:00f2).
"""
import sys
import argparse

try:
    import usb.core
    import usb.util
except ImportError:
    sys.exit("need pyusb:  pip install --user pyusb")

VID, PID = 0x047D, 0x00F2


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", type=int, required=True)
    ap.add_argument("--send", help="hex bytes to write to the first OUT endpoint")
    ap.add_argument("--listen", action="store_true", help="read the IN endpoint")
    ap.add_argument("--info", action="store_true", help="just print endpoints")
    ap.add_argument("--timeout", type=int, default=2000)
    a = ap.parse_args()

    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        sys.exit("VeriMark 047d:00f2 not found")

    reattach = False
    try:
        if dev.is_kernel_driver_active(a.iface):
            dev.detach_kernel_driver(a.iface)
            reattach = True
    except (usb.core.USBError, NotImplementedError):
        pass
    usb.util.claim_interface(dev, a.iface)

    cfg = dev.get_active_configuration()
    intf = cfg[(a.iface, 0)]
    ep_out = usb.util.find_descriptor(
        intf, custom_match=lambda e:
        usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
    ep_in = usb.util.find_descriptor(
        intf, custom_match=lambda e:
        usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)

    out_a = hex(ep_out.bEndpointAddress) if ep_out else None
    in_a = hex(ep_in.bEndpointAddress) if ep_in else None
    print(f"iface {a.iface}:  OUT={out_a}  IN={in_a}")

    try:
        if a.send:
            if not ep_out:
                print("no OUT endpoint on this interface — use control transfers "
                      "(see docstring)", file=sys.stderr)
            else:
                n = ep_out.write(bytes.fromhex(a.send), a.timeout)
                print(f"wrote {n} bytes")

        if (a.send or a.listen) and ep_in:
            try:
                data = ep_in.read(ep_in.wMaxPacketSize, a.timeout)
                print("recv:", bytes(data).hex())
            except usb.core.USBError as e:
                print("read:", e)
    finally:
        usb.util.release_interface(dev, a.iface)
        if reattach:
            try:
                dev.attach_kernel_driver(a.iface)
            except usb.core.USBError:
                pass


if __name__ == "__main__":
    main()
