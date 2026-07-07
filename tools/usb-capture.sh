#!/usr/bin/env bash
#
# usb-capture.sh — capture the VeriMark's USB traffic into ../captures/.
# Uses tshark + usbmon, filtered to the device's address.
#   ./usb-capture.sh            capture until Ctrl-C
#   ./usb-capture.sh 30         capture for 30 seconds
#
# NOTE: the *authoritative* handshake capture must be taken on Windows with
# USBPcap while the Kensington driver enrolls a finger (Linux can't enroll it).
# This script is for Linux-side experiments and prototype validation.
#
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$HERE/find-device.sh" --quiet || { echo "device not found" >&2; exit 1; }

mkdir -p "$HERE/../captures"
OUT="$HERE/../captures/verimark-$(date +%Y%m%d-%H%M%S).pcapng"

sudo modprobe usbmon 2>/dev/null
echo "Capturing bus $VM_BUSNUM, device address $VM_DEVNUM"
echo "  -> $OUT"
echo "Exercise the device now (swipe / plug). Ctrl-C to stop."

FILTER="usb.device_address == ${VM_DEVNUM}"
if [ -n "${1:-}" ]; then
    sudo tshark -i "usbmon${VM_BUSNUM}" -a "duration:$1" -Y "$FILTER" -w "$OUT"
else
    sudo tshark -i "usbmon${VM_BUSNUM}" -Y "$FILTER" -w "$OUT"
fi
echo "Saved: $OUT"
echo "Next: ./extract-usb-payloads.py '$OUT' --dev $VM_DEVNUM"
