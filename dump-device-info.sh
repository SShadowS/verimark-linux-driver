#!/usr/bin/env bash
#
# dump-device-info.sh — snapshot everything Linux can see about the VeriMark
# Desktop (047d:00f2) into ./reference/. Safe, read-only, re-runnable.
# Run from the verimark-driver/ folder. Uses sudo for the verbose descriptor.
#
set -u
VID=047d; PID=00f2
HERE="$(cd "$(dirname "$0")" && pwd)"
REF="$HERE/reference"
mkdir -p "$REF"
log() { printf '  %s\n' "$*"; }

echo "### snapshotting $VID:$PID into $REF/"

# 1. Verbose USB descriptor (needs root for the full dump)
sudo lsusb -v -d "$VID:$PID" > "$REF/lsusb-verbose.txt" 2>/dev/null \
    && log "[ok] lsusb-verbose.txt" || log "[--] lsusb -v failed (device unplugged?)"

# 2. Topology
lsusb -t > "$REF/usb-topology.txt" 2>/dev/null && log "[ok] usb-topology.txt"

# 3. sysfs attributes
SYS="$(dirname "$(grep -l "^${VID}\$" /sys/bus/usb/devices/*/idVendor 2>/dev/null | \
       while read -r f; do d="$(dirname "$f")"; \
       [ "$(cat "$d/idProduct" 2>/dev/null)" = "$PID" ] && echo "$f"; done | head -1)" 2>/dev/null)"
if [ -n "${SYS:-}" ] && [ -e "$SYS/idVendor" ]; then
    { echo "sysfs path: $SYS"
      for a in idVendor idProduct manufacturer product bcdDevice bMaxPower speed version bNumInterfaces; do
          [ -e "$SYS/$a" ] && printf '%-16s %s\n' "$a" "$(cat "$SYS/$a" 2>/dev/null)"
      done; } > "$REF/sysfs-attrs.txt"
    log "[ok] sysfs-attrs.txt ($SYS)"
fi

# 4. HID report descriptor (raw bytes) via usbhid-dump
if command -v usbhid-dump >/dev/null; then
    sudo usbhid-dump -d "$VID:$PID" > "$REF/usbhid-dump.txt" 2>/dev/null && log "[ok] usbhid-dump.txt"
else
    log "[--] usbhid-dump missing (sudo dnf install usbutils)"
fi

# 5. HID report descriptor (decoded) via debugfs
RDESC="$(find /sys/kernel/debug/hid -maxdepth 2 -iname rdesc 2>/dev/null | \
         while read -r r; do case "$(basename "$(dirname "$r")")" in *${VID^^}:${PID^^}*) echo "$r";; esac; done | head -1)"
if [ -n "${RDESC:-}" ]; then
    sudo cat "$RDESC" > "$REF/hid-report-descriptor.txt" 2>/dev/null && log "[ok] hid-report-descriptor.txt"
else
    log "[--] HID rdesc not in debugfs (try: sudo mount -t debugfs none /sys/kernel/debug)"
fi

# 6. FIDO probe (interface 0)
if command -v fido2-token >/dev/null; then
    DEV="$(fido2-token -L 2>/dev/null | grep -i "$VID:$PID\|vendor=0x$VID" | head -1 | cut -d: -f1)"
    { echo "# fido2-token probe  ($(date -Iseconds))"
      echo "## -L"; fido2-token -L 2>&1
      [ -n "${DEV:-}" ] && { echo; echo "## -I $DEV"; fido2-token -I "$DEV" 2>&1; }
    } > "$REF/fido2-probe.txt"
    log "[ok] fido2-probe.txt"
else
    log "[--] fido2-token missing (sudo dnf install fido2-tools)"
fi

echo "### done -> $REF/"
