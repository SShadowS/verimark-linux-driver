#!/usr/bin/env bash
#
# find-device.sh — locate the VeriMark 047d:00f2 on the USB bus.
# Prints sysfs path, bus/dev numbers, interfaces, hidraw nodes, and exports
# VM_SYS / VM_BUSNUM / VM_DEVNUM / VM_HIDRAW for scripts that `source` it.
#   ./find-device.sh            (human-readable)
#   source ./find-device.sh --quiet   (just set the vars)
#
VID=047d; PID=00f2

_vm_find() {
    local v d
    for v in /sys/bus/usb/devices/*/idVendor; do
        d=$(dirname "$v")
        [ "$(cat "$v" 2>/dev/null)" = "$VID" ] || continue
        [ "$(cat "$d/idProduct" 2>/dev/null)" = "$PID" ] || continue
        printf '%s\n' "$d"; return 0
    done
    return 1
}

VM_SYS=$(_vm_find)
if [ -z "${VM_SYS:-}" ]; then
    echo "VeriMark $VID:$PID not found on USB (plugged in?)" >&2
    return 1 2>/dev/null || exit 1
fi
VM_BUSNUM=$(cat "$VM_SYS/busnum" 2>/dev/null)
VM_DEVNUM=$(cat "$VM_SYS/devnum" 2>/dev/null)
_base=$(basename "$VM_SYS")
VM_HIDRAW=$(for h in /sys/class/hidraw/hidraw*; do
    [ -e "$h/device" ] || continue
    case "$(readlink -f "$h/device")" in
        *"$_base"*) printf '/dev/%s ' "$(basename "$h")" ;;
    esac
done)
export VM_SYS VM_BUSNUM VM_DEVNUM VM_HIDRAW

if [ "${1:-}" != "--quiet" ]; then
    echo "sysfs : $VM_SYS"
    echo "bus   : $VM_BUSNUM   dev: $VM_DEVNUM   (usbmon: capture on 'usbmon$VM_BUSNUM')"
    echo "hidraw: ${VM_HIDRAW:-<none>}"
    echo "ifaces:"
    for i in "$VM_SYS/$_base":*; do
        [ -e "$i/bInterfaceClass" ] || continue
        printf '  %-14s class=0x%s proto=0x%s\n' \
            "$(basename "$i")" \
            "$(cat "$i/bInterfaceClass")" "$(cat "$i/bInterfaceProtocol" 2>/dev/null)"
    done
fi
