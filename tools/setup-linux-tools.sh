#!/usr/bin/env bash
#
# setup-linux-tools.sh — install the Linux-side RE + driver-dev toolchain.
# Idempotent-ish; safe to re-run. Fedora (dnf). Elevates for package installs.
#
set -u
log() { printf '\n== %s ==\n' "$*"; }

log "dnf: USB + capture + build tools"
sudo dnf install -y \
    usbutils usbhid-dump \
    python3 python3-pip python3-devel gcc \
    wireshark-cli \
    libusb1 libusb1-devel \
    git meson ninja-build pkgconf-pkg-config || true

log "dnf: libfprint build dependencies (for the eventual driver)"
sudo dnf install -y \
    glib2-devel gusb-devel pixman-devel nss-devel \
    gobject-introspection-devel cairo-gobject-devel \
    gtk-doc || true

log "pip (user): device + capture + crypto + frida"
pip install --user --upgrade pyusb pyshark hidapi cryptography frida-tools || true

log "usbmon (USB capture kernel module)"
sudo modprobe usbmon && echo "usbmon loaded" || echo "could not load usbmon"

log ".NET SDK + ilspycmd (for any managed/.NET components)"
if ! command -v dotnet >/dev/null; then
    sudo dnf install -y dotnet-sdk-8.0 || echo "install dotnet-sdk manually if this failed"
fi
if command -v dotnet >/dev/null; then
    dotnet tool install --global ilspycmd 2>/dev/null || dotnet tool update --global ilspycmd || true
    echo 'Add to shell rc:  export PATH="$PATH:$HOME/.dotnet/tools"'
fi

log "fido2-tools (interface-0 FIDO probing)"
sudo dnf install -y fido2-tools || true

cat <<'NOTE'

== manual, not scriptable here ==
  * Ghidra (native RE): download https://ghidra-sre.org/  (needs JDK 21).
      Then GhidraMCP: https://github.com/lauriewired/ghidramcp
  * Frida: installed above (frida-tools); the JS hook runs on the WINDOWS RE box.
  * Windows RE box/VM: Kensington VeriMark driver + Wireshark + USBPcap + Ghidra/ILSpy.
See ../RESEARCH-PROMPT.md for the full workflow.
NOTE
