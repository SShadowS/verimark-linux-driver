#!/usr/bin/env bash
# install-verimark.sh — point the SYSTEM fprintd at the locally-built,
# verimark-enabled libfprint for on-device testing, WITHOUT touching
# /usr/lib*/libfprint-2.so* and WITHOUT `meson install`.
#
# Mechanism (fully reversible):
#   1. Install driver/60-verimark.rules into /usr/lib/udev/rules.d/ so the
#      logged-in seat gets uaccess to 047d:00f2.
#   2. Drop a systemd unit override on fprintd.service that sets
#      LD_LIBRARY_PATH to the build's libfprint/ dir, so the dynamic linker
#      finds our libfprint-2.so.2 before the system one on the default
#      search path. fprintd is D-Bus-activated, so stopping it is enough to
#      make the next activation pick up the new environment.
#
# --uninstall removes both changes and restarts fprintd on the stock system
# libfprint. Both directions are idempotent — safe to re-run.
#
# What this script does NOT do:
#   - It never runs `meson install` / `ninja install`.
#   - It never writes to /usr/lib*/libfprint-2.so* or any file owned by the
#     fprintd/libfprint RPMs.
#   - It never runs itself with sudo; individual privileged steps are
#     announced and run via `sudo` one at a time.
#
# Usage:
#   ./driver/install-verimark.sh [--build-dir PATH]
#   ./driver/install-verimark.sh --uninstall
#   ./driver/install-verimark.sh --help

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

DEFAULT_BUILD_DIR="/home/sshadows/verimark-build/libfprint/build"
BUILD_DIR="${VERIMARK_BUILD_DIR:-$DEFAULT_BUILD_DIR}"
DO_UNINSTALL=0

UDEV_RULE_SRC="$SCRIPT_DIR/60-verimark.rules"
UDEV_RULE_DST="/usr/lib/udev/rules.d/60-verimark.rules"

DROPIN_DIR="/etc/systemd/system/fprintd.service.d"
DROPIN_FILE="$DROPIN_DIR/10-verimark-libfprint.conf"

log()  { echo "==> $*"; }
warn() { echo "==> WARNING: $*" >&2; }
die()  { echo "==> ERROR: $*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: $(basename "$0") [--build-dir PATH] [--uninstall] [--help]

Point the system fprintd at a locally-built verimark-enabled libfprint via a
systemd drop-in (LD_LIBRARY_PATH), plus install the VeriMark udev rule.
Non-destructive: never touches /usr/lib*/libfprint-2.so*, never runs
'meson install'.

Options:
  --build-dir PATH   Path to the libfprint meson build directory whose
                      libfprint/ subdir holds libfprint-2.so.2.
                      Default: $DEFAULT_BUILD_DIR
                      (also settable via \$VERIMARK_BUILD_DIR)
  --uninstall         Revert: remove the systemd drop-in and udev rule, and
                      restart fprintd on the stock system libfprint.
  --help              Show this help and exit.

Examples:
  ./driver/install-verimark.sh
  ./driver/install-verimark.sh --build-dir /path/to/build
  ./driver/install-verimark.sh --uninstall
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --build-dir)
      [ $# -ge 2 ] || die "--build-dir requires an argument"
      BUILD_DIR="$2"
      shift 2
      ;;
    --build-dir=*)
      BUILD_DIR="${1#*=}"
      shift
      ;;
    --uninstall)
      DO_UNINSTALL=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "Unknown argument: $1 (see --help)"
      ;;
  esac
done

stop_fprintd() {
  # fprintd is D-Bus-activated (Type=dbus, no [Install] section). If it's
  # running, stop it so the next activation re-execs with the new/old
  # environment. If it isn't running, there's nothing to do — don't fail.
  if systemctl is-active --quiet fprintd 2>/dev/null; then
    log "Stopping fprintd (it will D-Bus-reactivate on next use)"
    sudo systemctl stop fprintd
  else
    log "fprintd is not currently active — nothing to stop (it will pick up the change on next activation)"
  fi
}

do_uninstall() {
  log "Reverting to the system fprintd + system libfprint"

  if [ -f "$DROPIN_FILE" ]; then
    log "Removing systemd drop-in: $DROPIN_FILE"
    sudo rm -f "$DROPIN_FILE"
  else
    log "Systemd drop-in already absent: $DROPIN_FILE"
  fi

  if [ -d "$DROPIN_DIR" ] && [ -z "$(ls -A "$DROPIN_DIR" 2>/dev/null)" ]; then
    log "Removing now-empty drop-in dir: $DROPIN_DIR"
    sudo rmdir "$DROPIN_DIR"
  fi

  if [ -f "$UDEV_RULE_DST" ]; then
    log "Removing udev rule: $UDEV_RULE_DST"
    sudo rm -f "$UDEV_RULE_DST"
  else
    log "udev rule already absent: $UDEV_RULE_DST"
  fi

  log "Reloading systemd units"
  sudo systemctl daemon-reload

  log "Reloading udev rules"
  sudo udevadm control --reload-rules
  sudo udevadm trigger --subsystem-match=usb || true

  stop_fprintd

  log "Done. fprintd will re-activate using the system libfprint-2.so.2"
  log "(the built-in Synaptics 06cb:0126 reader and any other supported"
  log "readers are back to normal; verimark support is removed)."
}

do_install() {
  # Resolve LIBDIR to an absolute path.
  local build_dir_abs
  build_dir_abs="$(readlink -f -- "$BUILD_DIR" 2>/dev/null || true)"
  [ -n "$build_dir_abs" ] || die "--build-dir '$BUILD_DIR' does not exist"
  LIBDIR="$build_dir_abs/libfprint"

  log "Build dir:  $build_dir_abs"
  log "Library dir: $LIBDIR"

  # ---- Preflight -----------------------------------------------------------
  local sofile=""
  if [ -e "$LIBDIR/libfprint-2.so.2.0.0" ]; then
    sofile="$LIBDIR/libfprint-2.so.2.0.0"
  elif [ -e "$LIBDIR/libfprint-2.so.2" ]; then
    sofile="$LIBDIR/libfprint-2.so.2"
  fi

  if [ -z "$sofile" ]; then
    die "No libfprint-2.so.2(.0.0) found under $LIBDIR
     Run ./driver/setup-libfprint-build.sh first to produce the build."
  fi
  log "Found built library: $sofile"

  log "Verifying the verimark driver is linked in"
  local has_verimark=0
  if command -v nm >/dev/null 2>&1; then
    if nm -D "$sofile" 2>/dev/null | grep -q fpi_device_verimark \
       || nm "$sofile" 2>/dev/null | grep -q fpi_device_verimark; then
      has_verimark=1
    fi
  fi
  if [ "$has_verimark" -eq 0 ] && command -v strings >/dev/null 2>&1; then
    if strings "$sofile" | grep -q 047d; then
      has_verimark=1
    fi
  fi
  [ "$has_verimark" -eq 1 ] || die "$sofile does not appear to contain the verimark driver
     (no fpi_device_verimark symbol / no '047d' string found).
     Run ./driver/setup-libfprint-build.sh first (with -Ddrivers=verimark or
     -Ddrivers=default,verimark) to produce a build that includes it."
  log "Confirmed: verimark driver is present in this build"

  # ---- Verimark-only heuristic warning -------------------------------------
  local has_synaptics=0
  if command -v nm >/dev/null 2>&1; then
    if nm -D "$sofile" 2>/dev/null | grep -q fpi_device_synaptics \
       || nm "$sofile" 2>/dev/null | grep -q fpi_device_synaptics; then
      has_synaptics=1
    fi
  fi
  if [ "$has_synaptics" -eq 0 ]; then
    warn "This build looks verimark-ONLY (no fpi_device_synaptics symbol)."
    warn "While this drop-in is active, fprintd will only see the VeriMark"
    warn "(047d:00f2) — the built-in Synaptics reader (06cb:0126) will be"
    warn "SHADOWED (its driver isn't in this .so, so fprintd can't use it)."
    warn "This is fine for a focused VeriMark test. To keep both readers"
    warn "working simultaneously, rebuild with:"
    warn "  ./driver/setup-libfprint-build.sh --drivers=default,verimark"
    warn "Continuing anyway."
  fi

  # ---- 1. udev rule ---------------------------------------------------------
  [ -f "$UDEV_RULE_SRC" ] || die "udev rule not found: $UDEV_RULE_SRC"
  log "Installing udev rule -> $UDEV_RULE_DST"
  sudo install -m0644 "$UDEV_RULE_SRC" "$UDEV_RULE_DST"

  log "Reloading udev rules"
  sudo udevadm control --reload-rules
  sudo udevadm trigger --subsystem-match=usb || true

  # ---- 2. systemd drop-in ---------------------------------------------------
  log "Creating systemd drop-in dir: $DROPIN_DIR"
  sudo mkdir -p "$DROPIN_DIR"

  log "Writing systemd drop-in: $DROPIN_FILE"
  sudo tee "$DROPIN_FILE" >/dev/null <<EOF
[Service]
Environment=LD_LIBRARY_PATH=$LIBDIR
EOF

  log "Reloading systemd units"
  sudo systemctl daemon-reload

  stop_fprintd
  log "(Note: a stop is sufficient — fprintd is D-Bus-activated and will"
  log "re-exec with the new environment on next use. Restarting explicitly"
  log "is also fine: sudo systemctl restart fprintd)"

  # ---- Post-install summary --------------------------------------------------
  cat <<EOF

==> Install complete.

Verify the drop-in took effect:
    systemctl show fprintd -p Environment
  should print:
    Environment=LD_LIBRARY_PATH=$LIBDIR

Test on-device:
  1. Plug in the Kensington VeriMark Desktop (047d:00f2).
  2. fprintd-enroll
       (press-and-hold; ~8 taps needed to reach full coverage, bitmask 0x7f)
  3. fprintd-verify

Revert everything (restore stock system libfprint, remove udev rule):
    ./driver/install-verimark.sh --uninstall

EOF
}

if [ "$DO_UNINSTALL" -eq 1 ]; then
  do_uninstall
else
  do_install
fi
