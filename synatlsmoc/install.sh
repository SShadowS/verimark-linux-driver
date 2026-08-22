#!/usr/bin/env bash
# install.sh — point the system fprintd at the synatlsmoc-based libfprint built
# by ./build.sh, so BOTH readers work: the Kensington VeriMark Desktop
# (047d:00f2, driver synatlsmoc) and the built-in Synaptics (06cb:0126, driver
# synaptics). Fully reversible; never touches the packaged /usr/lib*/libfprint.
#
# RUN WITH SUDO:  sudo ./install.sh
#
# What it does (mirrors the proven, SELinux-safe pattern from ../driver):
#   1. Removes our OLD clean-room verimark install if present (its drop-in +
#      relocated .so), so it can't shadow this one.
#   2. Copies dist/libfprint-2.so.2.0.0 into a SYSTEM lib path and relabels it
#      lib_t. REQUIRED: under SELinux Enforcing, fprintd runs confined as
#      fprintd_t and cannot dlopen a library from /home (or an unlabeled path);
#      ld.so silently falls back to the system libfprint and only stock readers
#      work. A system path relabeled lib_t is the verified fix.
#   3. Creates a root-owned 0700 dir for the driver's persistent pairing data
#      (the host EC key + sensor certs the driver writes on first pairing).
#   4. Drops a systemd override on fprintd.service that sets LD_LIBRARY_PATH +
#      SYNA_TLSMOC_PERSISTENT_DATA_FILE and adds `--no-timeout` (keeps the
#      daemon warm: ~2s auth instead of ~10s cold).
#   5. Installs the 047d:00f2 uaccess udev rule.
#
# The driver AUTO-PAIRS from Linux on the first open (first `fprintd-enroll`):
# it sends one PAIR (0x93), which REPLACES any existing Windows pairing, then
# writes the new pairing to the persistent file. No separate pairing step.
#
# Usage:
#   sudo ./install.sh                 # install (default; uses ./dist)
#   sudo ./install.sh --so PATH       # install a specific libfprint-2.so.2.0.0
#   sudo ./install.sh --status        # show current state
#   sudo ./install.sh --uninstall     # revert to stock libfprint (keeps pairing)
#   sudo ./install.sh --purge         # revert AND wipe pairing + enrolled prints
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# --- constants (exact paths; never rm -rf a variable that isn't one of these) -
RELOC_DIR="/usr/local/lib64/verimark-synatlsmoc"
DROPIN_DIR="/etc/systemd/system/fprintd.service.d"
DROPIN_FILE="$DROPIN_DIR/10-verimark-synatlsmoc.conf"
PDATA_DIR="/var/lib/fprint/verimark/047d-00f2"
PDATA_FILE="$PDATA_DIR/libfprint-persistent.bin"
UDEV_RULE_SRC="$SCRIPT_DIR/60-verimark.rules"
UDEV_RULE_DST="/usr/lib/udev/rules.d/60-verimark.rules"
FPRINTD_BIN="/usr/libexec/fprintd"

# old clean-room install (from ../driver/install-verimark.sh) — remove if present
OLD_RELOC_DIR="/usr/local/lib64/verimark-libfprint"
OLD_DROPIN_FILE="$DROPIN_DIR/10-verimark-libfprint.conf"

SO_SRC="$SCRIPT_DIR/dist/libfprint-2.so.2.0.0"
MODE="install"

log()  { echo "==> $*"; }
warn() { echo "==> WARNING: $*" >&2; }
die()  { echo "==> ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --so)         [ $# -ge 2 ] || die "--so needs a path"; SO_SRC="$2"; shift 2 ;;
    --so=*)       SO_SRC="${1#*=}"; shift ;;
    --status)     MODE="status"; shift ;;
    --uninstall)  MODE="uninstall"; shift ;;
    --purge)      MODE="purge"; shift ;;
    -h|--help)    grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)            die "unknown argument: $1 (see --help)" ;;
  esac
done

need_root() { [ "$(id -u)" -eq 0 ] || die "run with sudo: sudo $0 ${MODE/install/}"; }

stop_fprintd() {
  # fprintd is D-Bus-activated; stopping is enough — it re-execs with the new
  # environment on next use.
  if systemctl is-active --quiet fprintd 2>/dev/null; then
    log "Stopping fprintd (re-activates on next use)"
    systemctl stop fprintd || true
  fi
}

reload_all() {
  log "Reloading systemd + udev"
  systemctl daemon-reload
  udevadm control --reload-rules
  udevadm trigger --subsystem-match=usb || true
}

remove_old_cleanroom() {
  if [ -f "$OLD_DROPIN_FILE" ]; then
    log "Removing old clean-room drop-in: $OLD_DROPIN_FILE"
    rm -f "$OLD_DROPIN_FILE"
  fi
  if [ -d "$OLD_RELOC_DIR" ] && [ "$OLD_RELOC_DIR" = "/usr/local/lib64/verimark-libfprint" ]; then
    log "Removing old clean-room library dir: $OLD_RELOC_DIR"
    rm -rf -- "$OLD_RELOC_DIR"
  fi
}

do_status() {
  echo "== synatlsmoc / VeriMark install status =="
  echo "prebuilt .so : $SO_SRC $( [ -f "$SO_SRC" ] && echo "($(sha256sum "$SO_SRC" | awk '{print $1}'))" || echo '(missing — run ./build.sh)')"
  echo "installed .so: $( [ -f "$RELOC_DIR/libfprint-2.so.2.0.0" ] && echo "$RELOC_DIR/libfprint-2.so.2.0.0" || echo '(none)')"
  if [ -f "$RELOC_DIR/libfprint-2.so.2.0.0" ] && command -v ls >/dev/null; then
    echo "  SELinux type: $(ls -Z "$RELOC_DIR/libfprint-2.so.2.0.0" 2>/dev/null | awk '{print $1}')"
  fi
  echo "drop-in      : $( [ -f "$DROPIN_FILE" ] && echo "$DROPIN_FILE" || echo '(none)')"
  echo "udev rule    : $( [ -f "$UDEV_RULE_DST" ] && echo "$UDEV_RULE_DST" || echo '(none)')"
  echo "pairing file : $( [ -f "$PDATA_FILE" ] && echo "$PDATA_FILE (present — paired)" || echo '(none — will pair on first enroll)')"
  echo "old install  : $( [ -f "$OLD_DROPIN_FILE" ] || [ -d "$OLD_RELOC_DIR" ] && echo 'PRESENT (will be removed on install)' || echo 'absent')"
  echo "fprintd      : $(systemctl is-active fprintd 2>/dev/null || echo inactive) (D-Bus activated)"
  echo "Environment  :"; systemctl show fprintd -p Environment -p ExecStart 2>/dev/null | sed 's/^/  /'
  if command -v fprintd-list >/dev/null 2>&1; then
    echo "fprintd sees :"
    timeout 15 fprintd-list "${SUDO_USER:-root}" 2>/dev/null | grep -iE 'Device at|found|Fingerprints' | sed 's/^/  /' || true
  fi
}

do_install() {
  need_root
  [ -f "$SO_SRC" ] || die "library not found: $SO_SRC
     Build it first (as your normal user): ./build.sh"
  [ -x "$FPRINTD_BIN" ] || die "fprintd binary not found at $FPRINTD_BIN"

  # sanity: the .so must carry both drivers
  local strs; strs="$(strings "$SO_SRC" 2>/dev/null || true)"
  case "$strs" in *synatlsmoc*) : ;; *) die "$SO_SRC has no synatlsmoc driver" ;; esac
  log "Library validated: $SO_SRC"

  remove_old_cleanroom

  # 1. relocate + relabel
  log "Installing library -> $RELOC_DIR (relabel lib_t for SELinux fprintd_t)"
  install -d -m0755 "$RELOC_DIR"
  install -m0755 "$SO_SRC" "$RELOC_DIR/libfprint-2.so.2.0.0"
  ln -sf libfprint-2.so.2.0.0 "$RELOC_DIR/libfprint-2.so.2"
  if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
    chcon -t lib_t "$RELOC_DIR/libfprint-2.so.2.0.0"
  fi

  # 2. persistent pairing dir (driver writes host key + sensor certs here)
  log "Creating persistent pairing dir: $PDATA_DIR (root:root 0700)"
  install -d -m0700 -o root -g root "$PDATA_DIR"
  if command -v restorecon >/dev/null 2>&1; then restorecon -R "$PDATA_DIR" 2>/dev/null || true; fi

  # 3. systemd drop-in
  log "Writing systemd drop-in: $DROPIN_FILE"
  install -d -m0755 "$DROPIN_DIR"
  cat > "$DROPIN_FILE" <<EOF
[Service]
Environment=LD_LIBRARY_PATH=$RELOC_DIR
Environment=SYNA_TLSMOC_PERSISTENT_DATA_FILE=$PDATA_FILE
# keep the daemon warm so match-in-sensor auth is ~2s, not ~10s cold:
ExecStart=
ExecStart=$FPRINTD_BIN --no-timeout
EOF

  # 4. udev rule
  [ -f "$UDEV_RULE_SRC" ] || die "udev rule missing: $UDEV_RULE_SRC"
  log "Installing udev rule -> $UDEV_RULE_DST"
  install -m0644 "$UDEV_RULE_SRC" "$UDEV_RULE_DST"

  reload_all
  stop_fprintd

  cat <<EOF

==> Install complete.

Verify the environment took effect:
    systemctl show fprintd -p Environment -p ExecStart

Enroll (this triggers the one-time Linux pairing, replacing any Windows pairing):
    1. Plug the Kensington VeriMark Desktop (047d:00f2) directly into the machine.
    2. fprintd-enroll            # press-and-hold; ~7 presses to full coverage
    3. fprintd-verify
    Unplug the VeriMark and 'fprintd-enroll' again to use the built-in reader.

Revert to stock libfprint (keeps pairing):   sudo ./install.sh --uninstall
Revert AND wipe pairing + enrolled prints:   sudo ./install.sh --purge
EOF
}

do_uninstall() {
  need_root
  log "Reverting to stock system libfprint"
  [ -f "$DROPIN_FILE" ] && { log "Removing drop-in $DROPIN_FILE"; rm -f "$DROPIN_FILE"; }
  [ -d "$DROPIN_DIR" ] && [ -z "$(ls -A "$DROPIN_DIR" 2>/dev/null)" ] && rmdir "$DROPIN_DIR"
  [ -f "$UDEV_RULE_DST" ] && { log "Removing udev rule $UDEV_RULE_DST"; rm -f "$UDEV_RULE_DST"; }
  if [ -d "$RELOC_DIR" ] && [ "$RELOC_DIR" = "/usr/local/lib64/verimark-synatlsmoc" ]; then
    log "Removing installed library $RELOC_DIR"
    rm -rf -- "$RELOC_DIR"
  fi
  remove_old_cleanroom

  if [ "$MODE" = "purge" ]; then
    if [ -d "$PDATA_DIR" ] && [ "$PDATA_DIR" = "/var/lib/fprint/verimark/047d-00f2" ]; then
      warn "PURGE: removing pairing state $PDATA_DIR (you'll re-pair on next install)"
      rm -rf -- "$PDATA_DIR"
    fi
    warn "PURGE: to also drop enrolled prints, run: fprintd-delete \"\$USER\""
  else
    [ -f "$PDATA_FILE" ] && log "Keeping pairing file $PDATA_FILE (use --purge to remove)"
  fi

  reload_all
  stop_fprintd
  log "Done. The built-in Synaptics reader is back on stock libfprint."
  log "(VeriMark 047d:00f2 is unsupported by stock libfprint — reinstall to use it.)"
}

case "$MODE" in
  install)             do_install ;;
  status)              do_status ;;
  uninstall|purge)     do_uninstall ;;
esac
