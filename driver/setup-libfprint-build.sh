#!/usr/bin/env bash
#
# setup-libfprint-build.sh — build the Kensington VeriMark (047d:00f2) C
# libfprint driver end to end: install build deps, wire the driver into a
# real libfprint tree, compile it, install the udev rule, and print how to
# test it with fprintd. Fedora 44. Idempotent — safe to re-run.
#
# ---------------------------------------------------------------------------
# HOW DRIVER REGISTRATION ACTUALLY WORKS (found by reading the reference tree,
# re/synaTudor-rev/libfprint/libfprint/ — libfprint 1.90.7). There is NO
# per-driver meson.build / subdir() for multi-file drivers like goodixmoc;
# everything is inline in two files at the libfprint git-repo root:
#
#   libfprint/meson.build            ("LEVEL2" below)
#     - `drivers = get_option('drivers').split(',')`                 (line 90)
#     - `default_drivers = [ ... 'goodixmoc', 'tudor' ]`             (line 97)
#       -- a driver name MUST be in this list (or `all_drivers`) or meson
#          errors "Invalid driver '<name>'" (line 173-175: `if not
#          all_drivers.contains(driver) error(...)`).
#     - generates libfprint/fpi-drivers.c's body from `supported_drivers`:
#         drivers_type_list += 'extern GType (fpi_device_' + driver +
#                               '_get_type) (void);'                 (line 205)
#         drivers_type_func += '  t = fpi_device_' + driver + '_get_type ();'
#       i.e. for driver name "verimark" the driver MUST export a symbol
#       literally named `fpi_device_verimark_get_type`. That symbol is what
#       `G_DEFINE_TYPE (FpiDeviceVerimark, fpi_device_verimark, FP_TYPE_DEVICE)`
#       auto-generates from its *second* argument — so the meson driver-list
#       entry and the G_DEFINE_TYPE snake_case prefix must match exactly.
#
#   libfprint/libfprint/meson.build  ("LEVEL3" below)
#     - `foreach driver: drivers` gathers `drivers_sources` by literal name
#       match, e.g. for goodixmoc (line ~178):
#         if driver == 'goodixmoc'
#           drivers_sources += [ 'drivers/goodixmoc/goodix.c',
#                                 'drivers/goodixmoc/goodix_proto.c' ]
#         endif
#       This is the exact pattern this script replicates for 'verimark' (7
#       sources instead of 2). Multi-file drivers just live in their own
#       drivers/<name>/ directory; no sub-meson.build is read for them.
#     - `deps = [ enums_dep, gio_dep, glib_dep, gobject_dep, gusb_dep,
#                 imaging_dep, mathlib_dep, nss_dep, dependency('python3-embed') ]`
#       is the flat dependency list every driver object is compiled/linked
#       against. There is no per-driver dependency mechanism (LEVEL2 sets
#       nss_dep/imaging_dep conditionally for uru4000/aes3500/aes4000 the same
#       way, lines ~159-172) — this script adds a `crypto_dep` for 'libcrypto'
#       (openssl-devel) the identical way, since verimark-tls-crypto.c needs it
#       and driver/tests/meson.build already pins `dependency('libcrypto',
#       version:'>=3.0.0')`.
#
# VERIMARK.C/.H ALREADY MATCH THE CONVENTION — verified by reading both files:
#   driver/verimark.h:132  G_DECLARE_FINAL_TYPE (FpiDeviceVerimark,
#                             fpi_device_verimark, FPI, DEVICE_VERIMARK, FpDevice)
#   driver/verimark.c:34   G_DEFINE_TYPE (FpiDeviceVerimark, fpi_device_verimark,
#                             FP_TYPE_DEVICE)
#   driver/verimark.c:593  dev_class->id = "verimark";
# All three agree on "verimark" as the driver-list entry / get_type suffix /
# class id string. NO RENAME IS NEEDED. This script still runs a defensive
# check (fixup_type_symbol_if_needed) that would sed-fix the COPIED tree (never
# driver/ itself) if a future edit to verimark.c/.h broke this match.
#
# KNOWN API GAP (found by symbol-diffing driver/*.c against this reference
# tree's fp-device.h/fpi-device.h — see findings/52 point 2, confirmed exactly
# here): the bundled RE reference tree is libfprint 1.90.7, which predates
# `FpDeviceClass.features` / the `FP_DEVICE_FEATURE_*` enum entirely (not just
# renamed — grep finds zero hits) and has no `clear_storage` vfunc /
# `fpi_device_clear_storage_complete()`. verimark.c:599-604 sets
# `dev_class->features = FP_DEVICE_FEATURE_IDENTIFY | ... |
# FP_DEVICE_FEATURE_STORAGE_CLEAR` and verimark.c:613 wires
# `dev_class->clear_storage = dev_clear_storage` (dev_clear_storage defined at
# verimark.c:539) — both WILL fail to compile against this exact 1.90.7 tree.
# Every other libfprint symbol verimark.c/.h/-transport.c/-moc.c use
# (fpi_device_*_complete, fpi_usb_transfer_*, fpi_ssm_*, FpIdEntry, ...) DOES
# exist here — this is the only gap against 1.90.7. See preflight_api_check()
# below, which detects this at setup time and prints a note (non-fatal), and
# compile-failure guidance which repeats it if the build dies here.
#
# UPDATE 2026-07-10 — VERIFIED AGAINST REAL UPSTREAM (libfprint 1.94.10): this
# gap does NOT exist upstream (features/clear_storage landed well before
# 1.94.10) and the driver compiles + links cleanly there — 76 verimark symbols,
# registered in fpi-drivers.c (see findings/52, "Build status" section). Two
# things changed for that build that this script must account for:
#
#   1. driver-registration file FORMAT changed. Upstream 1.94.10 no longer
#      uses the flat `default_drivers = [ 'goodixmoc', ... ]` list / per-driver
#      `if driver == 'goodixmoc' drivers_sources += [...] endif` blocks
#      described above (that was accurate for the 1.90.7 reference tree this
#      script originally targeted). Upstream now uses:
#        - top-level meson.build: a `drivers_info` DICT, e.g.
#            drivers_info = {
#                ...
#                'goodixmoc': {},
#                ...
#            }
#          A driver needing an extra dependency declares it declaratively via
#          `'helper'`, e.g. `'verimark': { 'helper': ['openssl'] }` — this
#          alone pulls in libcrypto; no manual crypto_dep plumbing needed.
#        - libfprint/meson.build: a `driver_sources` DICT of files() calls,
#          e.g.
#            driver_sources = {
#                ...
#                'goodixmoc' : files(
#                    'drivers/goodixmoc/goodix.c',
#                    'drivers/goodixmoc/goodix_proto.c',
#                ),
#                ...
#            }
#      The registration step below (Section 2c) now DETECTS which format the
#      target tree uses (dict vs. the older flat-list form) and applies the
#      matching idempotent insertion for each — both are supported so this
#      script still works against the old bundled RE reference tree too.
#   2. tests/meson.build's `foreach driver_test: drivers_tests` (1-var foreach
#      over a dict) is rejected by some meson versions — Section 2d below
#      patches it to the 2-var form `foreach driver_test, _vmk_unused :
#      drivers_tests` when needed (idempotent). This must NOT be worked around
#      by disabling the tests/ or examples/ subdirs — core fpi-device.c
#      #includes a tests/-generated header (fpi-test-emulation.h), so
#      disabling them breaks the core build, not just tests.
#   3. The API-compat fixes this comment used to warn about at compile time
#      (fpi_ssm_jump_to_state_delayed's 3-arg signature, OPENSSL_API_COMPAT
#      defines for OpenSSL 3.0 deprecations) are now COMMITTED IN driver/*.c
#      ITSELF (see verimark-pairing.c, verimark-tls.c, verimark-tls-crypto.c,
#      verimark-transport.c, verimark-moc.c). This script does not and must
#      not patch those — they ship correct already.
#
# A random future upstream HEAD past 1.94.10 may change either meson format
# again (upstream is not API/build-format-stable) — if both the dict-format
# and list-format anchors below fail to match, the script exits with a
# MANUAL STEP pointing at the exact file to reconcile by hand; that is
# expected occasionally when following upstream HEAD rather than a pinned tag.
# ---------------------------------------------------------------------------

set -euo pipefail

# ---- defaults (all overridable) -------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DRIVER_SRC_DIR="$SCRIPT_DIR"                      # driver/*.c, *.h, 60-verimark.rules
REF_LIBFPRINT_SRC="$REPO_ROOT/re/synaTudor-rev/libfprint/libfprint"

WORK_DIR="${VERIMARK_WORK_DIR:-$HOME/verimark-build}"
LIBFPRINT_SRC="${VERIMARK_LIBFPRINT_SRC:-}"       # env override; empty = use REF_LIBFPRINT_SRC
DRIVERS_OPT="verimark"                            # -Ddrivers= value
MESON_TARGET=""                                   # empty = build everything (`meson compile -C build`)
UDEV_RULES_DIR="/usr/lib/udev/rules.d"
EXTRA_MESON_ARGS=()

DO_DEPS=1
DO_COPY=1
DO_BUILD=1
DO_UDEV=1
RECOPY_TREE=0

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
setup-libfprint-build.sh — build the VeriMark (047d:00f2) libfprint driver.

Usage: driver/setup-libfprint-build.sh [options]

Options:
  --work-dir PATH        Build tree location (default: $HOME/verimark-build,
                          env VERIMARK_WORK_DIR).
  --libfprint-src PATH    Use this libfprint checkout (env VERIMARK_LIBFPRINT_SRC)
                          instead of the default. DEFAULT (flag omitted): the
                          script CLONES a fresh upstream libfprint into
                          $WORK_DIR/upstream-libfprint — verified 2026-07-10 to
                          compile+link cleanly against upstream 1.94.10
                          (findings/52). Pass an existing checkout to skip the
                          clone, e.g. --libfprint-src /path/to/libfprint. The
                          bundled RE reference tree (re/synaTudor-rev/libfprint/
                          libfprint, libfprint 1.90.7) is NO LONGER the default —
                          it is too old to compile this driver and carries an
                          unrelated python3-embed 'tudor' dep; pass it explicitly
                          only for early compile-error iteration.
  --drivers LIST          -Ddrivers= value (default: verimark). Pass
                          "default" to build every normal driver plus
                          verimark (safe to `meson install` over the system
                          libfprint without losing other readers, e.g. the
                          built-in Synaptics 06cb:0126). Default builds ONLY
                          verimark — fast, isolated compile-error feedback,
                          but NOT what you want to `meson install`.
  --target NAME           `meson compile -C build <NAME>` instead of a full
                          build (e.g. --target fprint-drivers for just the
                          driver objects, fastest iteration loop).
  --recopy                Force a fresh copy of the libfprint source tree
                          (normal runs reuse an existing $WORK_DIR/libfprint
                          checkout + build cache and just re-sync driver/*.c
                          + re-apply the meson registration edits).
  --meson-arg=STRING      Extra raw meson setup argument; repeatable.
  --skip-deps             Don't run `sudo dnf install`.
  --skip-copy              Don't touch the work tree / driver files at all
                          (use an already-prepared $WORK_DIR/libfprint as-is).
  --skip-build             Don't run meson setup/compile.
  --skip-udev              Don't install the udev rule.
  -h, --help                Show this help.

Environment:
  VERIMARK_WORK_DIR, VERIMARK_LIBFPRINT_SRC — same as the flags above.

Typical first run:
  driver/setup-libfprint-build.sh

Iterating on compile errors after editing driver/*.c:
  driver/setup-libfprint-build.sh --skip-deps --target fprint-drivers
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --work-dir) WORK_DIR="$2"; shift 2 ;;
    --work-dir=*) WORK_DIR="${1#*=}"; shift ;;
    --libfprint-src) LIBFPRINT_SRC="$2"; shift 2 ;;
    --libfprint-src=*) LIBFPRINT_SRC="${1#*=}"; shift ;;
    --drivers) DRIVERS_OPT="$2"; shift 2 ;;
    --drivers=*) DRIVERS_OPT="${1#*=}"; shift ;;
    --target) MESON_TARGET="$2"; shift 2 ;;
    --target=*) MESON_TARGET="${1#*=}"; shift ;;
    --recopy) RECOPY_TREE=1; shift ;;
    --meson-arg=*) EXTRA_MESON_ARGS+=("${1#*=}"); shift ;;
    --skip-deps) DO_DEPS=0; shift ;;
    --skip-copy) DO_COPY=0; shift ;;
    --skip-build) DO_BUILD=0; shift ;;
    --skip-udev) DO_UDEV=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# Default source is a fresh UPSTREAM libfprint clone. The bundled RE reference
# clone ($REF_LIBFPRINT_SRC) is libfprint 1.90.7 — too old to compile this driver
# (no FP_DEVICE_FEATURE_*/clear_storage) AND it carries an unrelated python3-embed
# 'tudor' driver — so it is NOT the default; pass it explicitly via
# --libfprint-src "$REF_LIBFPRINT_SRC" only for early compile-error iteration.
UPSTREAM_URL="https://gitlab.freedesktop.org/libfprint/libfprint.git"
AUTO_CLONE=0
if [ -z "$LIBFPRINT_SRC" ]; then
  LIBFPRINT_SRC="$WORK_DIR/upstream-libfprint"
  AUTO_CLONE=1
fi

LIBFPRINT_WORK="$WORK_DIR/libfprint"          # copy of the libfprint git-repo root (LEVEL2 dir)
LEVEL2_MESON="$LIBFPRINT_WORK/meson.build"
LEVEL3_MESON="$LIBFPRINT_WORK/libfprint/meson.build"
DRIVERS_DEST="$LIBFPRINT_WORK/libfprint/drivers/verimark"
BUILD_DIR="$LIBFPRINT_WORK/build"

log "VeriMark libfprint driver build — work dir: $WORK_DIR"
echo "  libfprint source : $LIBFPRINT_SRC"
echo "  -Ddrivers=        : $DRIVERS_OPT"
echo "  build target      : ${MESON_TARGET:-<all>}"

# ---- 1. Fedora build deps --------------------------------------------------
if [ "$DO_DEPS" -eq 1 ]; then
  log "Installing build dependencies (sudo dnf install)"
  # Core list per the task brief, plus gcc-c++ (libfprint's project() declares
  # C++ as a language for examples/cpp-test.cpp — meson refuses to configure
  # at all without a C++ compiler, even when building only one C driver),
  # git (to fetch a real libfprint if --libfprint-src points at a URL-less
  # missing path later), and cmake (upstream 1.94.10's meson.build probes for
  # it via find_program/cmake module for some subproject/dependency fallback
  # paths during `meson setup` — absent on a fresh Fedora minimal install;
  # confirmed needed by the verified build, was missing from this list before).
  sudo dnf install -y \
    meson ninja-build cmake gcc gcc-c++ pkgconf-pkg-config \
    glib2-devel libgusb-devel openssl-devel json-glib-devel pixman-devel \
    nss-devel gobject-introspection-devel systemd-devel cairo-devel \
    fprintd fprintd-pam git \
  || die "dnf install failed — fix and re-run, or pass --skip-deps once satisfied"
else
  log "Skipping dependency install (--skip-deps)"
fi

# ---- 2. Prepare the libfprint work tree ------------------------------------
if [ "$DO_COPY" -eq 1 ]; then
  # Auto-clone a fresh upstream libfprint when no --libfprint-src was given.
  if [ "$AUTO_CLONE" -eq 1 ] && { [ ! -d "$LIBFPRINT_SRC" ] || [ ! -f "$LIBFPRINT_SRC/meson.build" ]; }; then
    log "No --libfprint-src given — cloning upstream libfprint -> $LIBFPRINT_SRC"
    command -v git >/dev/null 2>&1 || die "git not found (needed to auto-clone upstream libfprint); install git or pass --libfprint-src <checkout>"
    mkdir -p "$WORK_DIR"
    rm -rf "$LIBFPRINT_SRC"
    git clone --depth 1 "$UPSTREAM_URL" "$LIBFPRINT_SRC" \
      || die "git clone of upstream libfprint failed (network?) — clone it manually and re-run with --libfprint-src <checkout>"
  fi
  if [ ! -d "$LIBFPRINT_SRC" ] || [ ! -f "$LIBFPRINT_SRC/meson.build" ]; then
    die "libfprint source tree not found or invalid: $LIBFPRINT_SRC
MANUAL STEP: either
  (a) RECOMMENDED — point at a real upstream libfprint checkout:
      git clone https://gitlab.freedesktop.org/libfprint/libfprint.git /path/to/libfprint
      driver/setup-libfprint-build.sh --libfprint-src /path/to/libfprint/libfprint
      (verified 2026-07-10: the driver compiles + links cleanly against
      upstream 1.94.10 this way — see findings/52's Build status section)
  (b) or fetch the bundled RE reference clone instead (older, 1.90.7, fine for
      early compile-error iteration but not what was build-verified):
      git clone https://github.com/Popax21/synaTudor.git '$REPO_ROOT/re/synaTudor'
      git -C '$REPO_ROOT/re/synaTudor' worktree add '$REPO_ROOT/re/synaTudor-rev' rev
      (re/ is gitignored on purpose — proprietary/RE material, never committed)"
  fi

  # Stamp the work tree with the source it was copied from, and force a fresh
  # copy whenever that stamp is missing or differs from the requested source.
  # Without this, an existing $WORK_DIR/libfprint left over from a PRIOR run
  # against a DIFFERENT source (e.g. the old 1.90.7 RE reference clone) would be
  # silently reused while the log claims the newly-requested source — which is
  # exactly how a stale tree (and its bundled python3-embed 'tudor' driver) got
  # built by mistake. Cheap reuse is kept only for same-source re-runs.
  SRC_ABS="$(cd "$LIBFPRINT_SRC" && pwd -P)"
  SRC_STAMP="$LIBFPRINT_WORK/.verimark-src"
  WORK_SRC=""; [ -f "$SRC_STAMP" ] && WORK_SRC="$(cat "$SRC_STAMP" 2>/dev/null || true)"
  if [ "$RECOPY_TREE" -eq 1 ] || [ ! -f "$LEVEL2_MESON" ] || [ "$WORK_SRC" != "$SRC_ABS" ]; then
    if [ -f "$LEVEL2_MESON" ] && [ "$RECOPY_TREE" -ne 1 ] && [ "$WORK_SRC" != "$SRC_ABS" ]; then
      log "Existing work tree came from a different source ('${WORK_SRC:-unknown}' != '$SRC_ABS') — refreshing"
    fi
    log "Copying libfprint source tree -> $LIBFPRINT_WORK (leaves $LIBFPRINT_SRC untouched)"
    mkdir -p "$WORK_DIR"
    rm -rf "$LIBFPRINT_WORK"
    # rsync (fallback to cp) so re-running with --recopy is cheap and .git is excluded.
    if command -v rsync >/dev/null 2>&1; then
      rsync -a --exclude='.git' --exclude='build' "$LIBFPRINT_SRC/" "$LIBFPRINT_WORK/"
    else
      cp -a "$LIBFPRINT_SRC" "$LIBFPRINT_WORK"
      rm -rf "$LIBFPRINT_WORK/.git" "$LIBFPRINT_WORK/build"
    fi
    printf '%s\n' "$SRC_ABS" > "$SRC_STAMP"
  else
    log "Reusing existing work tree at $LIBFPRINT_WORK (same source; pass --recopy to force refresh)"
  fi

  # ---- 2a. Copy the driver sources in -----------------------------------
  log "Copying driver/*.c, driver/*.h -> $DRIVERS_DEST"
  mkdir -p "$DRIVERS_DEST"
  cp -f "$DRIVER_SRC_DIR"/*.c "$DRIVERS_DEST"/
  cp -f "$DRIVER_SRC_DIR"/*.h "$DRIVERS_DEST"/

  # ---- 2b. Defensive type-symbol check (see header comment) -------------
  # Confirms G_DEFINE_TYPE's snake_case prefix in the COPY matches the meson
  # driver-list entry "verimark" (-> required symbol fpi_device_verimark_get_type).
  # driver/verimark.c already matches (verified: G_DEFINE_TYPE (FpiDeviceVerimark,
  # fpi_device_verimark, FP_TYPE_DEVICE) at verimark.c:34) so this is a no-op
  # safety net, not an expected fixup.
  ACTUAL_PREFIX="$(grep -oE "G_DEFINE_TYPE *\([^,]+, *[A-Za-z0-9_]+" "$DRIVERS_DEST/verimark.c" \
                    | head -1 | sed -E 's/.*, *//')"
  if [ "$ACTUAL_PREFIX" != "fpi_device_verimark" ]; then
    warn "verimark.c's G_DEFINE_TYPE prefix is '$ACTUAL_PREFIX', not 'fpi_device_verimark' —" \
         "sed-fixing the COPY (never driver/ itself) so it matches the meson driver name 'verimark'."
    if [ -n "$ACTUAL_PREFIX" ]; then
      sed -i "s/\b${ACTUAL_PREFIX}\b/fpi_device_verimark/g" "$DRIVERS_DEST"/*.c "$DRIVERS_DEST"/*.h
    else
      die "MANUAL STEP: could not find a G_DEFINE_TYPE line in $DRIVERS_DEST/verimark.c at all — inspect it by hand."
    fi
  else
    echo "  type-symbol check: OK (fpi_device_verimark_get_type matches driver name 'verimark')"
  fi

  # ---- 2c. Register 'verimark' + its sources + its crypto dep -----------
  # Auto-detects which meson.build format the target tree uses and applies
  # the matching idempotent insertion:
  #   - DICT format (upstream 1.94.10+, verified 2026-07-10 — findings/52):
  #       drivers_info dict entry `'goodixmoc': {},` in $LEVEL2_MESON, and a
  #       `'goodixmoc' : files(...),` block in $LEVEL3_MESON. The dict format's
  #       `{ 'helper': ['openssl'] }` pulls in libcrypto on its own — no manual
  #       crypto_dep plumbing needed for this format.
  #   - LIST format (the bundled 1.90.7 RE reference tree): the older flat
  #       `default_drivers = [ 'goodixmoc', ... ]` list plus a per-driver
  #       `if driver == 'tudor' ... endif` block in the `foreach driver:
  #       drivers` loop, and manually-wired crypto_dep (as before).
  # If NEITHER anchor matches (a future upstream HEAD changed the format
  # again), this exits with a MANUAL STEP naming the exact file to reconcile —
  # see the header comment for both known formats.
  log "Wiring 'verimark' into $LEVEL2_MESON / $LEVEL3_MESON"
  python3 - "$LEVEL2_MESON" "$LEVEL3_MESON" <<'PYEOF'
import re, sys

level2_path, level3_path = sys.argv[1], sys.argv[2]

VERIMARK_SOURCES = [
    'drivers/verimark/verimark.c',
    'drivers/verimark/verimark-transport.c',
    'drivers/verimark/verimark-transport-framing.c',
    'drivers/verimark/verimark-tls.c',
    'drivers/verimark/verimark-tls-crypto.c',
    'drivers/verimark/verimark-pairing.c',
    'drivers/verimark/verimark-moc.c',
]

def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()

def write(p, s):
    with open(p, "w", encoding="utf-8") as f:
        f.write(s)

# =====================================================================
# LEVEL2 (top-level meson.build): register the 'verimark' driver itself
# =====================================================================
level2 = read(level2_path)

if re.search(r"'verimark'\s*:\s*\{", level2):
    level2_format = "dict"
    print("  = 'verimark' already in drivers_info dict (%s)" % level2_path)
elif "'verimark',\n" in level2:
    level2_format = "list"
    print("  = 'verimark' already in default_drivers list (%s)" % level2_path)
else:
    dict_anchor = re.search(r"^([ \t]*)'goodixmoc'\s*:\s*\{\}\s*,[ \t]*\n", level2, re.M)
    list_anchor = "    'goodixmoc',\n"
    if dict_anchor:
        indent = dict_anchor.group(1)
        insertion = "%s'verimark': { 'helper': ['openssl'] },\n" % indent
        level2 = level2[:dict_anchor.end()] + insertion + level2[dict_anchor.end():]
        level2_format = "dict"
        print("  + [dict format] added \"'verimark': { 'helper': ['openssl'] },\" to drivers_info (%s)" % level2_path)
    elif list_anchor in level2:
        level2 = level2.replace(list_anchor, list_anchor + "    'verimark',\n", 1)
        level2_format = "list"
        print("  + [list format] added 'verimark' to default_drivers (%s)" % level2_path)
    else:
        sys.exit(
            "MANUAL STEP: could not find a known 'goodixmoc' anchor in %s — checked both the "
            "upstream 1.94.10+ drivers_info dict format (\"    'goodixmoc': {},\") and the older "
            "default_drivers list format (\"    'goodixmoc',\"). This likely means a future "
            "upstream libfprint HEAD changed the format again. Open the file, find how "
            "'goodixmoc' is registered, and add an equivalent 'verimark' entry by hand (use "
            "{ 'helper': ['openssl'] } if it's still dict-shaped, to pull in libcrypto), then "
            "update this script's anchors to match." % level2_path)

# crypto_dep is only hand-wired for the OLD list format; the dict format's
# { 'helper': ['openssl'] } inserted above already pulls in libcrypto for us
# (verified against upstream 1.94.10 — see findings/52).
if level2_format == "list":
    if "crypto_dep = dependency(" not in level2:
        decl_marker = "imaging_dep = dependency('', required: false)\n"
        if decl_marker not in level2:
            sys.exit("MANUAL STEP: could not find the imaging_dep declaration in %s to anchor "
                      "the crypto_dep declaration — add\n"
                      "    crypto_dep = dependency('', required: false)\n"
                      "near nss_dep/imaging_dep by hand." % level2_path)
        level2 = level2.replace(decl_marker, decl_marker + "crypto_dep = dependency('', required: false)\n", 1)

        detect_anchor = "    if not all_drivers.contains(driver)\n"
        if detect_anchor not in level2:
            sys.exit("MANUAL STEP: could not find the 'if not all_drivers.contains(driver)' line in "
                      "%s to anchor the verimark crypto_dep detection — add an\n"
                      "    if driver == 'verimark'\n"
                      "        crypto_dep = dependency('libcrypto', version: '>=3.0.0', required: false)\n"
                      "        if not crypto_dep.found()\n"
                      "            error('OpenSSL (libcrypto >=3.0.0 / openssl-devel) is required for "
                      "the verimark driver')\n"
                      "        endif\n"
                      "    endif\n"
                      "block inside the `foreach driver: drivers` loop by hand." % level2_path)
        verimark_block = (
            "    if driver == 'verimark'\n"
            "        crypto_dep = dependency('libcrypto', version: '>=3.0.0', required: false)\n"
            "        if not crypto_dep.found()\n"
            "            error('OpenSSL (libcrypto >=3.0.0 / openssl-devel) is required for the verimark driver')\n"
            "        endif\n"
            "    endif\n"
        )
        level2 = level2.replace(detect_anchor, verimark_block + detect_anchor, 1)
        print("  + added crypto_dep (libcrypto) declaration + detection (%s)" % level2_path)
    else:
        print("  = crypto_dep already wired (%s)" % level2_path)
else:
    print("  = dict format: crypto_dep handled by { 'helper': ['openssl'] }, no manual wiring needed (%s)" % level2_path)

write(level2_path, level2)

# =====================================================================
# LEVEL3 (libfprint/meson.build): register 'verimark's 7 source files
# =====================================================================
level3 = read(level3_path)

if re.search(r"'verimark'\s*:\s*files\(", level3):
    level3_format = "dict"
    print("  = 'verimark' already in driver_sources files() dict (%s)" % level3_path)
elif "if driver == 'verimark'" in level3:
    level3_format = "list"
    print("  = drivers_sources block for 'verimark' already present (%s)" % level3_path)
else:
    dict_anchor = re.search(
        r"^([ \t]*)'goodixmoc'\s*:\s*files\(.*?\n[ \t]*\),[ \t]*\n",
        level3, re.M | re.S)
    list_anchor = "    if driver == 'tudor'\n"
    if dict_anchor:
        indent = dict_anchor.group(1)
        lines = "".join("%s    '%s',\n" % (indent, src) for src in VERIMARK_SOURCES)
        block = "%s'verimark' : files(\n%s%s),\n" % (indent, lines, indent)
        level3 = level3[:dict_anchor.end()] + block + level3[dict_anchor.end():]
        level3_format = "dict"
        print("  + [dict format] added \"'verimark' : files(...)\" block (7 sources, %s)" % level3_path)
    elif list_anchor in level3:
        verimark_sources = (
            "    if driver == 'verimark'\n"
            "        drivers_sources += [\n"
            + "".join("            '%s',\n" % src for src in VERIMARK_SOURCES) +
            "        ]\n"
            "    endif\n"
        )
        level3 = level3.replace(list_anchor, verimark_sources + list_anchor, 1)
        level3_format = "list"
        print("  + [list format] added drivers_sources block for 'verimark' (7 files, %s)" % level3_path)
    else:
        sys.exit(
            "MANUAL STEP: could not find a known anchor in %s — checked both the upstream "
            "1.94.10+ driver_sources files() dict format (\"'goodixmoc' : files(...)\") and the "
            "older per-driver \"if driver == 'tudor'\" foreach form. This likely means a future "
            "upstream libfprint HEAD changed the format again. Open the file, find how "
            "'goodixmoc' sources are listed, and add an equivalent 'verimark' entry (7 files "
            "under drivers/verimark/) by hand, then update this script's anchors to match." % level3_path)

# crypto_dep in the deps=[...] array is only needed for the OLD list format.
if level3_format == "list":
    if re.search(r"\bcrypto_dep,", level3) is None:
        deps_anchor = "    nss_dep,\n"
        if deps_anchor not in level3:
            sys.exit("MANUAL STEP: could not find \"    nss_dep,\" in the deps=[...] array in %s — "
                      "add \"    crypto_dep,\" to that list by hand." % level3_path)
        level3 = level3.replace(deps_anchor, deps_anchor + "    crypto_dep,\n", 1)
        print("  + added crypto_dep to deps=[...] (%s)" % level3_path)
    else:
        print("  = crypto_dep already in deps=[...] (%s)" % level3_path)
else:
    print("  = dict format: no manual deps=[...] wiring needed for verimark (helper handles it, %s)" % level3_path)

write(level3_path, level3)
PYEOF

  # ---- 2d. tests/meson.build meson-version compat patch -----------------
  # Some meson versions reject the 1-var foreach-over-dict form upstream uses:
  #   foreach driver_test: drivers_tests
  # Patch to the 2-var form (idempotent — only touches the exact old line).
  # Do NOT disable the tests/ or examples/ subdirs instead: core fpi-device.c
  # #includes a tests/-generated header (fpi-test-emulation.h), so disabling
  # them breaks the core build, not just the test suite.
  TESTS_MESON="$LIBFPRINT_WORK/tests/meson.build"
  if [ -f "$TESTS_MESON" ]; then
    if grep -qF 'foreach driver_test: drivers_tests' "$TESTS_MESON" \
       && ! grep -qF 'foreach driver_test, _vmk_unused : drivers_tests' "$TESTS_MESON"; then
      sed -i 's/foreach driver_test: drivers_tests/foreach driver_test, _vmk_unused : drivers_tests/' "$TESTS_MESON"
      echo "  + [tests/meson.build compat] patched 1-var foreach -> 2-var form ($TESTS_MESON)"
    elif grep -qF 'foreach driver_test, _vmk_unused : drivers_tests' "$TESTS_MESON"; then
      echo "  = tests/meson.build foreach compat patch already applied ($TESTS_MESON)"
    else
      echo "  = tests/meson.build foreach form not the known-incompatible 1-var pattern, left as-is ($TESTS_MESON)"
    fi
  fi

else
  log "Skipping work-tree / driver-source setup (--skip-copy)"
fi

# ---- 2e. Preflight API compatibility check (informational, non-fatal) -----
# See header comment: OLD pre-~1.92 trees (like the bundled 1.90.7 RE
# reference tree) lack FpDeviceClass's `features` field / FP_DEVICE_FEATURE_*
# enum, and the `clear_storage` vfunc / fpi_device_clear_storage_complete().
# verimark.c uses both. This is a non-fatal heads-up, not a build gate — it
# does NOT exit/die, it only prints guidance before the compiler would hit the
# same thing. Against upstream 1.94.10 (the recommended --libfprint-src target,
# verified 2026-07-10 — findings/52) this tree has both APIs and the check is
# expected to report OK / print nothing of concern; it only fires for older
# trees such as the bundled RE reference clone.
preflight_api_check() {
  local fp_h="$LIBFPRINT_WORK/libfprint/fp-device.h"
  local fpi_h="$LIBFPRINT_WORK/libfprint/fpi-device.h"
  [ -f "$fp_h" ] && [ -f "$fpi_h" ] || return 0

  local missing=()
  grep -q "FP_DEVICE_FEATURE" "$fp_h" 2>/dev/null || missing+=("FP_DEVICE_FEATURE_* enum (fp-device.h)")
  grep -q "features" "$fpi_h" 2>/dev/null || missing+=("FpDeviceClass.features field (fpi-device.h)")
  grep -q "clear_storage" "$fpi_h" 2>/dev/null || missing+=("FpDeviceClass.clear_storage vfunc (fpi-device.h)")
  grep -q "fpi_device_clear_storage_complete" "$fpi_h" 2>/dev/null || missing+=("fpi_device_clear_storage_complete() (fpi-device.h)")

  if [ "${#missing[@]}" -gt 0 ]; then
    warn "Preflight API check: this libfprint tree is missing:"
    local m
    for m in "${missing[@]}"; do echo "    - $m"; done
    cat <<EOF
  verimark.c:599-604 sets dev_class->features = FP_DEVICE_FEATURE_IDENTIFY | ... |
  FP_DEVICE_FEATURE_STORAGE_CLEAR, and verimark.c:613 wires
  dev_class->clear_storage = dev_clear_storage (defined at verimark.c:539).
  Both WILL fail to compile against a libfprint tree this old (pre-~1.92).
  This is just a heads-up, not a hard stop — the build will proceed and you'll
  hit this as an actual compile error if it applies. To sidestep it entirely:
    RECOMMENDED — build against upstream instead (has both APIs; verified
    working end-to-end at 1.94.10 on 2026-07-10, see findings/52):
      git clone https://gitlab.freedesktop.org/libfprint/libfprint.git /path/to/libfprint
      driver/setup-libfprint-build.sh --libfprint-src /path/to/libfprint/libfprint --recopy
    Alternative — patch the COPY (not driver/!) to drop clear_storage support
    so it matches this older API:
      $DRIVERS_DEST/verimark.c — remove the
      "FP_DEVICE_FEATURE_STORAGE_CLEAR" bit from the features assignment
      (line ~604) and the "dev_class->clear_storage = dev_clear_storage;"
      line (~613); rename dev_class->features itself if this tree lacks
      the field entirely (it does, per this check).
EOF
  else
    echo "  preflight API check: OK (features + clear_storage present in this tree)"
  fi
}
preflight_api_check

# ---- 3. meson setup + compile ----------------------------------------------
if [ "$DO_BUILD" -eq 1 ]; then
  log "meson setup / compile ($LIBFPRINT_WORK)"
  MESON_ARGS=(
    "-Ddrivers=$DRIVERS_OPT"
    "-Ddoc=false"        # avoids requiring gtk-doc/gi-docgen, not installed by this script
    "-Dgtk-examples=false"
    "-Dintrospection=false"  # avoids requiring gobject-introspection tooling for a driver-only build
    "${EXTRA_MESON_ARGS[@]}"
  )

  if [ -f "$BUILD_DIR/build.ninja" ]; then
    meson setup --reconfigure "${MESON_ARGS[@]}" "$BUILD_DIR" "$LIBFPRINT_WORK"
  else
    meson setup "${MESON_ARGS[@]}" "$BUILD_DIR" "$LIBFPRINT_WORK"
  fi

  set +e
  if [ -n "$MESON_TARGET" ]; then
    meson compile -C "$BUILD_DIR" "$MESON_TARGET"
  else
    meson compile -C "$BUILD_DIR"
  fi
  COMPILE_STATUS=$?
  set -e

  if [ "$COMPILE_STATUS" -ne 0 ]; then
    cat <<EOF

============================================================================
COMPILE FAILED (exit $COMPILE_STATUS). This is expected the first time a
hand-written driver meets a real libfprint API — see findings/52 ("C libfprint
driver port: OFFLINE-COMPLETE ... on-device build deferred") which flagged
exactly this reconciliation step. What to do:

  1. Re-run the preflight API check above — if it flagged missing symbols
     (features / clear_storage), that is very likely your error. Fix per its
     MANUAL STEP block.
  2. Otherwise, read the compiler errors: they're against the COPY at
       $DRIVERS_DEST
     not driver/ in this repo. Edit files there directly to iterate quickly,
     THEN copy your fix back into driver/*.c / driver/*.h in this repo once it
     compiles (this script overwrites the copy from driver/ on every run
     unless you pass --skip-copy).
  3. Fast rebuild loop once you're iterating in the copy:
       driver/setup-libfprint-build.sh --skip-deps --skip-copy --target fprint-drivers
  4. If the API surface is too different from this 1.90.7 reference tree,
     switch to a real upstream libfprint checkout:
       git clone https://gitlab.freedesktop.org/libfprint/libfprint.git /path/to/libfprint
       driver/setup-libfprint-build.sh --libfprint-src /path/to/libfprint/libfprint --recopy
============================================================================
EOF
    exit "$COMPILE_STATUS"
  fi
  log "Build OK: $BUILD_DIR"
else
  log "Skipping meson setup/compile (--skip-build)"
fi

# ---- 4. udev rule -----------------------------------------------------------
if [ "$DO_UDEV" -eq 1 ]; then
  log "Installing udev rule -> $UDEV_RULES_DIR/60-verimark.rules"
  sudo cp "$DRIVER_SRC_DIR/60-verimark.rules" "$UDEV_RULES_DIR/60-verimark.rules"
  sudo udevadm control --reload-rules
  sudo udevadm trigger --subsystem-match=usb || true
else
  log "Skipping udev rule install (--skip-udev)"
fi

# ---- 5. next steps -----------------------------------------------------------
cat <<EOF

============================================================================
DONE.

Build tree:   $LIBFPRINT_WORK
Build dir:    $BUILD_DIR
Built with:   -Ddrivers=$DRIVERS_OPT

IMPORTANT — this was built with -Ddrivers=$DRIVERS_OPT. If that is just
"verimark" (the default), the resulting libfprint.so supports ONLY the
VeriMark and DROPS every other driver, including "synaptics" (the built-in
06cb:0126 reader this machine currently relies on — see the repo CLAUDE.md).
Do NOT \`meson install\` this build over the system libfprint as-is.
  - To keep every existing reader working AND add the VeriMark, rebuild with:
      driver/setup-libfprint-build.sh --skip-deps --drivers=default --recopy
    ("default" already includes "verimark" — it was inserted into
    default_drivers by this script.)

Testing without touching the system libfprint install (recommended first):
  1. Plug in the VeriMark (047d:00f2) — the udev rule installed above grants
     seat access via uaccess (and GROUP=plugdev as a fallback).
  2. Point the fprintd service at the freshly built libfprint via an
     LD_LIBRARY_PATH drop-in (reversible, doesn't touch /usr):
       sudo mkdir -p /etc/systemd/system/fprintd.service.d
       printf '[Service]\nEnvironment=LD_LIBRARY_PATH=%s/libfprint\n' "$BUILD_DIR" \\
         | sudo tee /etc/systemd/system/fprintd.service.d/verimark-test.conf
       sudo systemctl daemon-reload
       sudo systemctl restart fprintd
  3. Sanity-check the device is seen, then test:
       fprintd-list "\$USER"
       fprintd-enroll "\$USER"      # guided swipe/press enroll on the VeriMark
       fprintd-verify "\$USER"
  4. Revert when done (also needed before using the built-in 06cb:0126 reader
     again, if this build didn't include the "synaptics" driver):
       sudo rm /etc/systemd/system/fprintd.service.d/verimark-test.conf
       sudo systemctl daemon-reload
       sudo systemctl restart fprintd

Offline unit tests for the driver's pure logic (no device, no libfprint
checkout needed) still live in driver/tests/ and are unaffected by this script:
  meson setup driver/tests/build driver/tests && meson test -C driver/tests/build
============================================================================
EOF
