#!/usr/bin/env bash
# build.sh — reproducibly build the synatlsmoc-based libfprint that supports
# BOTH this machine's fingerprint readers:
#   * Kensington VeriMark Desktop  047d:00f2  -> driver `synatlsmoc` (+Kensington patch)
#   * built-in Synaptics reader    06cb:0126  -> driver `synaptics`
#
# This is the upstream-track vojtapl/synaTudorMiS driver with the Uriziel01
# Kensington Match-in-Sensor patch applied (pinned + checksummed in
# versions.env). It replaces our earlier clean-room driver in ../driver/.
#
# Runs entirely as your normal user — NO sudo, NOTHING installed. It only
# clones the pinned source, applies the verified patch, and builds natively on
# Fedora into ./dist/libfprint-2.so.2.0.0. Run install.sh (with sudo) after.
#
# Build deps (Fedora): gcc glib2-devel libgusb-devel openssl-devel cairo-devel
#                      meson ninja-build pkgconf
#
# Usage:
#   ./build.sh            # prepare pinned source + build + self-test -> dist/
#   ./build.sh --clean    # remove ./src and ./dist first, then build
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# shellcheck source=versions.env
source "$SCRIPT_DIR/versions.env"

PATCH="$SCRIPT_DIR/$(basename "$VERIMARK_PATCH")"
# Layered local patch: make the driver self-pair + persist (see the patch header
# and the 2026-08-18 changelog). Applied after the upstream Kensington patch.
LOCAL_PATCH="$SCRIPT_DIR/0002-verimark-self-pairing.patch"
# Expected tree hash after BOTH patches (integrity check for the local layer).
LOCAL_PATCHED_TREE="ef0f853db39c4bf5b10bcd235513cbc39c35b608"
SRC_DIR="$SCRIPT_DIR/src/synaTudorMiS"
DIST_DIR="$SCRIPT_DIR/dist"
# The driver set: both readers this machine has. Add ,virtual_image etc. if you
# ever want more; 'all' pulls in image drivers with extra deps.
DRIVERS="synaptics,synatlsmoc"

log()  { echo "==> $*"; }
die()  { echo "==> ERROR: $*" >&2; exit 1; }

if [ "${1:-}" = "--clean" ]; then
  log "Cleaning ./src and ./dist"
  rm -rf -- "$SCRIPT_DIR/src" "$DIST_DIR"
fi

# ---- preflight: build tools -------------------------------------------------
missing=()
for t in git sha256sum gcc meson ninja pkg-config; do
  command -v "$t" >/dev/null 2>&1 || missing+=("$t")
done
if [ "${#missing[@]}" -gt 0 ]; then
  die "missing build tools: ${missing[*]}
     Install with: sudo dnf install -y gcc glib2-devel libgusb-devel \\
       openssl-devel cairo-devel meson ninja-build pkgconf"
fi
for dep in glib-2.0 gusb libcrypto cairo; do
  pkg-config --exists "$dep" || die "missing devel lib: $dep (see dnf line above)"
done

# ---- verify the pinned patch ------------------------------------------------
[ -f "$PATCH" ] || die "patch not found: $PATCH"
have="$(sha256sum "$PATCH" | awk '{print $1}')"
[ "$have" = "$VERIMARK_PATCH_SHA256" ] || die "patch checksum mismatch
     expected $VERIMARK_PATCH_SHA256
     got      $have"
log "Patch checksum OK ($VERIMARK_PATCH_SHA256)"

# ---- prepare pinned + patched source ----------------------------------------
if [ ! -d "$SRC_DIR/.git" ]; then
  log "Cloning $SYNATUDORMIS_REPOSITORY (blobless)"
  mkdir -p "$(dirname -- "$SRC_DIR")"
  git clone --filter=blob:none "$SYNATUDORMIS_REPOSITORY" "$SRC_DIR"
fi

log "Fetching + checking out pinned base $SYNATUDORMIS_BASE_COMMIT"
git -C "$SRC_DIR" fetch --quiet origin "$SYNATUDORMIS_BASE_COMMIT"

current_tree="$(git -C "$SRC_DIR" rev-parse 'HEAD^{tree}' 2>/dev/null || echo none)"
if [ "$current_tree" = "$LOCAL_PATCHED_TREE" ]; then
  log "Source already prepared (patched tree $LOCAL_PATCHED_TREE)"
else
  git -C "$SRC_DIR" checkout --quiet --detach "$SYNATUDORMIS_BASE_COMMIT"
  git -C "$SRC_DIR" clean -xffdq
  log "Applying upstream Kensington patch"
  git -C "$SRC_DIR" -c user.email=build@local -c user.name=build \
      am --committer-date-is-author-date "$PATCH"
  got_tree="$(git -C "$SRC_DIR" rev-parse 'HEAD^{tree}')"
  [ "$got_tree" = "$VERIMARK_PATCHED_TREE" ] || die "upstream patched tree mismatch
     expected $VERIMARK_PATCHED_TREE
     got      $got_tree"
  log "Upstream patched tree verified ($VERIMARK_PATCHED_TREE)"

  [ -f "$LOCAL_PATCH" ] || die "local patch missing: $LOCAL_PATCH"
  log "Applying local self-pairing patch"
  git -C "$SRC_DIR" -c user.email=build@local -c user.name=build \
      am --committer-date-is-author-date "$LOCAL_PATCH"
  got_tree="$(git -C "$SRC_DIR" rev-parse 'HEAD^{tree}')"
  [ "$got_tree" = "$LOCAL_PATCHED_TREE" ] || die "local patched tree mismatch
     expected $LOCAL_PATCHED_TREE
     got      $got_tree"
  log "Local patched tree verified ($LOCAL_PATCHED_TREE)"
fi

# ---- build ------------------------------------------------------------------
LF="$SRC_DIR/libfprint/libfprint"
BUILD="$LF/.build"
log "Configuring meson (drivers=$DRIVERS)"
if [ -f "$BUILD/build.ninja" ]; then
  meson setup --reconfigure "$BUILD" "$LF" \
    -Ddrivers="$DRIVERS" -Dgtk-examples=false -Ddoc=false \
    -Dintrospection=false -Dinstalled-tests=false >/dev/null
else
  meson setup "$BUILD" "$LF" \
    -Ddrivers="$DRIVERS" -Dgtk-examples=false -Ddoc=false \
    -Dintrospection=false -Dinstalled-tests=false >/dev/null
fi

log "Compiling"
ninja -C "$BUILD" >/dev/null

log "Running focused Kensington self-test"
meson test -C "$BUILD" synatlsmoc-kensington --print-errorlogs

so="$BUILD/libfprint/libfprint-2.so.2.0.0"
[ -f "$so" ] || die "build finished but $so is missing"

# ---- verify both readers are registered, then stage to dist/ ----------------
supported="$("$BUILD/libfprint/fprint-list-supported-devices" 2>/dev/null || true)"
case "$supported" in
  *047d:00f2*) : ;;
  *) die "built library does not register the VeriMark (047d:00f2)" ;;
esac
case "$supported" in
  *06cb:0126*) : ;;
  *) die "built library does not register the built-in Synaptics (06cb:0126)" ;;
esac

mkdir -p "$DIST_DIR"
install -m0644 "$so" "$DIST_DIR/libfprint-2.so.2.0.0"

cat <<EOF

==> Build complete.
    Library : $DIST_DIR/libfprint-2.so.2.0.0
    sha256  : $(sha256sum "$DIST_DIR/libfprint-2.so.2.0.0" | awk '{print $1}')
    Readers : 047d:00f2 (VeriMark -> synatlsmoc), 06cb:0126 (built-in -> synaptics)

Next (privileged): sudo ./install.sh
EOF
