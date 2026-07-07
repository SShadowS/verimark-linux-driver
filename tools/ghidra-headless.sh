#!/usr/bin/env bash
#
# ghidra-headless.sh — import + auto-analyze a binary into a Ghidra project
# headlessly, so the Ghidra GUI (and GhidraMCP) can attach to a ready project.
#
#   GHIDRA_HOME=/opt/ghidra ./ghidra-headless.sh re/driver/synaWudfBioUsb.dll
#   GHIDRA_HOME=/opt/ghidra ./ghidra-headless.sh <binary> [project-name]
#
# After it finishes: open the project in Ghidra, then start GhidraMCP's bridge
# so an agent can decompile/list/rename over MCP (see ../RESEARCH-PROMPT.md).
#
set -eu
: "${GHIDRA_HOME:?set GHIDRA_HOME to your Ghidra install directory}"
BIN="${1:?usage: ghidra-headless.sh <binary> [project-name]}"
PROJ="${2:-verimark}"

HERE="$(cd "$(dirname "$0")" && pwd)"
# Canonicalize (no '..' element — Ghidra's project-path validator rejects those).
PROJ_DIR="$(cd "$HERE/.." && pwd)/ghidra-projects"
mkdir -p "$PROJ_DIR"

[ -f "$BIN" ] || { echo "no such file: $BIN" >&2; exit 1; }
[ -x "$GHIDRA_HOME/support/analyzeHeadless" ] || {
    echo "analyzeHeadless not found under GHIDRA_HOME=$GHIDRA_HOME" >&2; exit 1; }

# Ghidra 12.x needs JDK 21; Fedora 44's default java is 25 (rejected). If JAVA_HOME
# isn't already a supported JDK, fall back to a local JDK 21 install.
if [ -z "${JAVA_HOME:-}" ] || ! "${JAVA_HOME}/bin/java" -version 2>&1 | grep -q '"21\.'; then
    for j in /opt/jdk21 /opt/jdk-21* "$HOME"/jdk-21* /usr/lib/jvm/java-21-* ; do
        [ -x "$j/bin/java" ] && { export JAVA_HOME="$j"; break; }
    done
fi
echo "Using JAVA_HOME=${JAVA_HOME:-<none — Ghidra will look on PATH>}"

echo "Importing $BIN into Ghidra project '$PROJ' ($PROJ_DIR)…"
"$GHIDRA_HOME/support/analyzeHeadless" "$PROJ_DIR" "$PROJ" \
    -import "$BIN" -overwrite \
    -analysisTimeoutPerFile 900

echo
echo "Done. Next:"
echo "  1. Open $PROJ_DIR/$PROJ.gpr in the Ghidra GUI."
echo "  2. Enable the GhidraMCP plugin, then register its bridge with your agent:"
echo "     claude mcp add ghidra -- python /path/to/bridge_mcp_ghidra.py \\"
echo "         --ghidra-server http://127.0.0.1:8080/"
