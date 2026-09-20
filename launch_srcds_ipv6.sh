#!/bin/bash
# Launch TF2 dedicated server (srcds) with IPv6 shim + Goldberg emu.
#
# Required convars (baked in):
#   +net_usesocketsforloopback 1  — force real UDP for localhost addresses.
#     Without this, NET_SendPacket redirects 127.0.0.1 responses to an
#     in-process loopback queue that external clients never read.
#   +tf_allow_server_hibernation 0 — keep the server active. Hibernating
#     servers do not process connectionless packets (queries/connects).
#
# Override paths via env vars if your layout differs:
#   TF2_SRCDS_ROOT  — path to your TF2 dedicated server install (default: ./tf2_srcds_v6)
#   GOLDBERG_DIR    — path to Goldberg emu linux/ dir (default: ./goldberg_linux)
#
# Usage: ./launch_srcds_ipv6.sh +ip [::]:27015 +hostport 27015 +maxplayers 24 +map cp_dustbowl
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GAMEROOT="${TF2_SRCDS_ROOT:-$SCRIPT_DIR/tf2_srcds_v6}"
SHIM="$SCRIPT_DIR/libtf2_ipv6_shim.so"
FAKEHOME="$SCRIPT_DIR/fakehome"
GOLDBERG="${GOLDBERG_DIR:-$SCRIPT_DIR/goldberg_linux}"

# Isolate from real Steam — use fake HOME with Goldberg's steamclient.so
export HOME="$FAKEHOME"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$FAKEHOME/.steam"
mkdir -p "$FAKEHOME/.steam/sdk64" 2>/dev/null || true

# Ensure Goldberg's steamclient.so is in the fake HOME
if [ ! -f "$FAKEHOME/.steam/sdk64/steamclient.so" ]; then
	if [ -f "$GOLDBERG/x86_64/steamclient.so" ]; then
		cp "$GOLDBERG/x86_64/steamclient.so" \
			"$FAKEHOME/.steam/sdk64/steamclient.so"
	else
		echo "ERROR: Goldberg steamclient.so not found at $GOLDBERG/x86_64/" >&2
		echo "Set GOLDBERG_DIR to point at the Goldberg emu linux/ directory." >&2
		exit 1
	fi
fi

# Set library paths (srcds looks in bin/ and bin/linux64/)
export LD_LIBRARY_PATH="${GAMEROOT}/bin:${GAMEROOT}/bin/linux64:${LD_LIBRARY_PATH}"

# Install the IPv6 shim
export LD_PRELOAD="$SHIM"

# srcds checks for sniper runtime — spoof it
export VERSION_CODENAME=sniper

cd "$GAMEROOT"
exec ./srcds_linux64 -game tf -console \
	+net_usesocketsforloopback 1 \
	+tf_allow_server_hibernation 0 \
	"$@"
