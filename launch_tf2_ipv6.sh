#!/bin/bash
# launch_tf2_ipv6.sh — launch TF2 (listen server or client) with Goldberg emu
# + IPv6 dual-stack shim.
#
# Uses an isolated fake HOME so the real Steam client is NEVER touched.
# This prevents VAC flagging and Steam interference.
#
# The shim is universal: it works for both the listen server (tf_linux64
# hosting a game) and the client (tf_linux64 connecting to a remote server).
#
# +net_usesocketsforloopback 1 is baked in — it's required for:
#   - Listen server: local client connects via real UDP instead of the
#     in-process loopback queue (works either way, but real UDP is more
#     reliable with the shim).
#   - Client connecting to srcds: the client's responses to the server must
#     go via real UDP, not the loopback queue.
#
# Override paths via env vars if your layout differs:
#   TF2_ROOT      — path to your TF2 install (default: ./tf2-ipv6)
#   GOLDBERG_DIR  — path to Goldberg emu linux/ dir (default: ./goldberg_linux)
#
# Usage:
#   Listen server:  bash launch_tf2_ipv6.sh -novid -console +sv_lan 1 +ip [::1]:27015 +hostport 27015 +maxplayers 2 +map cp_dustbowl
#   Client:         bash launch_tf2_ipv6.sh -novid -windowed -noborder +connect [::1]:27015

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TF2ROOT="${TF2_ROOT:-$SCRIPT_DIR/tf2-ipv6}"
SHIM="$SCRIPT_DIR/libtf2_ipv6_shim.so"
GOLD="${GOLDBERG_DIR:-$SCRIPT_DIR/goldberg_linux}"
FAKEHOME="$SCRIPT_DIR/fakehome"

cd "$TF2ROOT"

# Use an isolated fake HOME so real Steam is never touched.
# Goldberg's steamclient.so is in $FAKEHOME/.steam/sdk64/.
export HOME="$FAKEHOME"

# Goldberg env vars
export SteamAppId=440
export SteamGameId=440
export SteamAppPath="$TF2ROOT"
export STEAM_SDK64="$FAKEHOME/.steam/sdk64"

# Bypass the sniper-runtime check by spoofing VERSION_CODENAME
export VERSION_CODENAME="sniper"

# Add TF2's bin dir to library path
export LD_LIBRARY_PATH="$TF2ROOT/bin/linux64:$LD_LIBRARY_PATH"

# Install the IPv6 shim
export LD_PRELOAD="$SHIM${LD_PRELOAD:+:$LD_PRELOAD}"

# Run
ulimit -n 2048
exec ./tf_linux64 +net_usesocketsforloopback 1 "$@"
