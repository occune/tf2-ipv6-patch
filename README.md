# TF2 IPv6 Dual-Stack Patch

> **⚠️ Vibe-coded project disclosure**
>
> This project was developed through **vibe coding** — an iterative, AI-assisted
> process where the code was written collaboratively with an LLM (GLM-5.2 via
> OpenCode) driving the investigation, implementation, and debugging. The human
> provided goals, ran the game, and reported results; the AI disassembled
> binaries, traced packet flows with gdb, wrote the shim, and isolated root
> causes.
>
> The code works (gameplay verified end-to-end over IPv6), but it has not been
> audited line-by-line by a human security engineer. Use at your own risk. The
> binary patching and `mprotect` hook techniques are invasive by nature. Review
> the source before running it on any system you care about.

Native IPv6 support for live TF2 (AppID 440) via an `LD_PRELOAD` shim + binary
patching of `engine.so` / `engine_srv.so`. Works for both the listen server
(`tf_linux64`) and the dedicated server (`srcds_linux64`).

## How it works

TF2's engine is IPv4-only: `netadr_t` holds a 4-byte IPv4 address, sockets are
`AF_INET`, and the address parser `NET_StringToSockadr` only understands
`a.b.c.d:port`. The shim adds IPv6 support **without changing the engine's
internal address representation**:

1. **Socket shim** (`libtf2_ipv6_shim.so`): intercepts `socket()`/`bind()`/
   `connect()`/`sendto()`/`recvfrom()`/`gethostbyname()`/`dlopen()`. All
   `AF_INET` sockets are upgraded to `AF_INET6` with `IPV6_V6ONLY=0` (dual-
   stack). `sockaddr_in` ↔ `sockaddr_in6` translation happens at the syscall
   boundary — the engine still sees IPv4 addresses.

2. **Parser hook**: inline-hooks `NET_StringToSockadr` in `engine.so` /
   `engine_srv.so` by scanning executable segments for a unique 16-byte
   prologue. Once found, the prologue is patched with a jump to a relay that
   checks for `[` (bracketed IPv6 literal) and calls an inline IPv6 parser.
   No hardcoded offsets — works for both binaries.

3. **A2S query responder**: Goldberg's `ISteamGameServer::HandleIncomingPacket`
   is a stub that drops all server-browser queries (A2S_INFO, A2A_PING,
   A2S_PLAYER, A2S_RULES). The shim inspects connectionless packets received
   on the server socket and crafts responses directly via `sendto`, bypassing
   the stub.

### Address mapping

| IPv6 input            | Engine sees (netadr_t)   | Notes                                    |
|-----------------------|--------------------------|------------------------------------------|
| `::1` (loopback)      | `127.0.0.1`              | Engine's loopback queue works for local  |
| `::` (unspecified)    | `0.0.0.0`                | Bind to `[::]` for dual-stack            |
| `::ffff:a.b.c.d`      | `a.b.c.d` (v4-mapped)    | Extract IPv4 directly                    |
| Other pure IPv6       | `198.51.100.N` (sentinel)| RFC 5737 TEST-NET-2, peer table lookup   |

The sentinel range `198.51.100.0/24` is chosen because it's:
- NOT `127.0.0.0/8` — engine redirects 127.0.0.1 to in-process loopback queue
- NOT `240.0.0.0/4` — SteamNetworkingSockets FakeIP range

## Requirements

- TF2 install (copied to a separate directory, NOT the Steam install)
- [Goldberg Steam emu](https://gitlab.com/Mr_Goldberg/goldberg_emulator) (Linux build)
- GCC (build the shim with `-O0`)

### Directory layout

The launch scripts resolve paths relative to their own location and expect:

```
tf2-ipv6-patch/
├── libtf2_ipv6_shim.so      # build this (see below)
├── launch_srcds_ipv6.sh
├── launch_tf2_ipv6.sh
├── tf2_srcds_v6/            # your TF2 dedicated server copy (or set TF2_SRCDS_ROOT)
├── tf2-ipv6/                # your TF2 client/listen-server copy (or set TF2_ROOT)
├── goldberg_linux/          # Goldberg emu linux/ dir (or set GOLDBERG_DIR)
│   └── x86_64/steamclient.so
└── fakehome/                # auto-created; holds the isolated steamclient.so
```

All paths can be overridden with the `TF2_SRCDS_ROOT`, `TF2_ROOT`, and
`GOLDBERG_DIR` environment variables.

## Build

```bash
gcc -shared -fPIC -O0 -o libtf2_ipv6_shim.so tf2_ipv6_shim.c -ldl
```

**CRITICAL: must use `-O0`.** With `-O2`, GCC optimizes manual zeroing loops
into `memset` PLT calls that deadlock in the parser relay context (glibc/libdl
reentrancy). With `-O0`, compiler-generated `{0}` array init also deadlocks —
all arrays must be zeroed with explicit element-by-element assignment.

## Launch

### Dedicated server (srcds)

```bash
bash launch_srcds_ipv6.sh +ip [::]:27015 +hostport 27015 +maxplayers 24 +sv_lan 1 +map cp_dustbowl
```

Required convars (baked into the script):
- `+net_usesocketsforloopback 1` — force real UDP for localhost. Without this,
  `NET_SendPacket` redirects `127.0.0.1` responses to the in-process loopback
  queue, which external clients never read. **This was the root cause of all
  A2S query and client connection failures.**
- `+tf_allow_server_hibernation 0` — keep the server active. Hibernating
  servers do not process connectionless packets.

### Listen server

```bash
bash launch_tf2_ipv6.sh -novid -console +sv_lan 1 +ip [::1]:27015 +hostport 27015 +maxplayers 2 +map cp_dustbowl
```

### Client (connecting to a server)

```bash
# Connect to a srcds server:
bash launch_tf2_ipv6.sh -novid -windowed -noborder +connect [::1]:27015

# Connect to a listen server (same machine, needs unique TMPDIR for single-instance lock):
TMPDIR=/tmp/tf2_client bash launch_tf2_ipv6.sh -novid -windowed -noborder +connect [::1]:27015
```

## Verification

### A2S queries (server browser)

```python
# A2S_INFO over IPv6
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b'\xff\xff\xff\xffTSource Engine Query\x00', ('::1', 27015))
data, _ = s.recvfrom(1400)
print(f"Response: {len(data)} bytes")  # should be ~68 bytes
```

### Client connection

Launch srcds, then launch a client with `+connect [::1]:27015`. The client
should reach gameplay within ~30 seconds.

## Files

| File | Description |
|------|-------------|
| `tf2_ipv6_shim.c` | Shim source (build with `-O0`) |
| `libtf2_ipv6_shim.so` | Compiled shim |
| `launch_srcds_ipv6.sh` | Dedicated server launch script |
| `launch_tf2_ipv6.sh` | Listen server / client launch script |
| `fakehome/.steam/sdk64/steamclient.so` | Goldberg's steamclient (isolated) |
| `test_shim.c` | Unit test for v4↔v6 translation |

## Goldberg emu setup

The Goldberg emu isolates TF2 from real Steam (avoids VAC flagging):

1. `steam_appid.txt` = `440` (in TF2 root)
2. `steam_settings/steam_interfaces.txt` = generated via `find_interfaces.sh`
3. Goldberg's `libsteam_api.so` and `steamclient.so` replace originals
4. Real Steam is never touched — `HOME` is set to `fakehome/`

For srcds, AppID 232250 (TF2 dedicated server) appears in Breakpad, but
Goldberg uses 440 (`steam_appid.txt`).

## Key discoveries

### `net_usesocketsforloopback` (root cause of no-response bug)

The engine's `NET_SendPacket` checks `IsLocalhost()` on the destination
address. If true, it checks the `net_usesocketsforloopback` convar:
- **0 (default)**: redirect to `NET_SendLoopPacket` (in-process queue)
- **1**: use real UDP

When a client connects to `127.0.0.1` (which `::1` maps to), the server's
responses go to the in-process loopback queue. An external client process
never reads that queue, so **all responses are silently dropped**.

Fix: `+net_usesocketsforloopback 1` on both server and client.

### Goldberg's `HandleIncomingPacket` stub

Goldberg's `ISteamGameServer::HandleIncomingPacket` returns `true` but does
nothing. A2S_INFO/A2A_PING/A2S_PLAYER/A2S_RULES queries go through the
`default` case in `CBaseServer::ProcessConnectionlessPacket`, which forwards
them to `HandleIncomingPacket` — and they're dropped.

Fix: the shim's A2S query responder intercepts these packets in `recvfrom`
and crafts responses directly.

### `nsts_relay` register usage

The parser relay function must use `r11` (caller-saved scratch) for the jump
target, NOT `rax`. The original `NET_StringToSockadr` prologue sets `eax=2`
(AF_INET) which is used later in the function. Clobbering `rax` breaks the
function for ALL addresses.

### `::1` → `127.0.0.1` mapping (not sentinel)

`::1` maps to `127.0.0.1` (NOT a sentinel) so the listen server's local client
uses the in-process loopback queue. The `bind()` interceptor translates
`127.0.0.1` back to `[::1]` so the server socket receives pure IPv6.

### `0.0.0.0` → `[::]` bind

`bind()` translates `0.0.0.0` to `[::]` (in6addr_any), NOT `[::ffff:0.0.0.0]`.
With `IPV6_V6ONLY=0`, `[::]` receives BOTH v4-mapped and pure IPv6 traffic.
`[::ffff:0.0.0.0]` would only receive v4-mapped, dropping pure IPv6.
