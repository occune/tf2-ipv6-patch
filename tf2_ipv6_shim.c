// tf2_ipv6_shim.c — LD_PRELOAD shim that gives TF2 dual-stack IPv6 sockets
//
// Two mechanisms:
//   1. Socket shim: intercepts socket()/bind()/connect()/sendto()/recvfrom()/
//      gethostbyname()/inet_addr() so TF2's IPv4-only engine gets transparent
//      dual-stack (AF_INET6 with IPV6_V6ONLY=0) networking. sockaddr_in is
//      rewritten to v4-mapped sockaddr_in6 at the syscall boundary.
//   2. Parser hook: inline-hooks NET_StringToSockadr in engine.so (listen
//      server, tf_linux64) or engine_srv.so (dedicated server, srcds) so that
//      bracketed IPv6 literals like "[::1]:27015" are parsed. The hook target
//      is found dynamically by scanning executable segments for the unique
//      16-byte prologue — no hardcoded offsets.
//
// netadr_t stays IPv4 internally. Pure IPv6-only hosts that have no v4-mapped
// representation can still be bound/connected via the sentinel path.
//
// Build: gcc -shared -fPIC -O0 -o libtf2_ipv6_shim.so tf2_ipv6_shim.c -ldl
// Usage: LD_PRELOAD=./libtf2_ipv6_shim.so ./tf_linux64 ...   (listen server)
//        LD_PRELOAD=./libtf2_ipv6_shim.so ./srcds_linux64 ... (dedicated)

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <link.h>
#include <sys/mman.h>
#include <stdint.h>

// ============================================================================
// Real function pointers
// ============================================================================

static int (*real_socket)(int, int, int) = NULL;
static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*real_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *) = NULL;
static ssize_t (*real_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*real_recv_real)(int, void *, size_t, int) = NULL;
static ssize_t (*real_recvmsg)(int, struct msghdr *, int) = NULL;
static int (*real_setsockopt)(int, int, int, const void *, socklen_t) = NULL;
static int (*real_getsockname)(int, struct sockaddr *, socklen_t *) = NULL;
static int (*real_getpeername)(int, struct sockaddr *, socklen_t *) = NULL;
static struct hostent *(*real_gethostbyname)(const char *) = NULL;

static int g_init_done = 0;

/* Forward declarations */
static void ensure_parser_hook(void);

static void init_real_funcs(void)
{
	if (g_init_done) return;
	g_init_done = 1;
	real_socket = dlsym(RTLD_NEXT, "socket");
	real_bind = dlsym(RTLD_NEXT, "bind");
	real_connect = dlsym(RTLD_NEXT, "connect");
	real_sendto = dlsym(RTLD_NEXT, "sendto");
	real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
	real_send = dlsym(RTLD_NEXT, "send");
	real_recv_real = dlsym(RTLD_NEXT, "recv");
	real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
	real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
	real_getsockname = dlsym(RTLD_NEXT, "getsockname");
	real_getpeername = dlsym(RTLD_NEXT, "getpeername");
	real_gethostbyname = dlsym(RTLD_NEXT, "gethostbyname");
	fprintf(stderr, "[tf2_ipv6_shim] initialized (PID %d)\n", (int)getpid());
}

// ============================================================================
// Pure-IPv6 override (sentinel mechanism)
// ============================================================================
//
// Pure IPv6 addresses are stored in a peer table (g_peer_v6) and referenced
// via sentinel IPv4 addresses (198.51.100.N). The same table is used by both
// try_ipv6() (parsing) and from_in6() (receiving), ensuring address
// consistency. See the peer table comment below for details.

// Peer IPv6 table: maps sentinel IPv4 (198.51.100.N) to real IPv6 addresses.
// Used for BOTH:
//  - Parsing: try_ipv6() allocates a peer sentinel for pure IPv6 literals
//  - Receiving: from_in6() allocates a peer sentinel for pure IPv6 peers
// Using the SAME table for both ensures the address stored in netadr_t by
// the parser matches the source address of received packets. If they used
// different sentinels, the engine would reject responses (address mismatch).
//
// The sentinel range is 198.51.100.0/24 (RFC 5737 TEST-NET-2), reserved for
// documentation and never used in real traffic. This range is chosen because:
//  - NOT 127.0.0.0/8: the engine's NET_SendPacket redirects 127.0.0.1 traffic
//    to an in-process loopback queue (net_ws.cpp NET_SendLoopPacket), which
//    would prevent the response from reaching the real UDP socket.
//  - NOT 240.0.0.0/4: TF2's SteamNetworkingSockets uses this range for
//    "FakeIP" addresses (Steam P2P). If we used 240.x.x.x, the engine would
//    route packets through ISteamNetworking instead of real UDP, and the
//    response would never be sent via sendto().
#define MAX_PEER_V6 16
#define PEER_SENTINEL_BASE 0xC6336400u  /* 198.51.100.0 in host byte order */
struct peer_v6_entry {
	struct in6_addr addr6;
	int in_use;
};
static struct peer_v6_entry g_peer_v6[MAX_PEER_V6];

static uint32_t alloc_peer_v6(const struct in6_addr *addr)
{
	int i;
	/* Check if already in table */
	for (i = 0; i < MAX_PEER_V6; i++) {
		if (g_peer_v6[i].in_use &&
		    memcmp(&g_peer_v6[i].addr6, addr, 16) == 0) {
			return htonl(PEER_SENTINEL_BASE + (uint32_t)i + 1);
		}
	}
	/* Find free slot */
	for (i = 0; i < MAX_PEER_V6; i++) {
		if (!g_peer_v6[i].in_use) {
			g_peer_v6[i].addr6 = *addr;
			g_peer_v6[i].in_use = 1;
			return htonl(PEER_SENTINEL_BASE + (uint32_t)i + 1);
		}
	}
	/* Table full — reuse slot 0 */
	g_peer_v6[0].addr6 = *addr;
	g_peer_v6[0].in_use = 1;
	return htonl(PEER_SENTINEL_BASE + 1);
}

static int lookup_peer_v6(uint32_t sentinel_net, struct in6_addr *out)
{
	uint32_t s = ntohl(sentinel_net);
	if (s < PEER_SENTINEL_BASE + 1 || s >= PEER_SENTINEL_BASE + 1 + MAX_PEER_V6) return 0;
	int idx = (int)(s - (PEER_SENTINEL_BASE + 1));
	if (!g_peer_v6[idx].in_use) return 0;
	*out = g_peer_v6[idx].addr6;
	return 1;
}

static int try_override_v6(const struct sockaddr *in, struct sockaddr_in6 *out)
{
	if (!in || !out || in->sa_family != AF_INET) return 0;
	const struct sockaddr_in *in4 = (const struct sockaddr_in *)in;

	/* Peer sentinel (198.51.100.N) — translate to real IPv6 address */
	struct in6_addr peer6;
	if (lookup_peer_v6(in4->sin_addr.s_addr, &peer6)) {
		memset(out, 0, sizeof(*out));
		out->sin6_family = AF_INET6;
		out->sin6_port = in4->sin_port;
		memcpy(&out->sin6_addr, &peer6, 16);
		return 1;
	}

	return 0;
}

// ============================================================================
// sockaddr_in <-> sockaddr_in6 translation
// ============================================================================

static int to_in6(const struct sockaddr *in, socklen_t inlen,
                  struct sockaddr_in6 *out, socklen_t *outlen)
{
	(void)inlen;
	if (!in || !out) return -1;
	if (in->sa_family == AF_INET6)
	{
		memcpy(out, in, sizeof(struct sockaddr_in6));
		if (outlen) *outlen = sizeof(struct sockaddr_in6);
		return 0;
	}
	if (in->sa_family == AF_INET)
	{
		const struct sockaddr_in *in4 = (const struct sockaddr_in *)in;
		memset(out, 0, sizeof(*out));
		out->sin6_family = AF_INET6;
		out->sin6_port = in4->sin_port;
		out->sin6_flowinfo = 0;
		out->sin6_addr.s6_addr[10] = 0xff;
		out->sin6_addr.s6_addr[11] = 0xff;
		memcpy(&out->sin6_addr.s6_addr[12], &in4->sin_addr, 4);
		out->sin6_scope_id = 0;
		if (outlen) *outlen = sizeof(struct sockaddr_in6);
		return 1;
	}
	return -1;
}

static int from_in6(const struct sockaddr_in6 *in,
                    struct sockaddr *out, socklen_t *outlen)
{
	if (!in || !out) return -1;
	if (in->sin6_family == AF_INET6)
	{
		const unsigned char *b = in->sin6_addr.s6_addr;
		/* v4-mapped: extract IPv4 */
		if (b[0]==0 && b[1]==0 && b[2]==0 && b[3]==0 &&
		    b[4]==0 && b[5]==0 && b[6]==0 && b[7]==0 &&
		    b[8]==0 && b[9]==0 && b[10]==0xff && b[11]==0xff)
		{
			struct sockaddr_in out4;
			memset(&out4, 0, sizeof(out4));
			out4.sin_family = AF_INET;
			out4.sin_port = in->sin6_port;
			memcpy(&out4.sin_addr, &b[12], 4);
			memcpy(out, &out4, sizeof(out4));
			if (outlen) *outlen = sizeof(struct sockaddr_in);
			return 1;
		}
		/* Pure IPv6 loopback (::1) -> 127.0.0.1
		 * This is CRITICAL for listen servers: the engine's NET_SendPacket
		 * redirects 127.0.0.1 traffic to an in-process loopback queue
		 * (NET_SendLoopPacket), which is how the local client connects to
		 * the local server. If we used a peer sentinel here, the engine
		 * would try real UDP, hit the broken FakeUDP path, and the local
		 * client would fail to connect ("Connection failed after 4 retries").
		 * The bind() interceptor translates 127.0.0.1 back to [::1] so the
		 * server socket still receives pure IPv6 for external clients. */
		if (b[0]==0 && b[1]==0 && b[2]==0 && b[3]==0 &&
		    b[4]==0 && b[5]==0 && b[6]==0 && b[7]==0 &&
		    b[8]==0 && b[9]==0 && b[10]==0 && b[11]==0 &&
		    b[12]==0 && b[13]==0 && b[14]==0 && b[15]==1)
		{
			struct sockaddr_in out4;
			memset(&out4, 0, sizeof(out4));
			out4.sin_family = AF_INET;
			out4.sin_port = in->sin6_port;
			out4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			memcpy(out, &out4, sizeof(out4));
			if (outlen) *outlen = sizeof(struct sockaddr_in);
			return 1;
		}
		/* Pure IPv6 unspecified (::) -> 0.0.0.0
		 * (Safe — 0.0.0.0 doesn't trigger the engine's loopback redirect.) */
		if (b[0]==0 && b[1]==0 && b[2]==0 && b[3]==0 &&
		    b[4]==0 && b[5]==0 && b[6]==0 && b[7]==0 &&
		    b[8]==0 && b[9]==0 && b[10]==0 && b[11]==0 &&
		    b[12]==0 && b[13]==0 && b[14]==0 && b[15]==0)
		{
			struct sockaddr_in out4;
			memset(&out4, 0, sizeof(out4));
			out4.sin_family = AF_INET;
			out4.sin_port = in->sin6_port;
			out4.sin_addr.s_addr = htonl(INADDR_ANY);
			memcpy(out, &out4, sizeof(out4));
			if (outlen) *outlen = sizeof(struct sockaddr_in);
			return 1;
		}
		/* Other pure IPv6: allocate a peer sentinel (198.51.100.N) so the
		 * engine can store it in netadr_t. The sentinel is NOT 127.0.0.1
		 * (so loopback redirect doesn't trigger) and NOT in 240.0.0.0/4
		 * (Steam FakeIP range). Used for external IPv6 peers. */
		{
			uint32_t sentinel = alloc_peer_v6(&in->sin6_addr);
			struct sockaddr_in out4;
			memset(&out4, 0, sizeof(out4));
			out4.sin_family = AF_INET;
			out4.sin_port = in->sin6_port;
			out4.sin_addr.s_addr = sentinel;
			memcpy(out, &out4, sizeof(out4));
			if (outlen) *outlen = sizeof(struct sockaddr_in);
			return 1;
		}
	}
	if (outlen) *outlen = sizeof(struct sockaddr_in6);
	memcpy(out, in, sizeof(struct sockaddr_in6));
	return 0;
}

// ============================================================================
// Intercepted socket functions
// ============================================================================

int socket(int domain, int type, int protocol)
{
	if (!g_init_done) init_real_funcs();
	ensure_parser_hook();

	if (domain == AF_INET || domain == PF_INET)
		domain = AF_INET6;
	else if (domain == PF_INET6)
		domain = AF_INET6;

	int fd = real_socket(domain, type, protocol);
	if (fd >= 0 && domain == AF_INET6)
	{
		int v6only = 0;
		if (!real_setsockopt) real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
		real_setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
	}
	return fd;
}

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (!g_init_done) init_real_funcs();

	struct sockaddr_in6 override6;
	if (try_override_v6(addr, &override6))
	{
		return real_bind(fd, (const struct sockaddr *)&override6, sizeof(override6));
	}

	struct sockaddr_in6 addr6;
	socklen_t outlen;
	int r = to_in6(addr, addrlen, &addr6, &outlen);
	if (r >= 0)
	{
		/* Special case: IPv4 0.0.0.0 (INADDR_ANY) must bind to [::]
		 * (in6addr_any), NOT [::ffff:0.0.0.0]. With IPV6_V6ONLY=0:
		 *   [::]              -> receives BOTH v4-mapped and pure IPv6
		 *   [::ffff:0.0.0.0]  -> receives ONLY v4-mapped (pure IPv6 drops)
		 * If the client binds to [::ffff:0.0.0.0], it won't receive
		 * packets from pure IPv6 peers (e.g. ::1). */
		if (addr->sa_family == AF_INET)
		{
			const struct sockaddr_in *in4 = (const struct sockaddr_in *)addr;
			if (in4->sin_addr.s_addr == htonl(INADDR_ANY))
			{
				memset(&addr6, 0, sizeof(addr6));
				addr6.sin6_family = AF_INET6;
				addr6.sin6_port = in4->sin_port;
				addr6.sin6_addr = in6addr_any;
			}
			/* 127.0.0.1 -> [::1] so the server socket receives pure IPv6.
			 * The parser maps ::1 to 127.0.0.1 (for the loopback queue),
			 * but the actual socket must bind to [::1] to receive pure
			 * IPv6 traffic from external clients. */
			else if (in4->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
			{
				memset(&addr6, 0, sizeof(addr6));
				addr6.sin6_family = AF_INET6;
				addr6.sin6_port = in4->sin_port;
				addr6.sin6_addr = in6addr_loopback;
			}
		}

		return real_bind(fd, (const struct sockaddr *)&addr6, outlen);
	}
	return real_bind(fd, addr, addrlen);
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (!g_init_done) init_real_funcs();

	struct sockaddr_in6 override6;
	if (try_override_v6(addr, &override6))
	{
		return real_connect(fd, (const struct sockaddr *)&override6, sizeof(override6));
	}

	struct sockaddr_in6 addr6;
	socklen_t outlen;
	int r = to_in6(addr, addrlen, &addr6, &outlen);
	if (r >= 0)
		return real_connect(fd, (const struct sockaddr *)&addr6, outlen);
	return real_connect(fd, addr, addrlen);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest, socklen_t addrlen)
{
	if (!g_init_done) init_real_funcs();
	if (dest)
	{
		struct sockaddr_in6 override6;
		if (try_override_v6(dest, &override6))
		{
			return real_sendto(fd, buf, len, flags, (const struct sockaddr *)&override6, sizeof(override6));
		}

		struct sockaddr_in6 addr6;
		socklen_t outlen;
		int r = to_in6(dest, addrlen, &addr6, &outlen);
		if (r >= 0)
		{
			return real_sendto(fd, buf, len, flags, (const struct sockaddr *)&addr6, outlen);
		}
	}
	return real_sendto(fd, buf, len, flags, dest, addrlen);
}

// ============================================================================
// A2S query responder
// ============================================================================
//
// Goldberg's ISteamGameServer::HandleIncomingPacket is a stub (returns true,
// does nothing). This means A2S_INFO, A2S_PING, A2S_PLAYER, A2S_RULES queries
// are received by the server but never answered — the engine's default case
// in CBaseServer::ProcessConnectionlessPacket forwards them to the Steam
// interface, which drops them.
//
// This interceptor inspects connectionless packets received on the server's
// game socket (NS_SERVER, fd >= 10) and crafts responses directly via sendto,
// bypassing Goldberg's stub. Only the server process responds; the client
// process (which also loads the shim) is ignored because it never binds a
// listening game socket on port 27015.
//
// Supported queries:
//   A2S_INFO  ('T' + "Source Engine Query" + '\0')  -> S2A_INFO_SRC
//   A2A_PING  ('i')                                 -> A2A_ACK ('j')
//   A2S_PLAYER('U' + challenge)                     -> S2A_PLAYER (empty)
//   A2S_RULES ('V' + challenge)                     -> S2A_RULES (empty)

/* Server info fields — simple static defaults. */
static const char *A2S_HOSTNAME   = "TF2 IPv6 Server";
static const char *A2S_MAP        = "cp_dustbowl";
static const char *A2S_GAMEDIR    = "tf";
static const char *A2S_GAMEDESC   = "Team Fortress";
static const char *A2S_VERSION    = "1.0.0.0";
static const int  A2S_PROTOCOL    = 24;   /* Source protocol version */
static const int  A2S_MAX_PLAYERS = 24;
static const int  A2S_APPID       = 440;

static void send_a2s_response(int fd, const struct sockaddr_in6 *src6,
                              const unsigned char *query, ssize_t qlen)
{
	/* All A2S queries start with 4-byte 0xFF header + 1-byte command */
	if (qlen < 5) return;
	if (query[0] != 0xFF || query[1] != 0xFF ||
	    query[2] != 0xFF || query[3] != 0xFF) return;

	unsigned char resp[1400];
	int rlen = 0;
	int do_send = 0;
	unsigned char cmd = query[4];

	if (cmd == 'T')
	{
		/* A2S_INFO: verify "Source Engine Query\0" suffix */
		if (qlen < 5 + 20) return;
		if (memcmp(&query[5], "Source Engine Query", 19) != 0) return;
		if (query[24] != 0) return;

		/* S2A_INFO_SRC response */
		resp[0]=0xFF; resp[1]=0xFF; resp[2]=0xFF; resp[3]=0xFF;
		resp[4]='I';  /* S2A_INFO_SRC */
		resp[5]=(unsigned char)A2S_PROTOCOL;
		int off = 6;
		/* hostname */
		{ const char *s = A2S_HOSTNAME; while (*s) resp[off++]=*s++; resp[off++]=0; }
		/* map */
		{ const char *s = A2S_MAP; while (*s) resp[off++]=*s++; resp[off++]=0; }
		/* gamedir */
		{ const char *s = A2S_GAMEDIR; while (*s) resp[off++]=*s++; resp[off++]=0; }
		/* game description */
		{ const char *s = A2S_GAMEDESC; while (*s) resp[off++]=*s++; resp[off++]=0; }
		/* AppID (16-bit) */
		resp[off++]=(unsigned char)(A2S_APPID & 0xFF);
		resp[off++]=(unsigned char)((A2S_APPID >> 8) & 0xFF);
		/* num players, max players, bots */
		resp[off++]=0; resp[off++]=(unsigned char)A2S_MAX_PLAYERS; resp[off++]=0;
		/* server type: 'd' = dedicated */
		resp[off++]='d';
		/* OS: 'l' = Linux */
		resp[off++]='l';
		/* password: 0 = no */
		resp[off++]=0;
		/* VAC secure: 0 = no */
		resp[off++]=0;
		/* version string */
		{ const char *s = A2S_VERSION; while (*s) resp[off++]=*s++; resp[off++]=0; }
		/* No extra data flags (EDF) — keep it minimal */
		rlen = off;
		do_send = 1;
	}
	else if (cmd == 'i')
	{
		/* A2A_PING -> A2A_ACK ('j') */
		resp[0]=0xFF; resp[1]=0xFF; resp[2]=0xFF; resp[3]=0xFF;
		resp[4]='j';
		rlen = 5;
		do_send = 1;
	}
	else if (cmd == 'U')
	{
		/* A2S_PLAYER: respond with empty player list.
		 * Format: -1 header, 'U', challenge. We just send back the
		 * challenge they gave us (or -1 if they're requesting one). */
		resp[0]=0xFF; resp[1]=0xFF; resp[2]=0xFF; resp[3]=0xFF;
		resp[4]='U';
		/* player count = 0 */
		resp[5]=0;
		rlen = 6;
		do_send = 1;
	}
	else if (cmd == 'V')
	{
		/* A2S_RULES: respond with empty rules list. */
		resp[0]=0xFF; resp[1]=0xFF; resp[2]=0xFF; resp[3]=0xFF;
		resp[4]='V';
		/* rule count = 0 */
		resp[5]=0; resp[6]=0;
		rlen = 7;
		do_send = 1;
	}

	if (do_send)
	{
		real_sendto(fd, resp, rlen, 0,
		            (const struct sockaddr *)src6, sizeof(*src6));
	}
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *src, socklen_t *addrlen)
{
	if (!g_init_done) init_real_funcs();
	struct sockaddr_in6 src6;
	socklen_t in6len = sizeof(src6);
	ssize_t n = real_recvfrom(fd, buf, len, flags, (struct sockaddr *)&src6, &in6len);
	if (n >= 0)
	{
		/* A2S query responder: check for connectionless packets on the
		 * server game socket (fd >= 10). This bypasses Goldberg's stub
		 * HandleIncomingPacket which would normally drop these queries. */
		if (fd >= 10 && n >= 5)
		{
			const unsigned char *q = (const unsigned char *)buf;
			if (q[0]==0xFF && q[1]==0xFF && q[2]==0xFF && q[3]==0xFF)
			{
				send_a2s_response(fd, &src6, q, n);
			}
		}
		if (src && addrlen)
		{
			from_in6(&src6, src, addrlen);
		}
	}
	return n;
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	if (!g_init_done) init_real_funcs();
	return real_recv_real(fd, buf, len, flags);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
	if (!g_init_done) init_real_funcs();
	return real_recvmsg(fd, msg, flags);
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	if (!g_init_done) init_real_funcs();
	return real_send(fd, buf, len, flags);
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	if (!g_init_done) init_real_funcs();
	struct sockaddr_in6 addr6;
	socklen_t in6len = sizeof(addr6);
	int r = real_getsockname(fd, (struct sockaddr *)&addr6, &in6len);
	if (r == 0 && addr && addrlen)
		from_in6(&addr6, addr, addrlen);
	return r;
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	if (!g_init_done) init_real_funcs();
	struct sockaddr_in6 addr6;
	socklen_t in6len = sizeof(addr6);
	int r = real_getpeername(fd, (struct sockaddr *)&addr6, &in6len);
	if (r == 0 && addr && addrlen)
		from_in6(&addr6, addr, addrlen);
	return r;
}

// ============================================================================
// gethostbyname: resolve via getaddrinfo, prefer A records
// ============================================================================

static struct hostent g_he;
static char *g_h_addr_list[2];
static char g_h_addr_data[16];

struct hostent *gethostbyname(const char *name)
{
	if (!g_init_done) init_real_funcs();

	if (name && (!strcmp(name, "localhost") || !strncmp(name, "localhost:", 10)))
	{
		memset(&g_he, 0, sizeof(g_he));
		g_he.h_name = (char *)"localhost";
		g_he.h_addrtype = AF_INET;
		g_he.h_length = 4;
		struct in_addr lo;
		inet_pton(AF_INET, "127.0.0.1", &lo);
		memcpy(g_h_addr_data, &lo, 4);
		g_h_addr_list[0] = g_h_addr_data;
		g_h_addr_list[1] = NULL;
		g_he.h_addr_list = g_h_addr_list;
		return &g_he;
	}

	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_ADDRCONFIG;

	int err = getaddrinfo(name, NULL, &hints, &res);
	if (err != 0 || !res)
		return real_gethostbyname ? real_gethostbyname(name) : NULL;

	struct addrinfo *p;
	for (p = res; p; p = p->ai_next)
	{
		if (p->ai_family == AF_INET)
		{
			struct sockaddr_in *in4 = (struct sockaddr_in *)p->ai_addr;
			memset(&g_he, 0, sizeof(g_he));
			g_he.h_name = (char *)name;
			g_he.h_addrtype = AF_INET;
			g_he.h_length = 4;
			memcpy(g_h_addr_data, &in4->sin_addr, 4);
			g_h_addr_list[0] = g_h_addr_data;
			g_h_addr_list[1] = NULL;
			g_he.h_addr_list = g_h_addr_list;
			freeaddrinfo(res);
			return &g_he;
		}
	}

	for (p = res; p; p = p->ai_next)
	{
		if (p->ai_family == AF_INET6)
		{
			struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)p->ai_addr;
			const unsigned char *b = in6->sin6_addr.s6_addr;
			if (b[10]==0xff && b[11]==0xff)
			{
				memset(&g_he, 0, sizeof(g_he));
				g_he.h_name = (char *)name;
				g_he.h_addrtype = AF_INET;
				g_he.h_length = 4;
				memcpy(g_h_addr_data, &b[12], 4);
				g_h_addr_list[0] = g_h_addr_data;
				g_h_addr_list[1] = NULL;
				g_he.h_addr_list = g_h_addr_list;
				freeaddrinfo(res);
				return &g_he;
			}
			break;
		}
	}

	freeaddrinfo(res);
	return real_gethostbyname ? real_gethostbyname(name) : NULL;
}

// inet_addr / inet_ntoa: pass through
typedef in_addr_t (*inet_addr_t)(const char *);
static inet_addr_t real_inet_addr = NULL;
in_addr_t inet_addr(const char *cp)
{
	if (!g_init_done) init_real_funcs();
	if (!real_inet_addr) real_inet_addr = dlsym(RTLD_NEXT, "inet_addr");
	return real_inet_addr(cp);
}

typedef char *(*inet_ntoa_t)(struct in_addr);
static inet_ntoa_t real_inet_ntoa = NULL;
char *inet_ntoa(struct in_addr in)
{
	if (!real_inet_ntoa) real_inet_ntoa = dlsym(RTLD_NEXT, "inet_ntoa");
	return real_inet_ntoa(in);
}

// ============================================================================
// Parser hook: inline-hook NET_StringToSockadr in engine.so
// ============================================================================
//
// The function at engine.so+0x552e60 has this 16-byte prologue:
//   55              push rbp
//   b8 02 00 00 00  mov eax, 2
//   ba 80 00 00 00  mov edx, 0x80
//   48 89 e5        mov rsp, rbp
//   41 55           push r13
//
// We overwrite it with: mov rax, nsts_relay ; jmp rax ; nop*4
// The relay checks for '[' and calls try_ipv6, or falls through to original.

__attribute__((used))
static uintptr_t g_original_continue = 0;

__attribute__((used))
static int (*g_try_ipv6_ptr)(const char *, struct sockaddr *) = NULL;

static int try_ipv6(const char *s, struct sockaddr *out);

__attribute__((naked, used))
static void nsts_relay(void)
{
	__asm__ volatile (
		/* At entry, rsp ≡ 8 (mod 16) — original call pushed return addr.
		 * We must preserve this alignment when calling C functions.
		 *
		 * IMPORTANT: use r11 (caller-saved scratch) for jumps/loads, NOT rax.
		 * The original prologue sets eax=2 (AF_INET) which is used later.
		 * Clobbering rax breaks the function (listen server fails to connect). */
		"cmpb $0x5b, (%rdi)\n\t"      /* '[' = 0x5b */
		"jne 1f\n\t"
		/* IPv6 path: address starts with '['. Call try_ipv6.
		 * push rdi + push rsi = 16 bytes, rsp stays ≡ 8 (mod 16).
		 * sub $8 makes rsp ≡ 0, so at call entry rsp ≡ 8 (correct ABI). */
		"push %rdi\n\t"
		"push %rsi\n\t"
		"sub $8, %rsp\n\t"            /* align stack for ABI */
		"call *g_try_ipv6_ptr(%rip)\n\t"
		"add $8, %rsp\n\t"
		"pop %rsi\n\t"
		"pop %rdi\n\t"
		"testl %eax, %eax\n\t"
		"jnz 2f\n\t"
		"1:\n\t"
		/* Fall through to original code. Reconstruct original prologue:
		 *   push rbp ; mov eax,2 ; mov edx,0x80 ; mov rbp,rsp ; push r13
		 * then jump to original+16. Use r11 for jump target (not rax). */
		"push %rbp\n\t"
		"mov $2, %eax\n\t"
		"mov $0x80, %edx\n\t"
		"mov %rsp, %rbp\n\t"
		"push %r13\n\t"
		"movq g_original_continue(%rip), %r11\n\t"
		"jmpq *%r11\n\t"
		"2:\n\t"
		"mov $1, %eax\n\t"
		"ret\n\t"
	);
}

/*
 * try_ipv6 — parse a bracketed IPv6 literal like "[::1]:27015".
 * Fills *out as sockaddr_in. For v4-mapped, stores IPv4 directly. For pure
 * IPv6, stores sentinel 240.0.0.1 + saves real addr in g_override_v6.
 *
 * IMPORTANT: The inline IPv6 parser must NOT use compiler-generated array
 * initialization ({0}) — with -O0, GCC emits a memset PLT call that
 * deadlocks in the relay context (glibc/libdl reentrancy). All arrays are
 * zeroed with explicit element assignment.
 */
static int try_ipv6(const char *s, struct sockaddr *out)
{
	if (!s || !out) return 0;
	if (s[0] != '[') return 0;

	const char *close = strchr(s, ']');
	if (!close) return 0;

	char addr6[64];
	size_t len = close - s - 1;
	if (len == 0 || len >= sizeof(addr6)) return 0;
	memcpy(addr6, s + 1, len);
	addr6[len] = '\0';

	unsigned short port_net = 0;
	if (close[1] == ':')
		port_net = htons((unsigned short)atoi(close + 2));

	/* Inline IPv6 parser */
	struct in6_addr v6;
	int pton_ret = 0;
	/* Manually zero v6 (no {0} init) */
	{
		unsigned char *vb = (unsigned char *)&v6;
		int vi;
		for (vi = 0; vi < 16; vi++) vb[vi] = 0;
	}

	unsigned int words[8];
	/* Manually zero words (no {0} init) */
	words[0] = words[1] = words[2] = words[3] = 0;
	words[4] = words[5] = words[6] = words[7] = 0;

	{
		int nwords = 0, dblcolon = -1;
		const char *p = addr6;

		if (p[0] == ':' && p[1] == ':')
		{
			dblcolon = 0;
			p += 2;
			if (!*p) goto parse_done;
		}

		while (*p && nwords < 8)
		{
			/* Embedded IPv4? (dot must be before any remaining ':', room for 2 words) */
			{
				const char *nc = strchr(p, ':');
				const char *nd = strchr(p, '.');
				if (nd && (!nc || nd < nc) && nwords <= 6)
				{
					/* Embedded IPv4: a.b.c.d */
					unsigned int oct[4];
					int oi = 0, odig = 0;
					oct[0] = oct[1] = oct[2] = oct[3] = 0;
					while (*p && *p != ':')
					{
						if (*p == '.')
						{
							if (odig == 0 || oi >= 3) goto parse_fail;
							oi++; odig = 0; p++;
							continue;
						}
						if (*p < '0' || *p > '9') goto parse_fail;
						oct[oi] = oct[oi] * 10 + (*p - '0');
						odig++; p++;
						if (oct[oi] > 255) goto parse_fail;
					}
					if (oi != 3 || odig == 0) goto parse_fail;
					words[nwords++] = (oct[0] << 8) | oct[1];
					words[nwords++] = (oct[2] << 8) | oct[3];
					break;
				}
			}

			/* Check for :: (two consecutive colons) */
			if (*p == ':' && p[1] == ':')
			{
				if (dblcolon >= 0) goto parse_fail;
				dblcolon = nwords;
				p += 2;
				if (!*p) break;
				continue;
			}

			/* Skip single : separator */
			if (*p == ':')
			{
				p++;
				continue;
			}

			unsigned int word = 0;
			int digits = 0;
			while (*p && *p != ':')
			{
				char ch = *p;
				unsigned int val;
				if (ch >= '0' && ch <= '9') val = ch - '0';
				else if (ch >= 'a' && ch <= 'f') val = ch - 'a' + 10;
				else if (ch >= 'A' && ch <= 'F') val = ch - 'A' + 10;
				else goto parse_fail;
				word = word * 16 + val;
				digits++; p++;
				if (digits > 4) goto parse_fail;
			}
			if (digits == 0) goto parse_fail;
			words[nwords++] = word;
		}

	parse_done:
		if (dblcolon >= 0)
		{
			int nfill = 8 - nwords;
			int i;
			if (nfill < 0) goto parse_fail;
			for (i = nwords - 1; i >= dblcolon; i--)
				words[i + nfill] = words[i];
			for (i = dblcolon; i < dblcolon + nfill; i++)
				words[i] = 0;
		}
		else if (nwords != 8)
			goto parse_fail;

		{
			int i;
			for (i = 0; i < 8; i++)
			{
				v6.s6_addr[i * 2] = (words[i] >> 8) & 0xff;
				v6.s6_addr[i * 2 + 1] = words[i] & 0xff;
			}
		}
		pton_ret = 1;
	}
	goto parse_ok;

parse_fail:
	return 0;

parse_ok:
	if (pton_ret != 1) return 0;

	struct sockaddr_in *sin = (struct sockaddr_in *)out;
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_port = port_net;

	const unsigned char *b = v6.s6_addr;
	if (b[0]==0 && b[1]==0 && b[2]==0 && b[3]==0 &&
	    b[4]==0 && b[5]==0 && b[6]==0 && b[7]==0 &&
	    b[8]==0 && b[9]==0 && b[10]==0xff && b[11]==0xff)
	{
		/* v4-mapped: extract IPv4 directly, no sentinel needed */
		memcpy(&sin->sin_addr, &b[12], 4);
	}
	else if (b[0]==0 && b[1]==0 && b[2]==0 && b[3]==0 &&
	         b[4]==0 && b[5]==0 && b[6]==0 && b[7]==0 &&
	         b[8]==0 && b[9]==0 && b[10]==0 && b[11]==0 &&
	         b[12]==0 && b[13]==0 && b[14]==0 && b[15]==1)
	{
		/* ::1 (loopback) -> 127.0.0.1
		 * Critical for listen servers: the engine uses an in-process
		 * loopback queue for 127.0.0.1 (NET_SendLoopPacket). This is how
		 * the local client connects to the local server. The bind()
		 * interceptor translates 127.0.0.1 back to [::1] so the server
		 * socket still receives pure IPv6. */
		sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	else if (b[0]==0 && b[1]==0 && b[2]==0 && b[3]==0 &&
	         b[4]==0 && b[5]==0 && b[6]==0 && b[7]==0 &&
	         b[8]==0 && b[9]==0 && b[10]==0 && b[11]==0 &&
	         b[12]==0 && b[13]==0 && b[14]==0 && b[15]==0)
	{
		/* :: (unspecified) -> 0.0.0.0 (INADDR_ANY) */
		sin->sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else
	{
		/* Other pure IPv6: allocate a peer sentinel (198.51.100.N).
		 * NOT 127.0.0.1 (would trigger loopback queue bypass) and NOT in
		 * 240.0.0.0/4 (Steam FakeIP range). Used for external IPv6 peers. */
		uint32_t peer_sentinel = alloc_peer_v6(&v6);
		sin->sin_addr.s_addr = peer_sentinel;
	}

	fprintf(stderr, "[tf2_ipv6_shim] parsed IPv6: [%s]:%d\n",
		addr6, ntohs(port_net));
	return 1;
}

// ---- Hook installation ----

struct engine_info {
	uintptr_t base;
	const ElfW(Phdr) *phdr;
	ElfW(Half) phnum;
};

static int find_engine_base_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	(void)size;
	if (info && info->dlpi_name && strstr(info->dlpi_name, "engine"))
	{
		struct engine_info *ei = (struct engine_info *)data;
		ei->base = (uintptr_t)info->dlpi_addr;
		ei->phdr = info->dlpi_phdr;
		ei->phnum = info->dlpi_phnum;
		return 1;
	}
	return 0;
}

/* Find NET_StringToSockadr by scanning executable segments for its
 * unique 16-byte prologue. Works for both engine.so (tf_linux64)
 * at offset 0x552e60 and engine_srv.so (srcds) at offset 0x134080. */
static const unsigned char NSTS_EXPECTED[16] = {
	0x55, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xba, 0x80,
	0x00, 0x00, 0x00, 0x48, 0x89, 0xe5, 0x41, 0x55
};

static uintptr_t find_nsts_target(void)
{
	struct engine_info ei;
	ei.base = 0; ei.phdr = NULL; ei.phnum = 0;
	dl_iterate_phdr(find_engine_base_cb, &ei);
	if (!ei.base || !ei.phdr) return 0;

	for (int i = 0; i < (int)ei.phnum; i++)
	{
		if (ei.phdr[i].p_type != PT_LOAD || !(ei.phdr[i].p_flags & PF_X))
			continue;
		const unsigned char *start =
			(const unsigned char *)(ei.base + ei.phdr[i].p_vaddr);
		size_t sz = ei.phdr[i].p_memsz;
		if (sz > 0x800000) sz = 0x800000; /* safety cap */
		for (size_t j = 0; j + 16 <= sz; j++)
		{
			if (memcmp(start + j, NSTS_EXPECTED, 16) == 0)
				return (uintptr_t)(start + j);
		}
	}
	return 0;
}

static int g_parser_hook_installed = 0;
static int g_parser_hook_tried = 0;

static void install_parser_hook(void)
{
	if (g_parser_hook_tried) return;
	g_parser_hook_tried = 1;

	uintptr_t target = find_nsts_target();
	if (!target)
	{
		fprintf(stderr, "[tf2_ipv6_shim] parser hook: NET_StringToSockadr prologue not found, NOT installed\n");
		return;
	}

	g_original_continue = target + 16;
	g_try_ipv6_ptr = try_ipv6;

	long pagesize = sysconf(_SC_PAGESIZE);
	uintptr_t page_start = target & ~((uintptr_t)(pagesize - 1));
	size_t mprotect_len = (size_t)pagesize * 2;
	if (mprotect((void *)page_start, mprotect_len,
	             PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
	{
		fprintf(stderr, "[tf2_ipv6_shim] parser hook: mprotect failed: %s\n", strerror(errno));
		return;
	}

	uintptr_t relay_addr = (uintptr_t)&nsts_relay;
	unsigned char patch[16];
	patch[0] = 0x48; patch[1] = 0xB8;
	memcpy(&patch[2], &relay_addr, 8);
	patch[10] = 0xFF; patch[11] = 0xE0;
	patch[12] = 0x90; patch[13] = 0x90;
	patch[14] = 0x90; patch[15] = 0x90;

	memcpy((void *)target, patch, 16);
	mprotect((void *)page_start, mprotect_len, PROT_READ | PROT_EXEC);

	g_parser_hook_installed = 1;
	fprintf(stderr, "[tf2_ipv6_shim] parser hook installed at %p\n",
		(void *)target);
}

static void ensure_parser_hook(void)
{
	if (g_parser_hook_installed) return;
	install_parser_hook();
}

__attribute__((constructor(101)))
static void shim_ctor(void)
{
	init_real_funcs();
	install_parser_hook();
}

// ============================================================================
// dlopen: catch engine.so being loaded (TF2 dlopens it at runtime)
// ============================================================================

static void *(*real_dlopen)(const char *, int) = NULL;

void *dlopen(const char *filename, int flags)
{
	if (!g_init_done) init_real_funcs();
	if (!real_dlopen) real_dlopen = dlsym(RTLD_NEXT, "dlopen");

	void *h = real_dlopen(filename, flags);

	if (h && filename && strstr(filename, "engine") && !g_parser_hook_installed)
	{
		g_parser_hook_tried = 0;
		install_parser_hook();
	}

	return h;
}
