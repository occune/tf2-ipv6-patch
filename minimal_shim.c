// minimal_shim.c — ONLY upgrades AF_INET to AF_INET6, nothing else
// Tests whether the socket family upgrade alone breaks the listen server.
#include <sys/socket.h>
#include <dlfcn.h>
#include <stdio.h>

static int (*real_socket)(int, int, int) = NULL;

__attribute__((constructor(101)))
static void init(void)
{
	real_socket = dlsym(RTLD_NEXT, "socket");
	fprintf(stderr, "[minimal_shim] loaded (socket upgrade only)\n");
}

int socket(int domain, int type, int protocol)
{
	if (!real_socket) real_socket = dlsym(RTLD_NEXT, "socket");
	if (domain == AF_INET || domain == PF_INET)
		domain = AF_INET6;
	return real_socket(domain, type, protocol);
}
