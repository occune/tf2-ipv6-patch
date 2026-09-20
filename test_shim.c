#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static int to_in6(const struct sockaddr *in, socklen_t inlen, struct sockaddr_in6 *out, socklen_t *outlen)
{
	if (!in || !out) return -1;
	if (in->sa_family == AF_INET6) { memcpy(out, in, sizeof(*out)); if(outlen)*outlen=sizeof(*out); return 0; }
	if (in->sa_family == AF_INET) {
		const struct sockaddr_in *in4 = (const struct sockaddr_in *)in;
		memset(out, 0, sizeof(*out));
		out->sin6_family = AF_INET6; out->sin6_port = in4->sin_port;
		out->sin6_addr.s6_addr[10] = 0xff; out->sin6_addr.s6_addr[11] = 0xff;
		memcpy(&out->sin6_addr.s6_addr[12], &in4->sin_addr, 4);
		if(outlen)*outlen=sizeof(*out); return 1;
	}
	return -1;
}

static int from_in6(const struct sockaddr_in6 *in, struct sockaddr *out, socklen_t *outlen)
{
	if (!in || !out) return -1;
	if (in->sin6_family == AF_INET6) {
		const unsigned char *b = in->sin6_addr.s6_addr;
		if (b[0]==0&&b[1]==0&&b[2]==0&&b[3]==0&&b[4]==0&&b[5]==0&&b[6]==0&&b[7]==0&&b[8]==0&&b[9]==0&&b[10]==0xff&&b[11]==0xff) {
			struct sockaddr_in out4; memset(&out4,0,sizeof(out4));
			out4.sin_family = AF_INET; out4.sin_port = in->sin6_port;
			memcpy(&out4.sin_addr, &b[12], 4);
			memcpy(out, &out4, sizeof(out4));
			if(outlen)*outlen=sizeof(out4); return 1;
		}
		if(outlen)*outlen=sizeof(*in); memcpy(out,in,sizeof(*in)); return 0;
	}
	if(outlen)*outlen=sizeof(*in); memcpy(out,in,sizeof(*in)); return 0;
}

int main(void)
{
	int pass=0, fail=0;

	// T1: IPv4 -> v4-mapped
	{
		struct sockaddr_in in4; memset(&in4,0,sizeof(in4));
		in4.sin_family = AF_INET; in4.sin_port = htons(27015);
		inet_pton(AF_INET, "192.168.1.5", &in4.sin_addr);
		struct sockaddr_in6 out6; socklen_t outlen;
		int r = to_in6((struct sockaddr*)&in4, sizeof(in4), &out6, &outlen);
		char s6[INET6_ADDRSTRLEN]; inet_ntop(AF_INET6, &out6.sin6_addr, s6, sizeof(s6));
		printf("T1: 192.168.1.5:27015 -> [%s]:%d (r=%d)\n", s6, ntohs(out6.sin6_port), r);
		if (r==1 && out6.sin6_family==AF_INET6 && ntohs(out6.sin6_port)==27015 && !strcmp(s6,"::ffff:192.168.1.5")) {printf("  PASS\n");pass++;} else {printf("  FAIL\n");fail++;}
	}

	// T2: v4-mapped -> IPv4 (round-trip)
	{
		struct sockaddr_in6 in6; memset(&in6,0,sizeof(in6));
		in6.sin6_family = AF_INET6; in6.sin6_port = htons(27015);
		inet_pton(AF_INET6, "::ffff:127.0.0.1", &in6.sin6_addr);
		unsigned char buf[64]; struct sockaddr *out=(struct sockaddr*)buf; socklen_t outlen;
		int r = from_in6(&in6, out, &outlen);
		struct sockaddr_in *out4=(struct sockaddr_in*)buf;
		char s4[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &out4->sin_addr, s4, sizeof(s4));
		printf("T2: [::ffff:127.0.0.1]:27015 -> %s:%d (r=%d, fam=%d)\n", s4, ntohs(out4->sin_port), r, out4->sin_family);
		if (r==1 && out4->sin_family==AF_INET && !strcmp(s4,"127.0.0.1") && ntohs(out4->sin_port)==27015) {printf("  PASS\n");pass++;} else {printf("  FAIL\n");fail++;}
	}

	// T3: pure IPv6 stays IPv6
	{
		struct sockaddr_in6 in6; memset(&in6,0,sizeof(in6));
		in6.sin6_family = AF_INET6; in6.sin6_port = htons(27015);
		inet_pton(AF_INET6, "::1", &in6.sin6_addr);
		unsigned char buf[64]; struct sockaddr *out=(struct sockaddr*)buf; socklen_t outlen;
		int r = from_in6(&in6, out, &outlen);
		struct sockaddr_in6 *out6=(struct sockaddr_in6*)buf;
		char s6[INET6_ADDRSTRLEN]; inet_ntop(AF_INET6, &out6->sin6_addr, s6, sizeof(s6));
		printf("T3: [::1]:27015 -> [%s]:%d (r=%d, fam=%d)\n", s6, ntohs(out6->sin6_port), r, out6->sin6_family);
		if (r==0 && out6->sin6_family==AF_INET6 && !strcmp(s6,"::1")) {printf("  PASS\n");pass++;} else {printf("  FAIL\n");fail++;}
	}

	printf("\n=== %d passed, %d failed ===\n", pass, fail);
	return fail ? 1 : 0;
}
