#include "general.h"

int init_addr(const char *addr, struct sockaddr_storage *addr_st)
{
	struct sockaddr_in6 *in6 = (void *)addr_st;
	struct sockaddr_in *in = (void *)addr_st;
	char *separator = NULL, *port_str;
	unsigned short nport, af;
	int i, hport;
	size_t addrlen = strlen(addr) + 1;
	char tmp[1 + INET6_ADDRSTRLEN + 1 + 1 + 5];
	char *ipstr;

	if (addrlen > sizeof(tmp))
		return -EINVAL;

	strncpy(tmp, addr, addrlen);
	for (i = addrlen - 1; i > 0; i--) {
		if (tmp[i] == ':') {
			separator = &tmp[i];
			break;
		}
	}

	if (!separator)
		return -EINVAL;
	*separator = '\0';

	port_str = separator + 1;
	hport = atoi(port_str);
	if (!hport)
		return -EINVAL;
	if (hport > 65535 || hport < 0)
		return -EINVAL;
	nport = htons(hport);

	if (*tmp == '[') {
		af = AF_INET6;
		/* replace ']' with null-terminated byte */
		*(separator - 1) = '\0';
		ipstr = tmp + 1;
	} else {
		af = AF_INET;
		ipstr = tmp;
	}
	
	addr_st->ss_family = af;
	switch (af) {
	case AF_INET:
		in->sin_port = nport;
		if (!inet_pton(AF_INET, ipstr, &in->sin_addr))
			return -EINVAL;

		break;
	case AF_INET6:
		in6->sin6_port = nport;
		if (!inet_pton(AF_INET6, ipstr, &in6->sin6_addr))
			return -EINVAL;

		break;
	}

	return 0;
}

void get_addrstr(struct sockaddr *saddr, socklen_t slen, char *bufptr)
{
	struct sockaddr_in *in;
	struct sockaddr_in6 *in6;
	uint16_t port_nr;
	char addrbuf[INET6_ADDRSTRLEN];
	static const char *addr4fmt = "[%s]:%u";
	static const char *addr6fmt = "[%s]:%u";
	const char *addrfmt;

	switch (saddr->sa_family) {
	case AF_INET:
		in = (struct sockaddr_in *)saddr;
		inet_ntop(AF_INET, &in->sin_addr, addrbuf, slen);
		port_nr = ntohs(in->sin_port);
		addrfmt = addr4fmt;

		break;
	case AF_INET6:
		in6 = (struct sockaddr_in6 *)saddr;
		inet_ntop(AF_INET6, &in6->sin6_addr, addrbuf, slen);
		port_nr = ntohs(in6->sin6_port);
		addrfmt = addr6fmt;

		break;
	}

	snprintf(bufptr, ADDRSTR_SZ, addrfmt, addrbuf, port_nr);
}

void printBits(size_t const size, void const * const ptr)
{
	unsigned char *b = (unsigned char*) ptr;
	unsigned char byte;
	int i, j;
	
	for (i = size-1; i >= 0; i--) {
		for (j = 7; j >= 0; j--) {
			byte = (b[i] >> j) & 1;
			printf("%u", byte);
		}
	}
	puts("");
}
