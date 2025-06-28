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
