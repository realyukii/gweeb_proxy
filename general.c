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
		if (*(separator - 1) != ']')
			return -EINVAL;
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

void get_addrstr(struct sockaddr *saddr, char *bufptr)
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
		inet_ntop(AF_INET, &in->sin_addr, addrbuf, sizeof(addrbuf));
		port_nr = ntohs(in->sin_port);
		addrfmt = addr4fmt;

		break;
	case AF_INET6:
		in6 = (struct sockaddr_in6 *)saddr;
		inet_ntop(AF_INET6, &in6->sin6_addr, addrbuf, sizeof(addrbuf));
		port_nr = ntohs(in6->sin6_port);
		addrfmt = addr6fmt;

		break;
	}

	snprintf(bufptr, ADDRSTR_SZ, addrfmt, addrbuf, port_nr);
}

#ifndef VT_HEXDUMP_H
#define VT_HEXDUMP_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define CHDOT(C) (((32 <= (C)) && ((C) <= 126)) ? (C) : '.')

void vt_hexdump(const void *p, size_t size,
		const char *file, int line, const char *func) {
	const unsigned char *ptr = p;
	static const char fmt[] =
	"============ VT_HEXDUMP ============\n"
	"File\t\t: %s:%d\n"
	"Function\t: %s()\n"
	"Address\t\t: 0x%016lx\n"
	"Dump size\t: %ld bytes\n"
	"\n"
	"%s"
	"=====================================\n";
	size_t sz_perlines, tot_sz, last_sz, fixed_sz,
	r, i, j, k = 0, l, off = 0;
	char *tmp;
	/* process 16 byte per-line, calculate the line number */
	sz_perlines = size / 16;
	/* remainder of multiple 16, if any */
	r = size % 16;
	/* size of last line */
	last_sz = 
	21 /* address prefix */
	+ (3 * 16) /* hex-ascii digit padded with space */
	+ 2 /* " |" */
	+ r
	+ 2; /* "|\n" */
	/* fixed when r = 16 */
	fixed_sz = 89;
	tot_sz = (sz_perlines * fixed_sz) + last_sz;
	tmp = malloc(tot_sz + 1);
	if (!tmp)
		goto out;
	for (i = 0; i < ((size/16) + 1); i++) {
		snprintf(
			&tmp[off], 21 + 1,
			"0x%016lx|  ", (uintptr_t)(ptr + i * 16)
		);
		off += 21;
		l = k;
		for (j = 0; (j < 16) && (k < size); j++, k++) {
			snprintf(&tmp[off], 3 + 1, "%02x ", ptr[k]);
			off += 3;
		}		
		while (j++ < 16) {
			snprintf(&tmp[off], 3 + 1, "   ");
			off += 3;
		}		
		snprintf(&tmp[off], 2 + 1, " |");
		off += 2;
		for (j = 0; (j < 16) && (l < size); j++, l++) {
			snprintf(&tmp[off], 1 + 1, "%c", CHDOT(ptr[l]));
			off += 1;
		}
		snprintf(&tmp[off], 2 + 1, "|\n");
		off += 2;
	}
	fprintf(
		stderr, fmt,
		file, line,
		func,
		(uintptr_t)ptr,
		(size),
		tmp
	);
	free(tmp);
out:
}

#endif

bool is_ldh(char c)
{
	return (c >= 'A' && c <= 'Z')
		|| (c >= 'a' && c <= 'z')
		|| (c >= '0' && c <= '9')
		|| (c == '-')
		|| (c == '.');
}
