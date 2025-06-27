/*
* Implementation that compatible for both Windows and Linux.
*
* but may have different header for some typedef or function.
*/
/* unix-like header */
#include <arpa/inet.h>
/* TODO: windows header */
/* C header */
#include <string.h>

#define EINVAL 22

/*
* credit: https://gist.github.com/ammarfaizi2/e88a21171358b5092a3df412eeb80b2f
*/
#ifndef VT_HEXDUMP_H
#define VT_HEXDUMP_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define CHDOT(C) (((32 <= (C)) && ((C) <= 126)) ? (C) : '.')
#define VT_HEXDUMP(PTR, SIZE)                               \
  do {                                                      \
    size_t i, j, k = 0, l, size = (SIZE);                   \
    unsigned char *ptr = (unsigned char *)(PTR);            \
    printf("============ VT_HEXDUMP ============\n");       \
    printf("File\t\t: %s:%d\n", __FILE__, __LINE__);        \
    printf("Function\t: %s()\n", __FUNCTION__);             \
    printf("Address\t\t: 0x%016lx\n", (uintptr_t)ptr);      \
    printf("Dump size\t: %ld bytes\n", (size));             \
    printf("\n");                                           \
    for (i = 0; i < ((size/16) + 1); i++) {                 \
      printf("0x%016lx|  ", (uintptr_t)(ptr + i * 16));     \
      l = k;                                                \
      for (j = 0; (j < 16) && (k < size); j++, k++) {       \
        printf("%02x ", ptr[k]);                            \
      }                                                     \
      while (j++ < 16) printf("   ");                       \
      printf(" |");                                         \
      for (j = 0; (j < 16) && (l < size); j++, l++) {       \
        printf("%c", CHDOT(ptr[l]));                        \
      }                                                     \
      printf("|\n");                                        \
    }                                                       \
    printf("=====================================\n");      \
  } while(0)

#endif

/*
* Initialize address used to bind or connect a socket.
*
* @param addr Pointer to the string with fmt ip:port.
* @param addr_st Pointer to a sockaddr_storage structure to initialize.
* @return zero on success, or a negative integer on failure.
*/
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
		/* replace ] with null-terminated byte */
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
