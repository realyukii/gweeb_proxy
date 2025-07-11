/*
* Implementation that compatible for both Windows and Linux.
*
* but may have different header for some typedef or function.
*/

/* POSIX or unix-like header */
#include <arpa/inet.h>
/* TODO: windows header */
/* C header */
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#define EINVAL 22
#define ADDRSTR_SZ (1 + INET6_ADDRSTRLEN + 1 + 1 + 5 + 1)

#if ENABLE_LOG

#ifndef VT_HEXDUMP_H
#define VT_HEXDUMP_H

#define VT_HEXDUMP(PTR, SIZE)					\
do {								\
	vt_hexdump(PTR, SIZE, __FILE__, __LINE__, __FUNCTION__);\
} while (0);

#endif // VT_HEXDUMP_H
#else
#define VT_HEXDUMP(PTR, SIZE) {}

#endif // ENABLE_LOG

/*
* Initialize address used to bind or connect a socket.
*
* @param addr Pointer to the string with fmt ip:port.
* @param addr_st Pointer to a sockaddr_storage structure to initialize.
* @return zero on success, or a negative integer on failure.
*/
int init_addr(const char *addr, struct sockaddr_storage *addr_st);

/*
* Get printable network address.
*
* @param saddr
* @param bufptr
*/
void get_addrstr(struct sockaddr *saddr, char *bufptr);

/*
* check if a character conform the ldh rule (letter-digit-hypen)
* for domain name validation.
*
* @param c
*/
bool is_ldh(char c);

/*
* Dump the memory content of given pointer and size
* credit: https://gist.github.com/ammarfaizi2/e88a21171358b5092a3df412eeb80b2f
*/
void vt_hexdump(const void *p, size_t size,
		const char *file, int line, const char *func);