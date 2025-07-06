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

#define EINVAL 22
#define ADDRSTR_SZ (1 + INET6_ADDRSTRLEN + 1 + 1 + 5 + 1)

/*
* credit: https://gist.github.com/ammarfaizi2/e88a21171358b5092a3df412eeb80b2f
*/
#ifndef VT_HEXDUMP_H
#define VT_HEXDUMP_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#if ENABLE_LOG
#define CHDOT(C) (((32 <= (C)) && ((C) <= 126)) ? (C) : '.')
#define VT_HEXDUMP(PTR, SIZE)								\
do { 											\
	static const char fmt[] = 							\
	"============ VT_HEXDUMP ============\n" 					\
	"File\t\t: %s:%d\n"								\
	"Function\t: %s()\n"								\
	"Address\t\t: 0x%016lx\n"							\
	"Dump size\t: %ld bytes\n"							\
	"\n"										\
	"%s"										\
	"=====================================\n";					\
	size_t sz_perlines, tot_sz, last_sz, fixed_sz,					\
	r, i, j, k = 0, l, off = 0, size = (SIZE);					\
	unsigned char *ptr = (unsigned char *)(PTR);					\
	char *tmp;									\
	/* process 16 byte per-line, calculate the line number */			\
	sz_perlines = size / 16;							\
	/* remainder of multiple 16, if any */						\
	r = size % 16;									\
	/* size of last line */								\
	last_sz = 									\
	21 /* address prefix */								\
	+ (3 * 16) /* hex-ascii digit padded with space */				\
	+ 2 /* " |" */									\
	+ r										\
	+ 2; /* "|\n" */								\
	/* fixed when r = 16 */								\
	fixed_sz = 89;									\
	tot_sz = (sz_perlines * fixed_sz) + last_sz;					\
	tmp = malloc(tot_sz + 1);							\
	if (!tmp)									\
		goto out;								\
	for (i = 0; i < ((size/16) + 1); i++) {						\
		snprintf(&tmp[off], 21 + 1, "0x%016lx|  ", (uintptr_t)(ptr + i * 16));	\
		off += 21;								\
		l = k;									\
		for (j = 0; (j < 16) && (k < size); j++, k++) {				\
			snprintf(&tmp[off], 3 + 1, "%02x ", ptr[k]);			\
			off += 3;							\
		}									\
		while (j++ < 16) {							\
			snprintf(&tmp[off], 3 + 1, "   ");				\
			off += 3;							\
		}									\
		snprintf(&tmp[off], 2 + 1, " |");					\
		off += 2;								\
		for (j = 0; (j < 16) && (l < size); j++, l++) {				\
			snprintf(&tmp[off], 1 + 1, "%c", CHDOT(ptr[l]));		\
			off += 1;							\
		}									\
		snprintf(&tmp[off], 2 + 1, "|\n");					\
		off += 2;								\
	}										\
	fprintf(									\
		stderr, fmt,								\
		__FILE__, __LINE__,							\
		__FUNCTION__,								\
		(uintptr_t)ptr,								\
		(size),									\
		tmp									\
	);										\
	free(tmp);									\
out:											\
} while (0);
#else
#define VT_HEXDUMP(PTR, SIZE) {}
#endif // ENABLE_LOG
#endif

/*
* Initialize address used to bind or connect a socket.
*
* @param addr Pointer to the string with fmt ip:port.
* @param addr_st Pointer to a sockaddr_storage structure to initialize.
* @return zero on success, or a negative integer on failure.
*/
int init_addr(const char *addr, struct sockaddr_storage *addr_st);

/*
* Print a data in bits representation.
*
* credit: https://stackoverflow.com/a/3974138/22382954
*
* @param size of the data.
* @param ptr to the data.
*/
void printBits(size_t const size, void const * const ptr);

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
