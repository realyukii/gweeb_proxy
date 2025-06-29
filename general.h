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
