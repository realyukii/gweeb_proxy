#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include "general.c"

extern char *optarg;
static const char usage[] =
"description: convert address:port string to network-byte order.\n"
"usage: ./ip_converter <ip addres>:<port>\n";

int main(int argc, char **argv)
{
	size_t i;
	uint8_t *octet;
	char *addr_str;
	struct sockaddr_storage addr;
	struct sockaddr_in *in;
	struct sockaddr_in6 *in6;
	int ret;

	if (argc != 2) {
		puts(usage);
		return -EXIT_FAILURE;
	}

	addr_str = argv[1];
	printf("%s\n", addr_str);
	ret = init_addr(addr_str, &addr);
	if (ret < 0) {
		fprintf(stderr, "invalid format: %s\n", addr_str);
		return -EXIT_FAILURE;
	}

	switch (addr.ss_family) {
	case AF_INET:
		in = (void *)&addr;
		printf("network-byte order of IPv4:\n");
		for (i = 0; i < sizeof(in->sin_addr); i++) {
			octet = ((uint8_t *)(&in->sin_addr));
			printf("%02x", octet[i]);
		}
		puts("");

		printf("network-byte order of port:\n");
		for (i = 0; i < sizeof(in->sin_port); i++) {
			octet = ((uint8_t *)(&in->sin_port));
			printf("%02x", octet[i]);
		}
		puts("");
		break;
	case AF_INET6:
		in6 = (void *)&addr;
		printf("network-byte order of IPv6:\n");
		for (i = 0; i < sizeof(in6->sin6_addr); i++) {
			octet = ((uint8_t *)(&in6->sin6_addr));
			printf("%02x", octet[i]);
		}
		puts("");

		printf("network-byte order of port:\n");
		for (i = 0; i < sizeof(in6->sin6_port); i++) {
			octet = ((uint8_t *)(&in6->sin6_port));
			printf("%02x", octet[i]);
		}
		puts("");
		break;
	}

	return 0;
}
