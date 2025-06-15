#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <unistd.h>

#ifndef DEBUG_LVL
#define DEBUG_LVL 0
#endif
#define FOCUS 1
#define DEBUG 2
#define VERBOSE 3
#define pr_debug(lvl, fmt, ...)				\
do {							\
	if (DEBUG_LVL >= (lvl)) {			\
		fprintf(stderr, fmt, ##__VA_ARGS__);	\
	}						\
} while (0)

extern char *optarg;
static const char usage[] =
"usage: ./gwproxy [options]\n"
"-b\tIP address and port to be bound by the server\n"
"-t\tIP address and port \n"
"-h\tShow this help message and exit\n";

static int init_addr(char *addr, struct sockaddr *addr_st);
static int start_server(char *addr, unsigned short port);

int main(int argc, char *argv[])
{
	char c,  *bind_opt, *target_opt, *src_addr, *dst_addr;
	unsigned short src_port, dst_port;
	struct sockaddr src_addr_st, dst_addr_st;
	int ret;

	if (argc == 1) {
		printf("%s", usage);

		return 0;
	}

	bind_opt = target_opt = NULL;
	while ((c = getopt(argc, argv, "hb:t:")) != -1) {
		switch (c) {
		case 'b':
			bind_opt = optarg;
			break;
		case 't':
			target_opt = optarg;
			break;
		case 'h':
			printf("%s", usage);
			break;

		default:
			return -EINVAL;
		}
	}

	if (!target_opt) {
		fprintf(stderr, "-t option is required\n");
		return -EINVAL;
	}

	if (!bind_opt) {
		fprintf(stderr, "-b option is required\n");
		return -EINVAL;
	}

	ret = init_addr(bind_opt, &src_addr_st);
	if (ret < 0) {
		fprintf(stderr, "invalid format for %s\n", bind_opt);
		return -EINVAL;
	}

	ret = init_addr(target_opt, &dst_addr_st);
	if (ret < 0) {
		fprintf(stderr, "invalid format for %s\n", target_opt);
		return -EINVAL;
	}

	return 0;
}

static int start_server(char *addr, unsigned short port)
{
	/* TODO */
	return 0;
}

static int init_addr(char *addr, struct sockaddr *addr_st)
{
	struct sockaddr_in6 *in6 = (void *)addr_st;
	struct sockaddr_in *in = (void *)addr_st;
	char *separator = NULL, *port_str;
	unsigned short nport, hport, af;

	for (size_t i = strlen(addr); i > 0; i--) {
		if (addr[i] == ':') {
			separator = &addr[i];
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
	nport = htons(hport);

	if (*addr == '[') {
		af = AF_INET6;
		/* replace ] with null-terminated byte */
		*(separator - 1) = '\0';
		addr++;
	} else
		af = AF_INET;
	
	addr_st->sa_family = af;
	switch (af) {
	case AF_INET:
		in->sin_port = nport;
		if (!inet_pton(AF_INET, addr, &in->sin_addr))
			return -EINVAL;

		break;
	case AF_INET6:
		in6->sin6_port = nport;
		if (!inet_pton(AF_INET6, addr, &in6->sin6_addr))
			return -EINVAL;

		break;
	}
	pr_debug(VERBOSE, "address: %s:%d\n", addr, hport);

	return 0;
}
