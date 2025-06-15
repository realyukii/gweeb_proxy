#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
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


static int start_server(char *addr, unsigned short port)
{
	/* TODO */
	return 0;
}

static int init_addr(char *addr, struct sockaddr *addr_st)
{
	/* TODO */
	return 0;
}
