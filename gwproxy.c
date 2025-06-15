#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <unistd.h>

#define NR_EVENTS 512
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
"-t\tIP address and port of the target server\n"
"-h\tShow this help message and exit\n";

static int init_addr(char *addr, struct sockaddr *addr_st);
static int start_server(struct sockaddr *addr_st);

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
			return 0;

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

	ret = start_server(&src_addr_st);
	if (ret < 0) {
		perror("start_server");
		return ret;
	}

	return 0;
}

static int start_server(struct sockaddr *addr_st)
{
	int ret, tcp_sock, client_fd, epoll_fd, ready_nr;
	struct epoll_event ev;
	struct epoll_event evs[NR_EVENTS];
	ev.events = EPOLLIN;
	static const int flg = 1;

	tcp_sock = socket(addr_st->sa_family, SOCK_STREAM, 0);
	if (tcp_sock < 0)
		return -EXIT_FAILURE;

	setsockopt(tcp_sock, SOL_SOCKET, SO_REUSEADDR, &flg, sizeof(flg));
	setsockopt(tcp_sock, SOL_SOCKET, SO_KEEPALIVE, &flg, sizeof(flg));
	setsockopt(tcp_sock, IPPROTO_TCP, TCP_QUICKACK, &flg, sizeof(flg));
	setsockopt(tcp_sock, IPPROTO_TCP, TCP_NODELAY, &flg, sizeof(flg));

	if (bind(tcp_sock, addr_st, sizeof(*addr_st)) < 0)
		goto err;
	
	if (listen(tcp_sock, 10) < 0)
		goto err;

	epoll_fd = epoll_create(1);
	ev.data.fd = tcp_sock;
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tcp_sock, &ev);

	while (true) {
		ready_nr = epoll_wait(epoll_fd, evs, NR_EVENTS, -1);
		for (size_t i = 0; i < ready_nr; i++) {
			struct epoll_event *c_ev = &evs[i];
			if (c_ev->data.fd == tcp_sock) {
				client_fd = accept(tcp_sock, NULL, NULL);
				ev.data.fd = client_fd;
				epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
			} else {
				char buf[255] = {0};
				ret = recv(c_ev->data.fd, buf, sizeof(buf), 0);

				printf("%s\n", buf);
				printf("read %d bytes\n", ret);
			}
		}
	}

	return 0;
err:
	close(tcp_sock);
	return -EXIT_FAILURE;
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
