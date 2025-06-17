#include <sys/resource.h>
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

enum {
	EV_BIT_CLIENT		= (0x0001ULL << 48ULL),
	EV_BIT_TARGET		= (0x0002ULL << 48ULL)
};

#define ALL_EV_BIT	(EV_BIT_CLIENT | EV_BIT_TARGET)
#define GET_EV_BIT(X)	((X) & ALL_EV_BIT)
#define CLEAR_EV_BIT(X)	((X) & ~ALL_EV_BIT)

struct pair_connection {
	int csockfd;
	int tsockfd;
};

extern char *optarg;
static struct sockaddr src_addr_st, dst_addr_st;
static const struct rlimit file_limits = {
	.rlim_cur = 65536,
	.rlim_max = 65536
};
static const char usage[] =
"usage: ./gwproxy [options]\n"
"-b\tIP address and port to be bound by the server\n"
"-t\tIP address and port of the target server\n"
"-h\tShow this help message and exit\n";

/*
* Initialize address used to bind or connect a socket.
*
* @param addr Pointer to the string with fmt ip:port.
* @param addr_st Pointer to a sockaddr structure to initialize.
* @return zero on success, or a negative integer on failure.
*/
static int init_addr(char *addr, struct sockaddr *addr_st);

/*
* Start the TCP proxy server.
* 
* @return negative integer on failure.
*/
static int start_server(void);

/*
* Handle command-line arguments.
* 
* @param argc total argument passed.
* @param argv Pointer to an array of string.
* @return zero on success, or a negative integer on failure.
*/
static int handle_cmdline(int argc, char *argv[]);

int main(int argc, char *argv[])
{
	int ret;

	ret = handle_cmdline(argc, argv);
	if (ret < 0)
		return ret;

	setrlimit(RLIMIT_NOFILE, &file_limits);
	ret = start_server();
	if (ret < 0) {
		perror("start_server");
		return ret;
	}

	return 0;
}

static int start_server(void)
{
	int ret, tcp_sock, client_fd, epoll_fd, ready_nr;
	struct epoll_event ev;
	struct epoll_event evs[NR_EVENTS];
	ev.events = EPOLLIN;
	static const int flg = 1;

	tcp_sock = socket(src_addr_st.sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (tcp_sock < 0)
		return -EXIT_FAILURE;

	setsockopt(tcp_sock, SOL_SOCKET, SO_REUSEADDR, &flg, sizeof(flg));
	setsockopt(tcp_sock, SOL_SOCKET, SO_KEEPALIVE, &flg, sizeof(flg));
	setsockopt(tcp_sock, IPPROTO_TCP, TCP_QUICKACK, &flg, sizeof(flg));
	setsockopt(tcp_sock, IPPROTO_TCP, TCP_NODELAY, &flg, sizeof(flg));

	if (bind(tcp_sock, &src_addr_st, sizeof(src_addr_st)) < 0)
		goto err;
	
	if (listen(tcp_sock, 10) < 0)
		goto err;

	epoll_fd = epoll_create(1);
	ev.data.fd = tcp_sock;
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tcp_sock, &ev);

	while (true) {
		ready_nr = epoll_wait(epoll_fd, evs, NR_EVENTS, -1);
		if (ready_nr < 0) {
			if (errno == EINTR)
				continue;
			printf("errno = %d\n", errno);
			perror("epoll_wait");
			return -EXIT_FAILURE;
		}

		for (int i = 0; i < ready_nr; i++) {
			struct epoll_event *c_ev = &evs[i];
			if (c_ev->data.fd == tcp_sock) {
				struct pair_connection *pc = malloc(sizeof(*pc));
				client_fd = accept(tcp_sock, NULL, NULL);
				ev.data.u64 = 0;
				ev.data.ptr = pc;
				pc->csockfd = client_fd;
				ev.data.u64 |= EV_BIT_CLIENT;
				
				epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);

				int tsock = socket(dst_addr_st.sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
				ret = connect(tsock, &dst_addr_st, sizeof(dst_addr_st));
				if (ret == 0 || errno == EINPROGRESS || errno == EAGAIN) {
					ev.data.fd = tsock;
					ev.data.u64 = 0;
					ev.data.ptr = pc;
					pc->tsockfd = tsock;
					ev.data.u64 |= EV_BIT_TARGET;
					epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tsock, &ev);
				}
			} else {
				uint64_t ev_bit = GET_EV_BIT(c_ev->data.u64);
				c_ev->data.u64 = CLEAR_EV_BIT(c_ev->data.u64);
				struct pair_connection *pc = c_ev->data.ptr;
				int from, to;
				char buf[1024] = {0};
				switch (ev_bit) {
				case EV_BIT_CLIENT:
					from = pc->csockfd;
					to = pc->tsockfd;
					break;

				case EV_BIT_TARGET:
					from = pc->tsockfd;
					to = pc->csockfd;
					break;
				}

				ret = recv(from, buf, sizeof(buf), 0);
				if (ret < 0) {
					if (errno == EAGAIN)
						continue;
					perror("recv");
					close(from);
					close(to);
					free(pc);
					break;
				} else if (!ret) {
					close(from);
					close(to);
					free(pc);
					break;
				}

				ret = send(to, buf, ret, 0);
				if (ret < 0) {
					if (errno == EAGAIN)
						continue;
					perror("send");
					close(from);
					close(to);
					free(pc);
					break;
				} else if (!ret) {
					close(from);
					close(to);
					free(pc);
					break;
				}
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

static int handle_cmdline(int argc, char *argv[])
{
	char c,  *bind_opt, *target_opt;
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

	return 0;
}