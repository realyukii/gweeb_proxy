#define _GNU_SOURCE
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

#define DEFAULT_BUF_SZ	1024
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
	char *tbuf;
	size_t tlen;
	char *cbuf;
	size_t clen;
};

struct gwproxy {
	int listen_sock;
	int epfd;
};

extern char *optarg;
static struct sockaddr_storage src_addr_st, dst_addr_st;
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
static int init_addr(char *addr, struct sockaddr_storage *addr_st);

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

static int handle_incoming_client(struct gwproxy *gwp);

static int handle_data(struct epoll_event *c_ev);

/*
* Set socket attribute
*
* @param sock Network socket file descriptor.
*/
static void set_sockattr(int sock);

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
	int ret, ready_nr;
	socklen_t size_addr;
	struct epoll_event ev;
	struct gwproxy gwp;
	struct epoll_event evs[NR_EVENTS];
	static const int flg = 1;

	size_addr = src_addr_st.ss_family == AF_INET ? 
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

	ev.events = EPOLLIN;
	gwp.listen_sock = socket(src_addr_st.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (gwp.listen_sock < 0)
		return -EXIT_FAILURE;

	setsockopt(gwp.listen_sock, SOL_SOCKET, SO_REUSEADDR, &flg, sizeof(flg));

	if (bind(gwp.listen_sock, (struct sockaddr *)&src_addr_st, size_addr) < 0)
		goto err;
	
	if (listen(gwp.listen_sock, 10) < 0)
		goto err;

	gwp.epfd = epoll_create(1);
	ev.data.fd = gwp.listen_sock;
	epoll_ctl(gwp.epfd, EPOLL_CTL_ADD, gwp.listen_sock, &ev);

	while (true) {
		ready_nr = epoll_wait(gwp.epfd, evs, NR_EVENTS, -1);
		if (ready_nr < 0) {
			if (errno == EINTR)
				continue;
			printf("errno = %d\n", errno);
			perror("epoll_wait");
			return -EXIT_FAILURE;
		}

		for (int i = 0; i < ready_nr; i++) {
			struct epoll_event *c_ev = &evs[i];

			if (c_ev->data.fd == gwp.listen_sock) {
				ret = handle_incoming_client(&gwp);
				if (ret < 0)
					goto err;
			} else {
				ret = handle_data(c_ev);
				if (ret < 0)
					break;
			}
		}
	}

	return 0;
err:
	close(gwp.listen_sock);
	return -EXIT_FAILURE;
}

static int init_addr(char *addr, struct sockaddr_storage *addr_st)
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
	
	addr_st->ss_family = af;
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

static struct pair_connection *init_pair(void)
{
	struct pair_connection *pc;

	pc = malloc(sizeof(*pc));
	if (!pc)
		return NULL;

	pc->cbuf = malloc(DEFAULT_BUF_SZ);
	if (!pc->cbuf) {
		free(pc);
		return NULL;
	}

	pc->tbuf = malloc(DEFAULT_BUF_SZ);
	if (!pc->tbuf) {
		free(pc->cbuf);
		free(pc);
		return NULL;
	}
	pc->clen = 0;
	pc->tlen = 0;

	return pc;
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

static int handle_incoming_client(struct gwproxy *gwp)
{
	int client_fd, ret, tsock;
	struct epoll_event ev;
	socklen_t size_addr;
	struct pair_connection *pc = init_pair();
	if (!pc)
		return -ENOMEM;

	ev.events = EPOLLIN;
	client_fd = accept4(gwp->listen_sock, NULL, NULL, SOCK_NONBLOCK);
	set_sockattr(client_fd);
	ev.data.u64 = 0;
	ev.data.ptr = pc;
	pc->csockfd = client_fd;
	ev.data.u64 |= EV_BIT_CLIENT;

	epoll_ctl(gwp->epfd, EPOLL_CTL_ADD, client_fd, &ev);

	tsock = socket(dst_addr_st.sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (tsock < 0)
		return -EXIT_FAILURE;

	set_sockattr(tsock);
	size_addr = src_addr_st.ss_family == AF_INET ? 
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	ret = connect(tsock, (struct sockaddr *)&dst_addr_st, size_addr);
	if (ret == 0 || errno == EINPROGRESS || errno == EAGAIN) {
		ev.data.fd = tsock;
		ev.data.u64 = 0;
		ev.data.ptr = pc;
		pc->tsockfd = tsock;
		ev.data.u64 |= EV_BIT_TARGET;
		epoll_ctl(gwp->epfd, EPOLL_CTL_ADD, tsock, &ev);
	}

	return 0;
}

static int handle_data(struct epoll_event *c_ev)
{
	int from, to;
	ssize_t ret;
	uint64_t ev_bit = GET_EV_BIT(c_ev->data.u64);
	struct pair_connection *pc;
	char *buf;
	size_t *len, rlen;

	c_ev->data.u64 = CLEAR_EV_BIT(c_ev->data.u64);
	pc = c_ev->data.ptr;

	switch (ev_bit) {
	case EV_BIT_CLIENT:
		from = pc->csockfd;
		buf = pc->cbuf;
		len = &pc->clen;
		to = pc->tsockfd;
		break;

	case EV_BIT_TARGET:
		from = pc->tsockfd;
		buf = pc->tbuf;
		len = &pc->tlen;
		to = pc->csockfd;
		break;
	}

	rlen = DEFAULT_BUF_SZ - *len;
	if (rlen > 0) {
		ret = recv(from, &buf[*len], rlen, 0);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN || ret == EINTR)
				return 0;
			perror("recv");
			goto exit_err;
		} else if (!ret)
			goto exit_err;
		
		*len += (size_t)ret;
	}

	if (*len > 0) {
		ret = send(to, buf, *len, 0);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN || ret == EINTR) {
				
				return 0;
			}
			perror("send");
			goto exit_err;
		} else if (!ret)
			goto exit_err;
		
		*len -= ret;
		if (*len)
			memmove(buf, &buf[ret], *len);
	}

	return 0;

exit_err:
	close(from);
	close(to);
	free(pc);
	return -EXIT_FAILURE;
}

static void set_sockattr(int sock)
{
	static const int flg = 1;

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flg, sizeof(flg));
	setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &flg, sizeof(flg));
	setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &flg, sizeof(flg));
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flg, sizeof(flg));
}
