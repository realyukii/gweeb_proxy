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

struct single_connection {
	int sockfd;
	char *buf;
	size_t len;
	uint32_t epmask;
};

struct pair_connection {
	struct single_connection client;
	struct single_connection target;
};

struct gwproxy {
	int listen_sock;
	int epfd;
};

extern char *optarg;
static struct sockaddr_storage src_addr_st, dst_addr_st;
static const struct rlimit file_limits = {
	.rlim_cur = 100000,
	.rlim_max = 100000
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

/*
* Handle incoming client
*
* @param gwp Pointer to the global variable of gwproxy struct
* @return zero on success, or a negative integer on failure.
*/
static int handle_incoming_client(struct gwproxy *gwp);

/*
* Handle incoming and outgoing data
*
* @param c_ev Pointer to epoll' client event structure.
* @param gwp Pointer to the global variable of gwproxy struct
* @param is_pollout Boolean to indicate if the event currently handled
* is EPOLLOUT or EPOLLIN
* @return zero on success, or a negative integer on failure.
*/
static int handle_data(struct epoll_event *c_ev,
			struct gwproxy *gwp, bool is_pollout);

/*
* Process epoll event that are 'ready'
*
* @param ready_nr Number of ready events.
* @param evs Pointer to epoll event struct.
* @param gwp Pointer to the global variable of gwproxy struct.
* @return zero on success, or a negative integer on failure.
*/
static int process_ready_list(int ready_nr,
				struct epoll_event *evs, struct gwproxy *gwp);

/*
* Set EPOLLIN bit on epmask member.
*
* @param src Pointer to struct single_connection
* @param epmask_changed Pointer to boolean
*/
static void adjust_pollin(struct single_connection *src, bool *epmask_changed);

/*
* Set EPOLLOUT bit on epmask member of dst.
*
* @param src Pointer to struct single_connection
* @param dst Pointer to struct single_connection
* @param epmask_changed Pointer to boolean
*/
static void adjust_pollout(struct single_connection *src,
			struct single_connection *dst, bool *epmask_changed);

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

	ret = setrlimit(RLIMIT_NOFILE, &file_limits);
	if (ret < 0) {
		perror("setrlimit");
		return ret;
	}

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
	setsockopt(gwp.listen_sock, SOL_SOCKET, SO_REUSEPORT, &flg, sizeof(flg));

	ret = bind(gwp.listen_sock, (struct sockaddr *)&src_addr_st, size_addr);
	if (ret < 0)
		goto err;

	ret = listen(gwp.listen_sock, 10);
	if (ret < 0)
		goto err;

	gwp.epfd = epoll_create(1);
	ev.data.fd = gwp.listen_sock;
	ret = epoll_ctl(gwp.epfd, EPOLL_CTL_ADD, gwp.listen_sock, &ev);
	if (ret < 0) {
		perror("epoll_ctl");
		return -EXIT_FAILURE;
	}

	while (true) {
		ready_nr = epoll_wait(gwp.epfd, evs, NR_EVENTS, -1);
		if (ready_nr < 0) {
			if (errno == EINTR)
				continue;
			printf("errno = %d\n", errno);
			perror("epoll_wait");
			return -EXIT_FAILURE;
		}

		process_ready_list(ready_nr, evs, &gwp);
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
	unsigned short nport, af;
	int hport;
	size_t addrlen = strlen(addr) + 1;
	char tmp[1 + INET6_ADDRSTRLEN + 1 + 1 + 5];
	char *ipstr;

	if (addrlen > sizeof(tmp))
		return -EINVAL;

	strncpy(tmp, addr, addrlen);
	for (size_t i = addrlen - 1; i > 0; i--) {
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

	pr_debug(VERBOSE, "address: %s:%d\n", ipstr, hport);

	return 0;
}

static struct pair_connection *init_pair(void)
{
	struct pair_connection *pc;
	struct single_connection *client;
	struct single_connection *target;

	pc = malloc(sizeof(*pc));
	if (!pc)
		return NULL;

	client = &pc->client;
	target = &pc->target;

	client->buf = malloc(DEFAULT_BUF_SZ);
	if (!client->buf) {
		free(pc);
		return NULL;
	}

	target->buf = malloc(DEFAULT_BUF_SZ);
	if (!target->buf) {
		free(client->buf);
		free(pc);
		return NULL;
	}
	client->len = 0;
	target->len = 0;

	client->epmask = EPOLLIN;
	target->epmask = EPOLLIN | EPOLLOUT;

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

	ev.events = pc->client.epmask;
	client_fd = accept4(gwp->listen_sock, NULL, NULL, SOCK_NONBLOCK);
	set_sockattr(client_fd);
	pc->client.sockfd = client_fd;
	ev.data.u64 = 0;
	ev.data.ptr = pc;
	ev.data.u64 |= EV_BIT_CLIENT;

	ret = epoll_ctl(gwp->epfd, EPOLL_CTL_ADD, client_fd, &ev);
	if (ret < 0) {
		perror("epoll_ctl");
		return -EXIT_FAILURE;
	}

	tsock = socket(dst_addr_st.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (tsock < 0)
		return -EXIT_FAILURE;

	set_sockattr(tsock);
	size_addr = src_addr_st.ss_family == AF_INET ? 
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	ret = connect(tsock, (struct sockaddr *)&dst_addr_st, size_addr);
	if (ret == 0 || errno == EINPROGRESS || errno == EAGAIN) {
		ev.events = pc->target.epmask;
		ev.data.u64 = 0;
		ev.data.ptr = pc;
		pc->target.sockfd = tsock;
		ev.data.u64 |= EV_BIT_TARGET;
		ret = epoll_ctl(gwp->epfd, EPOLL_CTL_ADD, tsock, &ev);
		if (ret < 0) {
			perror("epoll_ctl");
			return -EXIT_FAILURE;
		}
	}

	return 0;
}

static int process_ready_list(int ready_nr,
				struct epoll_event *evs, struct gwproxy *gwp)
{
	int ret;

	for (int i = 0; i < ready_nr; i++) {
		struct epoll_event *c_ev = &evs[i];

		if (c_ev->data.fd == gwp->listen_sock) {
			ret = handle_incoming_client(gwp);
			if (ret < 0)
				return ret;
		} else {
			if (c_ev->events & EPOLLIN) {
				ret = handle_data(c_ev, gwp, false);
				if (ret < 0)
					break;
			}

			if (c_ev->events & EPOLLOUT) {
				ret = handle_data(c_ev, gwp, true);
				if (ret < 0)
					break;
			}
		}
	}

	return 0;
}

static void adjust_pollin(struct single_connection *src, bool *epmask_changed)
{
	/*
	* unset EPOLLIN from epmask when the buffer is full,
	* otherwise, set it.
	*/
	if (!(DEFAULT_BUF_SZ - src->len)) {
		if (src->epmask & EPOLLIN) {
			src->epmask &= ~EPOLLIN;
			*epmask_changed = true;
		}
	} else {
		if (!(src->epmask & EPOLLIN)) {
			src->epmask |= EPOLLIN;
			*epmask_changed = true;
		}
	}
}

static void adjust_pollout(struct single_connection *src,
			struct single_connection *dst, bool *epmask_changed)
{
	/*
	* set EPOLLOUT to epmask when there's remaining bytes in the buffer
	* waiting to be sent, otherwise, unset it.
	*/
	if (src->len > 0) {
		if (!(dst->epmask & EPOLLOUT)) {
			dst->epmask |= EPOLLOUT;
			*epmask_changed = true;
		}
	} else {
		if (dst->epmask & EPOLLOUT) {
			dst->epmask &= ~EPOLLOUT;
			*epmask_changed = true;
		}
	}
}

static int handle_data(struct epoll_event *c_ev,
			struct gwproxy *gwp, bool is_pollout)
{
	ssize_t ret;
	uint64_t ev_bit = GET_EV_BIT(c_ev->data.u64);
	struct pair_connection *pc;
	struct single_connection *from, *to, *tmp;
	struct epoll_event ev_from, ev_to;
	bool is_from_changed = false;
	bool is_to_changed = false;
	size_t rlen;

	c_ev->data.u64 = CLEAR_EV_BIT(c_ev->data.u64);
	pc = c_ev->data.ptr;

	switch (ev_bit) {
	case EV_BIT_CLIENT:
		from = &pc->client;
		to = &pc->target;
		break;

	case EV_BIT_TARGET:
		from = &pc->target;
		to = &pc->client;
		break;
	}

	if (is_pollout) {
		tmp = from;
		from = to;
		to = tmp;
	}

	if (from == &pc->client) {
		ev_from.data.u64 = 0;
		ev_from.data.ptr = pc;
		ev_from.data.u64 |= EV_BIT_CLIENT;

		ev_to.data.u64 = 0;
		ev_to.data.ptr = pc;
		ev_to.data.u64 |= EV_BIT_TARGET;
	} else {
		ev_from.data.u64 = 0;
		ev_from.data.ptr = pc;
		ev_from.data.u64 |= EV_BIT_TARGET;

		ev_to.data.u64 = 0;
		ev_to.data.ptr = pc;
		ev_to.data.u64 |= EV_BIT_CLIENT;
	}
	
	/* length of empty buffer */
	rlen = DEFAULT_BUF_SZ - from->len;
	if (rlen > 0) {
		ret = recv(from->sockfd, &from->buf[from->len], rlen, 0);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN || ret == EINTR)
				goto exit;
			perror("recv");
			goto exit_err;
		} else if (!ret)
			goto exit_err;

		from->len += (size_t)ret;
	}

	/* length of filled buffer */
	if (from->len > 0) {
		ret = send(to->sockfd, from->buf, from->len, 0);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN || ret == EINTR)
				goto exit;
			perror("send");
			goto exit_err;
		} else if (!ret)
			goto exit_err;

		from->len -= ret;
		if (from->len)
			memmove(from->buf, &from->buf[ret], from->len);
	}

exit:
	adjust_pollout(from, to, &is_to_changed);
	adjust_pollout(to, from, &is_from_changed);
	adjust_pollin(from, &is_from_changed);
	adjust_pollin(to, &is_to_changed);

	if (is_from_changed) {
		ev_from.events = from->epmask;
		ret = epoll_ctl(gwp->epfd, EPOLL_CTL_MOD, from->sockfd, &ev_from);
		if (ret < 0) {
			perror("epoll_ctl");
			goto exit_err;
		}
	}

	if (is_to_changed) {
		ev_to.events = to->epmask;
		ret = epoll_ctl(gwp->epfd, EPOLL_CTL_MOD, to->sockfd, &ev_to);
		if (ret < 0) {
			perror("epoll_ctl");
			goto exit_err;
		}
	}

	return 0;

exit_err:
	close(from->sockfd);
	close(to->sockfd);
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
