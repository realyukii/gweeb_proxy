#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/timerfd.h>
#include <unistd.h>

#define DEFAULT_TIMEOUT 5
#define DEFAULT_THREAD_NR 4
#define DEFAULT_BUF_SZ	1024
#define NR_EVENTS 512
#ifndef DEBUG_LVL
#define DEBUG_LVL 0
#endif
#define FOCUS 1
#define DEBUG 2
#define VERBOSE 3
#define DEBUG_EPOLL_EVENTS 4
#define pr_debug(lvl, fmt, ...)				\
do {							\
	if (DEBUG_LVL == (lvl)) {			\
		fprintf(stderr, fmt, ##__VA_ARGS__);	\
	}						\
} while (0)

enum {
	EV_BIT_CLIENT		= (0x0001ULL << 48ULL),
	EV_BIT_TARGET		= (0x0002ULL << 48ULL),
	EV_BIT_TIMER		= (0x0003ULL << 48ULL)
};

#define ALL_EV_BIT	(EV_BIT_CLIENT | EV_BIT_TARGET | EV_BIT_TIMER)
#define GET_EV_BIT(X)	((X) & ALL_EV_BIT)
#define CLEAR_EV_BIT(X)	((X) & ~ALL_EV_BIT)

struct single_connection {
	/* TCP socket file descriptor */
	int sockfd;
	/* buffer allocated on dynamic memory */
	char *buf;
	/* length of filled buffer */
	size_t len;
	/* epoll mask used to store epoll event*/
	uint32_t epmask;
};

struct pair_connection {
	/* represent client connection */
	struct single_connection client;
	/* represent target connection */
	struct single_connection target;
	/* timer file descriptor for setting timeout */
	int timerfd;
};

struct gwproxy {
	/* TCP socket file descriptor */
	int listen_sock;
	/* epoll file descriptor */
	int epfd;
};

struct gwp_args {
	struct sockaddr_storage src_addr_st, dst_addr_st;
	size_t thread_nr;
	size_t timeout;

};

extern char *optarg;
static const struct rlimit file_limits = {
	.rlim_cur = 100000,
	.rlim_max = 100000
};
static pthread_t *threads;
static const char opts[] = "hb:t:T:";
static const char usage[] =
"usage: ./gwproxy [options]\n"
"-b\tIP address and port to be bound by the server\n"
"-t\tIP address and port of the target server\n"
"-T\tnumber of thread (default: %d)\n"
"-w\twait time for timeout, set to zero for no timeout (default: %d seconds)"
"-h\tShow this help message and exit\n";

void printBits(size_t const size, void const * const ptr)
{
	unsigned char *b = (unsigned char*) ptr;
	unsigned char byte;
	int i, j;
	
	for (i = size-1; i >= 0; i--) {
		for (j = 7; j >= 0; j--) {
			byte = (b[i] >> j) & 1;
			printf("%u", byte);
		}
	}
	puts("");
}

/*
* Initialize address used to bind or connect a socket.
*
* @param addr Pointer to the string with fmt ip:port.
* @param addr_st Pointer to a sockaddr_storage structure to initialize.
* @return zero on success, or a negative integer on failure.
*/
static int init_addr(char *addr, struct sockaddr_storage *addr_st)
{
	struct sockaddr_in6 *in6 = (void *)addr_st;
	struct sockaddr_in *in = (void *)addr_st;
	char *separator = NULL, *port_str;
	unsigned short nport, af;
	int i, hport;
	size_t addrlen = strlen(addr) + 1;
	char tmp[1 + INET6_ADDRSTRLEN + 1 + 1 + 5];
	char *ipstr;

	if (addrlen > sizeof(tmp))
		return -EINVAL;

	strncpy(tmp, addr, addrlen);
	for (i = addrlen - 1; i > 0; i--) {
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

	return 0;
}

/*
* Handle command-line arguments and initialize gwp_args.
* 
* @param argc total argument passed.
* @param argv Pointer to an array of string.
* @param args Pointer to cmdline arguments to initialize.
* @return zero on success, or a negative integer on failure.
*/
static int handle_cmdline(int argc, char *argv[], struct gwp_args *args)
{
	char c,  *bind_opt, *target_opt, *thread_opt, *wait_opt;
	int thread_nr, timeout;
	int ret;

	if (argc == 1) {
		printf(usage, DEFAULT_THREAD_NR, DEFAULT_TIMEOUT);

		return 0;
	}

	wait_opt = thread_opt = bind_opt = target_opt = NULL;
	while ((c = getopt(argc, argv, opts)) != -1) {
		switch (c) {
		case 'b':
			bind_opt = optarg;
			break;
		case 't':
			target_opt = optarg;
			break;
		case 'T':
			thread_opt = optarg;
			break;
		case 'w':
			wait_opt = optarg;
			break;
		case 'h':
			printf(usage, DEFAULT_THREAD_NR, DEFAULT_TIMEOUT);
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

	if (thread_opt) {
		thread_nr = atoi(thread_opt);
		if (thread_nr <= 0)
			thread_nr = DEFAULT_THREAD_NR;
	} else {
		thread_nr = DEFAULT_THREAD_NR;
	}
	args->thread_nr = thread_nr;

	if (wait_opt) {
		timeout = atoi(wait_opt);
		if (timeout < 0)
			timeout = DEFAULT_TIMEOUT;
	} else {
		timeout = DEFAULT_TIMEOUT;
	}
	args->timeout = timeout;

	ret = init_addr(bind_opt, &args->src_addr_st);
	if (ret < 0) {
		fprintf(stderr, "invalid format for %s\n", bind_opt);
		return -EINVAL;
	}

	ret = init_addr(target_opt, &args->dst_addr_st);
	if (ret < 0) {
		fprintf(stderr, "invalid format for %s\n", target_opt);
		return -EINVAL;
	}

	return 0;
}

/*
* Set socket attribute
*
* @param sock Network socket file descriptor.
*/
static void set_sockattr(int sock)
{
	static const int val = 1;

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
	setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &val, sizeof(val));
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
}

/*
* Initialize a pair of connection: client:target.
*
* @return pointer to the malloc'd address
*/
static struct pair_connection *init_pair(void)
{
	struct pair_connection *pc;
	struct single_connection *client;
	struct single_connection *target;

	pc = malloc(sizeof(*pc));
	if (!pc)
		return NULL;
	pc->timerfd = -1;

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

/*
* Handle incoming client.
*
* @param gwp Pointer to the gwproxy struct (thread data).
* @return zero on success, or a negative integer on failure.
*/
static void handle_incoming_client(struct gwproxy *gwp, struct gwp_args *args)
{
	int client_fd, ret, tsock, flg;
	struct epoll_event ev;
	socklen_t size_addr;
	struct sockaddr_storage *d = &args->dst_addr_st;
	struct pair_connection *pc = init_pair();
	if (!pc)
		return;

	if (args->timeout) {
		int tmfd;
		struct itimerspec it = {
			.it_value = {
				.tv_sec = args->timeout,
				.tv_nsec = 0
			},
			.it_interval = {
				.tv_sec = 0,
				.tv_nsec = 0
			}
		};

		flg = TFD_NONBLOCK;
		tmfd = timerfd_create(CLOCK_MONOTONIC, flg);
		if (tmfd < 0) {
			perror("timerfd_create");
			goto exit_err;
		}
		pc->timerfd = tmfd;

		ev.events = EPOLLIN;
		ev.data.u64 = 0;
		ev.data.ptr = pc;
		ev.data.u64 |= EV_BIT_TIMER;
		ret = epoll_ctl(gwp->epfd, EPOLL_CTL_ADD, pc->timerfd, &ev);
		if (ret < 0) {
			perror("epoll_ctl");
			goto exit_err;
		}
		ret = timerfd_settime(pc->timerfd, 0, &it, NULL);
		if (ret < 0) {
			perror("timerfd_settime");
			goto exit_err;
		}
	}

	ev.events = pc->client.epmask;
	client_fd = accept4(gwp->listen_sock, NULL, NULL, SOCK_NONBLOCK);
	if (client_fd < 0) {
		perror("accept");
		ret = errno;
		if (ret != EINTR)
			goto exit_err;
	}
	set_sockattr(client_fd);
	pc->client.sockfd = client_fd;
	ev.data.u64 = 0;
	ev.data.ptr = pc;
	ev.data.u64 |= EV_BIT_CLIENT;

	ret = epoll_ctl(gwp->epfd, EPOLL_CTL_ADD, client_fd, &ev);
	if (ret < 0) {
		perror("epoll_ctl");
		goto exit_err;
	}

	tsock = socket(d->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (tsock < 0) {
		perror("socket");
		goto exit_err;
	}

	set_sockattr(tsock);
	size_addr = d->ss_family == AF_INET ? 
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	ret = connect(tsock, (struct sockaddr *)d, size_addr);
	if (ret < 0 && errno != EINPROGRESS) {
		perror("connect");
		goto exit_err;
	}

	ev.events = pc->target.epmask;
	ev.data.u64 = 0;
	ev.data.ptr = pc;
	pc->target.sockfd = tsock;
	ev.data.u64 |= EV_BIT_TARGET;
	ret = epoll_ctl(gwp->epfd, EPOLL_CTL_ADD, tsock, &ev);
	if (ret < 0) {
		perror("epoll_ctl");
		goto exit_err;
	}

	return;
exit_err:
	free(pc->client.buf);
	free(pc->target.buf);
	if (pc->timerfd != -1)
		close(pc->timerfd);
	free(pc);
	if (client_fd != -1)
		close(client_fd);
	if (tsock != -1)
		close(tsock);
}

/*
* Extract data returned by epoll_wait
* on particular event in particular socket file descriptor.
*
* @param ev Pointer to epoll event.
* @param pc caller-variable to initialize.
* @param from the socket that trigger epoll event;
* however, it is not the case for EV_BIT_TIMER.
* @param to the peer.
* @return zero on success, or a negative integer on failure.
*/
static int extract_data(struct epoll_event *ev, struct pair_connection **pc,
		struct single_connection **from, struct single_connection **to)
{
	uint64_t ev_bit = GET_EV_BIT(ev->data.u64);

	ev->data.u64 = CLEAR_EV_BIT(ev->data.u64);
	*pc = ev->data.ptr;

	pr_debug(
		DEBUG_EPOLL_EVENTS,
		"ressurected from sleep, let's start extracting the bit\n"
	);
	switch (ev_bit) {
	case EV_BIT_TIMER:
		/*
		* failed to establish connection from the client to the target
		* at specified time interval;
		* the order of assignment itself doesn't matter technically,
		* but this comment was made to emphasize "what's going on"
		* for the sake of readability.
		*/
		*from = &(*pc)->client;
		*to = &(*pc)->target;
		pr_debug(VERBOSE, "timed out, terminating the session\n");
		return -ETIMEDOUT;
	case EV_BIT_CLIENT:
		pr_debug(DEBUG_EPOLL_EVENTS, "receiving data from client\n");
		*from = &(*pc)->client;
		*to = &(*pc)->target;
		break;

	case EV_BIT_TARGET:
		pr_debug(DEBUG_EPOLL_EVENTS, "receiving data from target\n");
		*from = &(*pc)->target;
		*to = &(*pc)->client;
		break;
	}

	pr_debug(
		DEBUG_EPOLL_EVENTS,
		"current events on socket %d: ",
		(*from)->sockfd
	);
	if (DEBUG_LVL == DEBUG_EPOLL_EVENTS) {
		printBits(sizeof(ev->events), &ev->events);
	}

	return 0;
}

/*
* Handle incoming and outgoing data.
*
* remark:
* The caller must swap the argument passed into this function
* if the event was EPOLLOUT, as we're going to send instead of receive.
* this behavior is affected by/related to function extract_data.
*
* @param from The source of fetched data.
* @param to The destination of data to be sent.
* @return zero on success, or a negative integer on failure.
*/
static int handle_data(struct single_connection *from,
			struct single_connection *to)
{
	ssize_t ret;
	size_t rlen;
	
	/* length of empty buffer */
	rlen = DEFAULT_BUF_SZ - from->len;
	pr_debug(
		DEBUG_EPOLL_EVENTS,
		"receive from socket %d "
		"with buffer that have free space of %ld bytes\n",
		from->sockfd, rlen
	);
	if (rlen > 0) {
		ret = recv(from->sockfd, &from->buf[from->len], rlen, MSG_NOSIGNAL);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN || ret == EINTR) {
				/*
				* if buffer is not empty,
				* send it to the destination
				*/
				if (from->len)
					goto try_send;
				return 0;
			}
			perror("recv");
			return -EXIT_FAILURE;
		} else if (!ret)
			return -EXIT_FAILURE;

		from->len += (size_t)ret;
		pr_debug(DEBUG_EPOLL_EVENTS, "buffer filled with %ld bytes\n", from->len);
	}

try_send:
	pr_debug(DEBUG_EPOLL_EVENTS, "send to socket %d\n", to->sockfd);
	/* length of filled buffer */
	if (from->len > 0) {
		ret = send(to->sockfd, from->buf, from->len, MSG_NOSIGNAL);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN || ret == EINTR)
				return 0;
			perror("send");
			return -EXIT_FAILURE;
		} else if (!ret)
			return -EXIT_FAILURE;

		from->len -= ret;
		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"remaining bytes on the buffer: %ld\n",
			from->len
		);
		if (from->len)
			memmove(from->buf, &from->buf[ret], from->len);
	}

	return 0;
}

/*
* Set EPOLLOUT bit on epmask member of dst.
*
* @param src Pointer to struct single_connection.
* @param dst Pointer to struct single_connection.
* @param epmask_changed Pointer to boolean.
*/
static void adjust_pollout(struct single_connection *src,
			struct single_connection *dst, bool *epmask_changed)
{
	/*
	* set EPOLLOUT to epmask when there's remaining bytes in the buffer
	* waiting to be sent, otherwise, unset it.
	*/
	if (src->len > 0) {
		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"[set EPOLLOUT] there is still buffer remaining "
			"in socket %d, need to drain it by sending it "
			"to the socket %d\n",
			src->sockfd, dst->sockfd
		);

		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"current events on socket %d: ",
			dst->sockfd
		);
		if (DEBUG_LVL == DEBUG_EPOLL_EVENTS) {
			printBits(sizeof(dst->epmask), &dst->epmask);
		}
		if (!(dst->epmask & EPOLLOUT)) {
			dst->epmask |= EPOLLOUT;
			*epmask_changed = true;
		}
	} else {
		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"[unset EPOLLOUT] no buffer left on socket %d, "
			"it is fully empty, "
			"send to socket %d is now completed\n",
			src->sockfd, dst->sockfd
		);

		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"current events on socket %d: ",
			dst->sockfd
		);
		if (DEBUG_LVL == DEBUG_EPOLL_EVENTS) {
			printBits(sizeof(dst->epmask), &dst->epmask);
		}
		if (dst->epmask & EPOLLOUT) {
			dst->epmask &= ~EPOLLOUT;
			*epmask_changed = true;
		}
	}
}

/*
* Set EPOLLIN bit on epmask member.
*
* @param src Pointer to struct single_connection.
* @param epmask_changed Pointer to boolean.
*/
static void adjust_pollin(struct single_connection *src, bool *epmask_changed)
{
	/*
	* unset EPOLLIN from epmask when the buffer is full,
	* otherwise, set it.
	*/
	if (!(DEFAULT_BUF_SZ - src->len)) {
		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"[unset EPOLLIN] buffer on socket %d is full "
			"can't receive anymore\n",
			src->sockfd
		);

		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"current events on socket %d: ",
			src->sockfd
		);
		if (DEBUG_LVL == DEBUG_EPOLL_EVENTS) {
			printBits(sizeof(src->epmask), &src->epmask);
		}
		if (src->epmask & EPOLLIN) {
			src->epmask &= ~EPOLLIN;
			*epmask_changed = true;
		}
	} else {
		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"[set EPOLLIN] buffer on socket %d still have "
			"some free space to fill in\n",
			src->sockfd
		);

		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"current events on socket %d: ",
			src->sockfd
		);
		if (DEBUG_LVL == DEBUG_EPOLL_EVENTS) {
			printBits(sizeof(src->epmask), &src->epmask);
		}
		if (!(src->epmask & EPOLLIN)) {
			src->epmask |= EPOLLIN;
			*epmask_changed = true;
		}
	}
}

/*
* Adjust epoll events
* on registered member of interest list.
*
* @param epfd epoll file descriptor.
* @param pc Pointer that need to be saved 
* and returned once particular event is triggered.
* @return zero on success, or a negative integer on failure.
*/
static int adjust_events(int epfd, struct pair_connection *pc)
{
	int ret;
	bool is_client_changed = false;
	bool is_target_changed = false;
	struct epoll_event ev;
	struct single_connection *client = &pc->client, *target = &pc->target;

	adjust_pollout(client, target, &is_target_changed);
	adjust_pollout(target, client, &is_client_changed);
	adjust_pollin(client, &is_client_changed);
	adjust_pollin(target, &is_target_changed);

	if (is_client_changed) {
		ev.data.u64 = 0;
		ev.data.ptr = pc;
		ev.data.u64 |= EV_BIT_CLIENT;
		ev.events = client->epmask;

		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"modifying events on socket %d: ",
			client->sockfd
		);
		if (DEBUG_LVL == DEBUG_EPOLL_EVENTS) {
			printBits(sizeof(ev.events), &ev.events);
		}
		ret = epoll_ctl(epfd, EPOLL_CTL_MOD, client->sockfd, &ev);
		if (ret < 0) {
			perror("epoll_ctl");
			return -EXIT_FAILURE;
		}
	}

	if (is_target_changed) {
		ev.events = target->epmask;
		ev.data.u64 = 0;
		ev.data.ptr = pc;
		ev.data.u64 |= EV_BIT_TARGET;

		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"modifying events on socket %d: ",
			target->sockfd
		);
		if (DEBUG_LVL == DEBUG_EPOLL_EVENTS) {
			printBits(sizeof(ev.events), &ev.events);
		}
		ret = epoll_ctl(epfd, EPOLL_CTL_MOD, target->sockfd, &ev);
		if (ret < 0) {
			perror("epoll_ctl");
			return -EXIT_FAILURE;
		}
	}

	return 0;
}

/*
* Process epoll event from tcp connection.
*
* @param ev Pointer to epoll event structure.
* @param gwp Pointer to the gwproxy struct (thread data).
*/
static void process_tcp(struct epoll_event *ev, struct gwproxy *gwp)
{
	int ret;
	struct pair_connection *pc;
	struct single_connection *a, *b;

	ret = extract_data(ev, &pc, &a, &b);
	if (ret < 0)
		goto exit_err;
	if (ev->events & EPOLLIN) {
		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"current epoll events have EPOLLIN bit set\n"
		);
		ret = handle_data(a, b);
		if (ret < 0)
			goto exit_err;
	}

	if (ev->events & EPOLLOUT) {
		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"current epoll events have EPOLLOUT bit set\n"
		);

		if (pc->timerfd != -1) {
			close(pc->timerfd);
			pc->timerfd = -1;
		}

		ret = handle_data(b, a);
		if (ret < 0)
			goto exit_err;
	}

	adjust_events(gwp->epfd, pc);

	return;
exit_err:
	if (pc->timerfd != -1)
		close(pc->timerfd);
	close(a->sockfd);
	close(b->sockfd);
	free(pc->client.buf);
	free(pc->target.buf);
	free(pc);
}

/*
* Process epoll event that are 'ready'.
*
* @param ready_nr Number of ready events.
* @param args Pointer to cmdline arguments.
* @param evs Pointer to epoll event struct.
* @param gwp Pointer to the gwproxy struct (thread data).
* @return zero on success, or a negative integer on failure.
*/
static int process_ready_list(int ready_nr, struct gwp_args *args,
				struct epoll_event *evs, struct gwproxy *gwp)
{
	int ret, i;

	for (i = 0; i < ready_nr; i++) {
		struct epoll_event *ev = &evs[i];

		if (ev->data.fd == gwp->listen_sock) {
			pr_debug(VERBOSE, "serving new client\n");
			handle_incoming_client(gwp, args);
		} else
			process_tcp(ev, gwp);
	}

	return 0;
}

/*
* Start the TCP proxy server.
* 
* @param args Pointer to cmdline arguments.
* @return negative integer on failure.
*/
static int start_server(struct gwp_args *args)
{
	int ret, ready_nr, flg;
	socklen_t size_addr;
	struct epoll_event ev;
	struct gwproxy gwp;
	struct sockaddr_storage *s = &args->src_addr_st;
	struct epoll_event evs[NR_EVENTS];
	static const int val = 1;

	size_addr = s->ss_family == AF_INET ? 
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

	flg = SOCK_STREAM | SOCK_NONBLOCK;
	gwp.listen_sock = socket(s->ss_family, flg, 0);
	if (gwp.listen_sock < 0)
		return -EXIT_FAILURE;

	setsockopt(gwp.listen_sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(gwp.listen_sock, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));

	ret = bind(gwp.listen_sock, (struct sockaddr *)s, size_addr);
	if (ret < 0)
		goto err;

	ret = listen(gwp.listen_sock, 10);
	if (ret < 0)
		goto err;

	gwp.epfd = epoll_create(1);
	ev.events = EPOLLIN;
	ev.data.fd = gwp.listen_sock;
	ret = epoll_ctl(gwp.epfd, EPOLL_CTL_ADD, gwp.listen_sock, &ev);
	if (ret < 0) {
		perror("epoll_ctl");
		goto err;
	}

	while (true) {
		ready_nr = epoll_wait(gwp.epfd, evs, NR_EVENTS, -1);
		if (ready_nr < 0) {
			if (errno == EINTR)
				continue;
			perror("epoll_wait");
			goto err;
		}

		process_ready_list(ready_nr, args, evs, &gwp);
	}

err:
	close(gwp.listen_sock);
	if (gwp.epfd != -1)
		close(gwp.epfd);
	return -EXIT_FAILURE;
}

/*
* Thread callback
*
* @param args Pointer to cmdline arguments.
* @return NULL
*/
static void *thread_cb(void *args)
{
	int ret = start_server(args);

	return (void *)(intptr_t)ret;
}

int main(int argc, char *argv[])
{
	int ret, i;
	void *retval;
	struct gwp_args args;

	ret = handle_cmdline(argc, argv, &args);
	if (ret < 0)
		return ret;

	ret = setrlimit(RLIMIT_NOFILE, &file_limits);
	if (ret < 0) {
		perror("setrlimit");
		return ret;
	}

	threads = calloc(args.thread_nr, sizeof(pthread_t));
	if (!threads)
		return -ENOMEM;

	for (i = 0; i < args.thread_nr; i++) {
		ret = pthread_create(&threads[i], NULL, thread_cb, &args);
		if (ret) {
			errno = ret;
			perror("pthread_create");
			free(threads);
			return ret;
		}
	}

	for (i = 0; i < args.thread_nr; i++) {
		ret = pthread_join(threads[i], &retval);
		if (ret) {
			errno = ret;
			perror("pthread_join");
			free(threads);
			return ret;
		}

		if ((intptr_t)retval < 0) {
			fprintf(stderr, "fatal: failed to start server\n");
			free(threads);
			return -EXIT_FAILURE;
		}
	}

	return 0;
}
