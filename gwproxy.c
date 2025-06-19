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
#include <unistd.h>
#include <unistd.h>

#define DEFAULT_THREAD_NR 4
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

};

extern char *optarg;
struct gwp_args args;
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
"-T\tnumber of thread (default %d)\n"
"-h\tShow this help message and exit\n";

/*
* Handle command-line arguments and initialize gwp_args.
* 
* @param argc total argument passed.
* @param argv Pointer to an array of string.
* @return zero on success, or a negative integer on failure.
*/
static int handle_cmdline(int argc, char *argv[]);

/*
* Initialize address used to bind or connect a socket.
*
* @param addr Pointer to the string with fmt ip:port.
* @param addr_st Pointer to a sockaddr structure to initialize.
* @return zero on success, or a negative integer on failure.
*/
static int init_addr(char *addr, struct sockaddr_storage *addr_st);

/*
* Thread callback
*
* @param args unused
* @return NULL
*/
static void *thread_cb(void *args);

/*
* Start the TCP proxy server.
* 
* @return negative integer on failure.
*/
static int start_server(void);

/*
* Process epoll event that are 'ready'.
*
* @param ready_nr Number of ready events.
* @param evs Pointer to epoll event struct.
* @param gwp Pointer to the global variable of gwproxy struct.
* @return zero on success, or a negative integer on failure.
*/
static int process_ready_list(int ready_nr,
				struct epoll_event *evs, struct gwproxy *gwp);

/*
* Handle incoming client.
*
* @param gwp Pointer to the global variable of gwproxy struct.
* @return zero on success, or a negative integer on failure.
*/
static int handle_incoming_client(struct gwproxy *gwp);

/*
* Extract data returned by epoll_wait
* on particular event in particular socket file descriptor.
*
* @param ev Pointer to epoll event.
* @param pc caller-variable to initialize.
* @param from caller-variable to initialize.
* @param to caller-variable to initialize.
*/
static void extract_data(struct epoll_event *ev, struct pair_connection **pc,
		struct single_connection **from, struct single_connection **to);

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
			struct single_connection *to);

/*
* Adjust epoll events
* on registered member of interest list.
*
* @param epfd epoll file descriptor.
* @param pc Pointer that need to be saved 
* and returned once particular event is triggered.
* @param src Pointer that needs its epmask member to be adjusted
* @param dst Pointer that needs its epmask member to be adjusted
* @return zero on success, or a negative integer on failure.
*/
static int adjust_events(int epfd, struct pair_connection *pc,
			struct single_connection *src,
			struct single_connection *dst);

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

	threads = calloc(args.thread_nr, sizeof(pthread_t));
	if (!threads)
		return -ENOMEM;

	for (size_t i = 0; i < args.thread_nr; i++) {
		ret = pthread_create(&threads[i], NULL, thread_cb, NULL);
		if (ret < 0) {
			perror("pthread_create");
			return ret;
		}
	}

	for (size_t i = 0; i < args.thread_nr; i++) {
		ret = pthread_join(threads[i], NULL);
		if (ret < 0) {
			perror("pthread_join");
			return ret;
		}
	}

	return 0;
}

static void *thread_cb(__attribute__((__unused__)) void *args)
{
	/* TODO: what to do when start_server fail to run on this thread? */
	start_server();

	return NULL;
}

static int start_server(void)
{
	int ret, ready_nr, flg;
	socklen_t size_addr;
	struct epoll_event ev;
	struct gwproxy gwp;
	struct sockaddr_storage *s = &args.src_addr_st;
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
			printf("errno = %d\n", errno);
			perror("epoll_wait");
			goto err;
		}

		process_ready_list(ready_nr, evs, &gwp);
	}

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
	char c,  *bind_opt, *target_opt, *thread_opt;
	int thread_nr;
	int ret;

	if (argc == 1) {
		printf(usage, DEFAULT_THREAD_NR);

		return 0;
	}

	bind_opt = target_opt = NULL;
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
		case 'h':
			printf(usage, DEFAULT_THREAD_NR);
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
	args.thread_nr = thread_nr;

	ret = init_addr(bind_opt, &args.src_addr_st);
	if (ret < 0) {
		fprintf(stderr, "invalid format for %s\n", bind_opt);
		return -EINVAL;
	}

	ret = init_addr(target_opt, &args.dst_addr_st);
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
	struct sockaddr_storage *d = &args.dst_addr_st;
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

	tsock = socket(d->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (tsock < 0)
		return -EXIT_FAILURE;

	set_sockattr(tsock);
	size_addr = d->ss_family == AF_INET ? 
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	ret = connect(tsock, (struct sockaddr *)d, size_addr);
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
	struct pair_connection *pc;
	struct single_connection *from, *to;

	for (int i = 0; i < ready_nr; i++) {
		struct epoll_event *ev = &evs[i];

		if (ev->data.fd == gwp->listen_sock) {
			ret = handle_incoming_client(gwp);
			if (ret < 0)
				return ret;
		} else {
			extract_data(ev, &pc, &from, &to);
			if (ev->events & EPOLLIN) {
				ret = handle_data(from, to);
				if (ret < 0)
					goto exit_err;
				adjust_events(gwp->epfd, pc, from, to);
			}

			if (ev->events & EPOLLOUT) {
				ret = handle_data(to, from);
				if (ret < 0)
					goto exit_err;
				adjust_events(gwp->epfd, pc, to, from);
			}

		}
	}

	return 0;

exit_err:
	close(from->sockfd);
	close(to->sockfd);
	free(pc);
	return -EXIT_FAILURE;
}

static int adjust_events(int epfd, struct pair_connection *pc,
			struct single_connection *src,
			struct single_connection *dst)
{
	int ret;
	bool is_from_changed = false;
	bool is_to_changed = false;
	struct epoll_event ev;

	adjust_pollout(src, dst, &is_to_changed);
	adjust_pollout(dst, src, &is_from_changed);
	adjust_pollin(src, &is_from_changed);
	adjust_pollin(dst, &is_to_changed);

	if (is_from_changed) {
		ev.data.u64 = 0;
		ev.data.ptr = pc;
		ev.data.u64 |= EV_BIT_CLIENT;
		ev.events = src->epmask;
		ret = epoll_ctl(epfd, EPOLL_CTL_MOD, src->sockfd, &ev);
		if (ret < 0) {
			perror("epoll_ctl");
			return -EXIT_FAILURE;
		}
	}

	if (is_to_changed) {
		ev.events = dst->epmask;
		ev.data.u64 = 0;
		ev.data.ptr = pc;
		ev.data.u64 |= EV_BIT_TARGET;
		ret = epoll_ctl(epfd, EPOLL_CTL_MOD, dst->sockfd, &ev);
		if (ret < 0) {
			perror("epoll_ctl");
			return -EXIT_FAILURE;
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

static void extract_data(struct epoll_event *ev, struct pair_connection **pc,
		struct single_connection **from, struct single_connection **to)
{
	uint64_t ev_bit = GET_EV_BIT(ev->data.u64);

	ev->data.u64 = CLEAR_EV_BIT(ev->data.u64);
	*pc = ev->data.ptr;

	switch (ev_bit) {
	case EV_BIT_CLIENT:
		*from = &(*pc)->client;
		*to = &(*pc)->target;
		break;

	case EV_BIT_TARGET:
		*from = &(*pc)->target;
		*to = &(*pc)->client;
		break;
	}
}

static int handle_data(struct single_connection *from,
			struct single_connection *to)
{
	ssize_t ret;
	size_t rlen;
	
	/* length of empty buffer */
	rlen = DEFAULT_BUF_SZ - from->len;
	if (rlen > 0) {
		ret = recv(from->sockfd, &from->buf[from->len], rlen, 0);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN || ret == EINTR)
				return 0;
			perror("recv");
			return -EXIT_FAILURE;
		} else if (!ret)
			return -EXIT_FAILURE;

		from->len += (size_t)ret;
	}

	/* length of filled buffer */
	if (from->len > 0) {
		ret = send(to->sockfd, from->buf, from->len, 0);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN || ret == EINTR)
				return 0;
			perror("send");
			return -EXIT_FAILURE;
		} else if (!ret)
			return -EXIT_FAILURE;

		from->len -= ret;
		if (from->len)
			memmove(from->buf, &from->buf[ret], from->len);
	}

	return 0;
}

static void set_sockattr(int sock)
{
	static const int val = 1;

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
	setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &val, sizeof(val));
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
}
