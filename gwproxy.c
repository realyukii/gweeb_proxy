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
#include "linux.c"

#define REPLY_LEN 2
#define PORT_SZ 2
#define SOCKS5_VER 5
#define MAX_DOMAIN_LEN 255
#define MAX_FILEPATH 1024
#define MAX_USERPWD_PKT 1 + 1 + 255 + 1 + 255
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
#define DEBUG_SEND_RECV 5
#define pr_debug(lvl, fmt, ...)				\
do {							\
	if (DEBUG_LVL == (lvl)) {			\
		fprintf(stderr, fmt, ##__VA_ARGS__);	\
	}						\
} while (0)
#define pr_menu printf(usage, DEFAULT_THREAD_NR, DEFAULT_TIMEOUT)

enum typemask {
	/* indicate a client file descriptor */
	EV_BIT_CLIENT		= (0x0001ULL << 48ULL),
	/* indicate a target file descriptor */
	EV_BIT_TARGET		= (0x0002ULL << 48ULL),
	/* indicate a timer file descriptor */
	EV_BIT_TIMER		= (0x0003ULL << 48ULL)
};

enum gwp_substate {
	STATE_RECV	= (0x0 << 12ULL),
	STATE_SEND	= (0x1 << 12ULL)
};

enum gwp_state {
	/* not in socks5 mode */
	NO_SOCKS5		= 0x0,
	/* hello packet from client */
	STATE_ACCEPT_GREETING	= 0x1,
	/* send reply to the client */
	STATE_GREETING_ACCEPTED	= 0x2,
	/* negotiating authentication method */
	STATE_AUTH		= 0x4,
	/* client request. */
	STATE_REQUEST		= 0x8,
	/* exchange the data between client and destination */
	STATE_EXCHANGE		= 0x10
};

enum auth_type {
	NO_AUTH = 0x0,
	// GSSAPI, not supported yet
	USERNAME_PWD = 0x2,
	NONE = 0xFF
};

enum cmd_type {
	/*
	* we will focus on CONNECT first,
	* the rest implementation can follow later.
	*/
	CONNECT = 1,
	// BIND = 2,
	// UDP_ASSOCIATE = 3
};

enum addr_type {
	IPv4 = 1,
	DOMAIN = 3,
	IPv6 = 4
};

#define ALL_EV_BIT	(EV_BIT_CLIENT | EV_BIT_TARGET | EV_BIT_TIMER)
#define GET_EV_BIT(X)	((X) & ALL_EV_BIT)
#define CLEAR_EV_BIT(X)	((X) & ~ALL_EV_BIT)

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

struct single_connection {
	/* TCP socket file descriptor */
	int sockfd;
	/* buffer allocated on dynamic memory */
	char *buf;
	/* length of filled buffer */
	size_t len;
	/* offset (for short-send) */
	size_t off;
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
	/* connection state of target */
	bool is_connected;
	/* state of the established session */
	uint16_t state;
	/* the following is used on socks5 mode */
	enum auth_type preferred_method;
	bool is_authenticated;
};

struct gwproxy {
	/* TCP socket file descriptor */
	int listen_sock;
	/* epoll file descriptor */
	int epfd;
};

struct socks5_greeting {
	uint8_t ver;
	uint8_t nauth;
};

struct socks5_addr {
	/* see the available type in enum addr_type */
	uint8_t type;
	union {
		uint8_t ipv4[4];
		struct {
			uint8_t len;
			char domain[MAX_DOMAIN_LEN];
		} domain;
		uint8_t ipv6[16];
	} addr;
};

struct socks5_connect_request {
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	struct socks5_addr dst_addr;
	/*
	* since addr member of struct dst_addr use union,
	* the destination port is not specified explicitly as a struct member.
	*/
};

struct socks5_connect_reply {
	uint8_t ver;
	uint8_t status;
	uint8_t rsv;
	struct socks5_addr bnd_addr;
	/*
	* since addr member of struct bnd_addr use union,
	* the bnd port is not specified explicitly as a struct member.
	*/
};

struct socks5_userpwd {
	uint8_t ver;
	uint8_t ulen;
	char rest_bytes[];
};

struct gwp_args {
	struct userpwd_list userpwd_arr;
	/*
	* pointe to the buffer where content of auth file is stored
	* TODO:
	* only useful to store in this struct
	* if this program can perform graceful exit
	*/
	char *userpwd_buf;
	struct sockaddr_storage src_addr_st, dst_addr_st;
	size_t thread_nr;
	size_t timeout;
	bool socks5_mode;
};

extern char *optarg;
static const struct rlimit file_limits = {
	.rlim_cur = 100000,
	.rlim_max = 100000
};
static pthread_t *threads;
static const char opts[] = "hw:b:t:T:f:s";
static const char usage[] =
"usage: ./gwproxy [options]\n"
"-s\tenable socks5 mode\n"
"-f\tauthentication file for username/password method "
"(if not specified, no authentication is required)\n"
"-b\tIP address and port to be bound by the server\n"
"-t\tIP address and port of the target server (ignored in socks5 mode)\n"
"-T\tnumber of thread (default: %d)\n"
"-w\twait time for timeout, set to zero for no timeout (default: %d seconds)\n"
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
* @param args Pointer to application configuration to initialize.
* @return zero on success, or a negative integer on failure.
*/
static int handle_cmdline(int argc, char *argv[], struct gwp_args *args)
{
	char c,  *bind_opt, *target_opt, *thread_opt, *wait_opt, *auth_file_opt;
	int thread_nr, timeout;
	int ret;

	if (argc == 1) {
		pr_menu;

		return 0;
	}

	auth_file_opt = wait_opt = thread_opt = bind_opt = target_opt = NULL;
	args->socks5_mode = false;
	while ((c = getopt(argc, argv, opts)) != -1) {
		switch (c) {
		case 's':
			args->socks5_mode = true;
			break;
		case 'f':
			auth_file_opt = optarg;
			break;
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
			pr_menu;
			return 0;

		default:
			return -EINVAL;
		}
	}

	if (auth_file_opt) {
		ret = parse_auth_file(
			auth_file_opt,
			&args->userpwd_arr,
			&args->userpwd_buf
		);
		if (ret < 0)
			return -EXIT_FAILURE;
		if (!args->userpwd_arr.nr_entry)
			return -EINVAL;
	} else
		args->userpwd_arr.nr_entry = 0;

	if (!target_opt && !args->socks5_mode) {
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

	if (args->socks5_mode)
		return 0;

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

	client->sockfd = -1;
	target->sockfd = -1;

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
	client->off = 0;
	target->off = 0;

	client->epmask = EPOLLIN | EPOLLOUT;
	target->epmask = EPOLLIN | EPOLLOUT;

	return pc;
}

/*
* connect to the specified target.
*
* @param sockaddr Pointer to the sockaddr_storage structure.
* @return socket file descriptor on success or a negative integer on failure.
*/
static int set_target(struct sockaddr_storage *sockaddr)
{
	int ret, tsock;
	socklen_t size_addr;

	tsock = socket(sockaddr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (tsock < 0) {
		perror("socket");
		return -EXIT_FAILURE;
	}

	set_sockattr(tsock);
	size_addr = sockaddr->ss_family == AF_INET ? 
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	ret = connect(tsock, (struct sockaddr *)sockaddr, size_addr);
	if (ret < 0 && errno != EINPROGRESS) {
		perror("connect");
		return -EXIT_FAILURE;
	}

	return tsock;
}

/*
* Register events on socket file descriptor to the epoll's interest list.
*
* @param fd file descriptor to be registered.
* @param epfd epoll file descriptor.
* @param epmask epoll events.
* @param typemask used to identify the type of file descriptor.
* @param ptr a pointer to be saved and returned once particular events is ready.
*/
static int register_events(int fd, int epfd, uint32_t epmask,
				void *ptr, uint64_t typemask) {
	struct epoll_event ev;
	int ret;

	ev.events = epmask;
	ev.data.u64 = 0;
	ev.data.ptr = ptr;
	ev.data.u64 |= typemask;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
	if (ret < 0) {
		perror("epoll_ctl");
		return -EXIT_FAILURE;
	}

	return 0;
}

/*
* Handle incoming client.
*
* @param gwp Pointer to the gwproxy struct (thread data).
* @return zero on success, or a negative integer on failure.
*/
static void handle_incoming_client(struct gwproxy *gwp, struct gwp_args *args)
{
	int client_fd, ret;
	struct pair_connection *pc = init_pair();
	if (!pc)
		return;

	client_fd = -1;
	if (args->timeout) {
		int tmfd, flg;

		flg = TFD_NONBLOCK;
		tmfd = timerfd_create(CLOCK_MONOTONIC, flg);
		if (tmfd < 0) {
			perror("timerfd_create");
			goto exit_err;
		}
		pc->timerfd = tmfd;

		ret = register_events(tmfd, gwp->epfd, EPOLLIN, pc, EV_BIT_TIMER);
		if (ret < 0) {
			perror("epoll_ctl");
			goto exit_err;
		}
	}

	client_fd = accept4(gwp->listen_sock, NULL, NULL, SOCK_NONBLOCK);
	if (client_fd < 0) {
		ret = errno;
		perror("accept");
		if (ret != EINTR)
			goto exit_err;
	}
	set_sockattr(client_fd);
	pc->client.sockfd = client_fd;
	ret = register_events(client_fd, gwp->epfd, pc->client.epmask, pc, EV_BIT_CLIENT);
	if (ret < 0) {
		perror("epoll_ctl");
		goto exit_err;
	}

	if (args->socks5_mode)
		pc->state = STATE_ACCEPT_GREETING;
	else
		pc->state = NO_SOCKS5;

	return;
exit_err:
	free(pc->client.buf);
	free(pc->target.buf);
	if (pc->timerfd != -1)
		close(pc->timerfd);
	free(pc);
	if (client_fd != -1)
		close(client_fd);
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
			perror("recv on handle data");
			return -EXIT_FAILURE;
		} else if (!ret) {
			pr_debug(
				DEBUG_SEND_RECV,
				"EoF received on sockfd %d, "
				"closing the connection."
				" terminating the session.\n",
				from->sockfd
			);
			return -EXIT_FAILURE;
		}
		pr_debug(
			DEBUG_SEND_RECV,
			"%ld bytes were received from sockfd %d.\n",
			ret,
			from->sockfd
		);
		if (DEBUG_LVL == DEBUG_SEND_RECV)
			VT_HEXDUMP(&from->buf[from->len], ret);

		from->len += (size_t)ret;

		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"buffer filled with %ld bytes\n",
			from->len
		);
	}

try_send:
	pr_debug(DEBUG_EPOLL_EVENTS, "send to socket %d.\n", to->sockfd);
	/* length of filled buffer */
	if (from->len > 0) {
		ret = send(to->sockfd, &from->buf[from->off], from->len, MSG_NOSIGNAL);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN || ret == EINTR)
				return 0;
			perror("send on handle data");
			return -EXIT_FAILURE;
		} else if (!ret)
			return -EXIT_FAILURE;
		pr_debug(
			DEBUG_SEND_RECV,
			"%ld bytes were sent to sockfd %d.\n",
			ret, to->sockfd
		);

		from->len -= ret;
		from->off += ret;
		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"remaining bytes on the buffer: %ld\n",
			from->len
		);
		if (!from->len)
			from->off = 0;
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
* Handle exchange data.
*
* @param ev Pointer to epoll event.
* @param pc Pointer to pair_connection struct of current session.
* @param a Pointer to the connection (can be either client or target).
* @param b Pointer to the connection (can be either client or target).
* @param gwp Pointer to the gwproxy struct (thread data).
* @return zero on success, or a negative integer on failure.
*/
static int exchange_data(struct epoll_event *ev, struct pair_connection *pc,
			struct single_connection *a, struct single_connection *b,
			struct gwproxy *gwp)
{
	int ret;

	if (ev->events & EPOLLIN) {
		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"current epoll events have EPOLLIN bit set\n"
		);
		ret = handle_data(a, b);
		if (ret < 0)
			return -EXIT_FAILURE;
	}

	if (ev->events & EPOLLOUT) {
		pr_debug(
			DEBUG_EPOLL_EVENTS,
			"current epoll events have EPOLLOUT bit set\n"
		);

		ret = handle_data(b, a);
		if (ret < 0)
			return -EXIT_FAILURE;
	}

	adjust_events(gwp->epfd, pc);
	return 0;
}

/*
* Handshake with the client.
*
* @param pc Pointer to pair_connection struct of current session.
* @return zero on success, and a negative integer on failure.
*/
static int accept_greeting(struct pair_connection *pc, struct gwp_args *args)
{
	struct single_connection *a = &pc->client;
	struct socks5_greeting *g = (void *)a->buf;
	uint8_t *ptr;
	unsigned preferred_auth = NONE;
	int ret, i, rlen = DEFAULT_BUF_SZ - a->len;

	ret = recv(a->sockfd, &a->buf[a->len], rlen, 0);
	if (ret < 0) {
		if (errno == EAGAIN)
			return -EAGAIN;
		perror("recv on accept greeting");
		return -EXIT_FAILURE;
	}
	if (!ret) {
		pr_debug(
			VERBOSE,
			"sockfd %d closes the connection "
			"while accept greeting\n",
			a->sockfd
		);
		return -EXIT_FAILURE;
	}
	pr_debug(
		DEBUG_SEND_RECV,
		"%d bytes were received from sockfd %d.\n",
		ret,
		a->sockfd
	);
	if (DEBUG_LVL == DEBUG_SEND_RECV)
		VT_HEXDUMP(&a->buf[a->len], ret);
	a->len += ret;
	if (a->len < 2)
		return -EAGAIN;

	if (g->ver != SOCKS5_VER) {
		pr_debug(VERBOSE, "unsupported socks version.\n");
		return -EXIT_FAILURE;
	}
	
	if (g->nauth == 0) {
		pr_debug(VERBOSE, "invalid value in field nauth.\n");
		return -EXIT_FAILURE;
	}

	if (a->len - 2 < g->nauth)
		return -EAGAIN;

	ptr = &g->nauth + 1;
	for (i = 0; i < g->nauth; i++, ptr++) {
		switch (*ptr) {
		case NO_AUTH:
			if (args->userpwd_arr.nr_entry)
				continue;
			preferred_auth = NO_AUTH;
			goto auth_method_found;
		case USERNAME_PWD:
			preferred_auth = USERNAME_PWD;
			goto auth_method_found;
		}
	}

auth_method_found:
	pc->preferred_method = preferred_auth;
	a->len = 0;

	return 0;
}

/*
* Send a response to the client's greeting.
*
* @param pc Pointer to pair_connection struct of current session.
* @return zero on success, or a negative integer on failure.
*/
static int response_handshake(struct pair_connection *pc)
{
	struct single_connection *a = &pc->client;
	char server_choice[2];
	int ret;

	if (!a->len)
		a->len = sizeof(server_choice);
	server_choice[0] = SOCKS5_VER;
	server_choice[1] = pc->preferred_method;
	ret = send(
		a->sockfd,
		&server_choice[sizeof(server_choice) - a->len],
		a->len, 0
	);
	if (ret < 0) {
		if (errno == EAGAIN)
			return -EAGAIN;
		perror("send on response handshake");
		return -EXIT_FAILURE;
	}
	pr_debug(
		DEBUG_SEND_RECV,
		"%d bytes were sent to sockfd %d.\n",
		ret, a->sockfd
	);
	if (DEBUG_LVL == DEBUG_SEND_RECV)
		VT_HEXDUMP(&server_choice[sizeof(server_choice) - a->len], ret);

	a->len -= ret;
	if (a->len)
		return -EAGAIN;

	return 0;
}

/*
* Preparation before exchanging data.
*
* connecting to either the configured target supplied from cmdline args
* or the specified target by client in socks5 mode.
*
* @param gwp Pointer to the gwproxy struct (thread data).
* @param pc Pointer that need to be saved 
* @param dst the address structure to which the client connects.
* @param args Pointer to application configuration.
* @return zero on success, or a negative integer on failure.
*/
static int prepare_exchange(struct gwproxy *gwp, struct pair_connection *pc,
			struct sockaddr_storage *dst, struct gwp_args *args)
{
	int ret, tsock = set_target(dst);
	if (tsock < 0)
		return -EXIT_FAILURE;

	if (args->timeout) {
		const struct itimerspec it = {
			.it_value = {
				.tv_sec = args->timeout,
				.tv_nsec = 0
			},
			.it_interval = {
				.tv_sec = 0,
				.tv_nsec = 0
			}
		};
		ret = timerfd_settime(pc->timerfd, 0, &it, NULL);
		if (ret < 0) {
			perror("timerfd_settime");
			return -EXIT_FAILURE;
		}
	}

	pc->target.sockfd = tsock;
	ret = register_events(tsock, gwp->epfd, pc->target.epmask,
				pc, EV_BIT_TARGET);
	if (ret < 0) {
		perror("epoll_ctl");
		return -EXIT_FAILURE;
	}

	return 0;
}

/*
* Construct the reply message for each command of client's request.
*
* @param reply_buf Pointer to the buffer.
* @param d Pointer to be filled with bounded address to which the target is bound.
* @param sockfd network socket file descriptor of target.
* @return length of address field.
*/
static size_t craft_reply(struct socks5_connect_reply *reply_buf,
			struct sockaddr_storage *d, int sockfd)
{
	struct sockaddr_in *in;
	struct sockaddr_in6 *in6;
	struct socks5_addr *s;
	size_t bnd_len, reply_len;
	uint8_t ipv4_sz, ipv6_sz;
	socklen_t d_sz;

	s 	= &reply_buf->bnd_addr;
	ipv4_sz = sizeof(struct in_addr);
	ipv6_sz = sizeof(struct in6_addr);
	d_sz 	= sizeof(*d);
	in6	= (struct sockaddr_in6 *)d;
	in	= (struct sockaddr_in *)d;

	getsockname(sockfd, (struct sockaddr *)d, &d_sz);
	switch (d->ss_family) {
	case AF_INET:
		bnd_len = ipv4_sz;
		s->type = IPv4;
		memcpy(&s->addr.ipv4, &in->sin_addr, ipv4_sz);
		*(uint16_t *)((char *)&s->addr.ipv4 + ipv4_sz) = in->sin_port;
		break;
	case AF_INET6:
		bnd_len = ipv6_sz;
		s->type = IPv6;
		memcpy(&s->addr.ipv6, &in6->sin6_addr, ipv6_sz);
		*(uint16_t *)((char *)&s->addr.ipv6 + ipv6_sz) = in6->sin6_port;
		break;
	}
	/*
	* TODO: as per RFC, the bnd.addr is allowed to be filled with FQDN
	* however, I'm not sure in which scenario,
	* that the server would fill bnd.addr of the reply with FQDN?
	* is this common and practical cases?
	*/

	reply_buf->ver = SOCKS5_VER;
	reply_buf->status = 0x0;
	reply_buf->rsv = 0x0;

	reply_len = sizeof(*reply_buf) - sizeof(s->addr) + PORT_SZ;
	reply_len += bnd_len;
	return reply_len;
}

/*
* Read and evaluate client's request.
*
* @param a Pointer to the client's information.
* @param d Pointer of sockaddr to initialize.
* @return zero on success, or a negative integer on failure.
*/
static int parse_request(struct single_connection *a, struct sockaddr_storage *d)
{
	struct socks5_connect_request *c;
	struct sockaddr_in *in;
	struct sockaddr_in6 *in6;
	struct socks5_addr *s;
	uint8_t ipv4_sz, ipv6_sz, domainlen_sz, domainname_sz;
	size_t expected_len, fixed_len;

	c = (void *)a->buf;
	s = &c->dst_addr;
	ipv4_sz = sizeof(struct in_addr);
	ipv6_sz = sizeof(struct in6_addr);
	fixed_len = sizeof(*c) - sizeof(s->addr) + PORT_SZ;
	domainlen_sz = sizeof(s->addr.domain.len);
	domainname_sz = s->addr.domain.len;
	memset(d, 0, sizeof(*d));

	switch (s->type) {
	case IPv4:
		expected_len = fixed_len + ipv4_sz;
		if (a->len < expected_len)
			return -EAGAIN;

		in = (struct sockaddr_in *)d;
		in->sin_family = AF_INET;
		in->sin_port = *(uint16_t *)((char *)&s->addr.ipv4 + ipv4_sz);
		memcpy(&in->sin_addr, &s->addr.ipv4, ipv4_sz);

		break;
	case DOMAIN:
		expected_len = fixed_len + domainlen_sz + domainname_sz;
		if (a->len < expected_len)
			return -EAGAIN;
		/* TODO: resolve domain name */
		break;
	case IPv6:
		expected_len = fixed_len + ipv6_sz;
		if (a->len < expected_len)
			return -EAGAIN;

		in6 = (struct sockaddr_in6 *)d;
		in6->sin6_family = AF_INET6;
		in6->sin6_port = *(uint16_t *)((char *)&s->addr.ipv6 + ipv6_sz);
		memcpy(&in6->sin6_addr, &s->addr.ipv6, ipv6_sz);
		break;

	default:
		pr_debug(VERBOSE, "unknown address type.\n");
		return -EXIT_FAILURE;
	}

	return 0;
}

/*
* Handle client's CONNECT command.
* 
* @param pc Pointer to pair_connection struct of current session.
* @param gwp Pointer to the gwproxy struct (thread data).
* @param args Pointer to application configuration.
* @param d Pointer to initialized target address.
* @return zero on success, or a negative integer on failure.
*/
static int handle_connect(struct pair_connection *pc, struct gwproxy *gwp,
			struct gwp_args *args, struct sockaddr_storage *d)
{
	/* filled with target address to which the client connect. */
	struct single_connection *a = &pc->client;
	struct socks5_connect_reply reply_buf;
	int ret;
	size_t reply_len;

	/*
	* TODO:
	* check if the connection is successfuly established
	* or fail before sending a reply
	*/
	if (pc->target.sockfd == -1) {
		ret = prepare_exchange(gwp, pc, d, args);
		if (ret < 0)
			return -EXIT_FAILURE;
	}

	reply_len = craft_reply(&reply_buf, d, pc->target.sockfd);
	if (!a->off)
		a->off = reply_len;
	ret = send(
		a->sockfd,
		((char *)(&reply_buf)) + (reply_len - a->off),
		a->off, 0
	);
	if (ret < 0) {
		if (errno == EAGAIN)
			return -EAGAIN;
		perror("send on request connect");
		return -EXIT_FAILURE;
	}
	pr_debug(
		DEBUG_SEND_RECV,
		"%d bytes were sent to sockfd %d.\n",
		ret, a->sockfd
	);
	if (DEBUG_LVL == DEBUG_SEND_RECV)
		VT_HEXDUMP(((char *)(&reply_buf)) + (reply_len - a->off), ret);

	a->off -= ret;
	if (a->off)
		return -EAGAIN;
	a->len = 0;

	return 0;
}

/*
* Handle client's BIND command.
* 
*/
__attribute__((__unused__))
static int handle_bind()
{
	return 0;
}

/*
* Handle client's UDP ASSOCIATE command.
* 
*/
__attribute__((__unused__))
static int handle_udp(void)
{
	return 0;
}

/*
* Read user/password auth data.
*
* @param pc Pointer to pair_connection struct of current session.
* @param args Pointer to application configuration.
* @return zero on success, or a negative integer on failure.
*/
static int req_userpwd(struct pair_connection *pc, struct gwp_args *args)
{
	struct single_connection *c = &pc->client;
	struct socks5_userpwd *pkt = (void *)c->buf;
	struct userpwd_pair *p;
	char *username, *password;
	uint8_t *plen;
	size_t expected_len = 2;
	int rlen, i, ret;

	rlen = MAX_USERPWD_PKT - c->len;
	ret = recv(c->sockfd, &c->buf[c->len], rlen, 0);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return -ret;
		perror("recv on handle userpwd");
		return -EXIT_FAILURE;
	}
	if (!ret) {
		pr_debug(
			VERBOSE,
			"sockfd %d closes the connection "
			"while handle usr/pwd auth\n",
			c->sockfd
		);
		return -EXIT_FAILURE;
	}
	pr_debug(
		DEBUG_SEND_RECV,
		"%d bytes were received from sockfd %d.\n",
		ret,
		c->sockfd
	);
	if (DEBUG_LVL == DEBUG_SEND_RECV)
		VT_HEXDUMP(&c->buf[c->len], ret);

	c->len += ret;

	if (c->len < expected_len)
		return -EAGAIN;

	if (pkt->ver != 1) {
		pr_debug(
			VERBOSE,
			"invalid version, not comply with the RFC standard.\n"
		);
		return -EXIT_FAILURE;
	}

	expected_len += pkt->ulen + 1;
	if (c->len < expected_len)
		return -EAGAIN;
	
	username = pkt->rest_bytes;
	plen = (void *)&pkt->rest_bytes[pkt->ulen];

	expected_len += *plen;
	if (c->len < expected_len)
		return -EAGAIN;
	c->len = 0;

	password = (void *)(plen + 1);

	pc->is_authenticated = 0x1;
	for (i = 0; i < args->userpwd_arr.nr_entry; i++) {
		p = &args->userpwd_arr.arr[i];
		ret = memcmp(username, p->username, pkt->ulen);
		if (ret)
			continue;

		ret = memcmp(password, p->password, *plen);
		if (ret)
			continue;

		pc->is_authenticated = 0x0;
		break;
	}

	pc->state |= STATE_SEND;

	return 0;
}

/*
* Reply user/password auth sub-negotiation.
*
* @param c Pointer to client data
* @param reply_buf Pointer to the buffer.
* @return zero on success, or a negative integer on failure.
*/
static int rep_userpwd(struct single_connection *c, char *reply_buf)
{
	int ret;

	if (!c->len)
		c->len = REPLY_LEN;
	ret = send(c->sockfd, &reply_buf[REPLY_LEN - c->len], c->len, 0);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return -ret;
		perror("send on handle userpwd");
		return -EXIT_FAILURE;
	}
	pr_debug(
		DEBUG_SEND_RECV,
		"%d bytes were sent to sockfd %d.\n",
		ret, c->sockfd
	);
	if (DEBUG_LVL == DEBUG_SEND_RECV)
		VT_HEXDUMP(&reply_buf[REPLY_LEN - c->len], ret);

	c->len -= ret;
	if (c->len)
		return -EAGAIN;

	return 0;
}

/*
* Handle sub-negotiation with username/password auth method.
*
* @param pc Pointer to pair_connection struct of current session.
* @param args Pointer to application configuration.
* @return zero on success, or a negative integer on failure.
*/
static int handle_userpwd(struct pair_connection *pc, struct gwp_args *args)
{
	char reply_buf[2];
	int ret;

	if (!(pc->state & STATE_SEND)) {
		ret = req_userpwd(pc, args);
		if (ret < 0)
			return ret;
	}

	if ((pc->state & STATE_SEND)) {
		reply_buf[0] = 0x1;
		reply_buf[1] = pc->is_authenticated;
		ret = rep_userpwd(&pc->client, reply_buf);
		if (ret < 0)
			return ret;

		if (reply_buf[1] == 0x1)
			return -EXIT_FAILURE;
	}

	return 0;
}

/*
* Handle client's request, evaluate it and return a reply.
*
* @param pc Pointer to pair_connection struct of current session.
* @param gwp Pointer to the gwproxy struct (thread data).
* @param args Pointer to application configuration.
* @return zero on success, or a negative integer on failure.
*/
static int handle_request(struct pair_connection *pc,
			struct gwproxy *gwp, struct gwp_args *args)
{
	/* filled with target address to which the client connect. */
	struct sockaddr_storage d;
	struct single_connection *a = &pc->client;
	struct socks5_connect_request *c = (void *)a->buf;
	int ret, rlen = DEFAULT_BUF_SZ - a->len;
	size_t fixed_len;

	if (!(pc->state & STATE_SEND)) {
		ret = recv(a->sockfd, &a->buf[a->len], rlen, 0);
		if (ret < 0) {
			if (errno == EAGAIN)
				return -EAGAIN;
			perror("recv on handle request");
			return -EXIT_FAILURE;
		}
		if (!ret) {
			pr_debug(
				VERBOSE,
				"sockfd %d closes the connection "
				"while handle request\n",
				a->sockfd
			);
			return -EXIT_FAILURE;
		}
		pr_debug(
			DEBUG_SEND_RECV,
			"%d bytes were received from sockfd %d.\n",
			ret,
			a->sockfd
		);
		if (DEBUG_LVL == DEBUG_SEND_RECV)
			VT_HEXDUMP(&a->buf[a->len], ret);

		a->len += ret;
		fixed_len = sizeof(*c) - sizeof(c->dst_addr.addr) + PORT_SZ;
		if (a->len < fixed_len)
			return -EAGAIN;

		ret = parse_request(a, &d);
		if (ret < 0) {
			if (errno == EAGAIN)
				return -EAGAIN;
			return -EXIT_FAILURE;
		}

		pc->state |= STATE_SEND;
	}

	if (pc->state & STATE_SEND) {
		if (c->ver != SOCKS5_VER) {
			pr_debug(VERBOSE, "unsupported socks version.\n");
			return -EXIT_FAILURE;
		}

		if (c->cmd != CONNECT) {
			pr_debug(VERBOSE, "unsupported command, yet.\n");
			return -EXIT_FAILURE;
		}

		ret = handle_connect(pc, gwp, args, &d);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/*
* is the state of the socket connected?
*
* @param sockfd the socket file descriptor.
* @return true on connected, otherwise false.
*/
static bool is_sock_connected(int sockfd)
{
	int err;
	socklen_t len = sizeof(err);
	getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &len);

	return err == 0;
}

/*
* Process epoll event from tcp connection.
*
* currently, this function handle:
* - connection established from EINPROGRESS (EPOLLOUT).
* - socket that ready to read or write (EPOLLIN or EPOLLOUT).
*   * communication on simple TCP proxy with pre-defined target.
*   * communication on socks5 protocol.
*
* @param ev Pointer to epoll event structure.
* @param gwp Pointer to the gwproxy struct (thread data).
* @param args Pointer to application configuration.
* @return zero on success, or a negative integer on failure.
*/
static int process_tcp(struct epoll_event *ev, struct gwproxy *gwp,
			struct gwp_args *args)
{
	int ret;
	struct pair_connection *pc;
	struct single_connection *a, *b;

	ret = extract_data(ev, &pc, &a, &b);
	if (ret < 0)
		goto exit_err;

	if (!pc->is_connected && pc->target.sockfd != -1) {
		ret = is_sock_connected(pc->target.sockfd);
		if (ret && pc->timerfd != -1) {
			close(pc->timerfd);
			pc->timerfd = -1;
			pc->is_connected = true;
		}
	}

	if (pc->state == NO_SOCKS5) {
		ret = prepare_exchange(gwp, pc, &args->dst_addr_st, args);
		if (ret < 0)
			goto exit_err;

		pc->state = STATE_EXCHANGE;
	} else if (pc->state & STATE_ACCEPT_GREETING) {
		ret = accept_greeting(pc, args);
		if (ret < 0) {
			if (ret == -EAGAIN)
				return EAGAIN;
			goto exit_err;
		}

		pc->state = STATE_GREETING_ACCEPTED;
	}

	if (pc->state & STATE_GREETING_ACCEPTED) {
		ret = response_handshake(pc);
		if (ret < 0) {
			if (ret == -EAGAIN)
				return EAGAIN;
			goto exit_err;
		}

		if (pc->preferred_method == NO_AUTH)
			pc->state = STATE_REQUEST;
		else
			pc->state = STATE_AUTH;
	}

	if (pc->state & STATE_AUTH) {
		ret = handle_userpwd(pc, args);
		if (ret < 0) {
			if (ret == -EAGAIN)
				return EAGAIN;
			goto exit_err;
		}

		pc->state = STATE_REQUEST;
	}

	if (pc->state & STATE_REQUEST) {
		ret = handle_request(pc, gwp, args);
		if (ret < 0) {
			if (ret == -EAGAIN)
				return EAGAIN;
			goto exit_err;
		}

		pc->state = STATE_EXCHANGE;
	}

	if (pc->state & STATE_EXCHANGE) {
		ret = exchange_data(ev, pc, a, b, gwp);
		if (ret < 0)
			goto exit_err;
	}

	return 0;
exit_err:
	pr_debug(VERBOSE, "free the system resources for this session\n");
	if (pc->timerfd != -1)
		close(pc->timerfd);
	if (a->sockfd != -1)
		close(a->sockfd);
	if (b->sockfd != -1)
		close(b->sockfd);
	free(pc->client.buf);
	free(pc->target.buf);
	free(pc);
	return -EXIT_FAILURE;
}

/*
* Process epoll event that are 'ready'.
*
* @param ready_nr Number of ready events.
* @param args Pointer to application configuration.
* @param evs Pointer to epoll event struct.
* @param gwp Pointer to the gwproxy struct (thread data).
*/
static void process_ready_list(int ready_nr, struct gwp_args *args,
				struct epoll_event *evs, struct gwproxy *gwp)
{
	int i;
	pr_debug(VERBOSE, "number of epoll events %d\n", ready_nr);

	for (i = 0; i < ready_nr; i++) {
		struct epoll_event *ev = &evs[i];

		if (ev->data.fd == gwp->listen_sock) {
			pr_debug(VERBOSE, "serving new client\n");
			handle_incoming_client(gwp, args);
		} else
			if (process_tcp(ev, gwp, args) < 0)
				return;
	}

	return;
}

/*
* Start the TCP proxy server.
* 
* @param args Pointer to application configuration.
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
	if (gwp.listen_sock < 0) {
		perror("socket");
		return -EXIT_FAILURE;
	}
	gwp.epfd = -1;

	setsockopt(gwp.listen_sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(gwp.listen_sock, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));

	ret = bind(gwp.listen_sock, (struct sockaddr *)s, size_addr);
	if (ret < 0) {
		perror("bind");
		goto err;
	}

	ret = listen(gwp.listen_sock, 10);
	if (ret < 0) {
		perror("listen");
		goto err;
	}

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
* @param args Pointer to application configuration.
* @return NULL
*/
static void *thread_cb(void *args)
{
	int ret = start_server(args);

	return (void *)(intptr_t)ret;
}

int main(int argc, char *argv[])
{
	int ret;
	size_t i;
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
