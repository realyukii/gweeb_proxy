#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/inotify.h>
#include <sys/eventfd.h>
#include <signal.h>
#include <assert.h>
#include "linux.h"
#include "general.h"

#define REPLY_LEN 2
#define PORT_SZ 2
#define SOCKS5_VER 5
#define MAX_DOMAIN_LEN 255
#define MAX_FILEPATH 1024
#define MAX_USERPWD_PKT (1 + 1 + 255 + 1 + 255)
#define DEFAULT_TIMEOUT 5
#define DEFAULT_CLIENT 100
#define DEFAULT_THREAD_NR 4
#define DEFAULT_BUF_SZ	1024
#define NR_EVENTS 512
#define pr_menu printf(usage, DEFAULT_THREAD_NR, DEFAULT_TIMEOUT, DEFAULT_CLIENT)

enum evmask {
	/* indicate a client file descriptor */
	EV_BIT_CLIENT		= (0x0001ULL << 48ULL),
	/* indicate a target file descriptor */
	EV_BIT_TARGET		= (0x0002ULL << 48ULL),
	/* indicate a timer file descriptor */
	EV_BIT_TIMER		= (0x0003ULL << 48ULL),
	/* indicate dns request is completed */
	EV_BIT_DNS_RESOLVED	= (0x0004ULL << 48ULL)
};

enum gwp_state {
	/* not in socks5 mode */
	NO_SOCKS5		= 0x0,
	/* hello packet from client */
	STATE_GREETING		= 0x1,
	/* negotiating authentication method */
	STATE_AUTH		= 0x2,
	/* client request. */
	STATE_REQUEST		= 0x4,
	/* exchange the data between client and destination */
	STATE_EXCHANGE		= 0x8,
	/* dns query request is completed */
	STATE_DNS_RESOLV	= 0x16
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

#define ALL_EV_BIT	(EV_BIT_CLIENT | EV_BIT_TARGET | EV_BIT_TIMER | EV_BIT_DNS_RESOLVED)
#define GET_EV_BIT(X)	((X) & ALL_EV_BIT)
#define CLEAR_EV_BIT(X)	((X) & ~ALL_EV_BIT)

struct dns_req {
	char domainname[MAX_DOMAIN_LEN];
	int finishfd;
	struct sockaddr_in6 in;
	struct pair_conn *pc;
	struct dns_req *next;
};

struct dns_queue {
	struct dns_req *head;
	struct dns_req *tail;
};

struct gwp_conn {
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
	/* human-readable network address and port */
	char addrstr[ADDRSTR_SZ];
};

struct pair_conn {
	/* id of current session in the connection pool */
	unsigned int idx;
	/* represent client connection */
	struct gwp_conn client;
	/* represent target connection */
	struct gwp_conn target;
	/* timer file descriptor for setting timeout */
	int timerfd;
	/* connection state of target */
	bool is_connected;
	/* state of the established session */
	uint16_t state;
	/* the following is used on socks5 mode */
	enum auth_type preferred_method;
	/* username/pwd auth state */
	bool is_authenticated;
	/* used to track ownership of the client pointer */
	atomic_int refcnt;
	/* hold the processed request */
	struct dns_req *r;
};

struct connection_pool {
	/* number of active connection */
	unsigned nr_item;
	/* max number of allocated connection */
	unsigned max_item;
	/* array of pointer to established session */
	struct pair_conn **arr;
};

/*
* thread-specific data
*/
struct gwp_tctx {
	/* TCP socket file descriptor */
	int listen_sock;
	/* epoll file descriptor */
	int epfd;
	/* array of active connection */
	struct connection_pool p;
	struct gwp_ctx *pctx;
	pthread_t thandle;
};

struct commandline_args {
	bool socks5_mode;
	char *auth_file;
	int client_nr;
	size_t server_thread_nr;
	size_t timeout;
	/* local address to be bound */
	struct sockaddr_storage src_addr_st;
	/* only used on simple TCP proxy mode */
	struct sockaddr_storage dst_addr_st;
};

struct auth_creds {
	int authfd;
	int ifd;
	int epfd;
	pthread_rwlock_t creds_lock;
	struct userpwd_list userpwd_l;
	char *userpwd_buf;
	char *prev_userpwd_buf;
};

/*
* application-specific data
*/
struct gwp_ctx {
	struct commandline_args cargs;
	struct gwp_tctx *tctx_pool;
	struct auth_creds creds;
	struct dns_queue q;
	pthread_cond_t dns_cond;
	pthread_mutex_t dns_lock;
	int stopfd;
	volatile bool stop;
};

struct socks5_greeting {
	uint8_t ver;
	uint8_t nauth;
	uint8_t methods[255];
};

struct socks5_addr {
	/* see the available type in enum addr_type */
	uint8_t type;
	union {
		uint8_t ipv4[4];
		struct {
			uint8_t len;
			char name[MAX_DOMAIN_LEN];
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

extern char *optarg;

/* only accessed by the signal handler */
static struct gwp_ctx *gctx;
static const char opts[] = "hw:b:t:T:f:sn:";
static const char usage[] =
"usage: ./gwproxy [options]\n"
"-s\tenable socks5 mode\n"
"-f\tauthentication file for username/password method "
"(if not specified, no authentication is required)\n"
"-b\tIP address and port to be bound by the server\n"
"-t\tIP address and port of the target server (ignored in socks5 mode)\n"
"-T\tnumber of thread (default: %d)\n"
"-w\twait time for timeout, set to zero for no timeout (default: %d seconds)\n"
"-n\tnumber of client session to create pre-allocated pointer per-thread "
"(default: %d client)\n"
"-h\tShow this help message and exit\n";

/*
* Handle command-line arguments and initialize gwp_ctx.
*
* The function initialize the following configuration:
* - wait time out in seconds
* - server address to be bound
* - target address to connect (in conventional tcp proxy mode)
* - auth file (in socks5 proxy mode)
* - control thread number
*
* @param argc total argument passed.
* @param argv Pointer to an array of string.
* @param a Pointer to cmdline arguments to initialize.
* @return zero on success, or a negative integer on failure.
*/
static int handle_cmdline(int argc, char *argv[], struct commandline_args *a)
{
	char c,  *bind_opt, *target_opt, *server_thread_opt, *client_nr_opt,
	*wait_opt, *auth_file_opt;
	int server_thread_nr, client_nr, timeout;
	int ret;

	if (argc == 1) {
		pr_menu;

		return -1;
	}

	a->socks5_mode = false;
	a->auth_file = NULL;
	memset(&a->src_addr_st, 0, sizeof(a->src_addr_st));

	auth_file_opt = wait_opt = server_thread_opt = bind_opt = target_opt =
	client_nr_opt = NULL;
	while ((c = getopt(argc, argv, opts)) != -1) {
		switch (c) {
		case 's':
			a->socks5_mode = true;
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
			server_thread_opt = optarg;
			break;
		case 'w':
			wait_opt = optarg;
			break;
		case 'n':
			client_nr_opt = optarg;
			break;
		case 'h':
			pr_menu;
			return -1;

		default:
			return -EINVAL;
		}
	}

	if (!target_opt && !a->socks5_mode) {
		pr_err("-t option is required\n");
		return -EINVAL;
	}

	if (!bind_opt) {
		pr_err("-b option is required\n");
		return -EINVAL;
	}

	if (auth_file_opt)
		a->auth_file = auth_file_opt;

	if (client_nr_opt) {
		client_nr = atoi(client_nr_opt);
		if (client_nr <= 0)
			client_nr = DEFAULT_CLIENT;
	} else
		client_nr = DEFAULT_CLIENT;

	a->client_nr = client_nr;

	if (server_thread_opt) {
		server_thread_nr = atoi(server_thread_opt);
		if (server_thread_nr <= 0)
			server_thread_nr = DEFAULT_THREAD_NR;
	} else
		server_thread_nr = DEFAULT_THREAD_NR;

	a->server_thread_nr = server_thread_nr;

	if (wait_opt) {
		timeout = atoi(wait_opt);
		if (timeout < 0)
			timeout = DEFAULT_TIMEOUT;
	} else
		timeout = DEFAULT_TIMEOUT;

	a->timeout = timeout;

	ret = init_addr(bind_opt, &a->src_addr_st);
	if (ret < 0) {
		pr_err("invalid format for %s\n", bind_opt);
		return -EINVAL;
	}

	if (a->socks5_mode)
		return 0;

	ret = init_addr(target_opt, &a->dst_addr_st);
	if (ret < 0) {
		pr_err("invalid format for %s\n", target_opt);
		return -EINVAL;
	}

	return 0;
}

/*
* Register events on socket file descriptor to the epoll's interest list.
*
* @param fd file descriptor to be registered.
* @param epfd epoll file descriptor.
* @param epmask epoll events.
* @param ptr a pointer to be saved and returned once particular events is ready.
* @param evmask used to identify the epoll event.
*/
static int register_events(int fd, int epfd, uint32_t epmask,
				void *ptr, uint64_t evmask) {
	struct epoll_event ev;
	int ret;

	ev.events = epmask;
	ev.data.u64 = 0;
	ev.data.ptr = ptr;
	ev.data.u64 |= evmask;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
	if (ret < 0) {
		pr_err(
			"failed to register event to epoll: %s\n",
			strerror(errno)
		);
		return -EXIT_FAILURE;
	}

	return 0;
}

static struct dns_req *init_req(struct gwp_tctx *ctx, struct pair_conn *pc,
				char *domainname, uint8_t domainname_sz)
{
	struct dns_req *r = malloc(sizeof(*r));
	if (!r) {
		pr_err("insufficient memory to allocate new dns query req\n");
		return NULL;
	}

	r->pc = pc;
	r->in.sin6_family = AF_UNSPEC;
	r->in.sin6_port = *(uint16_t *)(domainname + domainname_sz);
	r->finishfd = eventfd(0, EFD_NONBLOCK);
	if (r->finishfd < 0) {
		pr_err(
			"failed to create event file descriptor: %s\n",
			strerror(errno)
		);

		free(r);
		return NULL;
	}
	register_events(r->finishfd, ctx->epfd, EPOLLIN, pc, EV_BIT_DNS_RESOLVED);
	memcpy(r->domainname, domainname, domainname_sz);
	r->domainname[domainname_sz] = '\0';

	return r;
}

static void enqueue_dns(struct dns_queue *q, struct dns_req *r)
{
	if (q->head) {
		q->tail->next = r;
		q->tail = r;
	} else
		q->head = q->tail = r;
}

static void dequeue_dns(struct dns_queue *q)
{
	struct dns_req *r = q->head;

	if (!r)
		return;

	q->head = q->head->next;
	if (!q->head)
		q->tail = NULL;
}

static bool put_pc(struct pair_conn *pc)
{
	int x = atomic_fetch_sub(&pc->refcnt, 1);

	assert(x >= 1);
	if (x == 1) {
		assert(pc->refcnt == 0);
		free(pc);
		return true;
	}

	return false;
}

/*
* Set socket attribute
*
* @param sock network socket file descriptor.
*/
static void set_sockattr(int sock)
{
	static const int val = 1;

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val));
	setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &val, sizeof(val));
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
}

static int realloc_pool(struct connection_pool *cp)
{
	int expand_sz = cp->max_item * 2;
	void *ptr = realloc(cp->arr, expand_sz * sizeof(cp->arr));
	if (!ptr)
		return -ENOMEM;

	cp->arr = ptr;
	memset(&cp->arr[cp->max_item], 0, cp->max_item * sizeof(cp->arr));
	cp->max_item = expand_sz;

	return 0;
}

/*
* Initialize a pair of connection: client:target.
*
* @param gwp Pointer to the gwp_tctx struct (thread data).
* @return pointer to the malloc'd address
*/
static struct pair_conn *init_pair(struct gwp_tctx *gwp)
{
	unsigned int idx;
	struct pair_conn *pc;
	struct gwp_conn *client;
	struct gwp_conn *target;

	gwp->p.nr_item++;
	if (gwp->p.nr_item > gwp->p.max_item) {
		if (realloc_pool(&gwp->p) < 0)
			return NULL;
	}

	pc = malloc(sizeof(*pc));
	if (!pc)
		return NULL;
	pc->timerfd = -1;
	pc->is_connected = false;

	client = &pc->client;
	target = &pc->target;

	client->sockfd = -1;
	target->sockfd = -1;

	client->buf = malloc(DEFAULT_BUF_SZ);
	if (!client->buf) {
		gwp->p.nr_item--;
		free(pc);
		return NULL;
	}

	target->buf = malloc(DEFAULT_BUF_SZ);
	if (!target->buf) {
		gwp->p.nr_item--;
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

	idx = gwp->p.nr_item - 1;
	gwp->p.arr[idx] = pc;
	pc->idx = idx;

	atomic_init(&pc->refcnt, 1);

	return pc;
}

/*
* connect to the specified target.
*
* @param sockaddr Pointer to the sockaddr_storage structure.
* @return socket file descriptor on success or a negative integer on failure.
*/
static int set_target(struct gwp_conn *tc, struct sockaddr_storage *sockaddr)
{
	int ret, tsock;
	socklen_t size_addr;

	tsock = socket(sockaddr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (tsock < 0) {
		pr_err("failed to create target socket: %s\n", strerror(errno));
		return -EXIT_FAILURE;
	}

	set_sockattr(tsock);
	size_addr = sockaddr->ss_family == AF_INET ? 
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	get_addrstr((struct sockaddr *)sockaddr, tc->addrstr);
	pr_info("attempting to connect to %s\n", tc->addrstr);
	ret = connect(tsock, (struct sockaddr *)sockaddr, size_addr);
	if (ret < 0 && errno != EINPROGRESS) {
		pr_err(
			"failed to connect to address %s: %s\n",
			tc->addrstr, strerror(errno)
		);
		return -EXIT_FAILURE;
	}

	return tsock;
}

/*
* Handle or serve incoming client.
*
* @param gwp Pointer to the gwp_tctx struct (thread data).
* @return zero on success, or a negative integer on failure.
*/
static void handle_incoming_client(struct gwp_tctx *tctx)
{
	int client_fd, ret;
	struct sockaddr_in6 addr;
	socklen_t addrlen;
	struct pair_conn *pc = init_pair(tctx);
	if (!pc)
		return;

	client_fd = -1;
	if (tctx->pctx->cargs.timeout) {
		int tmfd, flg;

		flg = TFD_NONBLOCK;
		tmfd = timerfd_create(CLOCK_MONOTONIC, flg);
		if (tmfd < 0) {
			pr_err(
				"failed to create timer file descriptor: %s\n",
				strerror(errno)
			);
			goto exit_err;
		}
		pc->timerfd = tmfd;

		ret = register_events(
			tmfd, tctx->epfd,
			EPOLLIN, pc, EV_BIT_TIMER
		);
		if (ret < 0)
			goto exit_err;
	}

	addrlen = sizeof(addr);
	client_fd = accept4(tctx->listen_sock, &addr, &addrlen, SOCK_NONBLOCK);
	if (client_fd < 0) {
		ret = errno;
		if (ret != EINTR)
			goto exit_err;
		pr_err(
			"failed to accept incoming client: %s\n",
			strerror(ret)
		);
	}
	get_addrstr((struct sockaddr *)&addr, pc->client.addrstr);
	pr_info(
		"new client %s accepted on socket %d\n",
		pc->client.addrstr, client_fd
	);
	set_sockattr(client_fd);
	pc->client.sockfd = client_fd;
	ret = register_events(
		client_fd, tctx->epfd,
		pc->client.epmask, pc, EV_BIT_CLIENT
	);
	if (ret < 0)
		goto exit_err;

	if (tctx->pctx->cargs.socks5_mode)
		pc->state = STATE_GREETING;
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
static int handle_data(struct gwp_conn *from,
			struct gwp_conn *to)
{
	ssize_t ret;
	size_t rlen;

	/* length of empty buffer */
	rlen = DEFAULT_BUF_SZ - from->len;
	pr_info(
		"receive from socket %d "
		"with buffer that have free space of %ld bytes\n",
		from->sockfd, rlen
	);
	if (rlen > 0) {
		ret = recv(
			from->sockfd, &from->buf[from->len],
			rlen, MSG_NOSIGNAL
		);
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
			pr_err(
				"failed to recv from %s: %s\n",
				from->addrstr, strerror(ret)
			);
			return -EXIT_FAILURE;
		} else if (!ret) {
			pr_info(
				"EoF received on sockfd %d, "
				"closing the connection."
				" terminating the session.\n",
				from->sockfd
			);
			return -EXIT_FAILURE;
		}
		pr_dbg(
			"%ld bytes were received from sockfd %d.\n",
			ret,
			from->sockfd
		);
		VT_HEXDUMP(&from->buf[from->len], ret);

		from->len += (size_t)ret;

		pr_info(
			"buffer on socket %d filled with %ld bytes\n",
			from->sockfd, from->len
		);
	}

try_send:
	pr_info("send to socket %d.\n", to->sockfd);
	/* length of filled buffer */
	if (from->len > 0) {
		ret = send(
			to->sockfd, &from->buf[from->off],
			from->len, MSG_NOSIGNAL
		);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN || ret == EINTR)
				return 0;
			pr_err(
				"failed to send to %s: %s\n",
				to->addrstr, strerror(ret)
			);
			return -EXIT_FAILURE;
		} else if (!ret)
			return -EXIT_FAILURE;
		pr_dbg(
			"%ld bytes were sent to sockfd %d.\n",
			ret, to->sockfd
		);

		from->len -= ret;
		from->off += ret;
		pr_info(
			"remaining bytes on the buffer: %ld\n",
			from->len
		);
		if (!from->len)
			from->off = 0;
	}

	return 0;
}

/*
* Set EPOLLOUT bit for SOCKS5 mode only.
*
* @param a Pointer to struct client.
* @param epmask_changed Pointer to boolean.
*/
static void adjust_single_pollout(struct gwp_conn *a,
					bool *epmask_changed)
{
	if (a->len > 0) {
		if (!(a->epmask & EPOLLOUT)) {
			a->epmask |= EPOLLOUT;
			*epmask_changed = true;
		}
	} else {
		if (a->epmask & EPOLLOUT) {
			a->epmask &= ~EPOLLOUT;
			*epmask_changed = true;
		}
	}
}

/*
* Set EPOLLOUT bit on epmask member of dst.
*
* @param src Pointer to struct gwp_conn.
* @param dst Pointer to struct gwp_conn.
* @param epmask_changed Pointer to boolean.
*/
static void adjust_pollout(struct gwp_conn *src,
			struct gwp_conn *dst, bool *epmask_changed)
{
	/*
	* set EPOLLOUT to epmask when there's remaining bytes in the buffer
	* waiting to be sent, otherwise, unset it.
	*
	* indonesian version:
	* kalau di src masih ada buffer yang belum dikirim, segera kirim ke-
	* dst
	*/
	if (src->len > 0) {
		pr_info(
			"set EPOLLOUT: there is still buffer remaining "
			"in socket %d, need to drain it by sending it "
			"to the socket %d\n",
			src->sockfd, dst->sockfd
		);

		if (!(dst->epmask & EPOLLOUT)) {
			dst->epmask |= EPOLLOUT;
			*epmask_changed = true;
		}
	} else {
		pr_info(
			"unset EPOLLOUT: no buffer left on socket %d, "
			"it is fully empty, "
			"send to socket %d is now completed\n",
			src->sockfd, dst->sockfd
		);

		if (dst->epmask & EPOLLOUT) {
			dst->epmask &= ~EPOLLOUT;
			*epmask_changed = true;
		}
	}
}

/*
* Set EPOLLIN bit on epmask member.
*
* @param src Pointer to struct gwp_conn.
* @param epmask_changed Pointer to boolean.
*/
static void adjust_pollin(struct gwp_conn *src, bool *epmask_changed)
{
	/*
	* unset EPOLLIN from epmask when the buffer is full,
	* otherwise, set it.
	*/
	if (!(DEFAULT_BUF_SZ - src->len)) {
		pr_info(
			"unset EPOLLIN: buffer on socket %d is full "
			"can't receive anymore\n",
			src->sockfd
		);

		if (src->epmask & EPOLLIN) {
			src->epmask &= ~EPOLLIN;
			*epmask_changed = true;
		}
	} else {
		pr_info(
			"set EPOLLIN: buffer on socket %d still have "
			"some free space to fill in\n",
			src->sockfd
		);

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
static int adjust_events(int epfd, struct pair_conn *pc)
{
	int ret;
	bool is_client_changed = false;
	bool is_target_changed = false;
	struct epoll_event ev;
	struct gwp_conn *client = &pc->client, *target = &pc->target;

	if (pc->state == STATE_EXCHANGE)
		adjust_pollout(target, client, &is_client_changed);
	else
		adjust_single_pollout(client, &is_client_changed);
	adjust_pollin(client, &is_client_changed);
	if (target->sockfd != -1) {
		adjust_pollout(client, target, &is_target_changed);
		adjust_pollin(target, &is_target_changed);
	}

	if (is_client_changed) {
		ev.data.u64 = 0;
		ev.data.ptr = pc;
		ev.data.u64 |= EV_BIT_CLIENT;
		ev.events = client->epmask;

		ret = epoll_ctl(epfd, EPOLL_CTL_MOD, client->sockfd, &ev);
		if (ret < 0) {
			pr_err("failed to modify event: %s\n", strerror(errno));
			return -EXIT_FAILURE;
		}
	}

	if (is_target_changed) {
		ev.events = target->epmask;
		ev.data.u64 = 0;
		ev.data.ptr = pc;
		ev.data.u64 |= EV_BIT_TARGET;

		ret = epoll_ctl(epfd, EPOLL_CTL_MOD, target->sockfd, &ev);
		if (ret < 0) {
			pr_err("failed to modify event: %s\n", strerror(errno));
			return -EXIT_FAILURE;
		}
	}

	return 0;
}

/*
* Handle exchange data.
* The connection represent client and target, or vice versa.
*
* @param ev Pointer to epoll event.
* @param a Pointer to the connection.
* @param b Pointer to the connection.
* @return zero on success, or a negative integer on failure.
*/
static int exchange_data(struct epoll_event *ev,
			struct gwp_conn *a, struct gwp_conn *b)
{
	int ret;

	if (ev->events & EPOLLIN) {
		pr_info("current epoll events have EPOLLIN bit set\n");
		ret = handle_data(a, b);
		if (ret < 0)
			return -EXIT_FAILURE;
	}

	if (ev->events & EPOLLOUT) {
		pr_info("current epoll events have EPOLLOUT bit set\n");

		ret = handle_data(b, a);
		if (ret < 0)
			return -EXIT_FAILURE;
	}

	return 0;
}

/*
* Handshake with the client.
*
* @param pc Pointer to pair_conn struct of current session.
* @param pctx Pointer to application data.
* @return zero on success, and a negative integer on failure.
*/
static int accept_greeting(struct pair_conn *pc, struct gwp_ctx *pctx)
{
	struct gwp_conn *a = &pc->client;
	struct socks5_greeting *g = (void *)a->buf;
	unsigned preferred_auth = NONE;
	bool have_entry;
	int ret, i, rlen = sizeof(*g) - a->len;

	ret = recv(a->sockfd, &a->buf[a->len], rlen, 0);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return -EAGAIN;
		pr_err(
			"failed to recv greeting from %s: %s\n",
			a->addrstr, strerror(ret)
		);
		return -EXIT_FAILURE;
	}
	if (!ret) {
		pr_warn(
			"sockfd %d closes the connection "
			"while accept greeting\n",
			a->sockfd
		);
		return -EXIT_FAILURE;
	}
	pr_dbg(
		"%d bytes were received from sockfd %d.\n",
		ret,
		a->sockfd
	);
	VT_HEXDUMP(&a->buf[a->len], ret);
	a->len += ret;
	if (a->len < 2)
		return -EAGAIN;

	if (g->ver != SOCKS5_VER) {
		pr_err("unsupported socks version.\n");
		return -EXIT_FAILURE;
	}
	
	if (g->nauth == 0) {
		pr_err("invalid value in field nauth.\n");
		return -EXIT_FAILURE;
	}

	if (a->len - 2 < g->nauth)
		return -EAGAIN;

	if (pctx->cargs.auth_file) {
		pr_dbg("attempting to lock creds_lock\n");
		pthread_rwlock_rdlock(&pctx->creds.creds_lock);
		pr_dbg("acquired creds_lock\n");
		have_entry = pctx->creds.userpwd_l.nr_entry;
		pr_dbg("releasing creds_lock\n");
		pthread_rwlock_unlock(&pctx->creds.creds_lock);
	}

	for (i = 0; i < g->nauth; i++) {
		switch (g->methods[i]) {
		case NO_AUTH:
			if (have_entry)
				continue;
			preferred_auth = NO_AUTH;
			goto auth_method_found;
		case USERNAME_PWD:
			if (have_entry) {
				preferred_auth = USERNAME_PWD;
				goto auth_method_found;
			}
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
* @param pc Pointer to pair_conn struct of current session.
* @return zero on success, or a negative integer on failure.
*/
static int response_handshake(struct pair_conn *pc)
{
	struct gwp_conn *a = &pc->client;
	char server_choice[2];
	int ret;

	if (!a->len)
		a->len = sizeof(server_choice);
	server_choice[0] = SOCKS5_VER;
	server_choice[1] = pc->preferred_method;
	ret = send(
		a->sockfd,
		&server_choice[sizeof(server_choice) - a->len],
		a->len, MSG_NOSIGNAL
	);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return -EAGAIN;
		pr_err(
			"failed to send response handshake to %s: %s\n",
			a->addrstr, strerror(ret)
		);
		return -EXIT_FAILURE;
	}
	pr_dbg(
		"%d bytes were sent to sockfd %d.\n",
		ret, a->sockfd
	);
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
* @param tctx Pointer to the gwp_tctx struct (thread data).
* @param pc Pointer that need to be saved 
* @param dst the address structure to which the client connects.
* @return zero on success, or a negative integer on failure.
*/
static int prepare_exchange(struct gwp_tctx *tctx, struct pair_conn *pc,
			struct sockaddr_storage *dst)
{
	int ret, tsock = set_target(&pc->target, dst);
	if (tsock < 0)
		return -EXIT_FAILURE;

	if (tctx->pctx->cargs.timeout) {
		const struct itimerspec it = {
			.it_value = {
				.tv_sec = tctx->pctx->cargs.timeout,
				.tv_nsec = 0
			},
			.it_interval = {
				.tv_sec = 0,
				.tv_nsec = 0
			}
		};
		ret = timerfd_settime(pc->timerfd, 0, &it, NULL);
		if (ret < 0) {
			pr_err("failed to set timeout: %s\n", strerror(errno));
			return -EXIT_FAILURE;
		}
	}

	pc->target.sockfd = tsock;
	ret = register_events(tsock, tctx->epfd, pc->target.epmask,
				pc, EV_BIT_TARGET);
	if (ret < 0)
		return -EXIT_FAILURE;

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

	ipv4_sz = sizeof(struct in_addr);
	ipv6_sz = sizeof(struct in6_addr);
	d_sz 	= sizeof(*d);
	in6	= (struct sockaddr_in6 *)d;
	in	= (struct sockaddr_in *)d;
	s 	= &reply_buf->bnd_addr;

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
* @param ctx Pointer to thread-specific data.
* @param pc Pointer to the pair connection struct.
* @param d Pointer of sockaddr to initialize.
* @return zero on success, or a negative integer on failure.
*/
static int parse_request(struct gwp_tctx *ctx,
			struct pair_conn *pc, struct sockaddr_storage *d)
{
	struct socks5_connect_request *c;
	struct sockaddr_in *in;
	struct sockaddr_in6 *in6;
	struct socks5_addr *s;
	struct gwp_conn *a;
	struct dns_req *r;
	uint8_t ipv4_sz, ipv6_sz, domainlen_sz, domainname_sz;
	size_t expected_len, fixed_len;
	char *dname_ptr;

	a = &pc->client;
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
		dname_ptr = s->addr.domain.name;
		r = init_req(ctx, pc, dname_ptr, domainname_sz);
		if (r) {
			atomic_fetch_add(&pc->refcnt, 1);
			pr_dbg("attempting to lock dns_lock\n");
			pthread_mutex_lock(&ctx->pctx->dns_lock);
			pr_dbg("acquired dns_lock\n");
			pr_info("sending request to dns resolver thread\n");
			enqueue_dns(&ctx->pctx->q, r);
			pthread_cond_signal(&ctx->pctx->dns_cond);
			pr_dbg("releasing dns_lock\n");
			pthread_mutex_unlock(&ctx->pctx->dns_lock);
		}
		pc->state = STATE_DNS_RESOLV;
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
		pr_err("unknown address type.\n");
		return -EXIT_FAILURE;
	}

	return 0;
}

/*
* Handle client's CONNECT command.
* 
* @param pc Pointer to pair_conn struct of current session.
* @param tctx Pointer to the gwp_tctx struct (thread data).
* @param d Pointer to initialized target address.
* @return zero on success, or a negative integer on failure.
*/
static int handle_connect(struct pair_conn *pc, struct gwp_tctx *tctx,
				struct sockaddr_storage *d)
{
	/* filled with target address to which the client connect. */
	struct gwp_conn *a = &pc->client;
	struct socks5_connect_reply reply_buf;
	int ret;
	size_t reply_len;

	if (pc->target.sockfd == -1) {
		ret = prepare_exchange(tctx, pc, d);
		if (ret < 0)
			return -EXIT_FAILURE;
	}

	reply_len = craft_reply(&reply_buf, d, pc->target.sockfd);
	if (!a->len)
		a->len = reply_len;
	ret = send(
		a->sockfd,
		((char *)(&reply_buf)) + (reply_len - a->len),
		a->len, MSG_NOSIGNAL
	);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return -EAGAIN;
		pr_err(
			"failed to send request connect reply to %s: %s\n",
			a->addrstr, strerror(ret)
		);
		return -EXIT_FAILURE;
	}
	pr_dbg(
		"%d bytes were sent to sockfd %d.\n",
		ret, a->sockfd
	);
	VT_HEXDUMP(((char *)(&reply_buf)) + (reply_len - a->len), ret);

	a->len -= ret;
	if (a->len)
		return -EAGAIN;

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
* @param pc Pointer to pair_conn struct of current session.
* @param creds Pointer to username/password credentials.
* @return zero on success, or a negative integer on failure.
*/
static int req_userpwd(struct pair_conn *pc, struct auth_creds *creds)
{
	struct gwp_conn *c = &pc->client;
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
		pr_err(
			"failed to recv username/password from %s: %s\n",
			c->addrstr, strerror(ret)
		);
		return -EXIT_FAILURE;
	}
	if (!ret) {
		pr_warn(
			"sockfd %d closes the connection "
			"while handle usr/pwd auth\n",
			c->sockfd
		);
		return -EXIT_FAILURE;
	}
	pr_dbg(
		"%d bytes were received from sockfd %d.\n",
		ret,
		c->sockfd
	);
	VT_HEXDUMP(&c->buf[c->len], ret);

	c->len += ret;

	if (c->len < expected_len)
		return -EAGAIN;

	if (pkt->ver != 1) {
		pr_err(
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
	pr_dbg("attempting to lock creds_lock\n");
	pthread_rwlock_rdlock(&creds->creds_lock);
	pr_dbg("acquired creds_lock\n");
	for (i = 0; i < creds->userpwd_l.nr_entry; i++) {
		p = &creds->userpwd_l.arr[i];

		if (pkt->ulen != p->ulen || *plen != p->plen)
			continue;

		ret = memcmp(username, p->username, pkt->ulen);
		if (ret)
			continue;

		ret = memcmp(password, p->password, *plen);
		if (ret)
			continue;

		pc->is_authenticated = 0x0;
		break;
	}
	pr_dbg("releasing creds_lock\n");
	pthread_rwlock_unlock(&creds->creds_lock);

	return 0;
}

/*
* Reply user/password auth sub-negotiation.
*
* @param c Pointer to client data
* @param reply_buf Pointer to the buffer.
* @return zero on success, or a negative integer on failure.
*/
static int rep_userpwd(struct gwp_conn *c, char *reply_buf)
{
	int ret;

	if (!c->len)
		c->len = REPLY_LEN;
	ret = send(c->sockfd, &reply_buf[REPLY_LEN - c->len], c->len, MSG_NOSIGNAL);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN)
			return -ret;
		pr_err(
			"failed to send auth response to %s: %s\n",
			c->addrstr, strerror(ret)
		);
		return -EXIT_FAILURE;
	}
	pr_dbg(
		"%d bytes were sent to sockfd %d.\n",
		ret, c->sockfd
	);
	VT_HEXDUMP(&reply_buf[REPLY_LEN - c->len], ret);

	c->len -= ret;
	if (c->len)
		return -EAGAIN;

	return 0;
}

/*
* Handle sub-negotiation with username/password auth method.
*
* @param pc Pointer to pair_conn struct of current session.
* @param pctx Pointer to application data.
* @return zero on success, or a negative integer on failure.
*/
static int handle_userpwd(struct epoll_event *ev, struct pair_conn *pc, struct gwp_ctx *pctx)
{
	char reply_buf[2];
	int ret;

	if (ev->events & EPOLLIN) {
		ret = req_userpwd(pc, &pctx->creds);
		if (ret < 0)
			return ret;
	}

	reply_buf[0] = 0x1;
	reply_buf[1] = pc->is_authenticated;
	ret = rep_userpwd(&pc->client, reply_buf);
	if (ret < 0)
		return ret;

	if (reply_buf[1] == 0x1)
		return -EXIT_FAILURE;

	return 0;
}

/*
* Handle client's request, evaluate it and return a reply.
*
* @param pc Pointer to pair_conn struct of current session.
* @param gwp Pointer to the gwp_tctx struct (thread data).
* @return zero on success, or a negative integer on failure.
*/
static int handle_request(struct epoll_event *ev, struct pair_conn *pc, struct gwp_tctx *gwp)
{
	/* filled with target address to which the client connect. */
	struct sockaddr_storage d;
	struct gwp_conn *a = &pc->client;
	struct socks5_connect_request *c = (void *)a->buf;
	int ret, rlen = (sizeof(*c) + PORT_SZ) - a->len;
	size_t fixed_len;

	if (ev->events & EPOLLIN) {
		ret = recv(a->sockfd, &a->buf[a->len], rlen, 0);
		if (ret < 0) {
			ret = errno;
			if (ret == EAGAIN)
				return -EAGAIN;
			pr_err(
				"failed to recv request from %s: %s\n",
				a->addrstr, strerror(ret)
			);
			return -EXIT_FAILURE;
		}
		if (!ret) {
			pr_info(
				"sockfd %d closes the connection "
				"while handle request\n",
				a->sockfd
			);
			return -EXIT_FAILURE;
		}
		pr_dbg(
			"%d bytes were received from sockfd %d.\n",
			ret, a->sockfd
		);
		VT_HEXDUMP(&a->buf[a->len], ret);

		a->len += ret;
		fixed_len = sizeof(*c) - sizeof(c->dst_addr.addr) + PORT_SZ;
		if (a->len < fixed_len)
			return -EAGAIN;

		ret = parse_request(gwp, pc, &d);
		if (ret < 0) {
			if (ret == -EAGAIN)
				return ret;
			return -EXIT_FAILURE;
		}
		a->len = 0;
	}

	if (c->ver != SOCKS5_VER) {
		pr_err("unsupported socks version.\n");
		return -EXIT_FAILURE;
	}

	if (c->cmd != CONNECT) {
		pr_err("unsupported command, yet.\n");
		return -EXIT_FAILURE;
	}

	ret = handle_connect(pc, gwp, &d);
	if (ret < 0)
		return ret;

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

static void cleanup_session(struct gwp_tctx *tctx, struct pair_conn *pc)
{
	pr_info(
		"free the system resources for session on %s\n",
		pc->client.addrstr
	);
	if (pc->idx == (tctx->p.nr_item - 1))
		tctx->p.nr_item--;
	if (pc->timerfd != -1) {
		pr_info("close timer file descriptor: %d\n", pc->timerfd);
		close(pc->timerfd);
	}
	if (pc->client.sockfd != -1) {
		pr_info(
			"close client connection on socket: "
			"%d\n", pc->client.sockfd
		);
		close(pc->client.sockfd);
	}
	if (pc->target.sockfd != -1) {
		pr_info(
			"close target connection on socket: "
			"%d\n", pc->target.sockfd
		);
		close(pc->target.sockfd);
	}
	pr_info("free client buffer: %p\n", pc->client.buf);
	free(pc->client.buf);
	pr_info("free target buffer: %p\n", pc->target.buf);
	free(pc->target.buf);
	tctx->p.arr[pc->idx] = NULL;

	if (put_pc(pc)) {
		pr_dbg("pointer to the session was freed: %p\n", pc);
	}
}

/*
* Process epoll event from tcp connection.
*
* currently, this function handle:
* - timer timed out (EPOLLIN).
* - connection established from EINPROGRESS (EPOLLOUT).
* - socket that ready to read or write (EPOLLIN or EPOLLOUT).
*   * communication on simple TCP proxy with pre-defined target.
*   * communication on socks5 protocol.
*
* @param ev Pointer to epoll event structure.
* @param tctx Pointer to the gwp_tctx struct (thread data).
* @return zero on success, or a negative integer on failure.
*/
static int process_tcp(struct epoll_event *ev, struct gwp_tctx *tctx)
{
	int ret;
	struct pair_conn *pc;
	struct gwp_conn *a, *b;

	uint64_t ev_bit = GET_EV_BIT(ev->data.u64);

	ev->data.u64 = CLEAR_EV_BIT(ev->data.u64);
	pc = ev->data.ptr;

	switch (ev_bit) {
	case EV_BIT_TIMER:
		pr_info(
			"timed out, terminating the session for %s\n",
			pc->client.addrstr
		);
		goto exit_err;
	case EV_BIT_CLIENT:
		pr_info("receiving data from client\n");
		a = &pc->client;
		b = &pc->target;
		break;

	case EV_BIT_TARGET:
		pr_info("receiving data from target\n");
		a = &pc->target;
		b = &pc->client;
		break;

	case EV_BIT_DNS_RESOLVED:
		// TODO: refactor codebase
		break;
	}

	if (!pc->is_connected && pc->target.sockfd != -1) {
		ret = is_sock_connected(pc->target.sockfd);
		if (ret && pc->timerfd != -1) {
			close(pc->timerfd);
			pc->timerfd = -1;
			pc->is_connected = true;
		}
	}

	if (pc->state == STATE_DNS_RESOLV) {
		// for testing purposes, always assume dns resolution always succeded
		ret = prepare_exchange(tctx, pc, (struct sockaddr_storage *)&pc->r->in);
		close(pc->r->finishfd);
		free(pc->r);
		if (ret < 0)
			goto exit_err;

		pc->state = STATE_EXCHANGE;
	}

	if (pc->state == NO_SOCKS5) {
		ret = prepare_exchange(tctx, pc, &tctx->pctx->cargs.dst_addr_st);
		if (ret < 0)
			goto exit_err;

		pc->state = STATE_EXCHANGE;
	} else if (pc->state == STATE_GREETING) {
		if (ev->events & EPOLLIN) {
			ret = accept_greeting(pc, tctx->pctx);
			if (ret < 0) {
				if (ret == -EAGAIN)
					goto adjust_epoll;
				goto exit_err;
			}
		}

		ret = response_handshake(pc);
		if (ret < 0) {
			if (ret == -EAGAIN)
				goto adjust_epoll;
			goto exit_err;
		}

		if (pc->preferred_method == NO_AUTH)
			pc->state = STATE_REQUEST;
		else
			pc->state = STATE_AUTH;
	}

	if (pc->state == STATE_AUTH) {
		ret = handle_userpwd(ev, pc, tctx->pctx);
		if (ret < 0) {
			if (ret == -EAGAIN)
				goto adjust_epoll;
			goto exit_err;
		}

		pc->state = STATE_REQUEST;
	}

	if (pc->state == STATE_REQUEST) {
		ret = handle_request(ev, pc, tctx);
		if (ret < 0) {
			if (ret == -EAGAIN)
				goto adjust_epoll;
			goto exit_err;
		}

		pc->state = STATE_EXCHANGE;
	}

	if (pc->state == STATE_EXCHANGE) {
		ret = exchange_data(ev, a, b);
		if (ret < 0)
			goto exit_err;
	}

adjust_epoll:
	adjust_events(tctx->epfd, pc);

	return 0;
exit_err:
	cleanup_session(tctx, pc);
	return -EXIT_FAILURE;
}

/*
* Process epoll event that are 'ready'.
*
* @param ready_nr Number of ready events.
* @param evs Pointer to epoll event struct.
* @param tctx Pointer to the gwp_tctx struct (thread data).
*/
static void process_ready_list(int ready_nr,
				struct epoll_event *evs, struct gwp_tctx *tctx)
{
	int i;
	pr_info("number of ready events %d\n", ready_nr);
	for (i = 0; i < ready_nr; i++) {
		struct epoll_event *ev = &evs[i];

		if (ev->data.fd == tctx->listen_sock) {
			handle_incoming_client(tctx);
		} else if (ev->data.fd == tctx->pctx->stopfd) {
			break;
		} else
			if (process_tcp(ev, tctx) < 0)
				return;
	}
}

/*
* allocate pool of established connection.
*
* @param  p Pointer to the pool.
* @param  client_nr number of client for pre-allocated memory.
* @return zero on success, or a negative integer on failure.
*/
static int init_conn_pool(struct connection_pool *p, int client_nr)
{
	p->arr = calloc(client_nr, sizeof(p->arr));
	if (!p->arr)
		return -ENOMEM;

	p->nr_item = 0;
	p->max_item = client_nr;

	return 0;
}

static int init_watcher_file(struct gwp_ctx *a)
{
	int ret, ifd, epfd, afd;
	struct auth_creds *ac;
	struct epoll_event ev;

	afd = open(a->cargs.auth_file, O_RDONLY);
	if (afd < 0) {
		pr_err("failed to load %s file\n", a->cargs.auth_file);
		return -EXIT_FAILURE;
	}

	ret = parse_auth_file(afd, &a->creds.userpwd_l, &a->creds.userpwd_buf);
	if (ret < 0) {
		pr_err("failed to parse %s file\n", a->cargs.auth_file);
		goto exit_close_filefd;
	}

	ifd = inotify_init1(IN_NONBLOCK);
	if (ifd < 0) {
		pr_err(
			"failed to create inotify file descriptor: %s\n",
			strerror(errno)
		);
		goto exit_close_filefd;
	}

	ret = inotify_add_watch(ifd, a->cargs.auth_file, IN_CLOSE_WRITE);
	if (ret < 0) {
		pr_err(
			"failed to add file to inotify watch: %s\n",
			strerror(errno)
		);
		goto exit_close_ifd;
	}

	epfd = epoll_create(1);
	if (epfd < 0) {
		pr_err(
			"failed to create epoll file descriptor: %s\n",
			strerror(errno)
		);
		goto exit_close_ifd;
	}

	ev.events = EPOLLIN;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, ifd, &ev);
	if (ret < 0) {
		pr_err(
			"failed to add inotifyfd to epoll: %s\n",
			strerror(errno)
		);
		goto exit_close_epfd;
	}

	ev.events = EPOLLIN;
	ev.data.fd = a->stopfd;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, a->stopfd, &ev);
	if (ret < 0) {
		pr_err(
			"failed to add eventfd to epoll: %s\n",
			strerror(errno)
		);
		goto exit_close_epfd;
	}

	ac = &a->creds;
	ac->epfd = epfd;
	ac->ifd = ifd;
	ac->authfd = afd;

	pthread_rwlock_init(&a->creds.creds_lock, NULL);

	return 0;
exit_close_epfd:
	close(epfd);
exit_close_ifd:
	close(ifd);
exit_close_filefd:
	close(afd);
	return -EXIT_FAILURE;
}

/*
* Start the TCP proxy server.
* 
* @param pctx Pointer to application data.
* @return zero on success, or a negative integer on failure.
*/
static int start_server(struct gwp_tctx *tctx)
{
	int ret, ready_nr;
	unsigned i;
	struct epoll_event evs[NR_EVENTS];

	while (!tctx->pctx->stop) {
		ready_nr = epoll_wait(tctx->epfd, evs, NR_EVENTS, -1);
		if (ready_nr < 0) {
			ret = errno;
			if (ret == EINTR)
				continue;
			pr_err("failed to wait on epoll: %s\n", strerror(ret));
			ret = -EXIT_FAILURE;
			goto exit;
		}

		process_ready_list(ready_nr, evs, tctx);
	}

	ret = 0;
exit:
	pr_info("closing tcp file descriptor: %d\n", tctx->listen_sock);
	close(tctx->listen_sock);

	for (i = 0; i < tctx->p.nr_item; i++) {
		struct pair_conn *pc = tctx->p.arr[i];
		if (pc)
			cleanup_session(tctx, pc);
	}

	pr_info("free the connection pool: %p\n", tctx->p.arr);
	free(tctx->p.arr);

	pr_info("closing epoll file descriptor: %d\n", tctx->epfd);
	close(tctx->epfd);

	return ret;
}

/*
* TCP proxy server thread
*
* @param tctx Pointer to thread-specific data.
* @return negative integer on failure.
*/
static void *server_thread(void *tctx)
{
	int ret = start_server(tctx);

	return (void *)(intptr_t)ret;
}

/*
* File watcher thread.
* dedicated thread to perform hot-reload username/pwd credential file
*
* @param args Pointer to application data.
* @return zero on success, or a negative integer on failure.
*/
static void *watcher_thread(void *args)
{
	int ret;
	struct gwp_ctx *a;
	struct auth_creds *ac;
	struct userpwd_pair *pr;
	struct inotify_event iev;
	struct epoll_event ev;

	size_t counter = 0;

	a = args;
	ac = &a->creds;

	while (!a->stop) {
		ret = epoll_wait(ac->epfd, &ev, 1, -1);
		if (ret < 0) {
			ret = errno;
			if (ret == EINTR)
				continue;
			pr_err(
				"failed to wait on epoll: %s\n",
				strerror(ret)
			);
			ret = -EXIT_FAILURE;
			goto exit_err;
		}

		if (ev.data.fd == a->stopfd)
			break;

		read(ac->ifd, &iev, sizeof(iev));
		printf("\e[1;1H\e[2J");
		printf(
			"File changed %ld times since program started, "
			"re-read the file content...\n",
			++counter
		);

		ac = &a->creds;
		if (ac->userpwd_l.nr_entry) {
			ac->userpwd_l.prev_arr = ac->userpwd_l.arr;
			ac->prev_userpwd_buf = ac->userpwd_buf;
		}

		pr_dbg("attempting to lock creds_lock\n");
		pthread_rwlock_wrlock(&a->creds.creds_lock);
		pr_dbg("acquired creds_lock\n");

		ret = parse_auth_file(a->creds.authfd,
					&ac->userpwd_l, &ac->userpwd_buf);
		if (!ret) {
			free(ac->userpwd_l.prev_arr);
			free(ac->prev_userpwd_buf);
		}

		pr_dbg("releasing creds_lock\n");
		pthread_rwlock_unlock(&a->creds.creds_lock);

		for (int i = 0; i < ac->userpwd_l.nr_entry; i++) {
			pr = &ac->userpwd_l.arr[i];
			printf("%d. %s:%s\n", i, pr->username, pr->password);
		}
	}

	ret = 0;
exit_err:
	pr_info("closing inotify file descriptor: %d\n", ac->ifd);
	close(ac->ifd);
	pr_info("closing epoll file descriptor: %d\n", ac->epfd);
	close(ac->epfd);

	return (void *)(intptr_t)ret;
}

void resolve_dns(struct dns_req *r)
{
	struct sockaddr_in *in, *tr;
	struct sockaddr_in6 *in6;
	struct addrinfo *l;
	int ret;

	ret = getaddrinfo(r->domainname, NULL, NULL, &l);
	if (ret != 0) {
		pr_err(
			"failed to resolve domain name %s: %s\n",
			r->domainname, gai_strerror(ret)
		);
		return;
	}

	switch (l->ai_family) {
	case AF_INET:
		tr = (void *)&r->in;
		tr->sin_family = AF_INET;
		in = (struct sockaddr_in *)l->ai_addr;
		memcpy(
			&tr->sin_addr, &in->sin_addr,
			sizeof(in->sin_addr)
		);
		break;
	case AF_INET6:
		r->in.sin6_family = AF_INET6;
		in6 = (struct sockaddr_in6 *)l->ai_addr;
		memcpy(
			&r->in.sin6_addr, &in6->sin6_addr,
			sizeof(in6->sin6_addr)
		);
		break;
	}

	freeaddrinfo(l);
}

/*
* Dedicated thread to resolve dns query request from another thread.
*/
static void *dns_resolver_thread(void *args)
{
	struct dns_req *r;
	struct gwp_ctx *ctx = args;
	uint64_t val = 1;

	pr_dbg("attempting to lock dns_lock\n");
	pthread_mutex_lock(&ctx->dns_lock);
	pr_dbg("acquired dns_lock\n");
	while (!ctx->stop) {
		r = ctx->q.head;
		if (!r) {
			pr_dbg("releasing dns_lock and waiting for signal\n");
			pthread_cond_wait(&ctx->dns_cond, &ctx->dns_lock);
			pr_dbg("acquired dns_lock\n");
			r = ctx->q.head;
			if (!r)
				continue;
		}

		pr_info("doing blocking operation, releasing dns_lock\n");
		pthread_mutex_unlock(&ctx->dns_lock);
		resolve_dns(r);
		pr_dbg("attempting to lock dns_lock\n");
		pthread_mutex_lock(&ctx->dns_lock);
		pr_dbg("acquired dns_lock\n");
		dequeue_dns(&ctx->q);
		if (put_pc(r->pc)) {
			pr_dbg("pointer to the session was freed: %p\n", r->pc);
			close(r->finishfd);
			free(r);
		} else
			write(r->finishfd, &val, sizeof(val));
	}
	pr_dbg("releasing dns_lock\n");
	pthread_mutex_unlock(&ctx->dns_lock);

	return NULL;
}

/*
* Signal handler.
* catch SIGINT and SIGTERM signal.
*
* @param c signal number.
*/
static void signal_handler(int c)
{
	uint64_t val = 1;

	switch (c) {
	case SIGTERM:
		pr_info(
			"SIGTERM signal received, "
			"gracefully exiting the program...\n"
		);
		break;
	case SIGINT:
		pr_info(
			"SIGINT signal received, "
			"gracefully exiting the program...\n"
		);
		break;
	}

	gctx->stop = true;
	write(gctx->stopfd, &val, sizeof(val));
	pthread_cond_signal(&gctx->dns_cond);
}

static int init_pctx(struct gwp_ctx *ctx)
{
	ctx->q.head = NULL;
	ctx->stop = false;
	ctx->stopfd = eventfd(0, EFD_NONBLOCK);
	if (ctx->stopfd < 0) {
		pr_err(
			"failed to create event file descriptor: %s\n",
			strerror(errno)
		);
		return -EXIT_FAILURE;
	}

	pr_info("initialize dns pthread_cond_t\n");
	pthread_cond_init(&ctx->dns_cond, NULL);
	pr_info("initialize dns pthread_mutex_t\n");
	pthread_mutex_init(&ctx->dns_lock, NULL);

	return 0;
}

static int init_tctx(struct gwp_ctx *pctx, struct gwp_tctx *tctx)
{
	int ret, flg;
	socklen_t size_addr;
	struct epoll_event ev;
	struct sockaddr_storage *s = &pctx->cargs.src_addr_st;
	static const int val = 1;

	tctx->pctx = pctx;

	size_addr = s->ss_family == AF_INET ? 
		sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

	flg = SOCK_STREAM | SOCK_NONBLOCK;
	tctx->listen_sock = socket(s->ss_family, flg, 0);
	if (tctx->listen_sock < 0) {
		pr_err(
			"failed to create TCP socket: %s\n",
			strerror(errno)
		);
		return -EXIT_FAILURE;
	}

	setsockopt(tctx->listen_sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(tctx->listen_sock, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));

	ret = bind(tctx->listen_sock, (struct sockaddr *)s, size_addr);
	if (ret < 0) {
		pr_err("failed to bind socket: %s\n", strerror(errno));
		goto exit_close_socket;
	}

	ret = listen(tctx->listen_sock, SOMAXCONN);
	if (ret < 0) {
		pr_err(
			"failed to prepare to accept connections: %s\n",
			strerror(errno)
		);
		goto exit_close_socket;
	}

	tctx->epfd = epoll_create(1);
	if (tctx->epfd < 0) {
		pr_err(
			"failed to create epoll file descriptor: %s\n",
			strerror(errno)
		);
		goto exit_close_socket;
	}

	ev.events = EPOLLIN;
	ev.data.fd = tctx->listen_sock;
	ret = epoll_ctl(tctx->epfd, EPOLL_CTL_ADD, tctx->listen_sock, &ev);
	if (ret < 0) {
		pr_err(
			"failed to register event for tcp socket: %s\n",
			strerror(errno)
		);
		goto exit_close_epfd;
	}

	ev.events = EPOLLIN;
	ev.data.fd = pctx->stopfd;
	ret = epoll_ctl(tctx->epfd, EPOLL_CTL_ADD, pctx->stopfd, &ev);
	if (ret < 0) {
		pr_err(
			"failed to register event for eventfd: %s\n",
			strerror(errno)
		);
		goto exit_close_epfd;
	}

	ret = init_conn_pool(&tctx->p, pctx->cargs.client_nr);
	if (ret)
		goto exit_close_epfd;

	return 0;
exit_close_epfd:
	close(tctx->epfd);
exit_close_socket:
	close(tctx->listen_sock);
	return -EXIT_FAILURE;
}

static int setfdlimit(void)
{
	struct rlimit file_limits;

	getrlimit(RLIMIT_NOFILE, &file_limits);
	file_limits.rlim_cur = file_limits.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &file_limits) < 0) {
		pr_err(
			"failed to set file descriptor limit: %s\n",
			strerror(errno)
		);
		return -EXIT_FAILURE;
	}

	return 0;
}

static int spawn_server_threads(struct gwp_ctx *ctx)
{
	int ret;
	size_t i;
	struct gwp_tctx *t;

	ctx->tctx_pool = malloc(ctx->cargs.server_thread_nr * sizeof(*ctx->tctx_pool));
	if (!ctx->tctx_pool) {
		pr_err("out of memory, can't allocate memory for threads\n");
		return -EXIT_FAILURE;
	}

	for (i = 0; i < ctx->cargs.server_thread_nr; i++) {
		t = &ctx->tctx_pool[i];
		ret = init_tctx(ctx, t);
		if (ret < 0)
			return -EXIT_FAILURE;
	}

	for (i = 0; i < ctx->cargs.server_thread_nr; i++) {
		t = &ctx->tctx_pool[i];
		if (i == 0)
			continue;
		pthread_create(&t->thandle, NULL, server_thread, t);
	}

	return start_server(ctx->tctx_pool);
}

int main(int argc, char *argv[])
{
	int ret;
	size_t i;
	void *retval;
	pthread_t watcher_t, dnsresolv_t;
	struct auth_creds *ac;
	struct gwp_ctx ctx;
	struct sigaction s = {
		.sa_handler = signal_handler
	};

	ret = handle_cmdline(argc, argv, &ctx.cargs);
	if (ret < 0)
		return -EXIT_FAILURE;

	ret = init_pctx(&ctx);
	if (ret < 0)
		return -EXIT_FAILURE;

	gctx = &ctx;

	ret = 0;
	ret |= sigaction(SIGTERM, &s, NULL);
	ret |= sigaction(SIGINT, &s, NULL);
	if (ret < 0) {
		pr_err("failed to register signal handler\n");
		goto exit_close_stopfd;
	}

	if (ctx.cargs.auth_file) {
		ret = init_watcher_file(&ctx);
		if (ret < 0)
			goto exit_close_stopfd;
		pthread_create(&watcher_t, NULL, watcher_thread, &ctx);
	}

	ret = setfdlimit();
	if (ret < 0)
		goto exit_cleanup_auth_creds;

	pthread_create(&dnsresolv_t, NULL, dns_resolver_thread, &ctx);
	spawn_server_threads(&ctx);

	if (ctx.cargs.auth_file)
		pthread_join(watcher_t, &retval);
	pthread_join(dnsresolv_t, &retval);

	for (i = 0; i < ctx.cargs.server_thread_nr; i++) {
		if (i == 0)
			continue;

		ret = pthread_join(ctx.tctx_pool[i].thandle, &retval);
		if (ret) {
			errno = ret;
			pr_err("failed to join the thread: %s\n", strerror(ret));
			ret = -EXIT_FAILURE;
			goto exit_free_pool;
		}

		if ((intptr_t)retval < 0) {
			pr_err("fatal: failed to start server\n");
			ret = (intptr_t)retval;
			goto exit_free_pool;
		}
	}

	ret = 0;
exit_free_pool:
	pr_info("free the threads pool: %p\n", ctx.tctx_pool);
	free(ctx.tctx_pool);
exit_cleanup_auth_creds:
	if (ctx.cargs.auth_file) {
		ac = &ctx.creds;
		pr_info("closing open file descriptor %d\n", ac->authfd);
		close(ac->authfd);
		if (ac->userpwd_l.arr) {
			pr_info("free array of userpwd: %p\n", ac->userpwd_l.arr);
			free(ac->userpwd_l.arr);
		}
		if (ac->userpwd_buf) {
			pr_info("free userpwd_buf: %p\n", ac->userpwd_buf);
			free(ac->userpwd_buf);
		}
	}

exit_close_stopfd:
	pr_info("closing stopfd file descriptor %d\n", ctx.stopfd);
	close(ctx.stopfd);

	pr_info(
		"all system resources were freed, "
		"now program can exit peacefully. "
		"transfer control back to the kernel.\n"
	);

	return ret;
}
