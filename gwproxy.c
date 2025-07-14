#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "linux.h"
#include "general.h"
#include "gwsocks5lib.h"

#define DEFAULT_EPOLL_EV 512
#define DEFAULT_THREAD_NR 4
#define DEFAULT_TIMEOUT_SEC 8
#define DEFAULT_PREALLOC_CONN 100
#define DEFAULT_BUFF_SZ 1024

#define DISCONNECTED -1

#define ALL_EV_BITS (GWP_EV_STOP | GWP_EV_ACCEPT | GWP_EV_CLIENT | GWP_EV_TARGET)
#define GET_EV_BIT(X) ((X) & ALL_EV_BITS)
#define CLEAR_EV_BIT(X) ((X) & ~ALL_EV_BITS)

#define pr_menu()					\
do {							\
printf(							\
	usage,						\
	DEFAULT_THREAD_NR, DEFAULT_TIMEOUT_SEC,		\
	DEFAULT_PREALLOC_CONN, DEFAULT_BUFF_SZ,		\
	DEFAULT_BUFF_SZ, DEFAULT_BUFF_SZ, DEFAULT_BUFF_SZ, \
	DEFAULT_BUFF_SZ, DEFAULT_BUFF_SZ		\
);							\
} while (0)

static const char opts[] = "hw:b:t:T:f:sn:g:j:k:l:p:y:";
static const char usage[] =
"usage: ./gwproxy [options]\n"
"main option:\n"
"-s\tenable socks5 mode (omit this flag to use simple tcp proxy mode)\n"
"-f\tcredential file for username/password authentication method (if not specified, imply no authentication is required)\n"
"-b\tIP address and port to be bound by the server\n"
"-t\tIP address and port of the target server (ignored in socks5 mode)\n"
"\n"
"advanced option:\n"
"-T\tnumber of tcp server thread (default: %d)\n"
"-w\twait time for timeout, set to zero for no timeout (default: %d seconds)\n"
"-n\tnumber of pre-allocated connection pointer per-thread (default: %d session)\n"
"-g\tclient buffer size of both recv and send (default: %d bytes)\n"
"-j\tclient buffer size of recv (default: %d bytes)\n"
"-l\tclient buffer size of send (default: %d bytes)\n"
"-y\ttarget buffer size of both recv and send (default: %d bytes)\n"
"-k\ttarget buffer size of recv (default: %d bytes)\n"
"-p\ttarget buffer size of send (default: %d bytes)\n"
"-h\tShow this help message and exit\n";

enum gwp_ev_bit {
	GWP_EV_STOP	= (0x1ULL << 48ULL),
	GWP_EV_ACCEPT	= (0x2ULL << 48ULL),
	GWP_EV_CLIENT	= (0x3ULL << 48ULL),
	GWP_EV_TARGET	= (0x4ULL << 48ULL)
};

struct gwp_pctx *gctx;

struct gwp_conn {
	int sockfd;
	char addrstr[ADDRSTR_SZ];
	char *recvbuf;
	size_t recvoff;
	size_t recvlen;
	size_t recvcap;
	char *sendbuf;
	size_t sendoff;
	size_t sendlen;
	size_t sendcap;
	uint64_t epmask;
};

struct gwp_pair_conn {
	size_t idx;
	struct gwp_conn client;
	struct gwp_conn target;
	struct socks5_conn *conn_ctx;
};

struct gwp_session_container {
	size_t session_nr;
	size_t capacity;
	struct gwp_pair_conn **sessions;
};

struct commandline_args {
	bool socks5_mode;
	char *auth_file;
	int connptr_nr;
	size_t server_thread_nr;
	size_t timeout;
	size_t t_recv_sz;
	size_t t_send_sz;
	size_t c_recv_sz;
	size_t c_send_sz;
	/* local address to be bound */
	struct sockaddr_storage src_addr_st;
	/* only used on simple TCP proxy mode */
	struct sockaddr_storage dst_addr_st;
};

struct buff_sz_opt {
	char *c_both_sz_opt;
	char *c_recv_sz_opt;
	char *c_send_sz_opt;
	char *t_both_sz_opt;
	char *t_recv_sz_opt;
	char *t_send_sz_opt;
};

/* program configuration and data */
struct gwp_pctx {
	struct commandline_args *args;
	struct gwp_tctx *tctx;
	struct socks5_ctx *socks5_ctx;
	int (*func_handler)(struct gwp_tctx *ctx, void *data, uint64_t ev_bit, uint32_t ev);
	int stopfd;
	volatile bool stop;
};

/* TCP server thread-specific data */
struct gwp_tctx {
	int epfd;
	int tcpfd;
	uint32_t epev;
	struct gwp_pair_conn *pc;
	pthread_t thandle;
	struct gwp_pctx *pctx;
	struct gwp_session_container container;
};

static int custom_epoll_ctl(int fd, int epfd, uint32_t epmask,
				void *ptr, uint64_t evmask, int op) {
	struct epoll_event ev;
	int ret;

	ev.events = epmask;
	ev.data.u64 = 0;
	ev.data.ptr = ptr;
	ev.data.u64 |= evmask;
	ret = epoll_ctl(epfd, op, fd, &ev);
	if (ret < 0) {
		pr_err(
			"failed to register event to epoll: %s\n",
			strerror(errno)
		);
		return -EXIT_FAILURE;
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
	return custom_epoll_ctl(fd, epfd, epmask, ptr, evmask, EPOLL_CTL_ADD);
}

static int mod_events(int fd, int epfd, uint32_t epmask,
				void *ptr, uint64_t evmask) {
	return custom_epoll_ctl(fd, epfd, epmask, ptr, evmask, EPOLL_CTL_MOD);
}

static int set_target(struct gwp_conn *t, struct sockaddr_storage *sockaddr)
{
	int ret, tsock;

	tsock = socket(sockaddr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (tsock < 0) {
		pr_err(
			"failed to create target socket: %s\n",
			strerror(errno)
		);
		return -EXIT_FAILURE;
	}

	pr_info("target tcp socket created: %d\n", tsock);

	get_addrstr((struct sockaddr *)sockaddr, t->addrstr);
	pr_info("attempting to connect to %s\n", t->addrstr);

	ret = connect(tsock, (struct sockaddr *)sockaddr, sizeof(*sockaddr));
	if (ret < 0 && errno != EINPROGRESS) {
		pr_err(
			"failed to connect to address %s: %s\n",
			t->addrstr, strerror(errno)
		);
		close(tsock);
		return -EXIT_FAILURE;
	}

	t->sockfd = tsock;
	return 0;
}

static bool _adjust_pollout(struct gwp_conn *dst, size_t len)
{
	bool epmask_changed = false;

	if (len > 0) {
		if (!(dst->epmask & EPOLLOUT)) {
			dst->epmask |= EPOLLOUT;
			epmask_changed = true;
		}
	} else {
		if (dst->epmask & EPOLLOUT) {
			dst->epmask &= ~EPOLLOUT;
			epmask_changed = true;
		}
	}

	return epmask_changed;
}

static bool adjust_pollout(struct gwp_conn *src, struct gwp_conn *dst)
{
	bool epmask_changed;
	/*
	* set EPOLLOUT to epmask when there's remaining bytes in the src' buffer
	* waiting to be sent, otherwise, unset it.
	*/
	epmask_changed = _adjust_pollout(dst, src->recvlen);
	if (epmask_changed && src->recvlen > 0) {
			pr_info(
				"set EPOLLOUT: %s's buffer is not fully drained"
				"; continuing transfer to %s\n",
				src->addrstr, dst->addrstr
			);
	} else {
			pr_info(
				"unset EPOLLOUT: buffer on %s is fully empty, "
				"stopping transfer to %s\n",
				src->addrstr, dst->addrstr
			);
	}

	return epmask_changed;
}

static void adjust_pollin(struct gwp_conn *src, bool *epmask_changed)
{
	/*
	* unset EPOLLIN from epmask when the src buffer is full,
	* otherwise, set it.
	*/
	if (src->recvcap == src->recvlen) {
		if (src->epmask & EPOLLIN) {
			pr_info(
				"unset EPOLLIN: %s's buffer is full "
				"can't receive anymore\n", src->addrstr
			);
			src->epmask &= ~EPOLLIN;
			*epmask_changed = true;
		}
	} else {
		if (!(src->epmask & EPOLLIN)) {
			pr_info(
				"set EPOLLIN: %s's buffer still has space "
				"to receive more data\n", src->addrstr
			);
			src->epmask |= EPOLLIN;
			*epmask_changed = true;
		}
	}
}

static void adjust_events(int epfd, struct gwp_pair_conn *pc)
{
	bool is_target_changed, is_client_changed;
	struct gwp_conn *client, *target;
	int ret;

	is_client_changed = false;
	is_target_changed = false;
	target = &pc->target;
	client = &pc->client;

	is_client_changed = adjust_pollout(target, client);
	adjust_pollin(client, &is_client_changed);
	if (target->sockfd != -1) {
		is_target_changed = adjust_pollout(client, target);
		adjust_pollin(target, &is_target_changed);
	}

	if (is_client_changed) {
		ret = mod_events(
			client->sockfd, epfd, client->epmask, pc, GWP_EV_CLIENT
		);
		if (ret < 0)
			pr_warn("failed to modify event: %s\n", strerror(errno));
	}

	if (is_target_changed) {
		ret = mod_events(
			target->sockfd, epfd, target->epmask, pc, GWP_EV_TARGET
		);
		if (ret < 0)
			pr_warn("failed to modify event: %s\n", strerror(errno));
	}
}

/*
* Preparation before forwarding data.
*
* connecting to either the configured target supplied from cmdline args
* or the specified target by client in socks5 mode.
*
* @param tctx Pointer to the gwp_tctx struct (thread data).
* @param pc Pointer that need to be saved 
* @param dst the address structure to which the client connects.
* @return zero on success, or a negative integer on failure.
*/
static int prepare_forward(struct gwp_tctx *tctx, struct gwp_pair_conn *pc,
			struct sockaddr_storage *dst)
{
	struct gwp_conn *t = &pc->target;

	int ret = set_target(t, dst);
	if (ret < 0)
		return -EXIT_FAILURE;

	ret = register_events(t->sockfd, tctx->epfd, t->epmask, pc, GWP_EV_TARGET);
	if (ret < 0)
		return -EXIT_FAILURE;

	return 0;
}

static int do_recv(struct gwp_conn *from, int len)
{
	int ret;

	ret = recv(
		from->sockfd, &from->recvbuf[from->recvlen],
		len, MSG_NOSIGNAL
	);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN || ret == EINTR)
			return 0;

		pr_err(
			"failed to recv from %s: %s\n",
			from->addrstr, strerror(ret)
		);
		return -ret;
	} else if (!ret) {
		pr_info(
			"EoF received on %s, "
			"closing the connection. "
			"terminating the session.\n",
			from->addrstr
		);
		return -EAGAIN;
	}

	pr_info(
		"%ld bytes were received from %s\n",
		ret, from->addrstr
	);
	VT_HEXDUMP(&from->recvbuf[from->recvlen], ret);
	if (ret != len)
		pr_warn(
			"incomplete recv: requested %d bytes, "
			"but only %d bytes received. "
			"Note: this might not indicate an actual short-recv.\n",
			len, ret
		);

	from->recvlen += (size_t)ret;

	return 0;
}

static int do_send(struct gwp_conn *to, char *buf, size_t len)
{
	ssize_t ret;

	ret = send(to->sockfd, buf, len, MSG_NOSIGNAL);
	if (ret < 0) {
		ret = errno;
		if (ret == EAGAIN || ret == EINTR)
			return 0;
		pr_err(
			"failed to send %ld bytes to %s: %s\n",
			to->addrstr, strerror(ret)
		);
		return -ret;
	}

	VT_HEXDUMP(buf, ret);
	if ((size_t)ret != len)
		pr_warn(
			"short send detected: "
			"attempted to send %d bytes, "
			"but only %d bytes were transmitted.\n",
			len, ret
		);

	return ret;
}

static void advance_recvbuff(struct gwp_conn *a, size_t len)
{
	a->recvoff += len;
	a->recvlen -= len;
	if (!a->recvlen)
		a->recvoff = 0;
}

static void advance_sendbuff(struct gwp_conn *a, size_t len)
{
	a->sendoff += len;
	a->sendlen -= len;
	if (!a->sendlen)
		a->sendoff = 0;
}

/*
* Handle incoming and outgoing data.
*
* @param from The source of fetched data.
* @param to The destination of data to be sent.
* @return zero on success, or a negative integer on failure.
*/
static int do_forwarding(struct gwp_conn *from, struct gwp_conn *to)
{
	ssize_t ret;
	size_t rlen;

	/* remaining space of the buffer */
	rlen = from->recvcap - from->recvlen;
	pr_info(
		"attempting to recv from %s with %ld bytes of free space\n",
		from->addrstr, rlen
	);
	if (rlen > 0) {
		ret = do_recv(from, rlen);
		if (ret)
			return ret;
	}

	pr_info(
		"attempting to send %ld bytes to %s\n",
		from->recvlen, to->addrstr
	);
	if (from->recvlen > 0) {
		ret = do_send(to, &from->recvbuf[from->recvoff], from->recvlen);
		if (ret < 0)
			return ret;

		pr_info(
			"%ld bytes were sent to %s\n",
			ret, to->addrstr
		);

		advance_recvbuff(from, ret);
		pr_info(
			"remaining bytes on %s's recv buffer: %ld\n",
			from->addrstr, from->recvlen
		);
	}

	return 0;
}

static int prepare_tcp_serv(struct gwp_tctx *ctx)
{
	struct commandline_args *args;
	uint64_t val;
	int ret;

	args = ctx->pctx->args;
	ret = socket(args->src_addr_st.ss_family, SOCK_STREAM, 0);
	if (ret < 0) {
		ret = errno;
		pr_err(
			"failed to create tcp socket file descriptor: %s\n",
			strerror(ret)
		);
		return ret;
	}

	val = 1;
	setsockopt(ret, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(ret, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
	ctx->tcpfd = ret;

	ret = bind(ret,
		(struct sockaddr *)&args->src_addr_st, sizeof(args->src_addr_st)
	);
	if (ret < 0) {
		ret = errno;
		pr_err(
			"failed to bind tcp socket file descriptor: %s\n",
			strerror(ret)
		);
		goto exit_close_sockfd;
	}

	ret = listen(ctx->tcpfd, SOMAXCONN);
	if (ret < 0) {
		ret = errno;
		pr_err(
			"failed to listen on socket %d: %s\n", ctx->tcpfd,
			strerror(ret)
		);
		goto exit_close_sockfd;
	}

	ret = epoll_create(1);
	if (ret < 0) {
		ret = errno;
		pr_err(
			"failed to create epoll file descriptor: %s\n",
			strerror(ret)
		);
		goto exit_close_sockfd;
	}

	ctx->epfd = ret;

	ret = register_events(ctx->tcpfd, ctx->epfd, EPOLLIN, NULL, GWP_EV_ACCEPT);
	if (ret < 0) {
		ret = errno;
		pr_err(
			"failed to register tcp file descriptor to epoll: %s\n",
			strerror(ret)
		);
		goto exit_close_epfd;
	}

	ret = register_events(ctx->pctx->stopfd, ctx->epfd, EPOLLIN, NULL, GWP_EV_STOP);
	if (ret < 0) {
		ret = errno;
		pr_err(
			"failed to register event file descriptor to epoll: %s\n",
			strerror(ret)
		);
		goto exit_close_epfd;
	}

	return 0;
exit_close_epfd:
	close(ctx->epfd);
exit_close_sockfd:
	close(ctx->tcpfd);
	return -ret;
}

int realloc_container(struct gwp_session_container *c)
{
	int expand_sz = c->capacity * 2;
	void *ptr = realloc(c->sessions, expand_sz * sizeof(c->sessions));
	if (!ptr)
		return -ENOMEM;

	c->sessions = ptr;
	memset(&c->sessions[c->capacity], 0, c->capacity * sizeof(c->sessions));
	c->capacity = expand_sz;

	return 0;
}

int alloc_recv_send_buff(struct gwp_tctx *ctx, struct gwp_pair_conn *s)
{
	struct commandline_args *args;
	struct gwp_conn *c, *t;

	args = ctx->pctx->args;
	c = &s->client;
	t = &s->target;
	c->recvbuf = malloc(args->c_recv_sz);
	if (!c->recvbuf)
		return -ENOMEM;

	c->recvoff = 0;
	c->recvlen = 0;
	c->recvcap = args->c_recv_sz;

	c->sendbuf = malloc(args->c_send_sz);
	if (!c->sendbuf)
		goto exit_free_c_recv;

	c->sendoff = 0;
	c->sendlen = 0;
	c->sendcap = args->c_send_sz;

	t->recvbuf = malloc(args->t_recv_sz);
	if (!t->recvbuf)
		goto exit_free_c_send;

	t->recvoff = 0;
	t->recvlen = 0;
	t->recvcap = args->t_recv_sz;

	t->sendbuf = malloc(args->t_send_sz);
	if (!t->sendbuf)
		goto exit_free_t_recv;

	c->sendoff = 0;
	t->sendlen = 0;
	t->sendcap = args->t_send_sz;

	return 0;
exit_free_t_recv:
	free(t->recvbuf);
exit_free_c_send:
	free(c->sendbuf);
exit_free_c_recv:
	free(c->recvbuf);
	return -ENOMEM;
}

static int alloc_new_session(struct gwp_tctx *ctx, struct sockaddr *in, int cfd)
{
	struct gwp_session_container *container;
	struct commandline_args *args;
	struct gwp_pair_conn *s;
	int ret;

	container = &ctx->container;
	args = ctx->pctx->args;
	if (container->session_nr >= container->capacity) {
		ret = realloc_container(&ctx->container);
		if (ret)
			return ret;
	}

	s = malloc(sizeof(struct gwp_pair_conn));
	if (!s) {
		pr_err("failed to allocate new session\n");
		ret = -ENOMEM;
		goto exit_close_sockfd;
	}

	get_addrstr(in, s->client.addrstr);
	pr_info("client %s on socket %d is accepted\n", s->client.addrstr, cfd);
	s->client.sockfd = cfd;
	s->idx = container->session_nr;

	ret = alloc_recv_send_buff(ctx, s);
	if (ret)
		goto exit_free_s;

	s->client.epmask = EPOLLIN | EPOLLOUT;
	ret = register_events(cfd, ctx->epfd, s->client.epmask, s, GWP_EV_CLIENT);
	if (ret < 0) {
		ret = -errno;
		pr_err("failed to register client to epoll: %s", strerror(-ret));
		goto exit_free_recv_send_buff;
	}

	s->target.epmask = EPOLLIN;
	s->target.sockfd = -1;

	if (args->socks5_mode) {
		s->conn_ctx = socks5_alloc_conn(ctx->pctx->socks5_ctx);
		if (!s->conn_ctx)
			goto exit_free_recv_send_buff;
	} else {
		ret = prepare_forward(ctx, s, &args->dst_addr_st);
		if (ret)
			goto exit_free_recv_send_buff;
	}

	container->sessions[container->session_nr] = s;
	container->session_nr++;

	return 0;
exit_free_recv_send_buff:
	free(s->target.sendbuf);
	free(s->target.recvbuf);
	free(s->client.sendbuf);
	free(s->client.recvbuf);
exit_free_s:
	free(s);
exit_close_sockfd:
	close(cfd);
	return ret;
}

static int accept_new_client(struct gwp_tctx *ctx)
{
	struct sockaddr_in6 in6;
	socklen_t in6_sz;
	int ret;

	in6_sz = sizeof(in6);
	ret = accept4(ctx->tcpfd, &in6, &in6_sz, SOCK_NONBLOCK);
	if (ret < 0) {
		ret = errno;
		pr_err("failed to accept new client: %s\n", strerror(ret));
		return -ret;
	}

	return alloc_new_session(ctx, (struct sockaddr *)&in6, ret);
}

static void _cleanup_pc(struct gwp_tctx *ctx, struct gwp_pair_conn *pc)
{
	if (pc->target.sockfd != -1)
		close(pc->target.sockfd);
	if (ctx->pctx->args->socks5_mode)
		socks5_free_conn(pc->conn_ctx);
	close(pc->client.sockfd);
	free(pc->client.recvbuf);
	free(pc->client.sendbuf);
	free(pc->target.recvbuf);
	free(pc->target.sendbuf);
	free(pc);
}

static void cleanup_pc(struct gwp_tctx *ctx, struct gwp_pair_conn *pc)
{
	pr_info(
		"client %s disconnected, cleaning up its resources\n",
		pc->client.addrstr
	);

	ctx->container.session_nr--;
	ctx->container.sessions[pc->idx] = NULL;
	_cleanup_pc(ctx, pc);
}

static int process_event(struct gwp_tctx *ctx, struct epoll_event *ev)
{
	uint64_t ev_bit;
	void *data;

	// debugging epoll
	// pr_info("epoll event:\n");
	// VT_HEXDUMP(&ev->events, sizeof(uint32_t));
	// pr_info("epoll data:\n");
	// VT_HEXDUMP(&ev->data, sizeof(epoll_data_t));

	ev_bit = GET_EV_BIT(ev->data.u64);
	// debugging epoll
	// pr_dbg("ev bit:\n");
	// VT_HEXDUMP(&ev_bit, 8);

	ev->data.u64 = CLEAR_EV_BIT(ev->data.u64);
	data = ev->data.ptr;
	switch (ev_bit) {
	case GWP_EV_STOP:
		break;
	case GWP_EV_ACCEPT:
		accept_new_client(ctx);
		break;

	default:
		if (ctx->pctx->func_handler(ctx, data, ev_bit, ev->events))
			return -EAGAIN;
	}

	return 0;
}

static void cleanup_tctx(struct gwp_tctx *ctx)
{
	struct gwp_pair_conn *pc;

	pr_info("unfreed resource of session: %d\n", ctx->container.session_nr);
	for (size_t i = 0; i < ctx->container.session_nr; i++) {
		pc = ctx->container.sessions[i];
		if (pc) {
			pr_info("disconnecting %s\n", pc->client.addrstr);
			_cleanup_pc(ctx, pc);
		}
	}

	pr_info("closing TCP socket file descriptor: %d\n", ctx->tcpfd);
	close(ctx->tcpfd);
	pr_info("closing epoll file descriptor: %d\n", ctx->epfd);
	close(ctx->epfd);
	pr_info("deallocate sessions ptr: %p\n", ctx->container.sessions);
	free(ctx->container.sessions);
}

static int start_tcp_serv(struct gwp_tctx *ctx)
{
	struct epoll_event evs[DEFAULT_EPOLL_EV];
	int i, ret, ready_nr;

	pr_info("start serving...\n");
	ret = 0;
	while (!ctx->pctx->stop) {
		ready_nr = epoll_wait(ctx->epfd, evs, DEFAULT_EPOLL_EV, -1);
		if (ready_nr < 0) {
			ret = errno;
			if (ret == EINTR)
				continue;
			pr_err(
				"an error occured on epoll_wait call: %s\n",
				strerror(ret)
			);
			break;
		}

		// debugging epoll
		// pr_info("ready events: %d\n", ready_nr);

		for (i = 0; i < ready_nr; i++) {
			ret = process_event(ctx, &evs[i]);
			if (ret)
				break;
		}
	}

	cleanup_tctx(ctx);
	return ret;
}

static int sp_forward(struct gwp_tctx *ctx, struct gwp_conn *a, struct gwp_conn *b);

static int socks5_handle_target(struct gwp_tctx* ctx)
{
	struct socks5_conn *conn;
	struct gwp_conn *a, *b;
	int ret;

	conn = ctx->pc->conn_ctx;
	a = &ctx->pc->target;
	b = &ctx->pc->client;

	switch (conn->state) {
	case SOCKS5_FORWARDING:
		ret = sp_forward(ctx, a, b);
		if (ret)
			return ret;
		break;
	default:
		pr_dbg("aborted\n");
		abort();
	}

	return 0;
}

static int socks5_do_send(struct gwp_tctx *ctx);

static int socks5_handle_connect(struct gwp_tctx* ctx)
{
	struct sockaddr_storage addr;
	struct socks5_conn *conn;
	struct socks5_request *r;
	struct gwp_conn *a, *b;
	struct socks5_addr sa;
	size_t aslen;
	int ret;

	conn = ctx->pc->conn_ctx;
	a = &ctx->pc->client;
	b = &ctx->pc->target;

	if (b->sockfd == DISCONNECTED) {
		r = (void *)a->recvbuf;
		memcpy(&sa, &r->dst_addr, sizeof(sa));
		socks5_convert_addr(&r->dst_addr, &addr);
		ret = prepare_forward(ctx, ctx->pc, &addr);
		if (ret)
			return ret;

		aslen = a->sendcap;
		ret = socks5_craft_connect_reply(
			conn, &sa, SOCKS5_SUCCEEDED, a->sendbuf, &aslen
		);

		if (ret)
			return ret;

		// fill send buff
		a->sendlen = aslen;
	}

	return socks5_do_send(ctx);
}

static int socks5_do_recv(struct gwp_tctx *ctx)
{
	size_t rlen, aslen, arlen;
	struct socks5_conn *conn;
	struct gwp_conn *a;
	int ret;

	conn = ctx->pc->conn_ctx;
	a = &ctx->pc->client;

	rlen = a->recvcap - a->recvlen;
	pr_info(
		"attempting to recv from %s "
		"with %ld bytes of free space\n",
		a->addrstr, rlen
	);
	ret = do_recv(a, rlen);
	if (ret)
		return ret;

	aslen = a->sendcap;
	arlen = a->recvlen - a->recvoff;
	ret = socks5_process_data(
		conn,
		&a->recvbuf[a->recvoff], &arlen,
		a->sendbuf, &aslen
	);
	if (ret) {
		ret = ret == -EAGAIN ? 0 : ret;
		return ret;
	}

	advance_recvbuff(a, arlen);
	// fill send buff
	a->sendlen += aslen;

	return 0;
}

static int socks5_do_send(struct gwp_tctx *ctx)
{
	int ret;
	struct gwp_conn *a;

	a = &ctx->pc->client;

	ret = do_send(a, &a->sendbuf[a->sendoff], a->sendlen);
	if (ret < 0)
		return ret;

	advance_sendbuff(a, ret);
	return 0;
}

static int socks5_handle_default(struct gwp_tctx* ctx)
{
	struct socks5_conn *conn;
	int ret;

	conn = ctx->pc->conn_ctx;
	ret = socks5_do_recv(ctx);
	if (ret)
		return ret;

	if (conn->state != SOCKS5_CONNECT)
		ret = socks5_do_send(ctx);

	return ret;
}

static int socks5_handle_client(struct gwp_tctx* ctx)
{
	struct socks5_conn *conn;
	struct gwp_conn *a, *b;
	int ret;

	conn = ctx->pc->conn_ctx;
	a = &ctx->pc->client;
	b = &ctx->pc->target;

	switch (conn->state) {
	case SOCKS5_FORWARDING:
		ret = sp_forward(ctx, a, b);
		break;
	case SOCKS5_CONNECT:
		ret = socks5_handle_connect(ctx);
		break;
	default:
		ret = socks5_handle_default(ctx);
	}

	return ret;
}

static int socks5_proxy_handler(struct gwp_tctx *ctx, void *data,
				uint64_t ev_bit, uint32_t ev)
{
	struct gwp_pair_conn *pc = data;
	int ret;

	ctx->pc = pc;
	ctx->epev = ev;

	switch (ev_bit) {
	case GWP_EV_CLIENT:
		ret = socks5_handle_client(ctx);
		if (ret)
			goto terminate_and_recall_epoll_wait;
		break;
	case GWP_EV_TARGET:
		ret = socks5_handle_target(ctx);
		if (ret)
			goto terminate_and_recall_epoll_wait;
		break;
	default:
		pr_dbg("aborted\n");
		abort();
	}

	adjust_events(ctx->epfd, ctx->pc);
	if (pc->conn_ctx->state == SOCKS5_CONNECT) {
		_adjust_pollout(&pc->client, 1);
		ret = mod_events(
			pc->client.sockfd, ctx->epfd, pc->client.epmask, pc, GWP_EV_CLIENT
		);
		if (ret < 0)
			pr_warn("failed to modify event: %s\n", strerror(errno));
	}
	return 0;
terminate_and_recall_epoll_wait:
	cleanup_pc(ctx, pc);
	return -EAGAIN;
}

static int sp_forward(struct gwp_tctx *ctx, struct gwp_conn *a, struct gwp_conn *b)
{
	int ret;
	if (ctx->epev & EPOLLIN) {
		ret = do_forwarding(a, b);
		if (ret)
			return ret;
	}

	if (ctx->epev & EPOLLOUT) {
		ret = do_forwarding(b, a);
		if (ret)
			return ret;
	}

	return 0;
}

static int sp_handler(struct gwp_tctx *ctx, void *data,
			uint64_t ev_bit, uint32_t ev)
{
	struct gwp_conn *a, *b;
	int ret;

	ctx->pc = data;
	ctx->epev = ev;

	a = &ctx->pc->client;
	b = &ctx->pc->target;

	switch (ev_bit) {
	case GWP_EV_CLIENT:
		ret = sp_forward(ctx, a, b);
		if (ret)
			goto terminate_and_recall_epoll_wait;
		break;
	case GWP_EV_TARGET:
		ret = sp_forward(ctx, b, a);
		if (ret)
			goto terminate_and_recall_epoll_wait;
		break;
	default:
		pr_dbg("aborted\n");
		abort();
	}

	adjust_events(ctx->epfd, ctx->pc);
	return 0;
terminate_and_recall_epoll_wait:
	cleanup_pc(ctx, data);
	return -EAGAIN;
}

static int init_container(struct gwp_session_container *container, size_t cap)
{
	container->capacity = cap;
	container->session_nr = 0;
	container->sessions = calloc(cap, sizeof(container->sessions));
	if (!container->sessions)
		return -ENOMEM;

	return 0;
}

static int init_tctx(struct gwp_tctx *tctx, struct gwp_pctx *pctx)
{
	int ret;
	tctx->pctx = pctx;
	ret = init_container(&tctx->container, pctx->args->connptr_nr);
	if (ret < 0)
		return -ENOMEM;
	return prepare_tcp_serv(tctx);
}

static int init_pctx(struct gwp_pctx *pctx, struct commandline_args *args)
{
	struct socks5_cfg cfg;
	int ret;

	ret = eventfd(0, EFD_NONBLOCK);
	if (ret < 0) {
		ret = errno;
		pr_err("failed to create eventfd: %s\n", strerror(ret));
		return -ret;
	}
	pctx->stopfd = ret;
	pctx->stop = false;
	pctx->args = args;
	pctx->tctx = malloc(args->server_thread_nr * sizeof(*pctx->tctx));
	if (!pctx->tctx) {
		close(pctx->stopfd);
		ret = errno;
		pr_err("failed to allocate threads data: %s\n", strerror(ret));
		return -ret;
	}

	ret = 0;
	pctx->func_handler = sp_handler;
	if (args->socks5_mode) {
		cfg.auth_file = args->auth_file;
		ret = socks5_init(&pctx->socks5_ctx, &cfg);
		pctx->func_handler = socks5_proxy_handler;
	}

	return ret;
}

static void *tcp_serv_thread(void *args)
{
	intptr_t ret;

	ret = start_tcp_serv(args);
	return (void *)ret;
}

static int spawn_threads(struct gwp_pctx *ctx)
{
	size_t i, thread_nr;
	int ret;

	thread_nr = ctx->args->server_thread_nr;
	for (i = 0; i < thread_nr; i++) {
		ret = init_tctx(&ctx->tctx[i], ctx);
		if (ret < 0)
			return ret;
	}

	for (i = 0; i < thread_nr; i++) {
		if (i == 0)
			continue;
		pthread_create(
			&ctx->tctx[i].thandle, NULL,
			tcp_serv_thread, &ctx->tctx[i]
		);
	}

	return start_tcp_serv(ctx->tctx);
}

static void join_threads(struct gwp_pctx *ctx)
{
	size_t i, thread_nr;
	intptr_t retval;

	thread_nr = ctx->args->server_thread_nr;
	for (i = 0; i < thread_nr; i++) {
		if (i == 0)
			continue;
		pthread_join(ctx->tctx[i].thandle, (void *)&retval);
	}
}

static void cleanup_resources(struct gwp_pctx *ctx)
{
	join_threads(ctx);

	if (ctx->args->socks5_mode) {
		pr_info("de-initialize socks5 library\n");
		socks5_free_ctx(ctx->socks5_ctx);
	}
	pr_info("deallocate pointer to threads data: %p\n", ctx->tctx);
	free(ctx->tctx);
	pr_info("closing stop file descriptor (eventfd): %d\n", ctx->stopfd);
	close(ctx->stopfd);
}

static void set_buffer_sizes(struct commandline_args *args, struct buff_sz_opt *b)
{
	int c_both_sz, c_recv_sz, c_send_sz, t_both_sz, t_recv_sz, t_send_sz;

	args->c_recv_sz = args->c_send_sz =
	args->t_recv_sz = args->t_send_sz = DEFAULT_BUFF_SZ;
	if (b->c_recv_sz_opt) {
		c_recv_sz = atoi(b->c_recv_sz_opt);
		if (c_recv_sz > 0)
			args->c_recv_sz = c_recv_sz;
	}

	if (b->c_send_sz_opt) {
		c_send_sz = atoi(b->c_send_sz_opt);
		if (c_send_sz > 0)
			args->c_send_sz = c_send_sz;
	}

	if (b->c_both_sz_opt) {
		c_both_sz = atoi(b->c_both_sz_opt);
		if (c_both_sz > 0)
			args->c_recv_sz = args->c_send_sz = c_both_sz;
	}

	if (b->t_recv_sz_opt) {
		t_recv_sz = atoi(b->t_both_sz_opt);
		if (t_recv_sz > 0)
			args->t_recv_sz = t_recv_sz;
	}

	if (b->t_send_sz_opt) {
		t_send_sz = atoi(b->t_both_sz_opt);
		if (t_send_sz > 0)
			args->t_send_sz = t_send_sz;
	}

	if (b->t_both_sz_opt) {
		t_both_sz = atoi(b->t_both_sz_opt);
		if (t_both_sz > 0)
			args->t_recv_sz = args->t_send_sz = t_both_sz;
	}
}

static int set_intval(char *val, int defaultval)
{
	int ival;
	if (val) {
		ival = atoi(val);
	} else
		ival = defaultval;

	return ival;
}

/*
* Handle and initialize command-line arguments.
*
* The function initialize the following configuration:
* - wait time out in seconds
* - server address to be bound
* - target address to connect (in simple tcp proxy mode)
* - auth file (in socks5 proxy mode)
* - control number of tcp server thread
* - size of pre-allocated pointer for connection
*
* @param argc Total argument passed.
* @param argv Pointer to an array of string.
* @param args Pointer to cmdline arguments to initialize.
* @return Zero on success, or a negative integer on failure.
*/
static int handle_cmdline(int argc, char *argv[], struct commandline_args *args)
{
	char *server_thread_opt, *client_nr_opt, *wait_opt;
	char *bind_opt, *target_opt;
	struct buff_sz_opt b;
	char *auth_file_opt;
	int ret;
	char c;

	if (argc == 1) {
		pr_menu();
		return -EXIT_FAILURE;
	}

	client_nr_opt = wait_opt = server_thread_opt = NULL;
	auth_file_opt = bind_opt = target_opt= NULL;
	args->socks5_mode = false;
	memset(&b, 0, sizeof(b));
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
			server_thread_opt = optarg;
			break;
		case 'w':
			wait_opt = optarg;
			break;
		case 'n':
			client_nr_opt = optarg;
			break;
		case 'g':
			b.c_both_sz_opt = optarg;
			break;
		case 'j':
			b.c_recv_sz_opt = optarg;
			break;
		case 'l':
			b.c_send_sz_opt = optarg;
			break;
		case 'y':
			b.t_both_sz_opt = optarg;
			break;
		case 'k':
			b.t_recv_sz_opt = optarg;
			break;
		case 'p':
			b.t_send_sz_opt = optarg;
			break;
		case 'h':
			pr_menu();
			return -EXIT_FAILURE;

		default:
			return -EINVAL;
		}
	}

	if (!target_opt && !args->socks5_mode) {
		pr_err("-t option is required\n");
		return -EINVAL;
	}

	if (!bind_opt) {
		pr_err("-b option is required\n");
		return -EINVAL;
	}

	set_buffer_sizes(args, &b);

	args->auth_file = NULL;
	if (auth_file_opt)
		args->auth_file = auth_file_opt;

	args->connptr_nr = set_intval(client_nr_opt, DEFAULT_PREALLOC_CONN);
	args->server_thread_nr = set_intval(server_thread_opt, DEFAULT_THREAD_NR);
	args->timeout = set_intval(wait_opt, DEFAULT_TIMEOUT_SEC);

	memset(&args->src_addr_st, 0, sizeof(args->src_addr_st));
	ret = init_addr(bind_opt, &args->src_addr_st);
	if (ret < 0) {
		pr_err("invalid format for %s\n", bind_opt);
		return -EINVAL;
	}

	if (args->socks5_mode)
		return 0;

	ret = init_addr(target_opt, &args->dst_addr_st);
	if (ret < 0) {
		pr_err("invalid format for %s\n", target_opt);
		return -EINVAL;
	}

	return 0;
}

static void signal_handler(int code)
{
	uint64_t val;
	switch (code) {
	case SIGTERM:
		pr_info("Program stopped by SIGTERM\n");
		break;
	case SIGINT:
		pr_info("Program stopped by SIGINT\n");
		break;
	}

	gctx->stop = true;
	val = 1;
	write(gctx->stopfd, &val, sizeof(val));
}

static int setfdlimit(void)
{
	struct rlimit file_limit;

	getrlimit(RLIMIT_NOFILE, &file_limit);
	file_limit.rlim_cur = file_limit.rlim_max;
	setrlimit(RLIMIT_NOFILE, &file_limit);
	return errno;
}

int main(int argc, char *argv[])
{
	struct commandline_args args;
	struct gwp_pctx ctx;
	struct sigaction sa = {
		.sa_handler = signal_handler
	};
	int ret;

	ret = handle_cmdline(argc, argv, &args);
	if (ret < 0)
		return ret;

	ret = init_pctx(&ctx, &args);
	if (ret < 0)
		return ret;

	gctx = &ctx;
	ret |= sigaction(SIGTERM, &sa, NULL);
	ret |= sigaction(SIGINT, &sa, NULL);
	if (ret < 0) {
		pr_err("failed to install signal handler\n");
		return ret;
	}

	ret = setfdlimit();
	if (ret < 0) {
		pr_err("failed to setrlimit: %s\n", strerror(ret));
		return -ret;
	}

	ret = spawn_threads(&ctx);
	if (ret < 0)
		return ret;

	cleanup_resources(&ctx);

	pr_info("all system resources were freed\n");

	return EXIT_SUCCESS;
}
