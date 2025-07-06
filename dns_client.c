/*
* DNS client for custom DNS resolver program.
* this program is created to stress-test concurrent connection and request
* to the DNS resolver.
*
* run without any arguments to see the usage.
*
* build without log: make CFLAGS=-DENABLE_LOG=false build/dns_client
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include "linux.h"
#include "general.h"

#define EPOLL_EVENT_NR 512
#define DEFAULT_BUFF_SZ 1024
#define DEFAULT_CONN_NR 100
#define DEFAULT_THREAD_NR 1
#define pr_menu printf(usage, DEFAULT_CONN_NR, DEFAULT_THREAD_NR)

struct net_pkt {
	uint8_t dlen;
	char dname[255];
};

struct connection {
	int tcpfd;
	int idx;
	size_t remaining;
	char buf[DEFAULT_BUFF_SZ];
};

struct connection_pool {
	int connection_nr;
	struct connection **c;
};

struct prog_ctx {
	bool stop;
	char *dname; // TODO: add support for file of list domain name and distribute the domain name evenly to the worker
	char *addrstr;
	uint8_t dnamelen;
	size_t concurrent_nr;
	size_t thread_nr;
	struct sockaddr_storage server_addr;
	struct thrd_ctx *tctx;
};

struct thrd_ctx {
	int epfd;
	pthread_t thandle;
	struct connection_pool cp;
	struct prog_ctx *pctx;
};

static char opts[] = "n:c:t:s:";
static struct prog_ctx *gctx;

static const char usage[] =
"usage: ./dns_client [options]\n"
"-n\tdomain name\n"
"-s\tip:port for server address\n"
"-c\tnumber of concurrent connection per-thread (default %d)\n"
"-t\tnumber of thread (default %d)\n";

static int parse_cmdline_args(int argc, char **argv, struct prog_ctx *ctx)
{
	char c, *dname_opt, *concurrent_opt, *thread_opt, *server_opt;
	size_t dlen;
	int ret, concurrent_nr, thread_nr;

	if (argc == 1)
		return -EXIT_FAILURE;

	dname_opt = concurrent_opt = thread_opt = NULL;
	server_opt = NULL;
	while ((c = getopt(argc, argv, opts)) != -1) {
		switch (c) {
		case 'n':
			dname_opt = optarg;
			break;
		case 'c':
			concurrent_opt = optarg;
			break;
		case 's':
			server_opt = optarg;
			break;
		case 't':
			thread_opt = optarg;
			break;
		}
	}

	if (!dname_opt)
		return -EXIT_FAILURE;

	if (!server_opt)
		return -EXIT_FAILURE;

	ctx->dname = dname_opt;
	dlen = strlen(dname_opt);
	if (dlen < 4) {
		pr_err("domain name too short, minimum is 4 character\n");
		return -EINVAL;
	}
	if (dlen > 255) {
		pr_err("domain name too long, maximum is 255 character\n");
		return -EINVAL;
	}
	ctx->dnamelen = dlen;

	ctx->addrstr = server_opt;
	ret = init_addr(server_opt, &ctx->server_addr);
	if (ret < 0) {
		pr_err(
			"invalid address, accepted format <ip>:<port>, "
			"wrap ip with bracket for IPv6 address\n"
		);
		return -EINVAL;
	}

	if (concurrent_opt)
		concurrent_nr = atoi(concurrent_opt);
	else
		concurrent_nr = DEFAULT_CONN_NR;

	if (concurrent_nr <= 0) {
		pr_err("concurrent number can't be zero or negative.\n");
		return -EINVAL;
	}

	if (thread_opt)
		thread_nr = atoi(thread_opt);
	else
		thread_nr = DEFAULT_THREAD_NR;

	if (thread_nr <= 0) {
		pr_err("thread number can't be zero or negative.\n");
		return -EINVAL;
	}

	ctx->thread_nr = thread_nr;
	ctx->concurrent_nr = concurrent_nr;

	return 0;	
}

static int validate_dname(char *dname)
{
	char *ptr = dname;

	while (*ptr) {
		if (!is_ldh(*ptr))
			return -EXIT_FAILURE;
		ptr++;
	}

	return 0;
}

static void free_connection_pool(struct connection_pool *cp)
{
	int i;
	struct connection *c;

	pr_info("free %d allocated connection\n", cp->connection_nr);
	for (i = 0; i < cp->connection_nr; i++) {
		c = cp->c[i];
		if (c) {
			if (c->tcpfd != -1)
				close(c->tcpfd);
			free(c);
		}
	}
}

static struct connection *allocate_connection(struct thrd_ctx *ctx, int serverfd)
{
	struct connection *c;
	c = malloc(sizeof(*c));
	if (!c) {
		pr_err(
			"not enough memory to allocate "
			"connection struct\n"
		);
		return NULL;
	}
	/*
	* the pool allocation is fixed.
	* depends on number of concurrent request, no need to realloc.
	*/
	c->tcpfd = serverfd;
	c->remaining = 0;
	c->idx = ctx->cp.connection_nr;
	ctx->cp.c[ctx->cp.connection_nr] = c;
	ctx->cp.connection_nr++;

	return c;
}

static int init_connection(struct thrd_ctx *ctx)
{
	int serverfd, ret;
	struct connection *c;
	uint8_t val = 1;
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT
	};
	size_t i;

	pr_info(
		"trying to establish %d concurrent connection to %s\n",
		ctx->pctx->concurrent_nr, ctx->pctx->addrstr
	);

	for (i = 0; i < ctx->pctx->concurrent_nr; i++) {
		serverfd = socket(ctx->pctx->server_addr.ss_family, SOCK_STREAM, 0);
		if (serverfd < 0) {
			pr_err("failed to create TCP socket\n");
			c->tcpfd = -1;
			return -EXIT_FAILURE;
		}
		setsockopt(
			serverfd,
			SOL_SOCKET, SOCK_NONBLOCK,
			&val, sizeof(val)
		);

		ret = connect(
			serverfd,
			(struct sockaddr *)&ctx->pctx->server_addr,
			sizeof(ctx->pctx->server_addr)
		);
		if (ret < 0 && errno != EINPROGRESS) {
			pr_err(
				"failed to connect at %d attempt, reason: %s\n",
				ctx->cp.connection_nr + 1, strerror(errno)
			);
			break;
		}
		c = allocate_connection(ctx, serverfd);
		if (!c)
			return -ENOMEM;

		ev.data.ptr = c;
		ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, serverfd, &ev);
		if (ret < 0) {
			pr_err(
				"failed to register epoll event "
				"on %d attempt\n",
				ctx->cp.connection_nr
			);
			return -EXIT_FAILURE;
		}
	}

	if (!ctx->cp.connection_nr)
		return -EXIT_FAILURE;
	pr_info("%d connection successfully established\n", ctx->cp.connection_nr);

	return 0;
}

static int send_payload(struct thrd_ctx *ctx, struct epoll_event *ev)
{
	struct connection *c = ev->data.ptr;
	int ret;
	struct net_pkt p;
	char *ptr;
	size_t off, pkt_len;

	memcpy(p.dname, ctx->pctx->dname, ctx->pctx->dnamelen);
	p.dlen = ctx->pctx->dnamelen;
	pkt_len = 1 + p.dlen;
	ptr = (void *)&p;
	if (!c->remaining)
		c->remaining = pkt_len;
	off = pkt_len - c->remaining;
	ret = send(c->tcpfd, &ptr[off], c->remaining, MSG_NOSIGNAL);
	if (ret < 0) {
		if (errno == EAGAIN)
			return -EAGAIN;
		pr_err("failed to send data packet to %s\n", ctx->pctx->addrstr);
		return -EXIT_FAILURE;
	}

	c->remaining -= ret;
	if (c->remaining)
		return -EAGAIN;

	ev->events = EPOLLIN;
	epoll_ctl(ctx->epfd, EPOLL_CTL_MOD, c->tcpfd, ev);

	return 0;
}

static int recv_response(struct connection *c)
{
	int ret;
	char *bufptr;

	if (!c->remaining)
		c->remaining = sizeof(c->buf);
	bufptr = &c->buf[sizeof(c->buf) - c->remaining];
	ret = recv(c->tcpfd, bufptr, c->remaining, 0);
	if (ret < 0) {
		if (errno == EAGAIN)
			return -EAGAIN;
		pr_err("failed to receive server's response\n");
		return -EXIT_FAILURE;
	}

	if (!ret) {
		pr_info(
			"connection reset on socket %d by peer\n",
			c->tcpfd
		);
		return 0;
	}

	VT_HEXDUMP(bufptr, ret);

	c->remaining -= ret;
	if (c->remaining)
		return -EAGAIN;

	/*
	* The connection will be closed when the recv buffer
	* is filled with sizeof(c->buf) bytes.
	*/
	return 0;
}

static int make_req(struct thrd_ctx *ctx, struct epoll_event *ev)
{
	struct connection *c = ev->data.ptr;
	int ret;

	if (ev->events & EPOLLOUT) {
		ret = send_payload(ctx, ev);
		if (ret < 0) {
			if (ret == -EAGAIN)
				return 0;
			goto exit_close;
		}
	}

	ret = recv_response(c);
	if (ret == -EAGAIN)
		return 0;

exit_close:
	pr_info(
		"disconnected from %s on socket file descriptor %d\n",
		ctx->pctx->addrstr, c->tcpfd
	);
	close(c->tcpfd);
	ctx->cp.c[c->idx] = NULL;
	ctx->cp.connection_nr--;
	free(c);
	return ret;
}

static int start_event_loop(struct thrd_ctx *ctx)
{
	int i, ret, ready_nr;
	struct epoll_event evs[EPOLL_EVENT_NR];
	struct epoll_event *ev;

	ctx->epfd = epoll_create(1);
	if (!ctx->epfd) {
		pr_err("failed to create epoll file descriptor\n");
		return -EXIT_FAILURE;
	}

	ctx->cp.c = calloc(ctx->pctx->concurrent_nr, sizeof(ctx->cp.c));
	if (!ctx->cp.c) {
		pr_err("not enough memory to pre-allocate pool\n");
		ret = -EXIT_FAILURE;
		goto exit_close_epfd;
	}

	ret = init_connection(ctx);
	if (ret < 0) {
		goto exit_terminate_connection;
	}

	while (!ctx->pctx->stop) {
		ready_nr = epoll_wait(ctx->epfd, evs, EPOLL_EVENT_NR, -1);
		if (ready_nr < 0) {
			if (errno == EINTR)
				continue;
			goto exit_terminate_connection;
		}
		for (i = 0; i < ready_nr; i++) {
			ev = &evs[i];
			ret = make_req(ctx, ev);
			if (ret < 0)
				goto exit_terminate_connection;
		}
		if (!ctx->cp.connection_nr)
			goto exit_free_pool;
	}

	ret = 0;
exit_terminate_connection:
	free_connection_pool(&ctx->cp);
exit_free_pool:
	pr_info("free the connection pool\n");
	free(ctx->cp.c);
exit_close_epfd:
	pr_info("close epoll file descriptor\n");
	close(ctx->epfd);
	return ret;
}

static void init_tctx(struct thrd_ctx *tctx, struct prog_ctx *pctx)
{
	tctx->cp.connection_nr = 0;
	tctx->pctx = pctx;
}

static void init_pctx(struct prog_ctx *ctx)
{
	gctx = ctx;
	ctx->stop = false;

	memset(&ctx->server_addr, 0, sizeof(ctx->server_addr));
}

static void signal_handler(int c)
{
	pr_info("interrupt signal received, exiting program...\n");
	gctx->stop = true;
	(void)c;
}

static void *worker(void *args)
{
	intptr_t ret;
	struct thrd_ctx *ctx = args;

	ret = start_event_loop(ctx);
	return (void *)ret;
}

static int spawn_threads(struct prog_ctx *ctx)
{
	size_t i;

	struct thrd_ctx *tc = malloc(sizeof(*tc) * ctx->thread_nr);
	if (!tc)
		return -ENOMEM;
	ctx->tctx = tc;

	for (i = 0; i < ctx->thread_nr; i++) {
		init_tctx(&tc[i], ctx);
		if (i == 0)
			continue;
		pthread_create(&tc[i].thandle, NULL, worker, &tc[i]);
	}

	return start_event_loop(&tc[0]);
}

int main(int argc, char **argv)
{
	intptr_t retval;
	int ret;
	struct prog_ctx ctx;
	struct sigaction sa = {
		.sa_handler = signal_handler
	};

	init_pctx(&ctx);

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	ret = parse_cmdline_args(argc, argv, &ctx);
	if (ret < 0) {
		if (ret == -EXIT_FAILURE)
			pr_menu;
		return -EXIT_FAILURE;
	}

	ret = validate_dname(ctx.dname);
	if (ret < 0) {
		pr_err("invalid domain name\n");
		return -EXIT_FAILURE;
	}
	
	ret = spawn_threads(&ctx);
	
	for (size_t i = 0; i < ctx.thread_nr; i++) {
		if (i == 0)
			continue;
		pthread_join(ctx.tctx[i].thandle, (void **)&retval);
	}
	pr_info("free memory of thread pool: %p\n", ctx.tctx);
	free(ctx.tctx);

	return ret;
}