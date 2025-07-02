/*
* TCP server program that will act as DNS resolver.
*
* each client can send a domain name and the server will simply reply
* the request with IP address of given domain name.
*
* The communication protocol is simple, the client MUST send the packet
* in the following format:
* +----+----------+----------+
* | LENGTH | DOMAIN NAME STR |
* +----+----------+----------+
* |   1    |     4 to 255    |
* +----+----------+----------+
*
* to be recognized as a valid domain name,
* only letter-digit-hypen are allowed in the domain name string.
*
* to store the log to a file, just use your shell's built-in redirect feature.
* redirect it to /dev/null to disable logging
* or build the program with -DENABLE_LOG=false if you prefer smol binary:
* make CFLAGS=-DENABLE_LOG=false build/dns_resolver
*
* all level of log (info, warning, error, debug) are enabled by default,
* if you want to enable only one, just filter it with grep or something.
*/

#define _GNU_SOURCE // somehow gettid and getopt require this constant.
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include "general.h"

#ifndef ENABLE_LOG
#define ENABLE_LOG true
#endif

#define DEFAULT_NR_EVENTS 512
#define DEFAULT_CAPACITY 512
#define MAX_CLIENT_BUFFER 256

#define INFO 1
#define WARN 2
#define ERROR 3
#define DEBUG 4

#if ENABLE_LOG
#define pr_log(LVL, FMT, ...) 				\
do {							\
	if (ENABLE_LOG)					\
		__pr_log(LVL, FMT, ##__VA_ARGS__);	\
} while (0);

static void generate_current_time(char *buf)
{
	time_t rawtime;
	struct tm timeinfo;

	time(&rawtime);
	localtime_r(&rawtime, &timeinfo);
	asctime_r(&timeinfo, buf);
	buf[26 - 2] = '\0';
}

static void __pr_log(unsigned lvl, const char *fmt, ...)
{
	/*
	* asctime(3): atleast 26 bytes of buffer is provided
	* 24 ascii character + newline + null terminated bytes.
	*/
	char human_readable_time[26] = {0};
	const char *level;
	pid_t tid;

	static const char *info = "info";
	static const char *warn = "warning";
	static const char *err = "error";
	static const char *dbg = "debug";

	va_list args;
	va_start(args, fmt);

	switch (lvl) {
	case INFO:
		level = info;
		break;
	case WARN:
		level = warn;
		break;
	case ERROR:
		level = err;
		break;
	case DEBUG:
		level = dbg;
		break;
	}

	tid = gettid();
	generate_current_time(human_readable_time);
	/*
	* the log format is consist of:
	* - current timestamp in human-readable form
	* - process identifier
	* - log level
	*/
	fprintf(
		stderr,
		"[%s] [%d] %s: ",
		human_readable_time, tid, level
	);
	vfprintf(stderr, fmt, args);
	va_end(args);
}
#else 
#define pr_log(LVL, FMT, ...)
#endif

#define pr_dbg(FMT, ...) pr_log(DEBUG, FMT, ##__VA_ARGS__)
#define pr_info(FMT, ...) pr_log(INFO, FMT, ##__VA_ARGS__)
#define pr_warn(FMT, ...) pr_log(WARN, FMT, ##__VA_ARGS__)
#define pr_err(FMT, ...) pr_log(ERROR, FMT, ##__VA_ARGS__)

enum communication_state {
	RECV_PAYLOAD,
	SEND_REPLY,
	TRY_RESOLVE_ADDR
};

struct net_pkt {
	uint8_t domainlen;
	char buff[MAX_CLIENT_BUFFER - 1];
};

struct client {
	int clientfd;
	char addrstr[ADDRSTR_SZ];
	unsigned idx;
	unsigned blen;
	unsigned boff;
	enum communication_state state;
	uint32_t epmask;
	bool is_valid_req;
	char buff[MAX_CLIENT_BUFFER];
};

struct client_pool {
	size_t nr_client;
	size_t cap;
	struct client **clients;
};

/*
* application data.
*/
struct dctx {
	/* local address and port for socket to be bound */
	struct sockaddr_storage d;
	/* main TCP socket file descriptor */
	int serverfd;
	/* a container of client data */
	struct client_pool cp;
	/* epoll file descriptor */
	int epfd;
	/* eventfd file descriptor */
	int evfd;
	/* flag to stop the program */
	bool stop;
};

/* allow signal handler to access application data. */
static struct dctx *gctx;

static const char wait_msg[] =
"wait a minute, "
"I will try to resolve the domain and back to you later\n";

static const char error_msg[] =
"the payload doesn't conform with "
"LDH rule, request aborted.";

static void print_usage(void)
{
	printf("usage: ./dns_resolver [options]\n");
	printf("-b <local address>:<local port> for socket to be bound\n");
}

static int parse_cmdline_args(int argc, char **argv, struct dctx *ctx)
{
	static const char opts[] = "b:";
	char c, *bind_arg = NULL;

	if (argc == 1)
		goto print_usage_n_exit;

	while ((c = getopt(argc, argv, opts)) != -1) {
		switch (c) {
		case 'b':
			bind_arg = optarg;
			break;

		default:
			goto print_usage_n_exit;
		}
	}

	if (!bind_arg)
		goto print_usage_n_exit;

	if (init_addr(bind_arg, &ctx->d) < 0)
		return -1;

	return 0;
print_usage_n_exit:
	print_usage();
	return -1;
}

static int init_ctx(struct dctx *ctx)
{
	memset(&ctx->d, 0, sizeof(ctx->d));
	ctx->cp.cap = DEFAULT_CAPACITY;
	ctx->stop = false;
	ctx->cp.nr_client = 0;
	ctx->cp.clients = calloc(DEFAULT_CAPACITY, sizeof(ctx->cp.clients));
	if (!ctx->cp.clients) {
		pr_err("not enough memory, failed to allocate client pool\n");
		return -ENOMEM;
	}

	return 0;
}

static int realloc_pool(struct client_pool *cp)
{
	unsigned next_cap = cp->cap * 2;
	void *tmp;
	tmp = realloc(cp->clients, next_cap * sizeof(cp->clients));
	if (!tmp) {
		pr_err("failed to resize the client pool\n");
		return -ENOMEM;
	}
	cp->clients = tmp;
	memset(&cp->clients[cp->cap], 0, cp->cap * sizeof(cp->clients));
	cp->cap = next_cap;

	return 0;
}

static struct client *init_client(struct dctx *ctx)
{
	struct client *c;
	unsigned idx;
	int ret;

	idx = ctx->cp.nr_client;
	if (++ctx->cp.nr_client > ctx->cp.cap) {
		ret = realloc_pool(&ctx->cp);
		if (ret < 0) {
			pr_err(
				"not enough memory, "
				"failed to re-allocate client pool\n"
			);
			goto exit_err;
		}
	}

	c = malloc(sizeof(*c));
	if (!c) {
		pr_err("not enough memory, failed to allocate client data\n");
		goto exit_err;
	}

	c->clientfd = -1;
	c->is_valid_req = true;
	c->state = RECV_PAYLOAD;
	c->epmask = EPOLLIN;
	c->idx = idx;
	c->blen = 0;
	c->boff = 0;
	ctx->cp.clients[idx] = c;
	return c;
exit_err:
	ctx->cp.nr_client--;
	return NULL;
}

static void serve_incoming_client(struct dctx *ctx)
{
	struct client *c;
	struct epoll_event ev;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int ret;

	c = init_client(ctx);
	if (!c)
		return;

	addrlen = sizeof(addr);
	c->clientfd = accept4(
		ctx->serverfd,
		(struct sockaddr *)&addr, &addrlen,
		SOCK_NONBLOCK
	);
	if (c->clientfd < 0) {
		pr_err("failed to accept new client\n");
		goto exit_err;
	}

	get_addrstr((struct sockaddr *)&addr, addrlen, c->addrstr);
	pr_info(
		"new client %s accepted with sockfd %d\n",
		c->addrstr, c->clientfd
	);

	ev.events = c->epmask;
	ev.data.ptr = c;
	ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, c->clientfd, &ev);
	if (ret < 0) {
		pr_err("failed to register events for new client\n");
		goto exit_close;
	}

	return;
exit_close:
	close(c->clientfd);
exit_err:
	free(c);
	ctx->cp.nr_client--;
	return;
}

static void cleanup_client(struct dctx *ctx, struct client *c)
{
	close(c->clientfd);
	ctx->cp.clients[c->idx] = NULL;
	ctx->cp.nr_client--;
	free(c);
}

static int send_wrapper(int sockfd, const void *buf, size_t len)
{
	int ret;
	ret = send(sockfd, buf, len, MSG_NOSIGNAL);
	return ret;
}

static void talk_to_client(struct dctx *ctx, struct epoll_event *ev)
{
	struct client *c = ev->data.ptr;
	struct net_pkt *pkt = (void *)c->buff;
	int i, ret, rlen;

	/*
	* if the client closing the connection,
	* EPOLLIN event will always fired (waiting the program to read EoF)
	* until either the socket file descriptor is closed
	* or EPOLLIN event is unregistered from epoll interest list
	* thus we need to always recv if EPOLLIN triggered.
	*/
	if (c->state == RECV_PAYLOAD || (ev->events & EPOLLIN)) {
		rlen = MAX_CLIENT_BUFFER - c->blen;
		ret = recv(c->clientfd, &c->buff[c->blen], rlen, 0);
		if (ret < 0) {
			if (ret == EAGAIN)
				return;
			pr_err(
				"an error occured while receiving "
				"packet from client %s\n",
				c->addrstr
			);
			goto terminate_session;
		}

		if (ret == 0) {
			pr_info(
				"client %s disconnected\n",
				c->addrstr
			);
			goto terminate_session;
		}

		c->blen += ret;

		VT_HEXDUMP(pkt, c->blen);

		/*
		* the shortest domain name I can think of: x.me
		* which is four character.
		*/
		if (pkt->domainlen < 4)
			goto terminate_session;

		if ((c->blen - 1) < pkt->domainlen) {
			pr_warn("short recv detected, waiting more data from client %s\n", c->addrstr);
			return;
		}

		c->state = SEND_REPLY;
	}

	if (c->state == SEND_REPLY) {
		size_t remaining;
		for (i = 0; i < pkt->domainlen; i++) {
			if (!is_ldh(pkt->buff[i])) {
				c->is_valid_req = false;
				break;
			}
		}

		if (c->is_valid_req) {
			if (!c->boff)
				c->boff = sizeof(wait_msg);
			remaining = sizeof(wait_msg) - c->boff;
			ret = send_wrapper(c->clientfd, &wait_msg[remaining], c->boff);
		} else {
			if (!c->boff)
				c->boff = sizeof(error_msg);
			remaining = sizeof(error_msg) - c->boff;
			ret = send_wrapper(c->clientfd, &error_msg[remaining], c->boff);
		}

		if (ret < 0) {
			if (errno == EAGAIN)
				return;
			pr_err(
				"an error occured while sending "
				"packet to client %s\n",
				c->addrstr
			);
			goto terminate_session;
		}

		c->boff -= ret;
		if (c->boff) {
			pr_warn(
				"short send detected, retrying to send "
				"remaining data to client %s\n",
				c->addrstr
			);
			return;
		}

		c->state = TRY_RESOLVE_ADDR;
	}

	if (c->state == TRY_RESOLVE_ADDR) {
	}

	return;
terminate_session:
	cleanup_client(ctx, c);
	return;
}

static void adjust_client_pollout(struct client *c, bool *changed)
{
	if (c->boff > 0) {
		if (!(c->epmask & EPOLLOUT)) {
			c->epmask |= EPOLLOUT;
			*changed = true;
		}
	} else {
		if (c->epmask & EPOLLOUT) {
			c->epmask &= ~EPOLLOUT;
			*changed = true;
		}
	}
}

static int adjust_client_events(struct dctx *ctx, struct client *c)
{
	int ret;
	struct epoll_event ev;
	bool is_client_changed = false;

	/*
	* There’s no need to rearm the client's POLLIN event.
	* If the client’s receive buffer is full and it keeps sending data,
	* the server will ignore the extra bytes
	* and close the connection automatically.
	*/
	adjust_client_pollout(c, &is_client_changed);

	if (is_client_changed) {
		ev.data.ptr = c;
		ev.events = c->epmask;
		ret = epoll_ctl(ctx->epfd, EPOLL_CTL_MOD, c->clientfd, &ev);
		if (ret < 0) {
			pr_err(
				"failed to modify epoll events on client %s\n",
				c->addrstr
			);
			return -EXIT_FAILURE;
		}
	}

	return 0;
}

static int fish_events(struct dctx *ctx)
{
	int nr_events, ret, i;
	struct epoll_event evs[DEFAULT_NR_EVENTS];
	struct epoll_event *ev;
	uint64_t evbuf;

	nr_events = epoll_wait(ctx->epfd, evs, DEFAULT_NR_EVENTS, -1);
	if (nr_events < 0) {
		if (errno == EINTR)
			return 0;
		pr_err("an error occured while waiting in epoll_wait\n");
		return -EXIT_FAILURE;
	}

	for (i = 0; i < nr_events; i++) {
		ev = &evs[i];
		if (ev->data.fd == ctx->evfd) {
			ret = read(ctx->evfd, &evbuf, sizeof(evbuf));
			if (ret < 0) {
				pr_err("failed to read buffer from evfd\n");
				return -EXIT_FAILURE;
			}

			/*
			* The system deliver SIGTERM or SIGINT,
			* the program MUST stop the event loop.
			*/
			if (evbuf == 1)
				return 0;

			continue;
		}

		if (ev->data.fd == ctx->serverfd)
			serve_incoming_client(ctx);
		else {
			talk_to_client(ctx, ev);
			adjust_client_events(ctx, ev->data.ptr);
		}
	}

	return 0;
}

static void terminate_clients(struct dctx *ctx)
{
	struct client *c;
	size_t i;

	if (!ctx->cp.nr_client)
		return;
	
	pr_info(
		"there are %d client(s) still connected to the server, "
		"let's free them\n",
		ctx->cp.nr_client
	);

	for (i = 0; i < ctx->cp.cap; i++) {
		c = ctx->cp.clients[i];
		if (!c)
			continue;

		pr_info(
			"free memory resource allocated for client %s\n",
			c->addrstr
		);
		free(c);
	}
}

static int start_event_loop(struct dctx *ctx)
{
	struct epoll_event ev;
	int ret = -1;
	ctx->epfd = epoll_create(1);
	if (ctx->epfd < 0) {
		pr_err("failed to create epoll instance\n");
		goto exit_err;
	}

	ev.events = EPOLLIN;
	ev.data.fd = ctx->serverfd;
	ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->serverfd, &ev);
	if (ret < 0) {
		pr_err("failed to register events for serverfd\n");
		goto exit_close_epfd;
	}

	ctx->evfd = eventfd(0, EFD_NONBLOCK);
	if (ctx->evfd < 0) {
		pr_err("failed to create eventfd\n");
		goto exit_close_epfd;
	}
	ev.events = EPOLLIN;
	ev.data.fd = ctx->evfd;
	ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->evfd, &ev);
	if (ret < 0) {
		pr_err("failed to register events for eventfd\n");
		goto exit_close_evfd;
	}

	while (!ctx->stop) {
		ret = fish_events(ctx);
		if (ret < 0)
			goto exit_cleanup_client;
	}

	ret = 0;
exit_cleanup_client:
	terminate_clients(ctx);
	pr_info("free client pool: %p\n", ctx->cp.clients);
	free(ctx->cp.clients);
exit_close_evfd:
	pr_info("closing eventfd file descriptor: %d\n", ctx->evfd);
	close(ctx->evfd);
exit_close_epfd:
	pr_info("closing epoll file descriptor: %d\n", ctx->epfd);
	close(ctx->epfd);
exit_err:
	return ret;
}

static int start_server(struct dctx *ctx)
{
	int ret = -1;
	const int val = 1;

	ctx->serverfd = socket(ctx->d.ss_family, SOCK_STREAM, 0);
	if (ctx->serverfd < 0) {
		pr_err("failed to create TCP socket\n");
		goto exit_failure;
	}

	setsockopt(ctx->serverfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	ret = bind(ctx->serverfd, (struct sockaddr *)&ctx->d, sizeof(ctx->d));
	if (ret < 0) {
		pr_err("failed to bind the socket\n");
		goto exit_close;
	}

	ret = listen(ctx->serverfd, SOMAXCONN);
	if (ret < 0) {
		pr_err("failed to listen\n");
		goto exit_close;
	}

	ret = start_event_loop(ctx);
	if (ret < 0) {
		pr_err("failed to start event loop\n");
		goto exit_close;
	}

exit_close:
	pr_info("closing main tcp file descriptor: %d\n", ctx->serverfd);
	close(ctx->serverfd);
exit_failure:
	return ret;
}

static void signal_handler(int c)
{
	const uint64_t n = 1;
	if (gctx->evfd == -1)
		return;

	switch (c) {
	case SIGINT:
		pr_info("interrupt signal received\n");
		break;
	case SIGTERM:
		pr_info("termination signal received\n");
		break;
	}

	gctx->stop = true;
	write(gctx->evfd, &n, sizeof(n));
}

int main(int argc, char **argv)
{
	int ret;
	struct dctx ctx;
	struct sigaction sa = {
		.sa_handler = signal_handler
	};

	ret = init_ctx(&ctx);
	if (ret < 0)
		return -EXIT_FAILURE;

	ret = parse_cmdline_args(argc, argv, &ctx);
	if (ret < 0) {
		pr_err("failed to parse command-line arguments\n");
		return -EXIT_FAILURE;
	}

	gctx = &ctx;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	ret = start_server(&ctx);
	if (ret < 0) {
		pr_err("failed to start TCP server\n");
		return -EXIT_FAILURE;
	}

	pr_info(
		"all system resources were freed. "
		"now the program exit gracefully, "
		"transfer control back to the kernel.\n"
	);

	return 0;
}
