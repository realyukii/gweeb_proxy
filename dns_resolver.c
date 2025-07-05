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
* the server then will reply with allowed or denied message
*
* if not allowed, the server wil close the connection after sending denied message.
*
* if allowed, and domain name is successfuly resolved,
* the server will reply with human-readable address (either IPv4 or IPv6).
* and close the connection.
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
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include "linux.h"
#include "general.h"

#define DEFAULT_EVENTS_NR 512
#define DEFAULT_THREAD_NR 2
#define DEFAULT_CAPACITY 512
#define MAX_CLIENT_BUFFER 256

#define pr_menu printf(usage, DEFAULT_THREAD_NR);

enum communication_state {
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

struct dns_req {
	char domainname[MAX_CLIENT_BUFFER - 1];
	char addrstr[INET6_ADDRSTRLEN];
	int evfd;
	int sockfd;
	struct dns_req *next;
};

struct dns_queue {
	struct dns_req *head;
	struct dns_req *tail;
};

/*
* application data.
*/
struct dctx {
	/* local address and port for socket to be bound */
	struct sockaddr_storage d;
	/* number of thread that serve TCP connection */
	int thread_nr;
	/* flag to stop the program */
	bool stop;
	/* a pointer to the pool of thread data */
	struct tctx *tc;
	struct dns_queue dqueue;
	/* pthread handle for dns thread */
	pthread_t dns_thandle;
	/* pthread mutex lock for dns thread */
	pthread_mutex_t dns_lock;
	/* pthread cond for dns thread */
	pthread_cond_t dns_cond;
};

/*
* thread-specific data.
*/
struct tctx {
	/* pthread handle */
	pthread_t handle;
	/* main TCP socket file descriptor */
	int serverfd;
	/* a container of client data */
	struct client_pool cp;
	/* epoll file descriptor */
	int epfd;
	/* eventfd file descriptor */
	int evfd;
	/* a pointer to the application data */
	struct dctx *dc;
};

/* allow signal handler to access application data. */
static struct dctx *gctx;

static const char wait_msg[] =
"wait a minute, "
"I will try to resolve the domain and back to you later\n";

static const char error_msg[] =
"the payload doesn't conform with "
"LDH rule, request aborted.";

static const char fail_msg[] = "the server can't resolve requested domain";

static const char usage[] =
"usage: ./dns_resolver [options]\n"
"-b <local address>:<local port> for socket to be bound\n"
"-t number of thread for serving incoming client (default %d)\n";

static int parse_cmdline_args(int argc, char **argv, struct dctx *ctx)
{
	static const char opts[] = "b:t:";
	int thread_nr;
	char c, *bind_arg, *thread_opt;

	if (argc == 1)
		goto print_usage_n_exit;
	
	thread_opt = bind_arg = NULL;
	while ((c = getopt(argc, argv, opts)) != -1) {
		switch (c) {
		case 'b':
			bind_arg = optarg;
			break;
		case 't':
			thread_opt = optarg;
			break;

		default:
			goto print_usage_n_exit;
		}
	}

	if (!bind_arg)
		goto print_usage_n_exit;

	if (thread_opt)
		thread_nr = atoi(thread_opt);
	else
		thread_nr = DEFAULT_THREAD_NR;

	if (thread_nr <= 0) {
		pr_err("thread number can't be zero or negative.\n");
		return -EINVAL;
	}
	ctx->thread_nr = thread_nr;

	if (init_addr(bind_arg, &ctx->d) < 0)
		return -EINVAL;

	return 0;
print_usage_n_exit:
	pr_menu;
	return -EXIT_FAILURE;
}

static struct dns_req *init_dns_req(struct net_pkt *p)
{
	struct dns_req *r;
	r = malloc(sizeof(*r));
	pr_dbg("new queue item initialized: %p\n", r);
	if (!r)
		return NULL;

	strncpy(r->domainname, p->buff, p->domainlen);
	r->domainname[p->domainlen] = '\0';
	r->next = NULL;

	return r;
}

static void enqueue_dns(struct dns_queue *q, struct dns_req *r)
{
	pr_dbg("enqueue item %p\n", r);
	if (!q->head) {
		/* when queue empty, init the queue */
		q->tail = q->head = r;
	} else {
		/*
		* when queue is not empty, push new item.
		* the head  == the tail
		*/
		q->tail->next = r;
		/*
		* grow the tail by shift it.
		* the head  != the tail
		*/
		q->tail = r;
	}
}

static void dequeue_dns(struct dns_queue *q)
{
	/* pop the earliest item from the queue */
	struct dns_req *r = q->head;
	if (!r)
		return;

	pr_dbg("dequeue item %p\n", r);

	q->head = r->next;

	if (!q->head)
		q->tail = NULL;

	free(r);
}

static int init_thread_ctx(struct tctx *tc)
{
	tc->cp.cap = DEFAULT_CAPACITY;
	tc->cp.nr_client = 0;
	tc->cp.clients = calloc(DEFAULT_CAPACITY, sizeof(tc->cp.clients));
	if (!tc->cp.clients) {
		pr_err("not enough memory, failed to allocate client pool\n");
		return -ENOMEM;
	}

	return 0;
}

static int init_main_ctx(struct dctx *dc)
{
	memset(&dc->d, 0, sizeof(dc->d));
	dc->stop = false;
	dc->dqueue.head = NULL;
	pthread_cond_init(&dc->dns_cond, NULL);
	pthread_mutex_init(&dc->dns_lock, NULL);

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

static struct client *init_client(struct tctx *ctx)
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
	c->state = SEND_REPLY;
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

static void serve_incoming_client(struct tctx *ctx)
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

static void cleanup_client(struct tctx *ctx, struct client *c)
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

static int read_payload(struct client *c)
{
	struct net_pkt *pkt = (void *)c->buff;
	int ret, rlen;

	rlen = MAX_CLIENT_BUFFER - c->blen;
	ret = recv(c->clientfd, &c->buff[c->blen], rlen, 0);
	if (ret < 0) {
		if (ret == EAGAIN)
			return -EAGAIN;
		pr_err(
			"an error occured while receiving "
			"packet from client %s\n",
			c->addrstr
		);
		return -EXIT_FAILURE;
	}

	if (ret == 0) {
		pr_info(
			"client %s disconnected\n",
			c->addrstr
		);
		return -EXIT_FAILURE;
	}

	c->blen += ret;

	VT_HEXDUMP(pkt, c->blen);

	/*
	* the shortest domain name I can think of: x.me
	* which is four character.
	*/
	if (pkt->domainlen < 4)
		return -EXIT_FAILURE;

	if ((c->blen - 1) < pkt->domainlen) {
		pr_warn(
			"short recv detected, "
			"waiting more data from client %s\n",
			c->addrstr
		);
		return -EAGAIN;
	}

	return 0;
}

static int send_hello(struct client *c)
{
	struct net_pkt *pkt = (void *)c->buff;
	int i, ret;

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
			return -EAGAIN;
		pr_err(
			"an error occured while sending "
			"packet to client %s\n",
			c->addrstr
		);
		return -EXIT_FAILURE;
	}

	c->boff -= ret;
	if (c->boff) {
		pr_warn(
			"short send detected, retrying to send "
			"remaining data to client %s\n",
			c->addrstr
		);
		return -EAGAIN;
	}

	c->state = TRY_RESOLVE_ADDR;
	return 0;
}

static int request_addr(struct client *c, struct tctx *ctx)
{
	struct net_pkt *pkt = (void *)c->buff;
	struct dns_req *r = init_dns_req(pkt);
	if (!r)
		return -ENOMEM;

	r->evfd = ctx->evfd;
	r->sockfd = c->clientfd;
	pr_dbg("attempting to lock dns_lock\n");
	pthread_mutex_lock(&ctx->dc->dns_lock);
	pr_dbg("acquired dns_lock\n");
	enqueue_dns(&ctx->dc->dqueue, r);
	pr_dbg("sending request to the dns resolver thread\n");
	pthread_cond_signal(&ctx->dc->dns_cond);
	pr_dbg("releasing dns_lock\n");
	pthread_mutex_unlock(&ctx->dc->dns_lock);

	return 0;
}

static void talk_to_client(struct tctx *ctx, struct epoll_event *ev)
{
	int ret;
	struct client *c = ev->data.ptr;

	/*
	* if the client closing the connection,
	* EPOLLIN event will always fired (waiting the program to read EoF)
	* until either the socket file descriptor is closed
	* or EPOLLIN event is unregistered from epoll interest list
	* thus we need to always recv if EPOLLIN triggered.
	*/
	if (ev->events & EPOLLIN) {
		ret = read_payload(c);
		if (ret < 0) {
			if (ret == -EAGAIN)
				return;
			goto terminate_session;
		}
	}

	if (c->state == SEND_REPLY) {
		ret = send_hello(c);
		if (ret < 0) {
			if (ret == -EAGAIN)
				return;
			goto terminate_session;
		}
	}

	if (c->state == TRY_RESOLVE_ADDR) {
		ret = request_addr(c, ctx);
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

static int adjust_client_events(struct tctx *ctx, struct client *c)
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

static int fish_events(struct tctx *ctx)
{
	int nr_events, ret, i;
	struct epoll_event evs[DEFAULT_EVENTS_NR];
	struct epoll_event *ev;
	uint64_t evbuf;

	nr_events = epoll_wait(ctx->epfd, evs, DEFAULT_EVENTS_NR, -1);
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


			pr_dbg("attempting to lock dns_lock\n");
			pthread_mutex_lock(&ctx->dc->dns_lock);
			pr_dbg("acquired dns_lock\n");
			if (evbuf == 2) {
				pr_dbg("resolved address: %s\n", ctx->dc->dqueue.head->addrstr);
				send(
					ctx->dc->dqueue.head->sockfd,
					"success", 8,
					MSG_NOSIGNAL
				);
			}

			if (evbuf == 3) {
				send(
					ctx->dc->dqueue.head->sockfd,
					fail_msg, sizeof(fail_msg),
					MSG_NOSIGNAL
				);
			}

			dequeue_dns(&ctx->dc->dqueue);
			pr_dbg("releasing dns_lock\n");
			pthread_mutex_unlock(&ctx->dc->dns_lock);
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

static void terminate_clients(struct tctx *ctx)
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

static int start_event_loop(struct tctx *ctx)
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

	while (!ctx->dc->stop) {
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

static int start_server(struct tctx *ctx)
{
	int ret = -1;
	const int val = 1;

	ret = init_thread_ctx(ctx);
	if (ret < 0)
		goto exit_failure;

	ctx->serverfd = socket(ctx->dc->d.ss_family, SOCK_STREAM, 0);
	if (ctx->serverfd < 0) {
		pr_err("failed to create TCP socket\n");
		goto exit_failure;
	}

	setsockopt(ctx->serverfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(ctx->serverfd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));

	ret = bind(
		ctx->serverfd,
		(struct sockaddr *)&ctx->dc->d, sizeof(ctx->dc->d)
	);
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

static void *serve_client_thread(void *args)
{
	struct tctx *ctx = args;
	int ret;
	ret = start_server(ctx);

	return (void *)(uintptr_t)ret;
}

int resolve_dns(struct dns_req *req)
{
	struct addrinfo *l;
	int ret;
	
	ret = getaddrinfo(req->domainname, NULL, NULL, &l);
	if (ret != 0) {
		pr_err(
			"failed to resolve domain name: %s\n",
			gai_strerror(ret)
		);
		return -EXIT_FAILURE;
	}

	get_addrstr(l->ai_addr, l->ai_addrlen, req->addrstr);
	VT_HEXDUMP(req, sizeof(*req));
	freeaddrinfo(l);

	return 0;
}

static void *dns_resolver_thread(void *args)
{
	struct dctx *ctx = args;
	struct dns_req *q;
	uint64_t r;
	int ret;

	pr_dbg("attempting to lock dns_lock\n");
	pthread_mutex_lock(&ctx->dns_lock);
	pr_dbg("acquired dns_lock\n");
	while (!ctx->stop) {
		pr_dbg("releasing dns_lock and start waiting\n");
		pthread_cond_wait(&ctx->dns_cond, &ctx->dns_lock);
		pr_dbg("acquired dns_lock\n");
		q = ctx->dqueue.head;
		/* if you leave the comment as is,
		* the dns resolver thread will process same request twice
		* because the consumer haven't consume or read it yet.
		* but if you uncomment the following comment,
		* the dns resolver thread may lost some signal dispatched from
		* pthread_cond_signal, this is a dilemma we need to change the
		* design of current implementation.
		*/
		// pr_dbg("first entry of the queue is acquired, releasing the lock\n");
		// pthread_mutex_unlock(&ctx->dns_lock);
		if (q) {
			pr_info("resolving %s\n", q->domainname);
			ret = resolve_dns(q);
			if (ret == -EXIT_FAILURE)
				r = 3;
			else
				r = 2;
			write(q->evfd, &r, sizeof(r));
		}
		// pr_dbg("attempting to re-lock dns_lock\n");
		// pthread_mutex_lock(&ctx->dns_lock);
	}
	pr_dbg("releasing dns_lock\n");
	pthread_mutex_unlock(&ctx->dns_lock);

	return NULL;
}

static void signal_handler(int c)
{
	int i;
	const uint64_t n = 1;

	switch (c) {
	case SIGINT:
		pr_info("interrupt signal received\n");
		break;
	case SIGTERM:
		pr_info("termination signal received\n");
		break;
	}

	for (i = 0; i < gctx->thread_nr; i++) {
		if (gctx->tc[i].evfd == -1)
			return;

		gctx->stop = true;
		write(gctx->tc[i].evfd, &n, sizeof(n));
	}
	pthread_cond_signal(&gctx->dns_cond);
}

static int spawn_threads(struct dctx *ctx)
{
	int i;
	struct tctx *tc = malloc(ctx->thread_nr * sizeof(struct tctx));
	ctx->tc = tc;

	pr_info("starting dns resolver thread\n");
	pthread_create(&ctx->dns_thandle, NULL, dns_resolver_thread, ctx);
	pr_info("starting %d thread(s) to serve TCP request\n", ctx->thread_nr);
	for (i = 0; i < ctx->thread_nr; i++) {
		/* reserve slot at index zero for main thread */
		ctx->tc[i].dc = ctx;
		if (i == 0)
			continue;
		pthread_create(&tc[i].handle, NULL, serve_client_thread, &tc[i]);
	}

	return start_server(&tc[0]);
}

int main(int argc, char **argv)
{
	int ret, i;
	intptr_t tret;

	struct dctx ctx;
	struct sigaction sa = {
		.sa_handler = signal_handler
	};

	ret = init_main_ctx(&ctx);
	if (ret < 0)
		return -EXIT_FAILURE;

	ret = parse_cmdline_args(argc, argv, &ctx);
	if (ret < 0) {
		if (ret == -EINVAL)
			pr_err("failed to parse command-line arguments\n");
		return -EXIT_FAILURE;
	}

	gctx = &ctx;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	ret = spawn_threads(&ctx);
	if (ret < 0) {
		pr_err("failed to start TCP server\n");
		return -EXIT_FAILURE;
	}

	pthread_join(ctx.dns_thandle, (void **)&ret);
	for (i = 0; i < ctx.thread_nr; i++) {
		if (i == 0)
			continue;
		pthread_join(ctx.tc[i].handle, (void **)&tret);
	}

	pr_info("free memory of thread pool: %p\n", ctx.tc);
	free(ctx.tc);

	pr_info(
		"all system resources were freed. "
		"now the program exit gracefully, "
		"transfer control back to the kernel.\n"
	);

	return 0;
}
