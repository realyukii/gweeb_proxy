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

#define DEFAULT_EPOLL_EV 512
#define DEFAULT_THREAD_NR 4
#define DEFAULT_TIMEOUT_SEC 8
#define DEFAULT_PREALLOC_CONN 100
#define DEFAULT_BUFF_SZ 1024

#define ALL_EV_BITS (GWP_STOP | GWP_ACCEPT | GWP_CLIENT)
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
	GWP_STOP	= (0x1ULL << 48ULL),
	GWP_ACCEPT	= (0x2ULL << 48ULL),
	GWP_CLIENT	= (0x3ULL << 48ULL)
};

struct gwp_pctx *gctx;

struct gwp_conn {
	int sockfd;
	char addrstr[ADDRSTR_SZ];
	char *recvbuf;
	size_t recvlen;
	char *sendbuf;
	size_t sendlen;
};

struct gwp_pair_conn {
	size_t idx;
	struct gwp_conn client;
	struct gwp_conn target;
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
	int stopfd;
	volatile bool stop;
};

/* TCP server thread-specific data */
struct gwp_tctx {
	int epfd;
	int tcpfd;
	pthread_t thandle;
	struct gwp_pctx *pctx;
	struct gwp_session_container container;
};

static int prepare_tcp_serv(struct gwp_tctx *ctx)
{
	int ret;
	struct commandline_args *args = ctx->pctx->args;
	struct epoll_event ev;
	uint64_t val;

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

	ev.data.u64 = GWP_ACCEPT;
	ev.events = EPOLLIN;
	ret = epoll_ctl(ret, EPOLL_CTL_ADD, ctx->tcpfd, &ev);
	if (ret < 0) {
		ret = errno;
		pr_err(
			"failed to register tcp file descriptor to epoll: %s\n",
			strerror(ret)
		);
		goto exit_close_epfd;
	}

	ev.data.u64 = GWP_STOP;
	ev.events = EPOLLIN;
	ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->pctx->stopfd, &ev);
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

static int alloc_new_session(struct gwp_tctx *ctx, struct sockaddr *in, int cfd)
{
	int ret;
	struct gwp_session_container *container = &ctx->container;
	struct gwp_pair_conn *s;
	struct epoll_event ev;

	if (container->session_nr >= container->capacity) {
		// realloc container...
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
	
	s->client.recvbuf = malloc(ctx->pctx->args->c_recv_sz);
	if (!s->client.recvbuf) {
		ret = -ENOMEM;
		goto exit_free_s;
	}
	s->client.recvlen = ctx->pctx->args->c_recv_sz;
	s->client.sendbuf = malloc(ctx->pctx->args->c_send_sz);
	if (!s->client.sendbuf) {
		ret = -ENOMEM;
		goto exit_free_c_recv;
	}
	s->client.sendlen = ctx->pctx->args->c_send_sz;
	
	s->target.recvbuf = malloc(ctx->pctx->args->t_recv_sz);
	if (!s->target.recvbuf) {
		ret = -ENOMEM;
		goto exit_free_c_send;
	}
	s->target.recvlen = ctx->pctx->args->t_recv_sz;
	s->target.sendbuf = malloc(ctx->pctx->args->t_send_sz);
	if (!s->target.sendbuf) {
		ret = -ENOMEM;
		goto exit_free_t_recv;
	}
	s->target.sendlen = ctx->pctx->args->t_send_sz;

	ev.data.u64 = 0;
	ev.data.ptr = s;
	ev.data.u64 |= GWP_CLIENT;
	ev.events = EPOLLIN;
	ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, cfd, &ev);
	if (ret < 0) {
		ret = -errno;
		pr_err("failed to register client to epoll: %s", strerror(-ret));
		goto exit_free_t_send;
	}

	container->sessions[container->session_nr] = s;
	container->session_nr++;

	return 0;
exit_free_t_send:
	free(s->target.sendbuf);
exit_free_t_recv:
	free(s->target.recvbuf);
exit_free_c_send:
	free(s->client.sendbuf);
exit_free_c_recv:
	free(s->client.recvbuf);
exit_free_s:
	free(s);
exit_close_sockfd:
	close(cfd);
	return ret;
}

static int accept_new_client(struct gwp_tctx *ctx)
{
	int ret;
	struct sockaddr_in6 in6;
	socklen_t in6_sz = sizeof(in6);

	ret = accept4(ctx->tcpfd, &in6, &in6_sz, SOCK_NONBLOCK);
	if (ret < 0) {
		ret = errno;
		pr_err("failed to accept new client: %s\n", strerror(ret));
		return -ret;
	}

	return alloc_new_session(ctx, (struct sockaddr *)&in6, ret);
}

static void _cleanup_pc(struct gwp_pair_conn *pc)
{
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
	_cleanup_pc(pc);
}

static void process_client(struct gwp_tctx *ctx, void *data)
{
	struct gwp_pair_conn *pc = data;
	int ret;

	ret = recv(pc->client.sockfd, pc->client.recvbuf, pc->client.recvlen, 0);
	if (!ret)
		cleanup_pc(ctx, pc);
	else
		VT_HEXDUMP(pc->client.recvbuf, ret);
}

static void process_event(struct gwp_tctx *ctx, struct epoll_event *ev)
{
	uint64_t ev_bit;
	void *data;
	
	ev_bit = GET_EV_BIT(ev->data.u64);
	ev->data.u64 = CLEAR_EV_BIT(ev->data.u64);
	data = ev->data.ptr;
	switch (ev_bit) {
	case GWP_STOP:
		break;
	case GWP_ACCEPT:
		accept_new_client(ctx);
		break;
	case GWP_CLIENT:
		process_client(ctx, data);
		break;
	
	default:
		abort();
	}
}

static void cleanup_tctx(struct gwp_tctx *ctx)
{
	struct gwp_pair_conn *pc;

	pr_info("unfreed resource of session: %d\n", ctx->container.session_nr);
	for (size_t i = 0; i < ctx->container.session_nr; i++) {
		pc = ctx->container.sessions[i];
		if (pc) {
			pr_info("disconnecting %s\n", pc->client.addrstr);
			_cleanup_pc(pc);
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
	int i, ret;
	struct epoll_event evs[DEFAULT_EPOLL_EV];

	pr_info("start serving...\n");
	ret = 0;
	while (!ctx->pctx->stop) {
		ret = epoll_wait(ctx->epfd, evs, DEFAULT_EPOLL_EV, -1);
		if (ret < 0) {
			ret = errno;
			if (ret == EINTR)
				continue;
			pr_err(
				"an error occured on epoll_wait call: %s\n",
				strerror(ret)
			);
			break;
		}

		for (i = 0; i < ret; i++)
			process_event(ctx, &evs[i]);
	}

	cleanup_tctx(ctx);
	return ret;
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

	return 0;
}

static void *tcp_serv_thread(void *args)
{
	intptr_t ret;
	struct gwp_tctx *ctx = args;

	ret = start_tcp_serv(ctx);
	return (void *)ret;
}

static int spawn_threads(struct gwp_pctx *ctx)
{
	int ret;
	size_t i, thread_nr = ctx->args->server_thread_nr;

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
	intptr_t retval;
	size_t i, thread_nr = ctx->args->server_thread_nr;

	for (i = 0; i < thread_nr; i++) {
		if (i == 0)
			continue;
		pthread_join(ctx->tctx[i].thandle, (void *)&retval);
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
	char c,
	*bind_opt, *target_opt, *server_thread_opt,
	*client_nr_opt, *wait_opt, *auth_file_opt;
	struct buff_sz_opt b = {0};
	int ret;

	if (argc == 1) {
		pr_menu();
		return -EXIT_FAILURE;
	}

	args->socks5_mode = false;

	auth_file_opt = wait_opt = server_thread_opt
	= bind_opt = target_opt = client_nr_opt = NULL;
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
	int ret;
	struct commandline_args args;
	struct gwp_pctx ctx;
	struct sigaction sa = {
		.sa_handler = signal_handler
	};

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

	join_threads(&ctx);

	pr_info("all system resources were freed\n");

	return EXIT_SUCCESS;
}
