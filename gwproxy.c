#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "linux.h"
#include "general.h"

#define DEFAULT_THREAD_NR 4
#define DEFAULT_TIMEOUT_SEC 8
#define DEFAULT_PREALLOC_CONN 100

#define pr_menu() 					\
do {							\
printf(							\
	usage,						\
	DEFAULT_THREAD_NR, DEFAULT_TIMEOUT_SEC,		\
	DEFAULT_PREALLOC_CONN				\
);							\
} while (0)

static const char opts[] = "hw:b:t:T:f:sn:";
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
"-h\tShow this help message and exit\n";

struct commandline_args {
	bool socks5_mode;
	char *auth_file;
	int connptr_nr;
	size_t server_thread_nr;
	size_t timeout;
	/* local address to be bound */
	struct sockaddr_storage src_addr_st;
	/* only used on simple TCP proxy mode */
	struct sockaddr_storage dst_addr_st;
};

/* program configuration and data */
struct gwp_pctx {
	struct commandline_args *args;
};

/* TCP server thread-specific data */
struct gwp_tctx {
	int epfd;
	int tcpfd;
	pthread_t thandle;
	struct gwp_pctx *pctx;
};

static int prepare_tcp_serv(struct gwp_tctx *ctx)
{
	int ret;
	struct commandline_args *args = ctx->pctx->args;
	struct epoll_event ev;

	ret = socket(args->src_addr_st.ss_family, SOCK_STREAM, 0);
	if (ret < 0) {
		ret = errno;
		pr_err(
			"failed to create tcp socket file descriptor: %s\n",
			strerror(ret)
		);
		return ret;
	}

	ctx->tcpfd = ret;

	ret = bind(ret, (struct sockaddr *)&args->src_addr_st, sizeof(args->src_addr_st));
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

	ev.data.fd = ctx->tcpfd;
	ev.events = EPOLLIN;
	ret = epoll_ctl(ret, EPOLL_CTL_ADD, ctx->tcpfd, &ev);
	if (ret < 0) {
		ret = errno;
		pr_err(
			"failed to register file descriptor to epoll: %s\n",
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

static void init_tctx(struct gwp_tctx *tctx, struct gwp_pctx *pctx)
{
	tctx->pctx = pctx;
}

static void init_pctx(struct gwp_pctx *pctx, struct commandline_args *args)
{
	pctx->args = args;
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
	int server_thread_nr, connptr_nr, timeout;
	int ret;

	if (argc == 1) {
		pr_menu();
		return -EXIT_FAILURE;
	}

	args->socks5_mode = false;
	args->auth_file = NULL;
	memset(&args->src_addr_st, 0, sizeof(args->src_addr_st));

	auth_file_opt = wait_opt = server_thread_opt = bind_opt = target_opt =
	client_nr_opt = NULL;
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

	if (auth_file_opt)
		args->auth_file = auth_file_opt;

	if (client_nr_opt) {
		connptr_nr = atoi(client_nr_opt);
		if (connptr_nr <= 0)
			connptr_nr = DEFAULT_PREALLOC_CONN;
	} else
		connptr_nr = DEFAULT_PREALLOC_CONN;

	args->connptr_nr = connptr_nr;

	if (server_thread_opt) {
		server_thread_nr = atoi(server_thread_opt);
		if (server_thread_nr <= 0)
			server_thread_nr = DEFAULT_THREAD_NR;
	} else
		server_thread_nr = DEFAULT_THREAD_NR;

	args->server_thread_nr = server_thread_nr;

	if (wait_opt) {
		timeout = atoi(wait_opt);
		if (timeout < 0)
			timeout = DEFAULT_TIMEOUT_SEC;
	} else
		timeout = DEFAULT_TIMEOUT_SEC;

	args->timeout = timeout;

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

int main(int argc, char *argv[])
{
	int ret;
	struct commandline_args args;
	struct gwp_pctx ctx;
	struct gwp_tctx tctx;

	ret = handle_cmdline(argc, argv, &args);
	if (ret < 0)
		return ret;

	init_pctx(&ctx, &args);
	init_tctx(&tctx, &ctx);
	ret = prepare_tcp_serv(&tctx);

	return ret;
}
