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
* to store the log to a file, just use your shell's built-in redirect feature.
* redirect it to /dev/null to disable logging
* or build the program with -DENABLE_LOG=false if you prefer smol binary.
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

/*
* application data.
*/
struct dctx {
	/* local address and port for socket to be bound */
	struct sockaddr_storage d;
	/* TCP socket file descriptor */
	int tcpfd;
	/* epoll file descriptor */
	int epfd;
	/* eventfd file descriptor */
	int evfd;
	/* flag to stop the program */
	bool stop;
};

/* allow signal handler to access application data. */
static struct dctx *gctx;

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

static void init_ctx(struct dctx *ctx)
{
	ctx->epfd = -1;
	ctx->evfd = -1;
	ctx->tcpfd = -1;
}

static int start_event_loop(struct dctx *ctx)
{
	struct epoll_event ev;
	uint64_t evbuf;
	int ret = -1;
	ctx->epfd = epoll_create(1);
	if (ctx->epfd < 0) {
		pr_err("failed to create epoll instance\n");
		goto exit_err;
	}

	ev.events = EPOLLIN;
	ev.data.fd = ctx->tcpfd;
	ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->tcpfd, &ev);
	if (ret < 0) {
		pr_err("failed to register events for tcpfd\n");
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
		ret = epoll_wait(ctx->epfd, &ev, 1, -1);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			pr_err("an error occured while waiting in epoll_wait\n");
			goto exit_close_evfd;
		}

		if (ev.data.fd == ctx->evfd) {
			ret = read(ctx->evfd, &evbuf, sizeof(evbuf));
			if (ret < 0) {
				pr_err("failed to read buffer from evfd\n");
				goto exit_close_evfd;
			}

			/*
			* system deliver SIGTERM or SIGINT, stop the event loop
			*/
			if (evbuf == 1)
				continue;
		}

		if (ev.data.fd == ctx->tcpfd) {
			/* accept incoming client. */
		} else {
			/* communicate with a client. */
		}
	}

	ret = 0;
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

	ctx->tcpfd = socket(ctx->d.ss_family, SOCK_STREAM, 0);
	if (ctx->tcpfd < 0) {
		pr_err("failed to create TCP socket\n");
		goto exit_failure;
	}

	setsockopt(ctx->tcpfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	ret = bind(ctx->tcpfd, (struct sockaddr *)&ctx->d, sizeof(ctx->d));
	if (ret < 0) {
		pr_err("failed to bind the socket\n");
		goto exit_close;
	}

	ret = listen(ctx->tcpfd, SOMAXCONN);
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
	pr_info("closing main tcp file descriptor: %d\n", ctx->tcpfd);
	close(ctx->tcpfd);
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

	ret = parse_cmdline_args(argc, argv, &ctx);
	if (ret < 0) {
		pr_err("failed to parse command-line arguments\n");
		return -1;
	}

	init_ctx(&ctx);
	gctx = &ctx;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	ret = start_server(&ctx);
	if (ret < 0) {
		pr_err("failed to start TCP server\n");
		return -1;
	}

	pr_info(
		"all system resources were freed. "
		"now the program exit gracefully, "
		"transfer control back to the kernel.\n"
	);
	return 0;
}
