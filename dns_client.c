/*
* DNS client for custom DNS resolver program.
* this program is created to stress-test concurrent connection and request
* to the DNS resolver.
*
* run without any arguments to see the usage.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include "general.h"
#include "linux.h"

#define DEFAULT_CONN_NR 100
#define DEFAULT_THREAD_NR 1
#define pr_menu printf(usage, DEFAULT_CONN_NR, DEFAULT_THREAD_NR)

struct net_pkt {
	uint8_t dlen;
	char dname[255];
};

struct prog_ctx {
	char *dname;
	char *addrstr;
	uint8_t dnamelen;
	struct sockaddr_storage s;
};

static char opts[] = "n:c:t:s:";

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
	int ret;

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
		case 'r':
			thread_opt = optarg;
			break;
		case 's':
			server_opt = optarg;
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
	memset(&ctx->s, 0, sizeof(ctx->s));
	ret = init_addr(server_opt, &ctx->s);
	if (ret < 0) {
		pr_err(
			"invalid address, accepted format <ip>:<port>, "
			"wrap ip with bracket for IPv6 address\n"
		);
		return -EINVAL;
	}

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

static int make_req(struct prog_ctx *ctx)
{
	int ret, serverfd;
	char recvbuf[255];
	struct net_pkt p;
	serverfd = socket(ctx->s.ss_family, SOCK_STREAM, 0);
	if (serverfd < 0) {
		pr_err("failed to create client socket\n");
		return -EXIT_FAILURE;
	}

	ret = connect(serverfd, (struct sockaddr *)&ctx->s, sizeof(ctx->s));
	if (ret < 0) {
		pr_err("failed to connect to %s\n", ctx->addrstr);
		return -EXIT_FAILURE;
	} else
		pr_info("connected to %s\n", ctx->addrstr);

	memcpy(p.dname, ctx->dname, ctx->dnamelen);
	p.dlen = ctx->dnamelen;
	ret = send(serverfd, &p, 1 + p.dlen, 0);
	if (ret < 0) {
		pr_err("failed to send data packet to %s\n", ctx->addrstr);
		return -EXIT_FAILURE;
	}

	ret = recv(serverfd, recvbuf, sizeof(recvbuf), 0);
	if (ret < 0) {
		pr_err("failed to receive server's response\n");
		return -EXIT_FAILURE;
	}
	if (!ret) {
		pr_info("server closed the connection\n");
		return 0;
	}

	VT_HEXDUMP(recvbuf, ret);

	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	struct prog_ctx ctx;

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

	ret = make_req(&ctx);
	if (ret < 0)
		return -EXIT_FAILURE;

	return 0;
}