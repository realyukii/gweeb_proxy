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
#define DEFAULT_REQ_NR 100
#define pr_menu printf(usage, DEFAULT_CONN_NR, DEFAULT_REQ_NR)

struct prog_ctx {
	char *dname;
	char *addrstr;
	struct sockaddr_storage s;
};

static char opts[] = "n:c:r:s:";

static const char usage[] =
"usage: ./dns_client [options]\n"
"-n\tdomain name\n"
"-s\tip:port for server address\n"
"-c\tnumber of concurrent connection (default %d)\n"
"-r\tnumber of request per-connection (default %d)\n";

static int parse_cmdline_args(int argc, char **argv, struct prog_ctx *ctx)
{
	char c, *dname_opt, *concurrent_opt, *req_opt, *server_opt;
	int ret;

	if (argc == 1)
		return -EXIT_FAILURE;

	dname_opt = concurrent_opt = req_opt = NULL;
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
			req_opt = optarg;
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
	ctx->addrstr = server_opt;
	memset(&ctx->s, 0, sizeof(ctx->s));
	ret = init_addr(server_opt, &ctx->s);
	if (ret < 0) {
		pr_err(
			"invalid address, accepted format <ip>:<port>\n"
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
	int ret, clientfd;
	clientfd = socket(ctx->s.ss_family, SOCK_STREAM, 0);
	if (clientfd < 0) {
		pr_err("failed to create client socket\n");
		return -EXIT_FAILURE;
	}
	
	ret = connect(clientfd, (struct sockaddr *)&ctx->s, sizeof(ctx->s));
	if (ret < 0) {
		pr_err("failed to connect to the server: %s\n", ctx->addrstr);
		return -EXIT_FAILURE;
	}
	pr_info("connected to %s\n", ctx->addrstr);

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