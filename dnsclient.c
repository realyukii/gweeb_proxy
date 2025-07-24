#define _GNU_SOURCE
#include "general.h"
#include "gwdnsresolvlib.h"

typedef struct {
	union gwdns_resolv_addr addr;
	char **domain;
	size_t domain_nr;
} gwdns_client_cfg;

static int parse_cmdline_args(gwdns_client_cfg *cfg, int argc, char **argv)
{
	int port, ret;
	struct sockaddr_in *addr;

	if (argc < 4) {
		fprintf(
			stderr,
			"usage: ./dnsclient "
			"<dns server ip> <dns server port> <domain name>\n"
		);

		return -EINVAL;
	}

	cfg->domain_nr = argc - 3;
	cfg->domain = &argv[3];

	port = atoi(argv[2]);
	if (port <= 0) {
		fprintf(stderr, "port number can't be zero or negative.\n");
		return -EINVAL;
	}

	addr = &cfg->addr.in;
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);
	ret = inet_pton(AF_INET, argv[1], &addr->sin_addr);
	if (!ret) {
		fprintf(
			stderr,
			"invalid dns server ip (currently only support IPv4)\n."
		);
		return -EINVAL;
	}
	
	return 0;
}

static int send_queries(gwdns_client_cfg *cfg, gwdns_resolv_ctx *resolv_ctx)
{
	gwdns_resolv_hint hint;
	int ret;

	hint.ra_family = AF_INET;
	hint.domain_nr = cfg->domain_nr;
	ret = gwdns_resolv_addr(cfg->domain, &hint, resolv_ctx);

	return ret;
}

int main(int argc, char **argv)
{
	gwdns_resolv_param resolv_param;
	gwdns_resolv_ctx resolv_ctx;
	gwdns_client_cfg cfg;
	int ret;

	srand(time(NULL));

	ret = parse_cmdline_args(&cfg, argc, argv);
	if (ret)
		return ret;

	resolv_param.servers = &cfg.addr;
	resolv_param.server_nr = 1;
	ret = init_gwdns_resolv(&resolv_ctx, &resolv_param);
	if (ret)
		return ret;

	ret = send_queries(&cfg, &resolv_ctx);
	if (ret)
		return ret;

	deinit_gwdns_resolv(&resolv_ctx);

	return EXIT_SUCCESS;
}