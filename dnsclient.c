#define _GNU_SOURCE
#include "general.h"
#include "gwdnsparserlib.h"

#define ID (0x3ULL << 32ULL)
#define EXTRACT_ID(mask) ((mask) & ID)
#define CLEAR_ID(mask) ((mask) & ~ID)

typedef struct {
	union gwdns_resolv_addr addr;
	char **domain;
	size_t domain_nr;
} gwdns_client_cfg;

static int init_gwdns_resolv(gwdns_resolv_ctx *ctx, gwdns_resolv_param *param)
{
	int ret;

	ret = io_uring_queue_init(8, &ctx->ring, 0);
	if (ret)
		return ret;

	ctx->sqe_nr = 0;

	ctx->server_nr = param->server_nr;
	ctx->servers = param->servers;

	return 0;
}

static int deinit_gwdns_resolv(gwdns_resolv_ctx *ctx)
{
	io_uring_queue_exit(&ctx->ring);

	return 0;
}

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

static int send_query(struct io_uring *ring, int sockfd, char *domain, gwdns_question_buffer *buff)
{
	struct io_uring_sqe *sqe;
	gwdns_question_part q;
	ssize_t payload_len;

	q.domain = domain;
	q.dst_buffer = buff->question;
	q.dst_len = UDP_MSG_LIMIT;
	q.ai_family = AF_INET6;
	payload_len = construct_question(&q);
	if (payload_len < 0)
		return -1;

	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -1;
	io_uring_prep_send(sqe, sockfd, buff->question, payload_len, 0);
	io_uring_sqe_set_data64(sqe, 2);
	sqe->flags |= IOSQE_IO_LINK;

	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -1;
	io_uring_prep_recv(sqe, sockfd, buff->answr, UDP_MSG_LIMIT, 0);
	uint64_t u64 = 0;
	memcpy(&u64, buff->question, sizeof(uint16_t));
	u64 |= ID;
	io_uring_sqe_set_data64(sqe, u64);
	sqe->flags |= IOSQE_IO_LINK;

	return 0;
}

static int resolv_addr(char **domains, gwdns_resolv_hint *hint, gwdns_resolv_ctx *ctx)
{
	gwdns_question_buffer *buff;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret, sockfd;
	unsigned head;
	size_t l, idx;

	sockfd = socket(hint->ra_family, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		ret = errno;
		fprintf(
			stderr,
			"error while creating socket: %s\n",
			strerror(ret)
		);
		return ret;
	}

	sqe = io_uring_get_sqe(&ctx->ring);
	if (!sqe)
		return -1;
	ctx->sqe_nr++;
	io_uring_prep_connect(sqe, sockfd, (struct sockaddr *)&ctx->servers->in, sizeof(ctx->servers->in));
	sqe->flags |= IOSQE_IO_LINK;
	io_uring_sqe_set_data64(sqe, 1);

	buff = malloc(sizeof(*buff) * hint->domain_nr);
	for (l = 0; l < hint->domain_nr; l++) {
		ret = send_query(&ctx->ring, sockfd, domains[l], &buff[l]);
		if (ret)
			return -1;
		ctx->sqe_nr += 2;
	}

	sqe = io_uring_get_sqe(&ctx->ring);
	if (!sqe)
		return -1;
	ctx->sqe_nr++;
	io_uring_prep_close(sqe, sockfd);
	sqe->flags |= IOSQE_IO_LINK;
	io_uring_sqe_set_data64(sqe, 4);

	printf("ctx->sqe_nr=%d\n", ctx->sqe_nr);
	ret = io_uring_submit_and_wait(&ctx->ring, ctx->sqe_nr);
	if (ret < 0)
		return ret;

	idx = l = 0;
	io_uring_for_each_cqe(&ctx->ring, head, cqe) {
		ctx->sqe_nr--;
		printf("cqe->res=%d cqe->user_data=%llx\n", cqe->res, CLEAR_ID(cqe->user_data));
		if (EXTRACT_ID(cqe->user_data) == ID) {
			char ipstr[INET6_ADDRSTRLEN];
			gwdns_answ_data d;

			cqe->user_data = CLEAR_ID(cqe->user_data);
			ret = serialize_answ((uint16_t)cqe->user_data, (uint8_t *)buff[idx].answr, cqe->res, &d);
			for (size_t i = 0; i < d.hdr.ancount; i++) {
				gwdns_serialized_answ *p = d.rr_answ[i];
				int sa_family = p->rr_type == TYPE_AAAA ? AF_INET6 : AF_INET;
				inet_ntop(sa_family, p->rdata, ipstr, sizeof(ipstr));
				printf("%s\n", ipstr);
			}
			
			idx++;
		}
		l++;
	}

	io_uring_cq_advance(&ctx->ring, l);
	free(buff);

	return 0;
}

static int send_queries(gwdns_client_cfg *cfg, gwdns_resolv_ctx *resolv_ctx)
{
	gwdns_resolv_hint hint;
	int ret;

	hint.ra_family = AF_INET;
	hint.domain_nr = cfg->domain_nr;
	ret = resolv_addr(cfg->domain, &hint, resolv_ctx);

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