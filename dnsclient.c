#define _GNU_SOURCE
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <liburing.h>
#include "general.h"

typedef enum {
	TYPE_A		= 1,	// a host address
	TYPE_NS		= 2,	// an authoritative name server
	TYPE_CNAME	= 5,	// the canonical name for an alias
	TYPE_SOA	= 6,	// marks the start of a zone of authority
	TYPE_MB		= 7,	// a mailbox domain name (EXPERIMENTAL)
	TYPE_MG		= 8,	// a mail group member (EXPERIMENTAL)
	TYPE_MR		= 9,	// a mail rename domain name (EXPERIMENTAL)
	TYPE_NULL	= 10,	// a null RR (EXPERIMENTAL)
	TYPE_WKS	= 11,	// a well known service description
	TYPE_PTR	= 12,	// a domain name pointer
	TYPE_HINFO	= 13,	// host information
	TYPE_MINFO	= 14,	// mailbox or mail list information
	TYPE_MX		= 15,	// mail exchange
	TYPE_TXT	= 16,	// text strings
	QTYPE_AXFR	= 252,	// A request for a transfer of an entire zone
	QTYPE_MAILB	= 253,	// A request for mailbox-related records (MB, MG or MR)
	QTYPE_ALL	= 255	// A request for all records
} DnsType;

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

/**
 * DNS OPCODE values (4-bit field in DNS header)
 * from RFC 1035 §4.1.1
 */
typedef enum {
	OPCODE_QUERY		= 0,	// Standard query (QUERY)
	OPCODE_IQUERY		= 1,	// Inverse query (IQUERY)
	OPCODE_STATUS		= 2,	// Server status request (STATUS)
	OPCODE_RESERVED_MIN	= 3,	// Reserved for future use (inclusive)
	OPCODE_RESERVED_MAX	= 15	// Reserved for future use (inclusive)
} DnsOpCode;

typedef enum {
	CLASS_IN	= 1,	// Internet
	CLASS_CH	= 3,	// CHAOS class
	CLASS_HS	= 4,	// Hesiod
	QCLASS_ANY	= 255	// ANY class (matches any class)
} DnsClass;

struct dns_flags {
	uint8_t rd	: 1;	/* recursion desired */
	uint8_t tc	: 1;	/* truncated */
	uint8_t aa	: 1;	/* authoritative answer */
	DnsOpCode opcode: 4;	/* query type */
	uint8_t qr	: 1;	/* 0 = query, 1 = response */

	uint8_t rcode	: 4;	/* response code */
	uint8_t z	: 3;	/* reserved (must be zero) */
	uint8_t ra	: 1;	/* recursion available */
} __packed;

struct dns_header_pkt {
	uint16_t id;
	struct dns_flags flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __packed;

struct dns_query_pkt {
	struct dns_header_pkt hdr;
	uint8_t body[1024];
};

typedef struct {
	struct sockaddr_storage addr;
	char **domain;
	size_t domain_nr;
} GWDnsClient_Cfg;

static ssize_t construct_qname(uint8_t *dst, size_t dst_len, const char *qname)
{
	const uint8_t *p = (const uint8_t *)qname;
	uint8_t *lp = dst; // Length position.
	uint8_t *sp = lp + 1;  // String position.
	size_t total = 0;
	uint16_t l;

	l = 0;
	while (1) {
		uint8_t c = *p++;

		total++;
		if (total >= dst_len)
			return -ENAMETOOLONG;

		if (c == '.' || c == '\0') {
			if (l < 1 || l > 255)
				return -EINVAL;

			*lp = (uint8_t)l;
			lp = sp++;
			l = 0;
			if (!c)
				break;
		} else {
			l++;
			*sp = c;
			sp++;
		}
	}

	return total;
}

/*
 * 4. MESSAGES
 * 4.1. Format
 *
 * All communications inside of the domain protocol are carried in a single
 * format called a message. The top-level format of a message is divided
 * into 5 sections (some of which may be empty in certain cases), shown below:
 *
 *     +---------------------+
 *     |        Header       |
 *     +---------------------+
 *     |       Question      | the question for the name server
 *     +---------------------+
 *     |        Answer       | RRs answering the question
 *     +---------------------+
 *     |      Authority      | RRs pointing toward an authority
 *     +---------------------+
 *     |      Additional     | RRs holding additional information
 *     +---------------------+
 *
 * These sections are defined in RFC 1035 §4.1. The Header section is always
 * present and includes fields that specify which of the other sections follow,
 * as well as metadata such as whether the message is a query or response,
 * the opcode, etc.
 */
static ssize_t construct_question(uint16_t id, uint8_t *buffer, size_t len, char *domain, uint16_t qtype, uint16_t qclass)
{
	struct dns_query_pkt pkt;
	struct dns_header_pkt *hdr;
	ssize_t bw;
	size_t required_len;

	hdr = &pkt.hdr;
	memset(hdr, 0, sizeof(*hdr));
	hdr->id = id;
	hdr->flags.aa = false;
	hdr->flags.opcode = OPCODE_QUERY;
	hdr->flags.rd = true;

	qtype = htons(qtype);
	qclass = htons(qclass);

	hdr->qdcount = htons(1);

	bw = construct_qname(pkt.body, sizeof(pkt.body) - 3, domain);
	if (bw < 0)
		return bw;

	pkt.body[bw++] = 0x0;
	memcpy(&pkt.body[bw], &qtype, 2);
	bw += 2;
	memcpy(&pkt.body[bw], &qclass, 2);
	bw += 2;

	required_len = sizeof(pkt.hdr) + bw;
	if (len < required_len)
		return -ENOBUFS;

	memcpy(buffer, &pkt, required_len);

	return required_len;
}

static int parse_cmdline_args(GWDnsClient_Cfg *cfg, int argc, char **argv)
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

	addr = (void *)&cfg->addr;
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

static int send_queries(GWDnsClient_Cfg *cfg)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct sockaddr_in *in;
	uint8_t bigbuff[1024];
	struct io_uring ring;
	char respbuf[1024];
	ssize_t send_len;
	int ret, sockfd;
	uint8_t sqe_nr;
	unsigned head;
	unsigned i;

	in = (struct sockaddr_in *)&cfg->addr;
	size_t off = 0, cap = 1024;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		ret = errno;
		fprintf(
			stderr,
			"error while creating socket: %s\n",
			strerror(ret)
		);
		return ret;
	}
	sqe_nr = 0;
	ret = io_uring_queue_init(8, &ring, 0);
	if (ret)
		return ret;

	sqe = io_uring_get_sqe(&ring);
	if (!sqe)
		return -1;
	sqe_nr++;
	io_uring_prep_connect(sqe, sockfd, (struct sockaddr *)in, sizeof(*in));
	sqe->flags |= IOSQE_IO_LINK;
	io_uring_sqe_set_data64(sqe, 1);

	for (size_t l = 0; l < cfg->domain_nr; l++) {
		send_len = construct_question(
			0xABC + l, &bigbuff[off], cap - off, cfg->domain[l], TYPE_A, CLASS_IN
		);
		if (send_len < 0)
			return -1;

		sqe = io_uring_get_sqe(&ring);
		if (!sqe)
			return -1;
		sqe_nr++;
		io_uring_prep_send(sqe, sockfd, &bigbuff[off], send_len, 0);
		io_uring_sqe_set_data64(sqe, 2);
		sqe->flags |= IOSQE_IO_LINK;
		off += send_len;

		sqe = io_uring_get_sqe(&ring);
		if (!sqe)
			return -1;
		sqe_nr++;
		io_uring_prep_recv(sqe, sockfd, respbuf, 1024, 0);
		io_uring_sqe_set_data64(sqe, 3);
		sqe->flags |= IOSQE_IO_LINK;

		printf("sqe_nr=%d\n", sqe_nr);
		ret = io_uring_submit_and_wait(&ring, sqe_nr);
		if (ret < 0)
			return ret;

		i = 0;
		io_uring_for_each_cqe(&ring, head, cqe) {
			sqe_nr--;
			printf("cqe->res=%d cqe->user_data=%lld\n", cqe->res, cqe->user_data);
			if (cqe->user_data == 3)
				VT_HEXDUMP(respbuf, cqe->res);
			i++;
		}

		io_uring_cq_advance(&ring, i);
	}

	close(sockfd);
	io_uring_queue_exit(&ring);

	return 0;
}

int main(int argc, char **argv)
{
	GWDnsClient_Cfg cfg;
	int ret;

	ret = parse_cmdline_args(&cfg, argc, argv);
	if (ret)
		return ret;

	ret = send_queries(&cfg);
	if (ret)
		return ret;

	return EXIT_SUCCESS;
}