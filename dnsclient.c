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

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

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

/* Flag bit position in little-endian machine */
#define DNS_QR_BIT		0xF
#define DNS_OPCODE_BIT		0xB	// 4-bit field
#define DNS_AA_BIT		0xA
#define DNS_TC_BIT		0x9
#define DNS_RD_BIT		0x8
#define DNS_RA_BIT		0x7
#define DNS_Z_BIT		0x4	// 3-bit field
#define DNS_RCODE_BIT		0x0	// 4-bit field
#define DNS_COMPRESSION_BIT	(0x3 << 0xE)

/* Flag extraction macros for listtle-endian machine */
#define DNS_QR(flags)		(((flags) >> DNS_QR_BIT) & 0x1)
#define DNS_OPCODE(flags)	(((flags) >> DNS_OPCODE_BIT) & 0xF)
#define DNS_RCODE(flags)	((flags) & 0xF)
#define DNS_IS_COMPRESSED(mask) ((mask) & DNS_COMPRESSION_BIT)

/* Flag construction macros for little-endian machine */
#define DNS_SET_RD(flags, val)	(flags) = ((flags) & ~(1 << DNS_RD_BIT)) | ((!!(val)) << DNS_RD_BIT)

typedef enum {
	OPCODE_QUERY		= 0,	// Standard query (QUERY)
	OPCODE_IQUERY		= 1,	// Inverse query (IQUERY)
	OPCODE_STATUS		= 2,	// Server status request (STATUS)
	OPCODE_RESERVED_MIN	= 3,	// Reserved for future use (inclusive)
	OPCODE_RESERVED_MAX	= 15	// Reserved for future use (inclusive)
} gwdns_op;

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
} gwdns_type;

typedef enum {
	CLASS_IN	= 1,	// Internet
	CLASS_CH	= 3,	// CHAOS class
	CLASS_HS	= 4,	// Hesiod
	QCLASS_ANY	= 255	// ANY class (matches any class)
} gwdns_class;

struct gwdns_header_pkt {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __packed;

struct gwdns_query_pkt {
	struct gwdns_header_pkt hdr;
	uint8_t body[1024];
};

struct query_buffer {
	uint8_t sendbuf[1024];
	char recvbuf[1024];
};

typedef struct {
	struct sockaddr_storage addr;
	char **domain;
	size_t domain_nr;
} gwdns_client_cfg;

typedef struct {
	uint8_t *dst_buffer;
	size_t dst_len;
	char *domain;
} gwdns_question_part;

/*
 * 4.1.3. Resource record format
 *
 * The answer, authority, and additional sections all share the same
 * format: a variable number of resource records, where the number of
 * records is specified in the corresponding count field in the header.
 */
typedef struct {
	uint8_t  *name;		// DOMAIN NAME: variable‑length sequence of labels (length-byte followed by label, ending in 0), possibly compressed
	uint16_t  type;		// TYPE: two-octet code identifying the RR type (see gwdns_type)
	uint16_t  class;	// CLASS: two-octet code identifying the RR class (see gwdns_class)
	uint32_t  ttl;		// TTL: 32-bit unsigned, time to live in seconds
	uint16_t  rdlength;	// RDLENGTH: length in octets of RDATA
	uint8_t  *rdata;	// RDATA: variable-length data, format depends on TYPE and CLASS
} gwdns_serialized_rr;

typedef gwdns_serialized_rr gwdns_serialized_answ;

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

static ssize_t calculate_question_len(uint8_t *in, size_t in_len)
{
	const uint8_t *p = in;
	size_t tot_len;

	tot_len = 0;
	while (true) {
		if (*p == 0x0)
			break;

		if (tot_len >= in_len)
			return -ENAMETOOLONG;

		tot_len += *p + 1;
		p += tot_len;
	}

	return  tot_len;
}

/*
* Serialize DNS server's answer
*
* @param txid	test if a transaction id is match with the requested one.
* @param in	a pointer to buffer that want to be parsed
* @param out	a pointer to serialized buffer of answer to question
* @return	zero on success or a negative number on failure
*
* possible error are:
* -EAGAIN in buffer is not sufficient, no bytes are processed, need more data.
* -EINVAL the content of in buffer is not valid.
* -ENOMEM failed to allocate dynamic memory.
* -ENODATA the packet didn't contain any answers.
* -EPROTO the DNS server can't understand your question
*/
static int serialize_answ(uint16_t txid, uint8_t *in, size_t in_len, gwdns_serialized_rr *out)
{
	struct gwdns_header_pkt *hdr;
	size_t advance_len, first_len;
	uint16_t raw_flags;
	int ret;

	advance_len = sizeof(*hdr);
	if (in_len < advance_len)
		return -EAGAIN;

	hdr = (void *)in;
	if (memcmp(&txid, &hdr->id, sizeof(txid)))
		return -EINVAL;

	memcpy(&raw_flags, &in[2], sizeof(raw_flags));
	raw_flags = ntohs(raw_flags);
	/* QR MUST 1 = response from dns server */
	if (!DNS_QR(raw_flags))
		return -EINVAL;

	/* OPCODE MUST 0 = standard query */
	if (DNS_OPCODE(raw_flags))
		return -EINVAL;
	
	/* RCODE MUST 0 = No error */
	if (DNS_RCODE(raw_flags))
		return -EPROTO;

	// is it safe or recommended to alter the in buffer directly?
	hdr->ancount = ntohs(hdr->ancount);
	if (!hdr->ancount)
		return -ENODATA;

	in += advance_len;
	in_len -= advance_len;

	first_len = 1 + in[0];
	advance_len = first_len + 1 + 2 + 2;
	if (in_len < advance_len)
		return -EAGAIN;

	ret = calculate_question_len(in, in_len);
	if (ret < 0)
		return -EINVAL;

	advance_len -= first_len;
	advance_len += ret;
	if (in_len < advance_len)
		return -EAGAIN;

	in += advance_len;
	in_len -= advance_len;
	for (size_t i = 0; i < hdr->ancount; i++) {
		char ipstr[INET_ADDRSTRLEN];
		uint16_t is_compressed, rdlength;

		memcpy(&is_compressed, in, sizeof(is_compressed));
		is_compressed = DNS_IS_COMPRESSED(ntohs(is_compressed));
		assert(is_compressed);
		in += 2; // NAME
	
		in += 2; // TYPE
		in += 2; // CLASS
		in += 4; // TTL

		memcpy(&rdlength, in, sizeof(rdlength));
		rdlength = ntohs(rdlength);
		assert(rdlength == 4);
		in += 2;

		inet_ntop(AF_INET, in, ipstr, sizeof(ipstr));
		printf("%s\n", ipstr);
		in += rdlength;
	}

	(void)out;

	return 0;
}

static ssize_t construct_question(gwdns_question_part *question)
{
	struct gwdns_header_pkt *hdr;
	struct gwdns_query_pkt pkt;
	uint16_t qtype, qclass;
	size_t required_len;
	ssize_t bw;

	hdr = &pkt.hdr;
	/*
	* the memset implicitly set opcode to query
	*/
	memset(hdr, 0, sizeof(*hdr));
	/*
	* TODO: how to make sure the txid didn't collide with other queries?
	* let the caller decide? provide an interface/helper function that
	* the caller can call it later to validate and check this problem?
	*/
	hdr->id = htons((uint16_t)rand());
	DNS_SET_RD(hdr->flags, true);
	hdr->flags = htons(hdr->flags);
	hdr->qdcount = htons(1);

	/*
	* pkt.body is interpreted as question section
	* for layout and format, see RFC 1035 4.1.2. Question section format
	*/
	bw = construct_qname(pkt.body, sizeof(pkt.body) - 3, question->domain);
	if (bw < 0)
		return bw;

	pkt.body[bw++] = 0x0;
	qtype = htons(TYPE_A);
	qclass = htons(CLASS_IN);
	memcpy(&pkt.body[bw], &qtype, 2);
	bw += 2;
	memcpy(&pkt.body[bw], &qclass, 2);
	bw += 2;

	required_len = sizeof(pkt.hdr) + bw;
	if (question->dst_len < required_len)
		return -ENOBUFS;

	memcpy(question->dst_buffer, &pkt, required_len);

	return required_len;
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

#define ID (0x3ULL << 32ULL)
#define EXTRACT_ID(mask) ((mask) & ID)
#define CLEAR_ID(mask) ((mask) & ~ID)

static int send_query(
	struct io_uring *ring, int sockfd,
	char *domain, uint8_t *sendbuf, size_t sendbuf_len,
	char *recvbuf, size_t recvbuf_len
)
{
	struct io_uring_sqe *sqe;
	gwdns_question_part q;
	ssize_t payload_len;

	q.domain = domain;
	q.dst_buffer = sendbuf;
	q.dst_len = sendbuf_len;
	payload_len = construct_question(&q);
	if (payload_len < 0)
		return -1;

	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -1;
	io_uring_prep_send(sqe, sockfd, sendbuf, payload_len, 0);
	io_uring_sqe_set_data64(sqe, 2);
	sqe->flags |= IOSQE_IO_LINK;

	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -1;
	io_uring_prep_recv(sqe, sockfd, recvbuf, recvbuf_len, 0);
	uint64_t u64 = 0;
	memcpy(&u64, sendbuf, sizeof(uint16_t));
	u64 |= ID;
	io_uring_sqe_set_data64(sqe, u64);
	sqe->flags |= IOSQE_IO_LINK;

	return 0;
}

static int send_queries(gwdns_client_cfg *cfg)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct sockaddr_in *in;
	struct io_uring ring;
	int ret, sockfd;
	uint8_t sqe_nr;
	unsigned head;
	size_t l, idx;

	struct query_buffer *arr = malloc(sizeof(*arr) * cfg->domain_nr);
	if (!arr)
		return -ENOMEM;

	in = (struct sockaddr_in *)&cfg->addr;
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

	for (l = 0; l < cfg->domain_nr; l++) {
		uint8_t *sendbuf = (uint8_t *)arr[l].sendbuf;
		size_t sendbuf_len = sizeof(arr[l].sendbuf);
		size_t recvbuf_len = sizeof(arr[l].recvbuf);
		char *recvbuf = arr[l].recvbuf;
		char *domain = cfg->domain[l];

		ret = send_query(
			&ring, sockfd, domain,
			sendbuf, sendbuf_len, recvbuf, recvbuf_len
		);
		if (ret)
			return -1;
		sqe_nr += 2;
	}

	sqe = io_uring_get_sqe(&ring);
	if (!sqe)
		return -1;
	sqe_nr++;
	io_uring_prep_close(sqe, sockfd);
	sqe->flags |= IOSQE_IO_LINK;
	io_uring_sqe_set_data64(sqe, 4);

	printf("sqe_nr=%d\n", sqe_nr);
	ret = io_uring_submit_and_wait(&ring, sqe_nr);
	if (ret < 0)
		return ret;

	idx = l = 0;
	io_uring_for_each_cqe(&ring, head, cqe) {
		printf("cqe->res=%d cqe->user_data=%llx\n", cqe->res, CLEAR_ID(cqe->user_data));
		if (EXTRACT_ID(cqe->user_data) == ID) {
			char *recvbuf = arr[idx].recvbuf;
			cqe->user_data = CLEAR_ID(cqe->user_data);
			ret = serialize_answ((uint16_t)cqe->user_data, (uint8_t *)recvbuf, cqe->res, NULL);
			printf("serialize return: %d\n", ret);
			idx++;
		}
		l++;
	}

	io_uring_cq_advance(&ring, l);
	io_uring_queue_exit(&ring);

	return 0;
}

int main(int argc, char **argv)
{
	gwdns_client_cfg cfg;
	int ret;

	srand(time(NULL));

	ret = parse_cmdline_args(&cfg, argc, argv);
	if (ret)
		return ret;

	ret = send_queries(&cfg);
	if (ret)
		return ret;

	return EXIT_SUCCESS;
}