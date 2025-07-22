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

/*
* the struct only represent serialized packet
* and not used to represent on-wire data
*/
struct dns_question {
	char *qname;
	uint16_t qtype;
	uint16_t qclass;
};

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

static ssize_t construct_qname(char *dst, size_t dst_len, const char *qname)
{
	const uint8_t *p = qname;
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
 * 4.1.1. Header section format
 *
 * The header contains the following fields:
 *
 *                                    1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      ID                       |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    QDCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ANCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    NSCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ARCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *   ID       – A 16‑bit identifier assigned by the program that
 *              generates a query; echoed in the reply to match requests.
 *   QR       – 1‑bit: 0 = query, 1 = response.
 *   Opcode   – 4‑bit field specifying the query type (e.g., standard, inverse, status).
 *   AA       – 1‑bit Authoritative Answer: valid in responses.
 *   TC       – 1‑bit TrunCation: indicates the message was truncated.
 *   RD       – 1‑bit Recursion Desired: set in query, copied in response.
 *   RA       – 1‑bit Recursion Available: set in response if recursive support is provided.
 *   Z        – 3‑bit reserved field; must be zero in all queries and responses.
 *   RCODE    – 4‑bit Response code: indicates success or various errors.
 *   QDCOUNT  – Unsigned 16‑bit: number of entries in the Question section.
 *   ANCOUNT  – Unsigned 16‑bit: number of RRs in the Answer section.
 *   NSCOUNT  – Unsigned 16‑bit: number of name server RRs in the Authority section.
 *   ARCOUNT  – Unsigned 16‑bit: number of RRs in the Additional section.
 *
 * (Diagram and field definitions adapted from RFC 1035 §4.1.1) :contentReference[oaicite:1]{index=1}
 */

static ssize_t construct_question(uint8_t *buffer, size_t len, char *domains[], size_t entry_nr, uint16_t qtype, uint16_t qclass)
{
	struct dns_query_pkt pkt;
	struct dns_header_pkt *hdr;
	ssize_t bw;
	size_t required_len;

	hdr = &pkt.hdr;
	memset(hdr, 0, sizeof(*hdr));
	/* TODO: somehow randomize the id */
	hdr->id = 0xFFFF;
	hdr->flags.aa = false;
	hdr->flags.opcode = OPCODE_QUERY;
	hdr->flags.rd = true;
	// 1000000

	qtype = htons(qtype);
	qclass = htons(qclass);

	hdr->qdcount = htons(entry_nr);

	for (size_t i = 0; i < entry_nr; i++) {
		char *domain = domains[i];
		bw = construct_qname(pkt.body, sizeof(pkt.body) - 3, domain);
		if (bw < 0)
			return bw;

		pkt.body[bw++] = 0x0;
		memcpy(&pkt.body[bw], &qtype, 2);
		bw += 2;
		memcpy(&pkt.body[bw], &qclass, 2);
		bw += 2;
		// VT_HEXDUMP(&pkt, sizeof(pkt.hdr) + bytes_written);
	}

	required_len = sizeof(pkt.hdr) + bw;
	if (len < required_len)
		return -ENOBUFS;

	VT_HEXDUMP(&pkt, required_len);
	memcpy(buffer, &pkt, required_len);

	// uint16_t little_endian = 128;
	// uint16_t big_endian = htons(little_endian);
	// VT_HEXDUMP(&big_endian, sizeof(uint16_t));
	// VT_HEXDUMP(&little_endian, sizeof(uint16_t));

	return required_len;
}

int main(int argc, char **argv)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct sockaddr_in addr;
	int ret, sockfd, port;
	struct io_uring ring;
	unsigned head;
	uint8_t bigbuff[1024];

	static char *qnames[] = {"google.com"};
	size_t send_len = construct_question(bigbuff, 1024, qnames, sizeof(qnames) / 8, TYPE_A, CLASS_IN);
	if (send_len < 0)
		return -1;

	printf("bytes to send: %d\n", send_len);

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret)
		return ret;
	
	sqe = io_uring_get_sqe(&ring);
	if (!sqe)
		return -1;
	const uint8_t temp_req[] = {
		0xfb, 0x1d, /* uint16_t id; */
		0x01, 0x00, /* uint16_t flags; */
		0x00, 0x01, /* uint16_t qdcount; */
		0x00, 0x00, /* uint16_t ancount; */
		0x00, 0x00, /* uint16_t nscount; */
		0x00, 0x00, /* uint16_t arcount; */
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, /* 6 byte legnth of google */
		0x03, 0x63, 0x6f, 0x6d, /* 3 byte length of com */
		0x00, /* NULL-terminated */
		0x00, 0x01, /* QTYPE */
		0x00, 0x01 /* QCLASS */
	};

	if (argc < 4) {
		fprintf(
			stderr,
			"usage: ./dnsclient "
			"<dns server ip> <dns server port> <domain name>\n"
		);

		return EINVAL;
	}

	port = atoi(argv[2]);
	if (port <= 0) {
		fprintf(stderr, "port number can't be zero or negative.\n");
		return EINVAL;
	}

	ret = inet_pton(AF_INET, argv[1], &addr.sin_addr);
	if (!ret) {
		fprintf(
			stderr,
			"invalid dns server ip (currently only support IPv4)\n."
		);
		return EINVAL;
	}

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

	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	io_uring_prep_connect(sqe, sockfd, (struct sockaddr *)&addr, sizeof(addr));
	sqe->flags |= IOSQE_IO_LINK;
	io_uring_sqe_set_data64(sqe, 1);

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_send(sqe, sockfd, bigbuff, send_len, 0);
	io_uring_sqe_set_data64(sqe, 2);
	sqe->flags |= IOSQE_IO_LINK;

	/*
	* example response:
	ID \x41\x41
	FLAG \x81\x80	10000001 10000000 = QR:response RD:true RA:true RCODE: no error
	QDCOUNT \x00\x01 
	ANCOUNT \x00\x06 6 record
	NSCOUNT \x00\x00
	ARCOUNT \x00\x00
	QNAME \x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00
	QTYPE \x00\x01 A
	QCLASS \x00\x01 Internet
	
	NAME \xc0\x0c offset = 12 (point to qname?)
	TYPE \x00\x01 A?
	CLASS \x00\x01 Internet?
	TTL \x00\x00\x02\x58
	RDLENGHT \x00\x04 
	RDATA \x40\xe9\xaa\x64
	
	NAME \xc0\x0c
	TYPE \x00\x01
	CLASS \x00\x01
	TTL \x00\x00\x02\x58
	RDLENGTH \x00\x04 4 bytes for IPv4
	RDATA \x40\xe9\xaa\x8a

	\xc0\x0c\x00\x01
	\x00\x01\x00\x00
	\x02\x58\x00\x04
	\x40\xe9\xaa\x65
	
	\xc0\x0c\x00\x01
	\x00\x01\x00\x00
	\x02\x58\x00\x04
	\x40\xe9\xaa\x8b
	
	\xc0\x0c\x00\x01
	\x00\x01\x00\x00
	\x02\x58\x00\x04
	\x40\xe9\xaa\x66
	
	\xc0\x0c\x00\x01
	\x00\x01\x00\x00
	\x02\x58\x00\x04
	\x40\xe9\xaa\x71
	
	*/

	char respbuf[1024];
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_recv(sqe, sockfd, respbuf, 1024, 0);
	io_uring_sqe_set_data64(sqe, 3);
	sqe->flags |= IOSQE_IO_LINK;

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_close(sqe, sockfd);
	io_uring_sqe_set_data64(sqe, 4);
	sqe->flags |= IOSQE_IO_LINK;
	
	ret = io_uring_submit_and_wait(&ring, 4);
	if (ret < 0)
		return -1;

	unsigned i = 0;
	int ready = io_uring_cq_ready(&ring);
	printf("ready list: %d\n", ready);
	io_uring_for_each_cqe(&ring, head, cqe) {
		if (cqe->user_data == 3)
			VT_HEXDUMP(respbuf, cqe->res);
		if (cqe->user_data == 2)
			VT_HEXDUMP(bigbuff, cqe->res);
		printf("data: %ld cqe res: %d\n", cqe->user_data, cqe->res);
		i++;
	}

	io_uring_cq_advance(&ring, i);
	io_uring_queue_exit(&ring);

	return EXIT_SUCCESS;
}