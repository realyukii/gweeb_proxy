#define _GNU_SOURCE
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <liburing.h>

#define QCLASS_IN 1
#define QTYPE_A 1

/*
* the struct only represent serialized packet
* and not used to represent on-wire data
*/
struct dns_question {
	char *qname;
	uint16_t qtype;
	uint16_t qclass;
};

struct dns_header_pkt {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((__packed__));

struct dns_query_pkt {
	struct dns_header_pkt hdr;
	uint8_t body[1024];
};

// static int construct_qname(const char *ptr)
// {
// 	size_t qname_len;
// 	char *qname;
	
// 	qname = strdup(ptr);
// 	if (!qname)
// 		return -ENOMEM;

// 	qname_len = strlen(qname);
// 	// for (size_t i = 0; i < qname_len; i++) {
// 	// 	// TODO
// 	// }
	
// }

int main(int argc, char **argv)
{
	struct dns_query_pkt pkt;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct sockaddr_in addr;
	int ret, sockfd, port;
	struct io_uring ring;
	size_t pkt_sz;
	unsigned head;

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret)
		return ret;
	
	sqe = io_uring_get_sqe(&ring);
	if (!sqe)
		return -1;


	static const uint8_t question[] = {
		0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,	/* 6 byte legnth of google */
		0x3, 0x63, 0x6f, 0x6d				/* 3 byte length of com */,
		0x0,						/* NULL-terminated */
		0x0, 0x1,					/* QTYPE */
		0x0, 0x1					/* QCLASS */
	};
	const static char *qnames[] = {"google.com", "youtube.com", "facebook.com"};
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

	memset(&pkt, 0, sizeof(pkt));
	memcpy(&pkt.hdr.id, "AA", 2);
	pkt.hdr.flags = 1;
	pkt.hdr.qdcount = 1 << 8;
	memcpy(&pkt.body, question, sizeof(question));
	pkt_sz = sizeof(pkt.hdr) + sizeof(question);
	// asm volatile("int3");
	// ret = send(sockfd, temp_req, sizeof(temp_req), 0);
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_send(sqe, sockfd, &pkt, pkt_sz, 0);
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
		printf("data: %ld cqe res: %d\n", cqe->user_data, cqe->res);
		i++;
	}

	io_uring_cq_advance(&ring, i);
	io_uring_queue_exit(&ring);

	return EXIT_SUCCESS;
}