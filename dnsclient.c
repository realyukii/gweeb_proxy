#define _GNU_SOURCE
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

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

// static int constuct_qname(const char *ptr)
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
	struct sockaddr_in addr;
	int ret, sockfd, port;
	size_t pkt_sz;

	static const uint8_t question[] = {
		0x6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,	/* 6 byte legnth of google */
		0x3, 0x63, 0x6f, 0x6d				/* 3 byte length of com */,
		0x0,						/* NULL-terminated */
		0x0, 0x1,					/* QTYPE */
		0x0, 0x1					/* QCLASS */
	};
	const uint8_t temp_req[] = {
		0xfb, 0x1d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01
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
	ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret) {
		ret = errno;
		fprintf(
			stderr,
			"error while attempting to connect to %s: %s\n",
			strerror(ret)
		);
		return ret;
	}

	memset(&pkt, 0, sizeof(pkt));
	memcpy(&pkt.hdr.id, "AA", 2);
	pkt.hdr.flags = 1 << 8;
	pkt.hdr.qdcount = 1 << 8;
	memcpy(&pkt.body, question, sizeof(question));
	pkt_sz = sizeof(pkt.hdr) + sizeof(question);
	ret = send(sockfd, temp_req, sizeof(temp_req), 0);
	if (ret < 0) {
		ret = errno;
		fprintf(
			stderr,
			"error while sending data to %s: %s\n",
			argv[1], strerror(ret)
		);
		return ret;
	}

	printf("%d bytes sent to %s\n", ret, argv[1]);

	char respbuf[1024];
	recv(sockfd, respbuf, 1024, 0);
	asm volatile("int3");

	return EXIT_SUCCESS;
}