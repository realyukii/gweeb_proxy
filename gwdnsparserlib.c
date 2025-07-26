#define _DEFAULT_SOURCE
#include <endian.h>
#include "gwdnsparserlib.h"

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
	size_t tot_len, advance_len;

	tot_len = 0;
	while (true) {
		if (*p == 0x0)
			break;

		if (tot_len >= in_len)
			return -ENAMETOOLONG;

		advance_len = *p + 1;
		tot_len += advance_len;
		p += advance_len;
	}

	return  tot_len;
}

int serialize_answ(uint16_t txid, uint8_t *in, size_t in_len, gwdns_answ_data *out)
{
	size_t advance_len, first_len;
	gwdns_header_pkt *hdr;
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

	out->hdr.ancount = hdr->ancount;
	out->rr_answ = malloc(hdr->ancount * sizeof(uint8_t *));
	for (size_t i = 0; i < hdr->ancount; i++) {
		uint16_t is_compressed, rdlength;
		gwdns_serialized_answ *item = malloc(sizeof(gwdns_serialized_answ));
		if (!item)
			return -ENOMEM;

		out->rr_answ[i] = item;

		memcpy(&is_compressed, in, sizeof(is_compressed));
		is_compressed = DNS_IS_COMPRESSED(ntohs(is_compressed));
		assert(is_compressed);
		in += 2; // NAME

		memcpy(&item->rr_type, in, 2);
		item->rr_type = ntohs(item->rr_type);
		in += 2; // TYPE
		memcpy(&item->rr_class, in, 2);
		item->rr_class = ntohs(item->rr_class);
		in += 2; // CLASS
		memcpy(&item->ttl, in, 4);
		item->ttl = be32toh(item->ttl);
		in += 4; // TTL

		memcpy(&rdlength, in, sizeof(rdlength));
		rdlength = ntohs(rdlength);
		if (item->rr_type == TYPE_AAAA && rdlength != sizeof(struct in6_addr))
			return -EINVAL;
		if (item->rr_type == TYPE_A && rdlength != sizeof(struct in_addr))
			return -EINVAL;
		item->rdlength = rdlength;
		in += 2;

		item->rdata = malloc(rdlength);
		memcpy(item->rdata, in, rdlength);
		in += rdlength;
	}

	return 0;
}

ssize_t construct_question(gwdns_question_part *question)
{
	gwdns_header_pkt *hdr;
	gwdns_query_pkt pkt;
	uint16_t qtype, qclass;
	size_t required_len;
	ssize_t bw;

	if (question->type != TYPE_AAAA && question->type != TYPE_A)
		return -EINVAL;

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
	qtype = htons(question->type);
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

#ifdef RUNTEST

void test_simulate_ipv4query(void)
{
	char buff[UDP_MSG_LIMIT];
	gwdns_query_pkt *send_pkt;
	uint8_t recv_pkt[] = {
		/* Header (12 bytes) */
		0x00, 0x00,		/* transaction ID - STUB! */
		0x81, 0x80,		/* Flags: QR=1, AA=0, RD=1, RA=1, RCODE=0 */
		0x00, 0x01,		/* QDCOUNT = 1 */
		0x00, 0x06,		/* ANCOUNT = 6 */
		0x00, 0x00,		/* NSCOUNT = 0 */
		0x00, 0x00,		/* ARCOUNT = 0 */
		
		/* Question Section */
		/* Pointer label compression may be used in answers */
		0x06, 'g','o','o','g','l','e',
		0x03, 'c','o','m',
		0x00,			/* Terminate name */
		0x00, 0x01,		/* QTYPE = A */
		0x00, 0x01,		/* QCLASS = IN */

		/* Answer Section (6 records) */
		/* Each Answer record: name pointer, type, class, ttl, rdlength, rdata */
		/* First Answer */
		0xC0, 0x0C,		/* Name: pointer to offset 0x0C (start of question name) */
		0x00, 0x01,		/* TYPE = A */
		0x00, 0x01,		/* CLASS = IN */
		0x00, 0x00, 0x08, 0x62, /* TTL = 0x00000862 = 2146 sec */
		0x00, 0x04,		/* RDLENGTH = 4 */
		0x4A, 0x7D, 0x18, 0x71,	/* RDATA = 74.125.24.113 */

		/* Second Answer */
		0xC0, 0x0C,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x08, 0x62,
		0x00, 0x04,
		0x4A, 0x7D, 0x18, 0x65, /* 74.125.24.101 */

		/* Third Answer */
		0xC0, 0x0C,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x08, 0x62,
		0x00, 0x04,
		0x4A, 0x7D, 0x18, 0x8B, /* 74.125.24.139 */

		/* Fourth Answer */
		0xC0, 0x0C,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x08, 0x62,
		0x00, 0x04,
		0x4A, 0x7D, 0x18, 0x8A, /* 74.125.24.138 */

		/* Fifth Answer */
		0xC0, 0x0C,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x08, 0x62,
		0x00, 0x04,
		0x4A, 0x7D, 0x18, 0x64, /* 74.125.24.100 */

		/* Sixth Answer */
		0xC0, 0x0C,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x08, 0x62,
		0x00, 0x04,
		0x4A, 0x7D, 0x18, 0x66, /* 74.125.24.102 */
	};
	gwdns_answ_data d;
	char first_label[] = "google";
	char second_label[] = "com";

	memset(&d, 0, sizeof(d));
	gwdns_question_part q = {
		.domain = "google.com",
		.dst_buffer = (uint8_t *)buff,
		.dst_len = sizeof(buff)
	};
	assert(construct_question(&q) > 0);

	assert(buff[12] == 6);
	assert(!memcmp(&buff[13], first_label, 6));

	assert(buff[13 + 6] == 3);
	assert(!memcmp(&buff[13 + 6 + 1], second_label, 3));

	// fill the STUB
	memcpy(recv_pkt, buff, 2);

	send_pkt = (void *)buff;
	assert(!serialize_answ(send_pkt->hdr.id, recv_pkt, sizeof(recv_pkt), &d));
}

void run_all_tests(void)
{
	test_simulate_ipv4query();
	fprintf(stderr, "all tests passed!\n");
}

int main(void)
{
	run_all_tests();
	return 0;
}

#endif
