#include "gwdnsresolvlib.h"

int init_gwdns_resolv(gwdns_resolv_ctx *ctx, gwdns_resolv_param *param)
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

int deinit_gwdns_resolv(gwdns_resolv_ctx *ctx)
{
	io_uring_queue_exit(&ctx->ring);

	return 0;
}

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
int serialize_answ(uint16_t txid, uint8_t *in, size_t in_len, gwdns_serialized_answ *out)
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

ssize_t construct_question(gwdns_question_part *question)
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
