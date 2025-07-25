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

	/* TODO: for now it's always assume the size is 4 bytes long (IPv4) */
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
		in += 2; // TYPE
		memcpy(&item->rr_class, in, 2);
		in += 2; // CLASS
		memcpy(&item->ttl, in, 4);
		in += 4; // TTL

		memcpy(&rdlength, in, sizeof(rdlength));
		rdlength = ntohs(rdlength);
		item->rdlength = rdlength;
		assert(rdlength == 4);
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
