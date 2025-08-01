#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <liburing.h>

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

/* as per RFC 1035 §2.3.4. Size limits */
#define DOMAIN_LABEL_LIMIT 63
#define DOMAIN_NAME_LIMIT 255
#define UDP_MSG_LIMIT 512

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
	TYPE_AAAA	= 28,	// text strings
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

typedef struct {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __packed gwdns_header_pkt;

typedef struct {
	uint8_t question[UDP_MSG_LIMIT];
	char answr[UDP_MSG_LIMIT];
} gwdns_question_buffer;

typedef struct {
	uint8_t *dst_buffer;
	uint16_t type;
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
	uint16_t  rr_type;	// TYPE: two-octet code identifying the RR type (see gwdns_type)
	uint16_t  rr_class;	// CLASS: two-octet code identifying the RR class (see gwdns_class)
	uint32_t  ttl;		// TTL: 32-bit unsigned, time to live in seconds
	uint16_t  rdlength;	// RDLENGTH: length in octets of RDATA
	uint8_t  *rdata;	// RDATA: variable-length data, format depends on TYPE and CLASS
} gwdns_serialized_rr;

typedef struct {
	char qname[DOMAIN_NAME_LIMIT];
	uint16_t qtype;
	uint16_t qclass;
} gwdns_serialized_question;

typedef gwdns_serialized_rr gwdns_serialized_answ;

typedef struct {
	gwdns_header_pkt hdr;
	uint8_t body[UDP_MSG_LIMIT];
} gwdns_query_pkt;

typedef struct {
	gwdns_header_pkt hdr;
	gwdns_serialized_question question;
	gwdns_serialized_answ **rr_answ;
} gwdns_answ_data;

/*
* Construct question packet
*
* @param	prepared question
* @return	length of bytes written into dst_buffer on success, or a negative integer on failure.
*
* possible error are:
* - ENAMETOOLONG	domain name in question.name is too long.
* - ENOBUFS		length in question.dst_len is not sufficient.
* - EINVAL		malformed or unsupported value in question data
*/
ssize_t construct_question(gwdns_question_part *question);

/*
* Serialize name server's answer
*
* @param txid	transaction id of question.
* @param in	a pointer to buffer that want to be parsed
* @param out	a pointer to serialized buffer of answer to question
* @return	zero on success or a negative number on failure
*
* possible error are:
* -EAGAIN	in buffer is not sufficient, no bytes are processed, need more data.
* -EINVAL	the content of in buffer is not valid.
* -ENOMEM	failed to allocate dynamic memory.
* -ENODATA	the packet didn't contain any answers.
* -EPROTO	the DNS server can't understand your question
*/
int serialize_answ(uint16_t txid, uint8_t *in, size_t in_len, gwdns_answ_data *out);