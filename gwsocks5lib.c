#define _GNU_SOURCE
#include <assert.h>
#include "gwsocks5lib.h"

#define PRTEST_OK() pr_info("Test passed: %s\n", __FUNCTION__)
#define HANDSHAKE_LEN 2
#define REPLY_REQ_IPV6_LEN (1 + 1 + 1 + 1 + 16 + 2)
#define MAX_USERPWD_PKT (1 + 1 + 255 + 1 + 255)

struct data_args {
	struct socks5_conn *conn;
	const void *in;
	unsigned *in_len;
	void *out;
	unsigned *out_len;
	unsigned total_advance;
	unsigned written_out;
};

// static void append_outbuf(struct data_args *args)
// {
// }

static void advance_inbuf(struct data_args *args, unsigned len)
{
	assert(len <= *args->in_len);
	args->in += len;
	*args->in_len -= len;
	args->total_advance += len;
}

static int socks5_load_creds_file(struct socks5_ctx *ctx, const char *auth_file)
{
	int ret, afd;
	struct socks5_creds *ac;

	ctx->creds.auth_file = strdup(auth_file);
	if (!ctx->creds.auth_file)
		return -ENOMEM;

	afd = open(ctx->creds.auth_file, O_RDONLY);
	if (afd < 0) {
		pr_err("failed to load %s file\n", ctx->creds.auth_file);
		return -errno;
	}

	ctx->creds.userpwd_buf = NULL;
	ctx->creds.userpwd_l.arr = NULL;
	ret = parse_auth_file(afd, &ctx->creds.userpwd_l, &ctx->creds.userpwd_buf);
	if (ret < 0) {
		ret = -EINVAL;
		pr_err("failed to parse %s file\n", ctx->creds.auth_file);
		goto exit_close_filefd;
	}

	ac = &ctx->creds;
	ac->authfd = afd;

	return 0;
exit_close_filefd:
	close(afd);
	return ret;
}

static int socks5_prepare_hotreload(struct socks5_ctx *ctx)
{
	int ret, ifd, epfd;
	struct epoll_event ev;
	struct socks5_creds *ac;

	ifd = inotify_init1(IN_NONBLOCK);
	if (ifd < 0) {
		pr_err(
			"failed to create inotify file descriptor: %s\n",
			strerror(errno)
		);
		return -EXIT_FAILURE;
	}

	ac = &ctx->creds;
	ret = inotify_add_watch(ifd, ac->auth_file, IN_CLOSE_WRITE);
	if (ret < 0) {
		pr_err(
			"failed to add file to inotify watch: %s\n",
			strerror(errno)
		);
		goto exit_close_ifd;
	}

	epfd = epoll_create(1);
	if (epfd < 0) {
		pr_err(
			"failed to create epoll file descriptor: %s\n",
			strerror(errno)
		);
		goto exit_close_ifd;
	}

	ev.events = EPOLLIN;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, ifd, &ev);
	if (ret < 0) {
		pr_err(
			"failed to add inotifyfd to epoll: %s\n",
			strerror(errno)
		);
		goto exit_close_epfd;
	}

	ac->ifd = ifd;

	return 0;
exit_close_epfd:
	close(epfd);
exit_close_ifd:
	close(ifd);
	return -EXIT_FAILURE;
}

static int socks5_init_creds(struct socks5_ctx *ctx, const char *auth_file)
{
	int ret;
	ret = socks5_load_creds_file(ctx, auth_file);
	if (ret < 0)
		return ret;

	ret = socks5_prepare_hotreload(ctx);
	return ret;
}

static int socks5_handle_greeting(struct data_args *args)
{
	uint8_t chosen_method;
	const uint8_t *ptr;
	unsigned exp_len, required_len = 2;
	bool acceptable;
	const unsigned char *in = args->in;
	struct socks5_handshake *out = args->out;

	if (*args->out_len < required_len) {
		*args->out_len = 2;
		return -ENOBUFS;
	}

	exp_len = 2;
	if (*args->in_len < exp_len) {
		*args->in_len = exp_len;
		return -EAGAIN;
	}
	
	if (in[0] != 0x5)
		return -EINVAL;
	
	if (in[1] == 0x0)
		return -EINVAL;

	exp_len += in[1];
	if (*args->in_len < exp_len) {
		*args->in_len = exp_len;
		return -EAGAIN;
	}
	advance_inbuf(args, exp_len);

	chosen_method = args->conn->ctx->creds.auth_file ? 0x2 : 0x0;
	acceptable = false;
	ptr = &in[2];
	for (size_t i = 0; i < in[1]; i++) {
		if (ptr[i] == chosen_method) {
			acceptable = true;
			break;
		}
	}

	out->ver = 0x5;
	out->chosen_method = acceptable ? chosen_method : 0xFF;
	args->written_out += required_len;
	args->out += required_len;
	*args->out_len -= required_len;

	args->conn->state = chosen_method == 0x2 ? SOCKS5_AUTH : SOCKS5_REQUEST;

	return 0;
}

static int socks5_handle_auth(struct data_args *args)
{
	struct userpwd_pair *p;
	const struct socks5_userpwd *in = args->in;
	const char *username, *password;
	char *out = args->out;
	bool is_authenticated;
	uint8_t *plen;
	unsigned exp_len = 2, required_len = 2;
	int i, ret;

	if (*args->out_len < required_len) {
		*args->out_len = required_len;
		return -ENOBUFS;
	}

	if (*args->in_len < exp_len)
		return -EAGAIN;

	// if (in->ver != 1) {
	// 	return -EINVAL;
	// }

	exp_len += in->ulen + 1;
	if (*args->in_len < exp_len)
		return -EAGAIN;

	username = in->rest_bytes;
	plen = (void *)&in->rest_bytes[in->ulen];

	exp_len += *plen;
	if (*args->in_len < exp_len)
		return -EAGAIN;

	advance_inbuf(args, exp_len);

	password = (void *)(plen + 1);

	is_authenticated = 0x1;
	for (i = 0; i < args->conn->ctx->creds.userpwd_l.nr_entry; i++) {
		p = &args->conn->ctx->creds.userpwd_l.arr[i];

		if (in->ulen != p->ulen || *plen != p->plen)
			continue;

		ret = memcmp(username, p->username, in->ulen);
		if (ret)
			continue;

		ret = memcmp(password, p->password, *plen);
		if (ret)
			continue;

		is_authenticated = 0x0;
		break;
	}

	out[0] = 0x1;
	out[1] = is_authenticated;
	args->written_out += required_len;
	args->out += required_len;
	*args->out_len -= required_len;

	return 0;
}

static void set_err_reply(struct socks5_reply *out, uint8_t rep_code)
{
	uint16_t port = 0;

	out->ver = 0x5;
	out->rep_code = rep_code;
	out->rsv = 0x0;
	out->bnd_addr.type = SOCKS5_IPv4;
	memset(out->bnd_addr.addr.ipv4, 0, 4);
	memcpy((void *)(out->bnd_addr.addr.ipv4 + 4), &port, 2);
}

static int socks5_handle_request(struct data_args *args)
{
	uint8_t atyp;
	struct socks5_reply *out = args->out;
	const struct socks5_request *in = args->in;
	enum socks5_state state;
	unsigned exp_len = 4, required_len = 4 + 4 + 2;

	if (*args->out_len < required_len) {
		*args->out_len = required_len;
		return -ENOBUFS;
	}

	if (*args->in_len < exp_len) {
		*args->in_len = exp_len;
		return -EAGAIN;
	}

	if (in->ver != 0x5) {
		set_err_reply(out, SOCKS5_GENERAL_FAILURE);
		args->written_out += required_len;
		args->out += required_len;
		*args->out_len -= required_len;
		return -EINVAL;
	}

	switch (in->cmd) {
	case SOCKS5_CMD_CONNECT:
		state = SOCKS5_CONNECT;
		break;

	/*
	* TODO(reyuki): implement other command:
	*/
	case SOCKS5_CMD_BIND:
	case SOCKS5_CMD_UDP_ASSOCIATE:
	default:
		set_err_reply(out, SOCKS5_CMD_NOT_SUPPORTED);
		args->written_out += required_len;
		args->out += required_len;
		*args->out_len -= required_len;
		return -EINVAL;
	}

	atyp = in->dst_addr.type;
	switch (atyp) {
	case SOCKS5_IPv4:
		exp_len += 4;
		break;
	case SOCKS5_DOMAIN:
		exp_len += 1;
		if (*args->in_len < exp_len)
			return -EAGAIN;
		exp_len += in->dst_addr.addr.domain.len;
		break;
	case SOCKS5_IPv6:
		exp_len += 16;
		break;
	default:
		set_err_reply(out, SOCKS5_ADDR_TYPE_NOT_SUPPORTED);
		args->written_out += required_len;
		args->out += required_len;
		*args->out_len -= required_len;
		return -EINVAL;
	}
	exp_len += 2;

	if (*args->in_len < exp_len) {
		*args->in_len = exp_len;
		return -EAGAIN;
	}

	advance_inbuf(args, exp_len);

	args->conn->state = state;

	return 0;
}

int socks5_reload_creds_file(struct socks5_ctx *ctx)
{
	int ret;
	struct socks5_creds *ac = &ctx->creds;
	if (ac->userpwd_l.nr_entry) {
		ac->userpwd_l.prev_arr = ac->userpwd_l.arr;
		ac->prev_userpwd_buf = ac->userpwd_buf;
	}

	ret = parse_auth_file(ac->authfd, &ac->userpwd_l, &ac->userpwd_buf);
	if (!ret) {
		free(ac->userpwd_l.prev_arr);
		free(ac->prev_userpwd_buf);
	}

	return ret;
}

int socks5_init(struct socks5_ctx **ctx, struct socks5_cfg *p)
{
	int r;
	struct socks5_ctx *c = malloc(sizeof(*c));
	if (!c)
		return -ENOMEM;

	*ctx = c;

	if (p->auth_file) {
		r = socks5_init_creds(c, p->auth_file);
		if (r < 0)
			return r;
	} else
		c->creds.auth_file = NULL;

	return 0;
}

struct socks5_conn *socks5_alloc_conn(struct socks5_ctx *ctx)
{
	if (!ctx)
		return NULL;

	struct socks5_conn *c = malloc(sizeof(*c));
	if (!c)
		return NULL;

	c->ctx = ctx;
	c->state = SOCKS5_GREETING;

	return c;
}

int socks5_process_data(struct socks5_conn *conn, const void *in, unsigned *in_len,
			void *out, unsigned *out_len)
{
	struct data_args args = {
		.conn = conn,
		.in = in,
		.in_len = in_len,
		.out = out,
		.out_len = out_len,
		.total_advance = 0,
		.written_out = 0
	};
	int r;

retry:
	switch (conn->state) {
	case SOCKS5_GREETING:
		r = socks5_handle_greeting(&args);
		break;
	case SOCKS5_AUTH:
		r = socks5_handle_auth(&args);
		break;
	case SOCKS5_REQUEST:
		r = socks5_handle_request(&args);
		break;
	default:
		abort();
		break;
	}

	if (!r && *args.in_len > 0)
		goto retry;

	*in_len = args.total_advance;
	*out_len = args.written_out;

	return r;
}

int socks5_handle_cmd_connect(struct socks5_conn *conn, struct socks5_addr *sa,
				uint8_t rep_code, void *rep_buf, unsigned *rep_len)
{
	struct socks5_reply *rep = rep_buf;
	unsigned required_len;
	uint8_t dlen;

	required_len = 4;
	if (*rep_len < required_len)
		return -ENOBUFS;

	rep->ver = 0x5;
	rep->rsv = 0x0;
	rep->rep_code = rep_code;
	rep->bnd_addr.type = sa->type;
	switch (sa->type) {
	case SOCKS5_IPv4:
		required_len += 4 + 2;
		if (*rep_len < required_len) {
			*rep_len = required_len;
			return -ENOBUFS;
		}
		memcpy(rep->bnd_addr.addr.ipv4, sa->addr.ipv4, 4);
		memcpy((void *)(rep->bnd_addr.addr.ipv4 + 4), &sa->port, 2);
		break;
	case SOCKS5_DOMAIN:
		dlen = sa->addr.domain.len;
		required_len += 1 + dlen + 2;
		if (*rep_len < required_len) {
			*rep_len = required_len;
			return -ENOBUFS;
		}
		rep->bnd_addr.addr.domain.len = dlen;
		memcpy(rep->bnd_addr.addr.domain.name, sa->addr.domain.name, dlen);
		memcpy((void *)(rep->bnd_addr.addr.domain.name + dlen), &sa->port, 2);
		break;
	case SOCKS5_IPv6:
		required_len += 16 + 2;
		if (*rep_len < required_len) {
			*rep_len = required_len;
			return -ENOBUFS;
		}
		memcpy(rep->bnd_addr.addr.ipv6, sa->addr.ipv6, 16);
		memcpy((void *)(rep->bnd_addr.addr.ipv6 + 16), &sa->port, 2);
		break;

	default:
		return -EINVAL;
	}
	conn->state = SOCKS5_FORWARDING;
	*rep_len = required_len;

	return 0;
}

void socks5_free_ctx(struct socks5_ctx *ctx)
{
	if (ctx->creds.auth_file) {
		free((void *)ctx->creds.auth_file);
		free(ctx->creds.userpwd_l.arr);
		free(ctx->creds.userpwd_buf);
		close(ctx->creds.authfd);
		close(ctx->creds.ifd);
	}

	free(ctx);
}

void socks5_free_conn(struct socks5_conn *c)
{
	free(c);
}

static void socks5_test_creds_file_not_found(void)
{
	int r;
	struct socks5_cfg param = {
		.auth_file = "./notfound.db"
	};
	struct socks5_ctx *ctx;
	r = socks5_init(&ctx, &param);
	assert(r == -ENOENT);

	PRTEST_OK();
}

static void socks5_test_invalid_creds_format(void)
{
	int r;
	struct socks5_cfg param = {
		.auth_file = "./invalid_creds.db"
	};
	struct socks5_ctx *ctx;
	r = socks5_init(&ctx, &param);
	assert(r == -EINVAL);

	PRTEST_OK();
}

#define socks5_do_init_ctx_noauth(CTX)				\
do {								\
	struct socks5_cfg param = {				\
		.auth_file = NULL				\
	};							\
	int _r;							\
	_r = socks5_init(CTX, &param);				\
	assert(!_r);						\
} while (0)

#define socks5_do_alloc_conn(CTX, CONN)				\
do {								\
	CONN = socks5_alloc_conn(CTX);				\
	assert(CONN);						\
	assert(CONN->state == SOCKS5_GREETING);			\
} while (0)

#define socks5_do_greeting_noauth(CONN)							\
do {											\
	int _r;										\
	const uint8_t _payload_greeting[] = {						\
		0x5, 0x1, 0x0,	/* VER, NMETHODS, NO AUTH METHOD */			\
	};										\
	char _out_buf[HANDSHAKE_LEN];							\
	unsigned _plen, _olen;								\
	_plen = sizeof(_payload_greeting);						\
	_olen = sizeof(_out_buf);							\
	_r = socks5_process_data(CONN, _payload_greeting, &_plen, _out_buf, &_olen);	\
	assert(!_r);									\
	assert(_plen == 3);								\
	assert(_olen == HANDSHAKE_LEN);							\
	assert(_out_buf[0] == 0x5);	/* VER */					\
	assert(_out_buf[1] == 0x0);	/* NO AUTH METHOD */				\
	assert(CONN->state == SOCKS5_REQUEST);						\
} while(0)

static void socks5_test_invalid_cmd(void)
{
	int r;
	unsigned plen, olen;
	struct socks5_conn *conn;
	struct socks5_ctx *ctx;
	char out_buf[1024];
	const uint8_t payload[] = {
		0x5, 0xf, 0x0, 0x5, 	// VER, invalid CMD, RSV, IPv6 ATYP
	};

	socks5_do_init_ctx_noauth(&ctx);
	socks5_do_alloc_conn(ctx, conn);
	socks5_do_greeting_noauth(conn);

	plen = sizeof(payload);
	olen = sizeof(out_buf);
	r = socks5_process_data(conn, payload, &plen, out_buf, &olen);
	assert(r == -EINVAL);

	socks5_free_conn(conn);
	socks5_free_ctx(ctx);
}

static void socks5_test_invalid_addr_type(void)
{
	int r;
	unsigned plen, olen;
	struct socks5_conn *conn;
	struct socks5_ctx *ctx;
	char out_buf[1024];
	const uint8_t payload[] = {
		0x5, 0x1, 0x0, 0x5, 	// VER, CONNECT CMD, RSV, invalid ATYP
	};

	socks5_do_init_ctx_noauth(&ctx);
	socks5_do_alloc_conn(ctx, conn);
	socks5_do_greeting_noauth(conn);

	plen = sizeof(payload);
	olen = sizeof(out_buf);
	r = socks5_process_data(conn, payload, &plen, out_buf, &olen);
	assert(r == -EINVAL);

	socks5_free_conn(conn);
	socks5_free_ctx(ctx);
}

static void socks5_test_ipv6_noauth(void)
{
	int r;
	unsigned plen, olen;
	char out_buf[1024];
	const uint8_t payload[] = {
		0x5, 0x1, 0x0, 0x4, 	// VER, CONNECT CMD, RSV, IPv6 ATYP
		0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x1,	// address ::1
		0x1f, 0x91		// port 8081
	};
	struct socks5_conn *conn;
	struct socks5_ctx *ctx;

	socks5_do_init_ctx_noauth(&ctx);
	socks5_do_alloc_conn(ctx, conn);
	socks5_do_greeting_noauth(conn);

	plen = sizeof(payload);
	olen = sizeof(out_buf);
	r = socks5_process_data(conn, payload, &plen, out_buf, &olen);
	assert(!r);
	assert(conn->state == SOCKS5_CONNECT);

	/* .. pretend perform connect syscall ... */

	struct socks5_addr saddr = {
		.type = 0x4,
		.port = htons(5081),
		.addr.ipv6 = {
			0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x1
		}
	};
	olen = sizeof(out_buf);
	socks5_handle_cmd_connect(conn, &saddr, 0, out_buf, &olen);
	assert(olen == REPLY_REQ_IPV6_LEN);

	assert(out_buf[0] == 0x5);				// VER
	assert(out_buf[1] == 0x0);				// REP success
	assert(out_buf[2] == 0x0);				// RSV
	assert(out_buf[3] == 0x4);				// ATYP IPv6
	assert(!memcmp(&out_buf[4], saddr.addr.ipv6, 16));	// BND ADDR ::1
	assert(!memcmp(&out_buf[20], "\x13\xd9", 2));		// BND PORT 5081

	socks5_free_conn(conn);
	socks5_free_ctx(ctx);

	PRTEST_OK();
}

static void socks5_test_two_state_at_once(void)
{
	int r;
	unsigned plen, olen;
	char out_buf[1024];
	const uint8_t payload[] = {
		0x5, 0x1, 0x0,		// VER, NMETHODS, METHOD NO AUTH
		0x5, 0x1, 0x0, 0x2, 	// VER, CONNECT CMD, RSV, invalid ATYP
		0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x1,	// address ::1
		0x1f, 0x91		// port 8081
	};
	struct socks5_conn *conn;
	struct socks5_ctx *ctx;

	socks5_do_init_ctx_noauth(&ctx);
	socks5_do_alloc_conn(ctx, conn);

	plen = sizeof(payload);
	olen = sizeof(out_buf);
	r = socks5_process_data(conn, payload, &plen, out_buf, &olen);
	assert(r == -EINVAL);
	assert(olen == 12);
	assert(conn->state == SOCKS5_REQUEST);

	socks5_free_conn(conn);
	socks5_free_ctx(ctx);

	PRTEST_OK();
}

static void socks5_run_tests()
{
	/* test case for improper usage of library */
	socks5_test_creds_file_not_found();
	socks5_test_invalid_creds_format();
	/* test case for malformed payload */
	socks5_test_invalid_cmd();
	socks5_test_invalid_addr_type();
	socks5_test_two_state_at_once();
	socks5_test_ipv6_noauth();
	pr_info("All tests passed!\n");
}

int main()
{
	socks5_run_tests();

	return 0;
}