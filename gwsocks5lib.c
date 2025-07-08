#define _GNU_SOURCE
#include <assert.h>
#include "gwsocks5lib.h"

#define PRTEST_OK() pr_info("Test passed: %s\n", __FUNCTION__)

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
		return -EXIT_FAILURE;
	}

	ctx->creds.userpwd_buf = NULL;
	ctx->creds.userpwd_l.arr = NULL;
	ret = parse_auth_file(afd, &ctx->creds.userpwd_l, &ctx->creds.userpwd_buf);
	if (ret < 0) {
		pr_err("failed to parse %s file\n", ctx->creds.auth_file);
		goto exit_close_filefd;
	}

	ac = &ctx->creds;
	// ac->epfd = epfd;
	// ac->ifd = ifd;
	ac->authfd = afd;

	return 0;
exit_close_filefd:
	close(afd);
	return -EXIT_FAILURE;
}

__attribute__((__unused__))
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

	// ev.events = EPOLLIN;
	// ev.data.fd = a->stopfd;
	// ret = epoll_ctl(epfd, EPOLL_CTL_ADD, a->stopfd, &ev);
	// if (ret < 0) {
	// 	pr_err(
	// 		"failed to add eventfd to epoll: %s\n",
	// 		strerror(errno)
	// 	);
	// 	goto exit_close_epfd;
	// }

	ac->ifd = ifd;
	pthread_rwlock_init(&ctx->creds.creds_lock, NULL);

	return 0;
exit_close_epfd:
	close(epfd);
exit_close_ifd:
	close(ifd);
	return -EXIT_FAILURE;
}

static int socks5_init_creds(struct socks5_ctx *ctx, const char *auth_file)
{
	return socks5_load_creds_file(ctx, auth_file);
	// TODO: when hot reload feature is enabled, figure out how other program interact with it.
	// socks5_prepare_hotreload(ctx);
}

/*
* Initialize socks5 instance.
*
* @param ctx
* @param p
* @return zero on success, or a negative integer on failure.
*/
static int socks5_init(struct socks5_ctx *ctx, struct socks5_param *p)
{
	int r;
	if (p->auth_file) {
		r = socks5_init_creds(ctx, p->auth_file);
		if (r < 0)
			return -EXIT_FAILURE;
	} else
		ctx->creds.auth_file = NULL;

	return 0;
}

// static struct socks5_conn *socks5_accept_greet(struct socks5_ctx *ctx,
static int socks5_accept_greet(struct socks5_ctx *ctx,
						struct socks5_greeting *buffer)
{
	uint8_t i, preferred_auth = NONE;

	if (buffer->ver != 0x5)
		return preferred_auth;

	for (i = 0; i < buffer->nauth; i++) {
		switch (buffer->methods[i]) {
		case NO_AUTH:
			if (ctx->creds.auth_file)
				continue;
			preferred_auth = NO_AUTH;
			goto auth_method_found;
		case USERNAME_PWD:
			if (ctx->creds.auth_file) {
				preferred_auth = USERNAME_PWD;
				goto auth_method_found;
			}
		}
	}

auth_method_found:
	return preferred_auth;
}

static int socks5_free_conn(struct socks5_ctx *ctx)
{
	if (ctx->creds.auth_file) {
		free((void *)ctx->creds.auth_file);
		free(ctx->creds.userpwd_l.arr);
		free(ctx->creds.userpwd_buf);
		close(ctx->creds.authfd);
		// destroyed only when hot reload feature is enabled
		// pthread_rwlock_destroy(&ctx->creds.creds_lock);
	}

	return 0;
}

static void socks5_test_noauth(void)
{
	int r;
	struct socks5_param param = {
		.auth_file = NULL
	};
	struct socks5_greeting greeting_buf;
	struct socks5_ctx ctx;
	r = socks5_init(&ctx, &param);
	assert(!r);

	greeting_buf.ver = 0x5;
	greeting_buf.nauth = 0x1;
	greeting_buf.methods[0] = NO_AUTH;
	r = socks5_accept_greet(&ctx, &greeting_buf);
	assert(r == NO_AUTH);

	socks5_free_conn(&ctx);
	PRTEST_OK();
}

static void socks5_test_userpwd(void)
{
	int r;
	struct socks5_param param = {
		.auth_file = "./auth.db"
	};
	struct socks5_greeting greeting_buf;
	struct socks5_ctx ctx;
	r = socks5_init(&ctx, &param);
	assert(!r);

	greeting_buf.ver = 0x5;
	greeting_buf.nauth = 0x1;
	greeting_buf.methods[0] = USERNAME_PWD;
	r = socks5_accept_greet(&ctx, &greeting_buf);
	assert(r == USERNAME_PWD);

	socks5_free_conn(&ctx);
	PRTEST_OK();
}

static void socks5_test_creds_file_not_found(void)
{
	int r;
	struct socks5_param param = {
		.auth_file = "./notfound.db"
	};
	struct socks5_ctx ctx;
	r = socks5_init(&ctx, &param);
	assert(r);

	PRTEST_OK();
}

static void socks5_test_invalid_creds_format(void)
{
	int r;
	struct socks5_param param = {
		.auth_file = "./invalid_creds.db"
	};
	struct socks5_ctx ctx;
	r = socks5_init(&ctx, &param);
	assert(r);

	PRTEST_OK();
}

static void socks5_run_tests()
{
	socks5_test_noauth();
	socks5_test_userpwd();
	socks5_test_creds_file_not_found();
	socks5_test_invalid_creds_format();
	pr_info("All tests passed!\n");
}

int main()
{
	socks5_run_tests();

	return 0;
}