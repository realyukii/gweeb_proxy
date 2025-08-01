#include "gwdnslib.h"

static void enqueue_req(struct dns_queue *q, struct gwdns_req *r)
{
	if (q->head) {
		q->tail->next = r;
		q->tail = r;
	} else
		q->head = q->tail = r;
}

static void dequeue_req(struct dns_queue *q)
{
	struct gwdns_req *r = q->head;

	if (!r)
		return;
	
	q->head = r->next;
	if (!q->head)
		q->tail = NULL;
}

static void resolve_dns(struct gwdns_req *req)
{
	struct addrinfo *l;
	int ret;

	ret = getaddrinfo(req->domainname, req->port, NULL, &l);
	if (ret != 0) {
		pr_err(
			"failed to resolve domain name %s reason: %s\n",
			req->domainname, gai_strerror(ret)
		);
		req->status = ret;
		return;
	}

	req->status = 0;
	memcpy(&req->result, l->ai_addr, l->ai_addrlen);
	freeaddrinfo(l);
}

static void *dns_serv_thread(void *args)
{
	struct gwdns_ctx *dctx;
	struct gwdns_req *r;
	intptr_t ret;

	ret = 0;
	dctx = args;
	pr_dbg("attempting to lock dns\n");
	pthread_mutex_lock(&dctx->dns_lock);
	pr_dbg("dns_lock acquired\n");
	while (!dctx->should_stop) {
		r = dctx->q.head;
		if (!r) {
			dctx->sleep_nr++;
			pr_dbg("releasing dns_lock and waiting signal\n");
			pthread_cond_wait(&dctx->dns_cond, &dctx->dns_lock);
			pr_dbg("dns_lock acquired\n");
			dctx->sleep_nr--;
			continue;
		}

		pr_dbg("doing blocking operation, releasing dns_lock\n");
		dequeue_req(&dctx->q);
		pthread_mutex_unlock(&dctx->dns_lock);
		resolve_dns(r);
		eventfd_write(r->evfd, 1);
		gwdns_release_req(r);

		pr_dbg("attempting to lock dns_lock\n");
		pthread_mutex_lock(&dctx->dns_lock);
		pr_dbg("acquired dns_lock\n");
	}
	pr_dbg("releasing dns_lock\n");
	pthread_mutex_unlock(&dctx->dns_lock);

	return (void *)ret;
}

int gwdns_init_ctx(struct gwdns_ctx **ctx, struct gwdns_cfg *cfg)
{
	struct gwdns_ctx *dctx;
	char tname[255];
	int i;

	dctx = malloc(sizeof(*dctx));
	if (!dctx)
		return -ENOMEM;

	pthread_mutex_init(&dctx->dns_lock, NULL);
	pthread_cond_init(&dctx->dns_cond, NULL);
	dctx->dns_t_pool = malloc(cfg->thread_nr * sizeof(pthread_t));
	if (!dctx->dns_t_pool) {
		free(dctx);
		return -ENOMEM;
	}

	dctx->sleep_nr = 0;
	dctx->thread_nr = cfg->thread_nr;
	dctx->q.head = NULL;
	dctx->should_stop = false;

	for (i = 0; i < cfg->thread_nr; i++) {
		pthread_create(
			&dctx->dns_t_pool[i], NULL, dns_serv_thread, dctx
		);
		snprintf(tname, sizeof(tname), "dns-serv-%d", i);
		pthread_setname_np(dctx->dns_t_pool[i], tname);
	}

	*ctx = dctx;
	return 0;
}

void gwdns_free_ctx(struct gwdns_ctx *ctx)
{
	struct gwdns_req *r, *tmp;
	int i;

	ctx->should_stop = true;
	pthread_cond_broadcast(&ctx->dns_cond);

	for (i = 0; i < ctx->thread_nr; i++)
		pthread_join(ctx->dns_t_pool[i], NULL);

	tmp = NULL;
	for (r = ctx->q.head; r; r = tmp) {
		tmp = r->next;
		pr_verbose("free %p uncompleted request of %s\n", r, r->domainname);
		gwdns_release_req(r);
	}

	pthread_cond_destroy(&ctx->dns_cond);
	pthread_mutex_destroy(&ctx->dns_lock);
	free(ctx->dns_t_pool);
	free(ctx);
}

struct gwdns_req *gwdns_enqueue_req(struct gwdns_ctx *ctx, char *domain,
					int domain_len, uint16_t port)
{
	struct gwdns_req *r = malloc(sizeof(*r));
	if (!r)
		return NULL;

	r->evfd = eventfd(0, EFD_NONBLOCK);
	if (r->evfd < 0) {
		free(r);
		return NULL;
	}

	r->next = NULL;

	sprintf(r->port, "%d", ntohs(port));

	memcpy(r->domainname, domain, domain_len);
	r->domainname[domain_len] = '\0';

	atomic_init(&r->refcnt, 2);
	pr_dbg("attempting to lock dns_lock\n");
	pthread_mutex_lock(&ctx->dns_lock);
	pr_dbg("acquired dns_lock\n");

	enqueue_req(&ctx->q, r);
	if (ctx->sleep_nr)
		pthread_cond_signal(&ctx->dns_cond);

	pr_dbg("releasing dns_lock\n");
	pthread_mutex_unlock(&ctx->dns_lock);

	return r;
}

bool gwdns_release_req(struct gwdns_req *req)
{
	int x = atomic_fetch_sub(&req->refcnt, 1);

	assert(x > 0);
	if (x == 1) {
		close(req->evfd);
		free(req);
		return true;
	}

	return false;
}

#ifdef RUNTEST

static void gwdns_test_orphan_client()
{
	struct gwdns_ctx *ctx;
	struct gwdns_cfg cfg;
	struct gwdns_req *r;
	bool last_holder;
	uint16_t port;
	size_t i;
	int ret;

	cfg.thread_nr = 2;
	ret = gwdns_init_ctx(&ctx, &cfg);
	assert(!ret);

	port = htons(80);
	static const char domain[] = "fb.me";
	static char randomized_domain[255];
	int subdomain;
	srand(5);
	for (i = 0; i < 1000; i++) {
		subdomain = rand();
		snprintf(randomized_domain, sizeof(randomized_domain), "%d.%s", subdomain, domain);
		r = gwdns_enqueue_req(ctx, randomized_domain, strlen(randomized_domain), port);
		assert(r);

		last_holder = gwdns_release_req(r);
		assert(!last_holder);
	}
	
	gwdns_free_ctx(ctx);
}

static void gwdns_run_tests()
{
	gwdns_test_orphan_client();
	pr_info("[OK] all tests passed!\n");
}

int main(void)
{
	gwdns_run_tests();

	return 0;
}

#endif
