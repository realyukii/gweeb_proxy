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

	close(r->evfd);
	free(r);
}

static void resolve_dns(struct gwdns_req *req)
{
	struct addrinfo *l;
	int ret;

	ret = getaddrinfo(req->domainname, NULL, NULL, &l);
	if (ret != 0) {
		pr_err(
			"failed to resolve domain name: %s\n",
			gai_strerror(ret)
		);
		return;
	}

	memcpy(&req->result, l->ai_addr, l->ai_addrlen);
	freeaddrinfo(l);
}

static void *dns_serv_thread(void *args)
{
	struct gwdns_ctx *dctx;
	struct gwdns_req *r;
	intptr_t ret, val;

	ret = 0;
	val = 1;
	dctx = args;
	pr_dbg("attempting to lock dns\n");
	pthread_mutex_lock(&dctx->dns_lock);
	pr_dbg("dns_lock acquired\n");
	while (!dctx->should_stop) {
		r = dctx->q.head;
		if (!r) {
			pr_dbg("releasing dns_lock and waiting signal\n");
			pthread_cond_wait(&dctx->dns_cond, &dctx->dns_lock);
			pr_dbg("dns_lock acquired\n");
			r = dctx->q.head;
			if (!r)
				continue;
		}

		pr_dbg("doing blocking operation, releasing dns_lock\n");
		pthread_mutex_unlock(&dctx->dns_lock);
		resolve_dns(r);
		pr_dbg("attempting to lock dns_lock\n");
		pthread_mutex_lock(&dctx->dns_lock);
		pr_dbg("acquired dns_lock\n");
		dequeue_req(&dctx->q);

		write(r->evfd, &val, sizeof(val));
	}
	pr_dbg("releasing dns_lock\n");
	pthread_mutex_unlock(&dctx->dns_lock);

	return (void *)ret;
}

int gwdns_init_ctx(struct gwdns_ctx **ctx, struct gwdns_cfg *cfg)
{
	struct gwdns_ctx *dctx;
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

	dctx->thread_nr = cfg->thread_nr;
	dctx->q.head = NULL;
	dctx->should_stop = false;

	for (i = 0; i < cfg->thread_nr; i++)
		pthread_create(
			&dctx->dns_t_pool[i], NULL, dns_serv_thread, dctx
		);

	*ctx = dctx;
	return 0;
}

void gwdns_free_ctx(struct gwdns_ctx *ctx)
{
	int i;

	ctx->should_stop = true;
	pthread_cond_broadcast(&ctx->dns_cond);

	for (i = 0; i < ctx->thread_nr; i++)
		pthread_join(ctx->dns_t_pool[i], NULL);

	free(ctx->dns_t_pool);
	free(ctx);
}

struct gwdns_req *gwdns_enqueue_req(struct gwdns_ctx *ctx, char *domain, int domain_len)
{
	struct gwdns_req *r = malloc(sizeof(*r));
	if (!r)
		return NULL;
	
	r->evfd = eventfd(0, EFD_NONBLOCK);
	if (r->evfd < 0) {
		free(r);
		return NULL;
	}

	memcpy(r->domainname, domain, domain_len);
	r->domainname[domain_len] = '\0';

	pr_dbg("attempting to lock dns_lock\n");
	pthread_mutex_lock(&ctx->dns_lock);

	pr_dbg("acquired dns_lock\n");
	enqueue_req(&ctx->q, r);
	pthread_cond_signal(&ctx->dns_cond);

	pr_dbg("releasing dns_lock\n");
	pthread_mutex_unlock(&ctx->dns_lock);

	return r;
}