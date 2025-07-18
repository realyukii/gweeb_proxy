#define _GNU_SOURCE
#include <pthread.h>
#include <sys/socket.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <assert.h>

#include "linux.h"
#include "general.h"

struct gwdns_req {
	struct sockaddr_storage result;
	struct gwdns_req *next;
	char domainname[255 + 1];
	char port[5 + 1];
	int evfd;
	atomic_int refcnt;
	int status;
};

struct dns_queue {
	struct gwdns_req *head;
	struct gwdns_req *tail;
};

struct gwdns_ctx {
	pthread_mutex_t dns_lock;
	pthread_cond_t dns_cond;
	pthread_t *dns_t_pool;
	struct dns_queue q;
	bool should_stop;
	pthread_t tdns;
	int thread_nr;
	int sleep_nr;
};

struct gwdns_cfg {
	int thread_nr;
};

/*
* Initialize gwdns context.
*
* @param ctx	gwdns context to initialize
* @param cfg	caller-provided gwdns configuration
*/
int gwdns_init_ctx(struct gwdns_ctx **ctx, struct gwdns_cfg *cfg);

/*
* Free resources used by gwdns lib.
*
* @param ctx
*/
void gwdns_free_ctx(struct gwdns_ctx *ctx);

/*
* Create new dns query request.
*
* @param	ctx
* @param	domain
* @param	domain_len
* @return	a pointer to newly allocated dns_req.
*		it contain valid event file descriptor, the caller can use this
*		to register it to epoll and read the answer to the request.
*/
struct gwdns_req *gwdns_enqueue_req(struct gwdns_ctx *ctx, char *domain,
					int domain_len, uint16_t port);

/*
* Release dns query when no longer needed.
*
* @param req
*/
bool gwdns_release_req(struct gwdns_req *req);