// https://gist.github.com/ammarfaizi2/ebb964ce64399acf8675d30b893174e4
// https://gist.github.com/ammarfaizi2/53324bb7dd8ca7cb73a92b80b62f8f3b
// gcc -Wall -ggdb3 -Wextra -Os stress.c -o stress
// ./stress ::1 1111 20000
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/epoll.h>
#include <stdbool.h>
#include <time.h>
#include <assert.h>

#ifndef VT_HEXDUMP_H
#define VT_HEXDUMP_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define CHDOT(C) (((32 <= (C)) && ((C) <= 126)) ? (C) : '.')

__attribute__((__unused__))
static void vt_hexdump(const void *p, size_t size, const char *file, int line,
		       const char *func)
{
	const unsigned char *ptr = p;
	static const char fmt[] =
	"============ VT_HEXDUMP ============\n"
	"File\t\t: %s:%d\n"
	"Function\t: %s()\n"
	"Address\t\t: 0x%016lx\n"
	"Dump size\t: %ld bytes\n"
	"\n"
	"%s"
	"=====================================\n";
	size_t sz_perlines, tot_sz, last_sz, fixed_sz,
	r, i, j, k = 0, l, off = 0;
	char *tmp;
	/* process 16 byte per-line, calculate the line number */
	sz_perlines = size / 16;
	/* remainder of multiple 16, if any */
	r = size % 16;
	/* size of last line */
	last_sz = 
	21 /* address prefix */
	+ (3 * 16) /* hex-ascii digit padded with space */
	+ 2 /* " |" */
	+ r
	+ 2; /* "|\n" */
	/* fixed when r = 16 */
	fixed_sz = 89;
	tot_sz = (sz_perlines * fixed_sz) + last_sz;
	tmp = malloc(tot_sz + 1);
	if (!tmp)
		return;
	for (i = 0; i < ((size/16) + 1); i++) {
		snprintf(
			&tmp[off], 21 + 1,
			"0x%016lx|  ", (uintptr_t)(ptr + i * 16)
		);
		off += 21;
		l = k;
		for (j = 0; (j < 16) && (k < size); j++, k++) {
			snprintf(&tmp[off], 3 + 1, "%02x ", ptr[k]);
			off += 3;
		}		
		while (j++ < 16) {
			snprintf(&tmp[off], 3 + 1, "   ");
			off += 3;
		}		
		snprintf(&tmp[off], 2 + 1, " |");
		off += 2;
		for (j = 0; (j < 16) && (l < size); j++, l++) {
			snprintf(&tmp[off], 1 + 1, "%c", CHDOT(ptr[l]));
			off += 1;
		}
		snprintf(&tmp[off], 2 + 1, "|\n");
		off += 2;
	}
	fprintf(
		stderr, fmt,
		file, line,
		func,
		(uintptr_t)ptr,
		size,
		tmp
	);
	free(tmp);
}

#define VT_HEXDUMP(PTR, SIZE)						\
do {									\
	vt_hexdump((PTR), (SIZE), __FILE__, __LINE__, __FUNCTION__);	\
} while (0);

#endif // VT_HEXDUMP_H

struct sockaddr_in46 {
	union {
		struct sockaddr sa;
		struct sockaddr_in i4;
		struct sockaddr_in6 i6;
	};
};

struct conn {
	char	*sbuf;
	char	*orig;
	size_t	slen;
	int	fd;
	uint32_t idx;
	bool	sent_socks5_data;
};

static struct sockaddr_in46 g_target;
static char g_sbuf[1024*1024*100];
static size_t g_sbuf_len;

static int create_sock_and_connect(struct sockaddr_in46 *si);
static int init_conn(struct conn *c, struct sockaddr_in46 *dst)
{
	static const char req[] =
		"GET / HTTP/1.1\r\n"
		"Host: fb.me\r\n"
		"\r\n";
	uint16_t port;
	char *b, *e;
	size_t l, dl;
	int r;

	c->sent_socks5_data = false;
	c->fd = create_sock_and_connect(dst);
	if (c->fd < 0)
		return c->fd;

	if (g_sbuf_len == 0) {
		l = 0;
		e = g_sbuf + sizeof(g_sbuf);
		b = g_sbuf;
		while (&b[sizeof(req) - 1] < e) {
			memcpy(b, req, sizeof(req) - 1);
			l += sizeof(req) - 1;
			b += sizeof(req) - 1;
		}
		g_sbuf_len = l;
	}


	l = 0;
	b = malloc(8192);
	assert(b);
	c->sbuf = c->orig = b;
	e = b + 8192;
	b[l++] = '\x05'; // VER
	b[l++] = '\x01'; // NMETHODS: 1
	b[l++] = '\x00'; // METHOD: NO AUTHENTICATION REQUIRED
	b[l++] = '\x05'; // VER
	b[l++] = '\x01'; // CMD: CONNECT
	b[l++] = '\x00'; // RSV
	// b[l++] = '\x04'; // ATYP: IPV6

	// FB IP: 2a03:2880:f360:1:face:b00c:0:25de
	// r = inet_pton(AF_INET6, "2a03:2880:f360:1:face:b00c:0:25de", &b[l]);
	// assert(r == 1);
	// l += 16; // IPv6 address length

	b[l++] = '\x03'; // ATYP: DOMAINNAME
	dl = l++; // Reserve space for domain length
	// if ((c->idx % 100000) == 0) {
	// 	static const char d[] = "theofficialabsolutelongestdomainnameregisteredontheworldwideweb.international";
	// 	strncpy(&b[l], d, 255);
	// 	r = strlen(d);
	// } else {
	// 	r = snprintf(&b[l], 255,
	// 			"%08u-%d-%d-%d-%d-%d-%d-%d.fb.me",
	// 			c->idx,
	// 			rand() % 100000,
	// 			rand() % 100000,
	// 			rand() % 100000,
	// 			rand() % 100000,
	// 			rand() % 100000,
	// 			rand() % 100000,
	// 			rand() % 100000);
	// }
	memcpy(&b[l], "localhost", 9);
	l += 9;
	b[dl] = 9;
	// b[dl] = r > 255 ? 255 : r; // Fill in domain length.
	// l += r;

	port = htons(8081);
	memcpy(b + l, &port, sizeof(port));
	l += sizeof(port);

	if (c->idx % 2 == 0) {
		b = &b[l];
		while (&b[sizeof(req) - 1] < e) {
			memcpy(b, req, sizeof(req) - 1);
			l += sizeof(req) - 1;
			b += sizeof(req) - 1;
		}
	}

	c->slen = l;
	assert(c->slen <= 8192);
	return 0;
}

static void free_conn(struct conn *c)
{
	if (c->fd >= 0) {
		close(c->fd);
		c->fd = -1;
	}

	free(c->orig);
}

static void free_conns(struct conn *conns, size_t nr_conn)
{
	size_t i;

	for (i = 0; i < nr_conn; i++)
		free_conn(&conns[i]);
	free(conns);
}

static int create_conns(struct conn **conns_p, struct sockaddr_in46 *dst, size_t nr_conn)
{
	struct conn *conns;
	size_t i;
	int r;

	conns = malloc(nr_conn * sizeof(*conns));
	if (!conns) {
		perror("malloc");
		return -ENOMEM;
	}

	for (i = 0; i < nr_conn; i++) {
		conns[i].fd = -1;
		conns[i].idx = i;
		r = init_conn(&conns[i], dst);
		if (r < 0) {
			fprintf(stderr, "Failed to initialize connection %zu: %s\n", i, strerror(-r));
			free_conns(conns, i);
			return r;
		}
	}

	*conns_p = conns;
	return 0;
}

static int handle_epollin(struct conn *c)
{
	static char buf[1024*1024];
	ssize_t r;

	r = recv(c->fd, buf, sizeof(buf), MSG_NOSIGNAL);
	if (r < 0) {
		r = errno;
		if (r == EAGAIN || r == EINTR)
			return 0;
		if (r == EPIPE)
			r = ECONNRESET;
		if (r != ECONNRESET)
			printf("\r[conn %07u] recv() failed: %s\033[K", c->idx, strerror(r));
		return -r;
	} else if (r == 0) {
		return -ECONNRESET;
	}

	printf("\r[conn %07u] Received %zd bytes\033[K", c->idx, r);
	return 0;
}

static int handle_epollout(int ep, struct conn *c)
{
	ssize_t r;

ae:
	if (c->slen == 0) {
		struct epoll_event ev;
		ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
		ev.data.ptr = c;
		if (epoll_ctl(ep, EPOLL_CTL_MOD, c->fd, &ev) < 0) {
			r = errno;
			perror("epoll_ctl");
			return -r;
		}

		return 0;
	}

	r = send(c->fd, c->sbuf, c->slen, MSG_NOSIGNAL);
	if (r < 0) {
		r = errno;
		if (r == EAGAIN || r == EINTR)
			return 0;
		if (r == EPIPE)
			r = ECONNRESET;
		if (r != ECONNRESET)
			printf("\r[conn %07u] send() failed: %s\033[K", c->idx, strerror(r));
		return -r;
	}

	printf("\r[conn %07u] Sent %zd bytes\033[K", c->idx, r);
	c->slen -= r;
	c->sbuf += r;
	if (!c->sent_socks5_data && !c->slen) {
		free(c->orig);
		c->orig = NULL;
		c->sbuf = g_sbuf;
		c->slen = g_sbuf_len;
		c->sent_socks5_data = true;
	}
	if (!c->slen)
		goto ae;

	return 0;
}

static int recreate_conn(int ep, struct conn *c)
{
	struct epoll_event ev;
	int r;

	free_conn(c);
	r = init_conn(c, &g_target);
	if (r < 0) {
		fprintf(stderr, "Failed to recreate connection %u: %s\n", c->idx, strerror(-r));
		return r;
	}

	ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR;
	ev.data.ptr = c;
	r = epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ev);
	if (r < 0) {
		r = errno;
		perror("epoll_ctl");
		free_conn(c);
		return -r;
	}

	printf("\rRecreated connection %u\033[K", c->idx);
	return 0;
}

static int handle_events(int ep, int num_events, struct epoll_event *events)
{
	static uint32_t iter;
	int i, r = 0;

	for (i = 0; i < num_events; i++) {
		struct conn *c = events[i].data.ptr;

		if (events[i].events & EPOLLIN) {
			r = handle_epollin(c);
			if (r == -ECONNRESET) {
				r = recreate_conn(ep, c);
				if (r)
					break;
				else
					continue;
			}
		}

		if (events[i].events & EPOLLOUT) {
			r = handle_epollout(ep, c);
			if (r == -ECONNRESET) {
				r = recreate_conn(ep, c);
				if (r)
					break;
				else
					continue;
			}
		}

		if (events[i].events & EPOLLRDHUP) {
			printf("\r[conn %07u] Remote closed connection\033[K", c->idx);
			r = recreate_conn(ep, c);
			if (r)
				break;
			else
				continue;
		}

		if (iter++) {
			if ((iter % 8192) == 0)
				shutdown(c->fd, SHUT_RD);
		}

		if (r)
			break;
	}

	return r;
}

static int create_sock_and_connect(struct sockaddr_in46 *si)
{
	socklen_t addrlen;
	int fd, r;

	fd = socket(si->sa.sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		r = errno;
		perror("socket");
		return -r;
	}

	addrlen = (si->sa.sa_family == AF_INET) ? sizeof(si->i4) : sizeof(si->i6);
	if (connect(fd, &si->sa, addrlen) < 0) {
		r = errno;
		if (r != EINPROGRESS) {
			perror("connect");
			close(fd);
			return -r;
		}
	}

	return fd;
}

static int parse_addr(struct sockaddr_in46 *si, const char *ip, const char *port)
{
	memset(si, 0, sizeof(*si));
	if (inet_pton(AF_INET, ip, &si->i4.sin_addr) == 1) {
		si->sa.sa_family = AF_INET;
		si->i4.sin_port = htons(atoi(port));
		return 0;
	} else if (inet_pton(AF_INET6, ip, &si->i6.sin6_addr) == 1) {
		si->sa.sa_family = AF_INET6;
		si->i6.sin6_port = htons(atoi(port));
		return 0;
	}
	return -EAFNOSUPPORT;
}

static int bomb_target(struct sockaddr_in46 *dst, size_t nr_conn)
{
	struct conn *conns = NULL;
	struct epoll_event ev;
	int ep, r;
	size_t i;

	r = create_conns(&conns, dst, nr_conn);
	if (r < 0) {
		fprintf(stderr, "Failed to create connections: %s\n", strerror(-r));
		return r;
	}

	ep = epoll_create1(0);
	if (ep < 0) {
		r = -errno;
		perror("epoll_create1");
		goto out;
	}

	for (i = 0; i < nr_conn; i++) {
		ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR;
		ev.data.ptr = &conns[i];
		r = epoll_ctl(ep, EPOLL_CTL_ADD, conns[i].fd, &ev);
		if (r < 0) {
			r = -errno;
			perror("epoll_ctl");
			goto out_ep;
		}
	}

	while (1) {
		struct epoll_event events[1024];
		static const size_t max_events = sizeof(events) / sizeof(events[0]);
		r = epoll_wait(ep, events, max_events, -1);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			r = -errno;
			perror("epoll_wait");
			goto out_ep;
		}

		r = handle_events(ep, r, events);
		if (r < 0) {
			fprintf(stderr, "Error handling events: %s\n", strerror(-r));
			goto out_ep;
		}
	}


	r = 0;
out_ep:
	close(ep);
out:
	free_conns(conns, nr_conn);
	putchar('\n');
	return r;
}

int main(int argc, char *argv[])
{
	struct sockaddr_in46 si;
	size_t nr_conn;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <ip> <port> <nr_conn>\n", argv[0]);
		return 1;
	}

	if (parse_addr(&si, argv[1], argv[2]) < 0) {
		fprintf(stderr, "Invalid address format: %s:%s\n", argv[1], argv[2]);
		return 1;
	}

	nr_conn = strtoul(argv[3], NULL, 10);
	if (nr_conn == 0) {
		fprintf(stderr, "Number of connections must be greater than 0\n");
		return 1;
	}

	g_target = si;
	srand(time(NULL) + getpid());
	return bomb_target(&si, nr_conn);
}
