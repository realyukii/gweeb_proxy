#define _GNU_SOURCE
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

// used for hot reload feature
#include <sys/epoll.h>
#include <sys/inotify.h>

#include "linux.h"

#define MAX_DOMAIN_LEN 255
#define MAX_METHODS 255

enum socks5_state {
	GREETING,
	AUTH,
	REQUEST
};

enum auth_type {
	NO_AUTH = 0x0,
	// GSSAPI, not supported yet
	USERNAME_PWD = 0x2,
	NONE = 0xFF
};

struct socks5_conn {
	enum socks5_state s;
	/* capacity of buffer */
	size_t clen;
	/* processed length */
	size_t plen;
	char buffer[];
};

struct socks5_param {
	const char *auth_file;
};

struct socks5_creds {
	int authfd;
	int ifd;
	int epfd;
	pthread_rwlock_t creds_lock;
	const char *auth_file;
	struct userpwd_list userpwd_l;
	char *userpwd_buf;
	char *prev_userpwd_buf;
};

struct socks5_ctx {
	struct socks5_conn c;
	struct socks5_creds creds;
};

struct socks5_greeting {
	uint8_t ver;
	uint8_t nauth;
	uint8_t methods[MAX_METHODS];
};

struct socks5_addr {
	/* see the available type in enum addr_type */
	uint8_t type;
	union {
		uint8_t ipv4[4];
		struct {
			uint8_t len;
			char name[MAX_DOMAIN_LEN];
		} domain;
		uint8_t ipv6[16];
	} addr;
};

struct socks5_connect_request {
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	struct socks5_addr dst_addr;
	/*
	* since addr member of struct dst_addr use union,
	* the destination port is not specified explicitly as a struct member.
	*/
};

struct socks5_connect_reply {
	uint8_t ver;
	uint8_t status;
	uint8_t rsv;
	struct socks5_addr bnd_addr;
	/*
	* since addr member of struct bnd_addr use union,
	* the bnd port is not specified explicitly as a struct member.
	*/
};

struct socks5_userpwd {
	uint8_t ver;
	uint8_t ulen;
	char rest_bytes[];
};

struct userpwd_pair {
	char *username;
	char *password;
	uint8_t ulen;
	uint8_t plen;
};

struct userpwd_list {
	int nr_entry;
	struct userpwd_pair *arr;
	struct userpwd_pair *prev_arr;
};
