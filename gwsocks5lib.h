#define _GNU_SOURCE
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
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

enum socks5_rep_code {
	SOCKS5_SUCCEEDED,
	SOCKS5_GENERAL_FAILURE,
	SOCKS5_CONN_NOT_ALLOWED,
	SOCKS5_HOST_UNREACH,
	SOCKS5_NETWORK_UNREACH,
	SOCKS5_CONN_REFUSED,
	SOCKS5_TTL_EXPIRED,
	SOCKS5_CMD_NOT_SUPPORTED,
	SOCKS5_ADDR_TYPE_NOT_SUPPORTED
};

enum socks5_atyp {
	SOCKS5_IPv4 = 1,
	SOCKS5_DOMAIN = 3,
	SOCKS5_IPv6 = 4
};

enum socks5_state {
	SOCKS5_GREETING,
	SOCKS5_AUTH,
	SOCKS5_REQUEST,
	SOCKS5_CONNECT
};

enum socks5_cmd {
	SOCKS5_CMD_CONNECT,
	SOCKS5_CMD_BIND,
	SOCKS5_CMD_UDP_ASSOCIATE
};

enum auth_type {
	NO_AUTH = 0x0,
	// GSSAPI, not supported yet
	USERNAME_PWD = 0x2,
	NONE = 0xFF
};

struct socks5_conn {
	enum socks5_state state;
	struct socks5_ctx *ctx;
};

struct socks5_cfg {
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
	struct socks5_creds creds;
};

struct socks5_greeting {
	uint8_t ver;
	uint8_t nauth;
	uint8_t methods[MAX_METHODS];
};

struct socks5_handshake {
	uint8_t ver;
	uint8_t chosen_method;
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
	uint16_t port;
} __attribute__((packed));

struct socks5_request {
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	struct socks5_addr dst_addr;
	/*
	* since addr member of struct dst_addr use union,
	* the destination port is not specified explicitly as a struct member.
	*/
};

struct socks5_reply {
	uint8_t ver;
	uint8_t rep_code;
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

/*
* Initialize SOCKS5 instance.
* the caller MUST free the initialized pointer using socks5_free_ctx function.
*
* @param ctx Pointer to the pointer of socks5_ctx struct.
* @param cfg Pointer to struct socks5_cfg
* @return zero on success, or a negative integer on failure.
*/
int socks5_init(struct socks5_ctx **ctx, struct socks5_cfg *cfg);

/*
* Allocate data for SOCKS5 connection.
* the caller MUST free the pointer of allocated data using socks5_free_conn function.
*/
struct socks5_conn *socks5_alloc_conn(struct socks5_ctx *ctx);

void socks5_free_ctx(struct socks5_ctx *ctx);
void socks5_free_conn(struct socks5_conn *conn);

/*
* Process available data.
*
* The function consume in buffer and fill out buffer, and modify the state.
* on failure, the function may return:
* -EAGAIN if more data is needed.
* -EINVAL if the payload is malformed.
* -ENOBUFS if no more space left in the out buffer
* and out_len is used as a hint for required size.
*
* @param conn Pointer to the SOCKS5 connection data.
* @param in Pointer to buffer to be consumed.
* @param in_len length of available buffer
* @param out Pointer to buffer to be filled
* @param out_len length of filled buffer
* @return zero on success, or a negative integer on failure.
*/
int socks5_process_data(struct socks5_conn *conn,
			const void *in, unsigned *in_len, void *out, unsigned *out_len);

/*
* Craft response to CONNECT request with given address and reply code.
*/
int socks5_handle_cmd_connect(struct socks5_conn *conn, struct socks5_addr *addr,
				uint8_t rep_code, void *replybuf, unsigned *replylen);
