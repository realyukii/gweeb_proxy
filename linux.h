#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdarg.h>

#define MAX_LEN 255

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

#ifndef ENABLE_LOG
#define ENABLE_LOG true
#endif

#define INFO 1
#define WARN 2
#define ERROR 3
#define DEBUG 4

#if ENABLE_LOG
#define pr_log(LVL, FMT, ...) 				\
do {							\
	if (ENABLE_LOG)					\
		__pr_log(LVL, FMT, ##__VA_ARGS__);	\
} while (0);
#else 
#define pr_log(LVL, FMT, ...) {}
#endif

#define pr_dbg(FMT, ...) pr_log(DEBUG, "[%s:%d] " FMT, __FILE__, __LINE__, ##__VA_ARGS__)
#define pr_info(FMT, ...) pr_log(INFO, FMT, ##__VA_ARGS__)
#define pr_warn(FMT, ...) pr_log(WARN, FMT, ##__VA_ARGS__)
#define pr_err(FMT, ...) pr_log(ERROR, FMT, ##__VA_ARGS__)

/*
* Parse auth file.
*
* The function expect file content format with newline-terminated
* like:
* username:password\\n
*
* maximum length for each username and password is 255.
* 
* the caller is responsible to decide when to free existing resources.
*
* @param filefd open file descriptor to the auth file.
* @param l a pointer to struct that
* will be initialized with array of username:pwd.
* @param buffer to free after you are done using it.
* @return zero on success, or a negative integer on failure.
*/
int parse_auth_file(int filefd, struct userpwd_list *l, char **buf);

void __pr_log(unsigned lvl, const char *fmt, ...);

void generate_current_time(char *buf);
