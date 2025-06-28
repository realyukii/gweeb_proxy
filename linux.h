#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>

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