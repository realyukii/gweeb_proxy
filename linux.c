/*
* Linux-specific implementation with libc.
*/
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdio.h> // temporary for printf

#define MAX_LEN 255

struct userpwd_pair {
	char *username;
	char *password;
};

struct userpwd_list {
	int nr_entry;
	struct userpwd_pair *arr;
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
* @param filefd open file descriptor to the auth file.
* @param ptr unallocated buffer to be initialized with array of struct.
* @param buffer to free after you are done using it.
* @return zero on success, or a negative integer on failure.
*/
int parse_auth_file(int filefd, struct userpwd_list *l, char **buf)
{
	char *svptr, *line, *colon, c;
	int item_nr, i, ulen, plen;
	long fsize;
	int ret;
	struct userpwd_pair **ptr;
	struct userpwd_pair *p;
	struct stat st;

	if (fstat(filefd, &st) < 0)
		return -1;

	fsize = st.st_size;
	ptr = &l->arr;
	*ptr = NULL;

	/* extra one bytes for null-terminated byte */
	*buf = malloc(fsize + 1);
	if (!*buf)
		goto error;
	(*buf)[fsize] = '\0';

	ret = read(filefd, *buf, fsize);
	if (ret < 0)
		goto error;

	if (!ret) {
		fprintf(stderr, "file is empty.\n");
		goto error;
	}

	item_nr = 0;
	for (i = 0; i < fsize; i++) {
		c = (*buf)[i];
		if (c == '\n')
			item_nr++;
	}

	/* if last line isn’t newline-terminated, we still have an entry */
	if ((*buf)[fsize - 1] != '\n')
		item_nr++;

	*ptr = malloc((item_nr) * sizeof(**ptr));
	if (!*ptr)
		goto error;

	/* begin parsing buffer */
	svptr = *buf;
	i = 0;
	while ((line = strsep(&svptr, "\n"))) {
		if (*line == '\0') {
			if (!svptr)
				break;
			item_nr--;
			continue;
		}
		colon = strchr(line, ':');
		if (!colon) {
			fprintf(
				stderr,
				"missing ':' as delimiter, malformed line\n"
			);
			goto error;
		}
		*colon = '\0';

		p = &(*ptr)[i];
		ulen = colon - line;
		if (ulen > MAX_LEN) {
			fprintf(
				stderr,
				"username only allowed up to 255 character\n"
			);
			goto error;
		}
		/* no more svptr, indicating this is the last line */
		if (!svptr)
			plen = &(*buf)[fsize - 1] - (colon);
		else
			plen = (svptr - 1) - (colon + 1);
		if (plen > MAX_LEN) {
			fprintf(
				stderr,
				"password only allowed up to 255 character\n"
			);
			goto error;
		}
		if (!ulen || !plen) {
			fprintf(
				stderr,
				"username or password is not allowed to be empty\n"
			);
			goto error;
		}

		p->username = line;
		p->password = colon + 1;
		i++;
	}

	if (!item_nr) {
		fprintf(
			stderr,
			"file is still empty, "
			"don't try to fool me with newline.\n"
		);
		goto error;
	}

	l->nr_entry = item_nr;
	return 0;
error:
	if (*buf)
		free(*buf);
	if (*ptr)
		free(*ptr);

	return -1;
}

// int main(void)
// {
// 	char *buf;
// 	struct userpwd_pair *ptr;
// 	int i, ret = parse_auth_file("./socks5_userpwd_list.db", &ptr, &buf);
// 	if (ret < 0)
// 		return -1;

// 	for (i = 0; i < ret; i++)
// 		printf("%d. %s:%s\n", i, ptr[i].username, ptr[i].password);

// 	free(buf);
// 	free(ptr);
// 	return 0;
// }
