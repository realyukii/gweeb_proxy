/*
* Linux-specific implementation with libc.
*/
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h> // temporary for printf

#define MAX_LEN 255

struct userpwd_pair {
	char *username;
	char *password;
};

/*
* Calculate length of file contents.
*
* @param f file name.
* @param filefd pointer to the caller to initialize.
* @return length of file contents on success, or a negative integer on failure.
*/
static int rfile(char *f, int *filefd)
{
	off_t off;
	*filefd = open(f, O_RDONLY);
	if (*filefd < 0)
		return -1;

	off = lseek(*filefd, 0, SEEK_END);
	if (off < 0)
		return -1;

	lseek(*filefd, 0, SEEK_SET);
	return off;
}

/*
* Parse auth file.
*
* The function expect file content format with newline-terminated
* like:
* username:password\\n
*
* maximum length for each username and password is 255.
*
* @param filename path to the filename.
* @param ptr unallocated buffer to be initialized with array of struct.
* @param buffer to free after you are done using it.
* @return number of item on success, or a negative integer on failure.
*/
int parse_auth_file(char *filename, struct userpwd_pair **ptr, char **buf)
{
	char *pbuf, c;
	int filefd, item_nr, i, l;
	long fsize;
	__uint8_t ulen, plen;
	struct userpwd_pair *p;

	fsize = rfile(filename, &filefd);
	if (fsize < 0)
		return -1;

	// extra one bytes for null-terminated byte
	*buf = malloc(fsize + 1);
	if (!*buf)
		goto error;
	(*buf)[fsize] = '\0';

	if (read(filefd, *buf, fsize) < 0)
		goto error;
	close(filefd);
	filefd = -1;

	item_nr = ulen = plen = 0;
	for (i = 0; i < fsize; i++) {
		c = (*buf)[i];
		if (c == '\n')
			item_nr++;
	}

	if (!item_nr) {
		fprintf(stderr, "file is empty.\n");
		goto error;
	}

	/*
	* plus one extra space for file that didn't contain newline at the EoF
	*/
	if ((*buf)[fsize - 1] != '\n')
		item_nr++;
	// asm volatile("int3");
	*ptr = malloc((item_nr) * sizeof(**ptr));
	if (!*ptr)
		goto error;

	l = 0;
	p = &(*ptr)[l];
	p->username = NULL;
	for (i = 0; i < fsize; i++) {
		pbuf = &(*buf)[i];

		if (p->username == NULL)
			p->username = *buf;
		if (*pbuf == '\n') {
			// asm volatile("int3");
			*pbuf = '\0';
			pbuf++;
			l++;
			p = &(*ptr)[l];
			p->username = pbuf;
		}

		if (*pbuf == ':') {
			// asm volatile("int3");
			*pbuf = '\0';
			pbuf++;
			p->password = pbuf;
		}
	}

	return item_nr;
error:
	if (filefd != -1)
		close(filefd);
	if (*buf)
		free(buf);

	return -1;
}


int main(void)
{
	char *buf;
	struct userpwd_pair *ptr;
	int i, ret = parse_auth_file("./socks5_userpwd_list.db", &ptr, &buf);
	if (ret < 0)
		return -1;

	// asm volatile ("int3");
	for (i = 0; i < ret; i++)
		printf("%d. %s:%s\n", i, ptr[i].username, ptr[i].password);

	free(buf);
	free(ptr);
	return 0;
}