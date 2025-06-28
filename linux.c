/*
* Linux-specific implementation with libc.
*/
#include "linux.h"

int parse_auth_file(int filefd, struct userpwd_list *l, char **buf)
{
	char *svptr, *line, *colon, c, *tmpbuf;
	int item_nr, i, ulen, plen;
	long fsize;
	int ret;
	struct userpwd_pair **ptr, *p, *tmpp;
	struct stat st;

	/* when failed, it may indicate file is deleted.
	* hot-reload mechanism may need to adjust in regard to this error
	* by re-open the file? for now it just silently fail. */
	if (fstat(filefd, &st) < 0)
		return -1;

	fsize = st.st_size;
	ptr = &l->arr;
	tmpp = NULL;
	if (*ptr)
		tmpp = *ptr;

	tmpbuf = NULL;
	if (*buf)
		tmpbuf = *buf;

	/* extra one bytes for null-terminated byte */
	*buf = malloc(fsize + 1);
	if (!*buf) {
		fprintf(stderr, "out of memory, can't allocate buf\n");
		goto error;
	}

	(*buf)[fsize] = '\0';

	ret = read(filefd, *buf, fsize);
	if (ret < 0) {
		fprintf(stderr, "failed to read\n");
		goto error;
	}

	if (!ret) {
		fprintf(stderr, "file is empty.\n");
		goto error;
	}
	lseek(filefd, 0, SEEK_SET);

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
	if (!*ptr) {
		fprintf(stderr, "out of memory, can't allocate ptr\n");
		goto error;
	}

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
		p->ulen = ulen;
		p->plen = plen;
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
	if (*ptr && *ptr != tmpp)
		free(*ptr);
	if (*buf && *buf != tmpbuf)
		free(*buf);
	/* restore previous state (if any) when something wrong occured */
	if (tmpp)
		fprintf(
			stderr,
			"failed to update username/pwd list, "
			"using previous config.\n"
		);

	*buf = tmpbuf;
	*ptr = tmpp;

	return -1;
}
