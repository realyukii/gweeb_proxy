/*
* Linux-specific implementation with libc.
*/
#define _GNU_SOURCE
#include "linux.h"

#if ENABLE_LOG

void generate_current_time(char *buf)
{
	time_t rawtime;
	struct tm timeinfo;

	time(&rawtime);
	localtime_r(&rawtime, &timeinfo);
	asctime_r(&timeinfo, buf);
	buf[26 - 2] = '\0';
}

void __pr_log(unsigned lvl, const char *fmt, ...)
{
	/*
	* asctime(3): atleast 26 bytes of buffer is provided
	* 24 ascii character + newline + null terminated bytes.
	*/
	char human_readable_time[26] = {0};
	char localbuf[4096];
	const char *level;
	pid_t tid;

	static const char *info = "info";
	static const char *warn = "warning";
	static const char *err = "error";
	static const char *dbg = "debug";
	static const char *vrbs = "verbose";

	va_list args;
	va_start(args, fmt);

	switch (lvl) {
	case INFO:
		level = info;
		break;
	case WARN:
		level = warn;
		break;
	case ERROR:
		level = err;
		break;
	case DEBUG:
		level = dbg;
		break;
	case VERBOSE:
		level = vrbs;
		break;
	default:
		return;
	}

	vsnprintf(localbuf, sizeof(localbuf), fmt, args);
	tid = gettid();
	generate_current_time(human_readable_time);
	/*
	* the log format is consist of:
	* - current timestamp in human-readable form
	* - process identifier
	* - log level
	*/
	fprintf(
		stderr,
		"[%s] [%d] %s: %s",
		human_readable_time, tid, level, localbuf
	);

	va_end(args);
}
#endif

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
	if (*ptr && *ptr != tmpp) {
		free(*ptr);
		*ptr = NULL;
	}
	if (*buf && *buf != tmpbuf) {
		free(*buf);
		*buf = NULL;
	}
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
