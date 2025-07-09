#define _GNU_SOURCE
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include "linux.h"

static const char auth_file[] = "./auth.db";
static size_t counter = 0;

static bool stop = false;

static void intrHandler(__attribute__((__unused__))int c)
{
	stop = true;
}

int main(void)
{
	int i, ret, ifd, epfd, authfd;
	struct epoll_event ev;
	struct userpwd_list l;
	struct userpwd_pair *pr;
	char *buf, *prevbuf;
	struct inotify_event iev[2];
	struct sigaction s = {
		.sa_handler = intrHandler
	};

	sigaction(SIGINT, &s, NULL);

	ifd = inotify_init1(IN_NONBLOCK);
	inotify_add_watch(ifd, auth_file, IN_CLOSE_WRITE);

	epfd = epoll_create(1);
	ev.events = EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_ADD, ifd, &ev);

	authfd = open(auth_file, O_RDONLY);
	buf = NULL;
	l.arr = NULL;
	l.nr_entry = 0;
	prevbuf = NULL;
	while (!stop) {
		ret = epoll_wait(epfd, &ev, 1, -1);
		if (ret < 0) {
			ret = errno;
			if (ret == EINTR)
				continue;
			pr_err(
				"failed to wait on epoll: %s\n",
				strerror(ret)
			);
			break;
		}

		read(ifd, &iev, sizeof(iev));
		printf("\e[1;1H\e[2J");
		printf(
			"File changed %ld times since program started, "
			"re-read the file content...\n",
			++counter
		);

		if (l.nr_entry) {
			l.prev_arr = l.arr;
			prevbuf = buf;
		}

		ret = parse_auth_file(authfd, &l, &buf);
		if (!ret && prevbuf) {
			free(l.prev_arr);
			free(prevbuf);
		}

		for (i = 0; i < l.nr_entry; i++) {
			pr = &l.arr[i];
			printf("%d. %s:%s\n", i, pr->username, pr->password);
		}
	}

	fprintf(
		stderr,
		"closing file descriptor of %s file\n",
		auth_file
	);
	close(authfd);

	fprintf(
		stderr,
		"closing file descriptor of inotify: %d\n",
		ifd
	);
	close(ifd);

	fprintf(
		stderr,
		"closing file descriptor of epoll: %d\n",
		epfd
	);
	close(epfd);

	if (buf) {
		fprintf(
			stderr,
			"free memory of file content at %p\n",
			buf
		);
		free(buf);
	}

	if (l.arr) {
		fprintf(
			stderr,
			"free memory of array of username/password struct at %p\n",
			l.arr
		);
		free(l.arr);
	}

	return 0;
}