#include <sys/epoll.h>
#include <sys/inotify.h>
#include <stdio.h>
#include <stdbool.h>
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
	char *buf;
	struct inotify_event iev[2];

	signal(SIGINT, intrHandler);

	ifd = inotify_init1(IN_NONBLOCK);
	inotify_add_watch(ifd, auth_file, IN_CLOSE_WRITE);
	epfd = epoll_create(1);
	ev.events = EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_ADD, ifd, &ev);

	authfd = open(auth_file, O_RDONLY);
	while (true) {
		ret = epoll_wait(epfd, &ev, 1, -1);
		if (stop) {
			fprintf(
				stderr,
				"interrupt signal received, "
				"stopping the program\n"
			);
			break;
			
		}

		read(ifd, iev, sizeof(iev));
		printf("\e[1;1H\e[2J");
		printf(
			"File changed %ld times, re-read the file content:\n",
			++counter
		);
		ret = parse_auth_file(authfd, &l, &buf);
		lseek(authfd, 0, SEEK_SET);
		if (ret < 0)
			continue;
		for (i = 0; i < l.nr_entry; i++) {
			pr = &l.arr[i];
			printf("%d. %s:%s\n", i, pr->username, pr->password);
		}
		free(buf);
		free(l.arr);
	}

	return 0;
}