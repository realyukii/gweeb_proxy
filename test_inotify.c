#include <sys/epoll.h>
#include <sys/inotify.h>
#include <stdio.h>
#include "linux.c"

static const char auth_file[] = "./auth.db";
static size_t counter = 0;

int main(void)
{
	int ret, ifd, wfd, epfd, authfd;
	struct epoll_event ev;
	struct userpwd_list l;
	struct userpwd_pair *pr;
	char *buf;
	struct inotify_event iev[2];
	size_t i;

	ifd = inotify_init1(IN_NONBLOCK);
	wfd = inotify_add_watch(ifd, auth_file, IN_CLOSE_WRITE);
	epfd = epoll_create(1);
	ev.events = EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_ADD, ifd, &ev);

	authfd = open(auth_file, O_RDONLY);
	while (1) {
		ret = epoll_wait(epfd, &ev, 1, -1);
		read(ifd, iev, sizeof(iev));
		printf("\e[1;1H\e[2J");
		printf(
			"File changed %ld times, re-read the file content:\n",
			++counter
		);
		ret = parse_auth_file(authfd, &l, &buf);
		if (ret < 0) {
			lseek(authfd, 0, SEEK_SET);
			continue;
		}
		for (i = 0; i < l.nr_entry; i++) {
			pr = &l.arr[i];
			printf("%d. %s:%s\n", i, pr->username, pr->password);
		}
		lseek(authfd, 0, SEEK_SET);
		free(buf);
		free(l.arr);
	}

	return 0;
}