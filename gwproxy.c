#include <stdio.h>
#include <unistd.h>
#include <unistd.h>
#include <errno.h>

static const char usage[] =
"usage: ./gwproxy [options]\n"
"-b, --bind-addr\t\tIP address and port to be bound by the server\n"
"-t, --target-addr\tIP address and port \n"
"-h, --help\t\tShow this help message and exit\n";

int main(int argc, char *argv[])
{
	char c;

	if (argc == 1) {
		printf("%s", usage);

		return 0;
	}

	while ((c = getopt(argc, argv, "hb:t:")) != -1) {
		switch (c) {
		case 'b':
			puts("bind");
			break;
		case 't':
			puts("target");
			break;
		case 'h':
			printf("%s", usage);
			break;

		default:
			return -EINVAL;
		}
	}

	return 0;
}
