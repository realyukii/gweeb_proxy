all: build/test_inotify build/ip_converter build/gwproxy build/gwproxy_gdb build/gwproxy_memcheck

build/test_inotify: test_inotify.c
	gcc -Wextra -Wall $^ -o $@
build/ip_converter: ip_converter.c
	gcc -Wextra -Wall $^ -o $@
build/gwproxy: gwproxy.c
	gcc -Wmaybe-uninitialized -DDEBUG_LVL=5 -Wall -Wextra $^ -o $@
build/gwproxy_memcheck: gwproxy.c
	gcc -fsanitize=address -Wall -Wextra -DDEBUG_LVL=1 -g3 $^ -o $@
build/gwproxy_gdb: gwproxy.c
	gcc -Wall -Wextra -DDEBUG_LVL=3 -g3 $^ -o $@
test_conventional: all
	./build/gwproxy -t [::1]:8088 -b [::1]:8080 -T 1
test_socks5: all
	strace -x -f ./build/gwproxy -f ./auth.db -s -b [::]:1080 -T 1 -w 60