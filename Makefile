all: build/gwproxy build/gwproxy_gdb build/gwproxy_memcheck

build/gwproxy: gwproxy.c
	gcc -Wall -Wextra $^ -o $@
build/gwproxy_memcheck: gwproxy.c
	gcc -fsanitize=address -Wall -Wextra -DDEBUG_LVL=1 -g3 $^ -o $@
build/gwproxy_gdb: gwproxy.c
	gcc -Wall -Wextra -DDEBUG_LVL=3 -g3 $^ -o $@
test: all
	./build/gwproxy -t [::1]:8081 -b [::]:8080 -T 1