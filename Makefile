build/gwproxy: gwproxy.c
	gcc -fsanitize=address -Wall -Wextra -DDEBUG_LVL=1 -g3 $^ -o $@
test: ./build/gwproxy
	strace ./build/gwproxy -t 127.0.0.1:8081 -b 127.0.0.1:8080
