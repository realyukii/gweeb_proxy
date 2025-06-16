build/gwproxy: gwproxy.c
	gcc -DDEBUG_LVL=1 -g3 $^ -o $@
test: ./build/gwproxy
	strace ./build/gwproxy -t 127.0.0.1:8888 -b 127.0.0.1:8080
