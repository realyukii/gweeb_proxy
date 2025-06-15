build/gwproxy: gwproxy.c
	gcc -DDEBUG_LVL=1 -g3 $^ -o $@
test: ./build/gwproxy
	./build/gwproxy -t 8.8.8.8:8888 -b 127.0.0.1:8080
