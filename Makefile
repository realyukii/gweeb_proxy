build/gwproxy: gwproxy.c
	gcc -Wall -Wextra $^ -o $@
build/gwproxy_debug: gwproxy.c
	gcc -fsanitize=address -Wall -Wextra -DDEBUG_LVL=1 -g3 $^ -o $@
test: ./build/gwproxy
	./build/gwproxy -t [::1]:8081 -b [::]:8080 &
	./build/gwproxy -t [::1]:8081 -b [::]:8080 &
	./build/gwproxy -t [::1]:8081 -b [::]:8080 &
	./build/gwproxy -t [::1]:8081 -b [::]:8080 &
	./build/gwproxy -t [::1]:8081 -b [::]:8080 &
	./build/gwproxy -t [::1]:8081 -b [::]:8080 &
	./build/gwproxy -t [::1]:8081 -b [::]:8080 &
	./build/gwproxy -t [::1]:8081 -b [::]:8080 &
	./build/gwproxy -t 192.168.1.3:8081 -b [::]:8080 &
	./build/gwproxy -t 192.168.1.3:8081 -b [::]:8080 &
	./build/gwproxy -t 192.168.1.3:8081 -b [::]:8080 &
	./build/gwproxy -t 192.168.1.3:8081 -b [::]:8080 &
	./build/gwproxy -t 192.168.1.3:8081 -b [::]:8080 &
	./build/gwproxy -t 192.168.1.3:8081 -b [::]:8080 &
	./build/gwproxy -t 192.168.1.3:8081 -b [::]:8080 &
	./build/gwproxy -t 192.168.1.3:8081 -b [::]:8080