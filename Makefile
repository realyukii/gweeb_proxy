build/gwproxy: gwproxy.c
	gcc -DDEBUG_LVL=3 $^ -o $@
