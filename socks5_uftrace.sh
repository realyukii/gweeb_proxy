gcc -DENABLE_LOG=false -Wmaybe-uninitialized -Wall -Wextra -g3 -pg  -c gwproxy.c -o build/gwproxy.o
gcc -DENABLE_LOG=false -Wmaybe-uninitialized -Wall -Wextra -g3 -pg  -c gwsocks5lib.c -o build/gwsocks5lib.o
gcc -DENABLE_LOG=false -Wmaybe-uninitialized -Wall -Wextra -g3 -pg  -c linux.c -o build/linux.o
gcc -pg  build/gwproxy.o build/gwsocks5lib.o build/linux.o build/general.o   -o build/gwproxy
uftrace live -F start_tcp_serv --no-pager -a -- build/gwproxy -s -b [::]:1080 -T 1 -w 60