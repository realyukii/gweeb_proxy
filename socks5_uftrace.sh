gcc -DENABLE_LOG=false -Wmaybe-uninitialized -Wall -Wextra -g3 -pg  -c gwproxy.c -o build/gwproxy.o
gcc -DENABLE_LOG=false -Wmaybe-uninitialized -Wall -Wextra -g3 -pg  -c gwsocks5lib.c -o build/gwsocks5lib.o
gcc -DENABLE_LOG=false -Wmaybe-uninitialized -Wall -Wextra -g3 -pg  -c gwdnslib.c -o build/gwdnslib.o
gcc -DENABLE_LOG=false -Wmaybe-uninitialized -Wall -Wextra -g3 -pg  -c general.c -o build/general.o
gcc -DENABLE_LOG=false -Wmaybe-uninitialized -Wall -Wextra -g3 -pg  -c linux.c -o build/linux.o
gcc -pg  build/gwproxy.o build/gwsocks5lib.o build/linux.o build/gwdnslib.o build/general.o   -o build/gwproxy
uftrace live -F dns_serv_thread -F start_tcp_serv --no-pager -a -- build/gwproxy -s -b [::]:1080 -T 1 -w 60

# gcc -g3 -pg -DENABLE_LOG=false -c dns_resolver.c -o build/dns_resolver.o
# gcc -g3 -pg -DENABLE_LOG=false -c general.c -o build/general.o
# gcc -g3 -pg -DENABLE_LOG=false -c linux.c -o build/linux.o
# gcc -pg  build/dns_resolver.o build/general.o build/linux.o   -o build/dns_resolver
# uftrace live --no-pager -a -- build/dns_resolver -b [::]:6969 -t 1