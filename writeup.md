sequence of program flow:
1. program start
2. start listening on specified bind port
3. accept new client (established connection)
4. connect to specified target
5. start receiving data from client
6. start forwarding data to target
7. start receiving response from target
8. start forwarding response to client
9. repeat to step 5 until both parties done exchange data
10. thanks to event notification mechanism (that allow non blocking behavior), without blocking step 5-9, repeat to step 3

socks5 proxy:
1. client greeting
2. server either refuse or pick one of the authentication methods from step 1
3. negotiation of authentication method (no negotiation happened for no authentication method)
4. if negotiation succeed, client send request
4. server parsing the client request, and connect to the requested target address
5. perform standard proxy operation as usual, like before.

testing socks5 proxy with bash:
```bash
# open a tcp connection
exec 3<>/dev/tcp/::1/1080
# send client greeting packet,
# tell the server that we prefer username/password auth method
printf '\x05\x01\x02' >&3
# read greeting reply from server
head -c2 <&3 | xxd
# send username/password packet
printf '\x01\x05\x6c\x6f\x72\x65\x6d\x05\x69\x70\x73\x75\x6d' >&3
# read the server response
head -c2 <&3 | xxd
# send request with connect command
printf '%b%b' \
"\x05\x01\x00\x04" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" \
"\x1f\x91" >&3
# now we can send actual data to be tunneled, raw http GET request
printf "GET / HTTP/1.1\r\nHost: whatever.com\r\nConnection: close\r\n\r\n" >&3
# read http response (gwhttpd server always return static, fixed response)
head -c333 <&3 | xxd
```

close the socket file descriptor:
```bash
exec 3>&- 3<&-
```

tips, construct network packet with printf, xxd and sed (and my tool: ip converter):
```bash
# username password packet
printf "\x01\x05lorem\x05ipsum" | xxd -p | sed 's/../\\x&/g'
```

```bash
./ip_converter [::1]:8081
printf "output ip"  | sed 's/../\\x&/g'
printf "output port"  | sed 's/../\\x&/g'
```

testing socks5 proxy with curl:
```bash
strace -x -e trace=recvfrom  curl -so /dev/null -v -x socks5://lorem:ipsum@[::1]:1080 [::1]:8081
```

for observing established connection from client to socks5 proxy server:
```bash
ss -tpn -o state established '( dport = 1080 )'
```

for observing established connection from socks5 proxy server to target:
```bash
ss -tpn -o state established '( sport != 1080 )' | grep gwproxy
```

set the socket file descriptor (opened from bash) with python:
```bash
python3 - <<'EOF'
import fcntl, os
flags = fcntl.fcntl(3, fcntl.F_GETFL)
fcntl.fcntl(3, fcntl.F_SETFL, flags | os.O_NONBLOCK)
EOF
```

when the socket is non block, you can use `cat` instead of `head` without specifying its length:
```bash
cat <&3 | xxd
```
this is useful when you don't know the length, and want to print available data
without waiting connection to be closed.


read flags or attributes of the socket with python:
```bash
python3 - <<'EOF'
import fcntl, os

# 1) File‐status flags (e.g. O_NONBLOCK, O_APPEND, etc)
flags = fcntl.fcntl(3, fcntl.F_GETFL)
print("File‐status flags:", flags, hex(flags))

# 2) Descriptor flags (e.g. FD_CLOEXEC)
fd_flags = fcntl.fcntl(3, fcntl.F_GETFD)
print("FD‐flags:", fd_flags, hex(fd_flags))

# 3) Decode which O_* bits are present
print("\nDecoded O_* flags:")
for name in dir(os):
    if name.startswith("O_"):
        val = getattr(os, name)
        if flags & val:
            print(f"  {name}")
EOF
```

benchmark with iperf3 tool:
start server:
```shell
iperf3 -s
```

set the proxy to simple tcp proxy that target to ::1 port 5201 (default port of iperf server)

start client:
```shell
iperf3 -c ::1 -p 8085 -n 100g -P 5
```

test race condition and deadlock with valgrind:
```shell
valgrind --tool=helgrind ./build/dns_resolver -b [::]:6969 -t 1
```

test memory error and memory leak with valgrind:
```shell
valgrind --leak-check=full --show-leak-kinds=all --leak-resolution=high --log-file=leaks.log ./build/dns_resolver -b [::]:6969 -t 1
```

profiles CPU/cache performance:
```
valgrind --tool=callgrind build/gwproxy -f ./auth.db -s -b [::]:1080 -T 1 -w 60
```

print function call trace with arguments and its return value (require -pg, see https://github.com/namhyung/uftrace/discussions/2012)
```
uftrace live --no-pager --no-libcall -a -- build/gwproxy -s -b [::]:1080 -T 1 -w 60
```

strace -x -f -e trace=%net,read,write sh test_disconnect.sh 

reproduce segfault (make sure the user auth method is no auth, the payload is not using username/password auth method)
x=2; for i in $(seq 1 $x); do bash ./test_disconnect.sh; done