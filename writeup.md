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
