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