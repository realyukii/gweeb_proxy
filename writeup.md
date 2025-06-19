sequence of program flow:
1. program start
2. start listening on specified bind port
3. accept new client (established connection)
4. connect to specified target
5. start receiving data from client
6.0 check if the target connection is established
6.1 start forwarding data to target
7. start receiving response from target
8. start forwarding response to client
9. repeat to step 5 until both parties done exchange data
10. thanks to event notification mechanism (that allow non blocking behavior), without blocking step 5-9, repeat to step 3
