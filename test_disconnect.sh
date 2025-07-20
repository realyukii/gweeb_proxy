echo "connecting"

# open a tcp connection
exec 3<>/dev/tcp/::1/1080
# send client greeting packet,
# tell the server that we prefer no auth method
printf '\x05\x01\x00' >&3
# read greeting reply from server
head -c2 <&3 | xxd
# send connect command request
printf '\x05\x01\x00\x03\x0b\x79\x6f\x75\x74\x75\x62\x65\x2e\x63\x6f\x6d\x00\x50' >&3

exec 3>&- 3<&-

echo "disconnected"
