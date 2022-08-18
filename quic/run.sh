modprobe quic
echo "file net/quic/* +p" > /sys/kernel/debug/dynamic_debug/control || exit 1
echo "file crypto/tls_hs.c +p" > /sys/kernel/debug/dynamic_debug/control || exit 1
CASE="basic notification psk session certificates keyupdate token"
ip link set lo mtu 1500
for name in $CASE; do
	./server_$name &
	sleep 2 && ./client_$name || echo "Failed $name"
	sleep 3 && pkill server_$name
	echo "=> $name done"
done
