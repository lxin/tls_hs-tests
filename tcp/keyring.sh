keyctl newring tcp-1 @u
keyctl add user psk-0-id "13aa" %:tcp-1
keyctl add user psk-0-master `echo 5ac851e04710692cdb8da27668839d60 | xxd -r -p` %:tcp-1

keyctl newring tcp-0 @u
keyctl add user psk-0-id "13aa" %:tcp-0
keyctl add user psk-0-master `echo 5ac851e04710692cdb8da27668839d60 | xxd -r -p` %:tcp-0

keyctl padd user pkey %:tcp-1 < ./crts/ServerKey.der
keyctl padd user crt-0 %:tcp-1 < ./crts/ServerCA.der
keyctl padd user crt-1 %:tcp-1 < ./crts/IntermediateCA.der
keyctl padd user crt-2 %:tcp-1 < ./crts/RootCA.der
keyctl padd user ca %:tcp-1 < ./crts/RootCA.der

keyctl padd user pkey %:tcp-0 < ./crts/ServerKey.der
keyctl padd user crt-0 %:tcp-0 < ./crts/ServerCA.der
keyctl padd user crt-1 %:tcp-0 < ./crts/IntermediateCA.der
keyctl padd user crt-2 %:tcp-0 < ./crts/RootCA.der
keyctl padd user ca %:tcp-0 < ./crts/RootCA.der

keyctl show
echo "file crypto/tls_hs.c +p" > /sys/kernel/debug/dynamic_debug/control
