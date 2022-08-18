# tls_hs-tests

This repo provides the test cases for tls_hs and its sub-projects:

- tls_hs/tls_hs_gen: https://github.com/lxin/tls_hs
- tcp: https://github.com/lxin/tls_hs/tree/tcp
- quic: https://github.com/lxin/tls_hs/tree/quic
- nfs: https://github.com/lxin/tls_hs/tree/sunrpc

'tls_hs' is the core tls handshaking MSG processing, and 'tls_hs_gen'
wrapping the tls_hs APIs can complete the TLS handshaking over a TCP
established socket then collabrate with kTLS.

'tcp' branch provides users a getsockopt TLS_HS_TCP to do TLS 1.3
handshaking via 'tls_hs_gen' in Kernel and return users a kTLS socket.

'quic' branch is using the lower level 'tls_hs' APIs to do its own
handshaking which is simliar with TLS 1.3's.

'nfs' branch is like 'tcp' branch using tls_hs_gen to do TLS handshaking.

```
TLS_HS
   |-- TLS_HS_GEN
   |      |
   |      |---- TLS_HS_TCP (see I)
   |      |---- NFS (see III)
   |
   |-- QUIC (see II)
```

## I. TLS_HS_TCP

### Setup

- Build kernel:
```
# git clone https://github.com/lxin/tls_hs -b tcp
(CONFIG_CRYPTO_TLS_HS=y)
# echo "file crypto/tls_hs.c +p" > /sys/kernel/debug/dynamic_debug/control
(For debug output in dmesg)
```
- Build testcases and setup psks/certs
```
# yum install -y openssl-devel # RHEL-8
# cd tcp/
# make   # build apps and generate psks/certs
# make install  # install psks/certs into keyring
```

'make run' to run all tests or run one by one as below:

### PSK tests:

This includes psk authentication and early data send and receive,
and interaction with openssl.

- Test 1: Kernel Client -> Kernel Server
```
# ./tcps psk 1234
# ./tcpc psk 1234
```
- Test 2: Kernel Client -> User Server
```
# ./ssls_psk 1234
# ./tcpc psk 1234
```
- Test 3: User Client -> Kernel Server
```
# ./tcps psk 1234
# ./sslc_psk 1234
```
- Test 4: User Client -> User Server
```
# ./ssls_psk 1234
# ./sslc_psk 1234
```

### CERTIFICATES tests:

This includes certificate chain and ca validation for both client
and server, and interaction with openssl.

- Test 1: Kernel Client -> Kernel Server
```
# ./tcps crt 1234
# ./tcpc crt 1234
```
- Test 2: Kernel Client -> User Server
```
# ./ssls_crt 1234
# ./tcpc crt 1234
```
- Test 3: User Client -> Kernel Server
```
# ./tcps crt 1234
# ./sslc_crt 1234
```
- Test 4: User Client -> User Server
```
# ./ssls_crt 1234
# ./sslc_crt 1234
```

## II. QUIC
- Build kernel:
```
# git clone https://github.com/lxin/tls_hs -b quic
(CONFIG_IP_QUIC=m)
# modprobe quic
# echo "file crypto/tls_hs.c +p" > /sys/kernel/debug/dynamic_debug/control
# echo "file net/quic/* +p" > /sys/kernel/debug/dynamic_debug/control
(For debug output in dmesg)
```
- Build ngtcp2:
```
see https://github.com/ngtcp2/ngtcp2
```
- Build testcases and setup psks/certs
```
# cd quic/
# make   # build apps and generate psks/certs
```

### self tests

'make run' to run all tests or run one by one as below:

- Test 1: hello world test with self-signed certificate:
```
# ./server_basic
# ./client_basic
```
- Test 2: psk:
```
# ./server_psk
# ./client_psk
```
- Test 3: session resumption and early data:
```
# ./server_session
# ./client_session
```
- Test 4: certificates chain and ca and client cert request
```
# ./server_certificates
# ./client_certificates
```
- Test 5: key update
```
# ./server_keyupdate
# ./client_keyupdate
```
- Test 6: retry with token
```
# ./server_token
# ./client_token
```
- Test 7: notification to users
```
# ./server_notification
# ./client_notification
```

### interaction test with ngtcp2
- Test 1: Kernel Client -> User Server
```
# cd ngtcp2/examples/
# ./server 127.0.0.1 1234 ./pkey.key ./cert.crt -s
  (pkey.pem and cert.pem are tls_hs/quic/certs)
# cd tls_hs/quic/
# ./client_basic
```
- Test 2: User Client -> Kernel Server
```
# cd tls_hs/quic/
# ./server_basic
# cd ngtcp2/examples/
# ./client 127.0.0.1 1234 -s --groups="P-256"
```

## III. NFS
- TODO
