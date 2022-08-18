all: tcpc.c tcps.c
	gcc tcps.c -o tcps
	gcc tcpc.c -o tcpc
	gcc ssls_crt.c -o ssls_crt -lssl -lcrypto
	gcc sslc_crt.c -o sslc_crt -lssl -lcrypto
	gcc ssls_psk.c -o ssls_psk -lssl -lcrypto
	gcc sslc_psk.c -o sslc_psk -lssl -lcrypto
	cd crts/ && sh gen_certs.sh
clean:
	rm -rf tcpc tcps ssls_crt sslc_crt ssls_psk sslc_psk
	cd crts/ && rm -rf *.der *.srl *.crt *.key *.csr
install:
	sh keyring.sh
run:
	sh run.sh
