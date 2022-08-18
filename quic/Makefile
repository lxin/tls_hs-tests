all: 
	gcc client_basic.c -o client_basic
	gcc server_basic.c -o server_basic
	gcc client_notification.c -o client_notification
	gcc server_notification.c -o server_notification
	gcc client_psk.c -o client_psk
	gcc server_psk.c -o server_psk
	gcc client_session.c -o client_session
	gcc server_session.c -o server_session
	gcc client_certificates.c -o client_certificates
	gcc server_certificates.c -o server_certificates
	gcc client_keyupdate.c -o client_keyupdate
	gcc server_keyupdate.c -o server_keyupdate
	gcc client_token.c -o client_token
	gcc server_token.c -o server_token
	cd psks && sh psk.sh
	cd certs && sh gen_certs.sh
clean:
	rm -rf client_basic server_basic 
	rm -rf client_notification server_notification
	rm -rf client_psk server_psk
	rm -rf client_session server_session
	rm -rf client_certificates server_certificates
	rm -rf client_keyupdate server_keyupdate
	rm -rf client_token server_token
	cd psks && rm -rf gen_psk *.der
	cd certs && rm -rf *.der *.srl *.crt *.key *.csr gen_chain
run:
	sh run.sh
