#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLS_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx)
		return NULL;

	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, NULL);
	if (SSL_CTX_load_verify_locations(ctx, "crts/RootCA.crt", NULL) <= 0) {
		printf("Unable to SSL_CTX_load_verify_locations\n");
		return NULL;
	}

	if (SSL_CTX_use_certificate_chain_file(ctx, "crts/Bundle.crt") <= 0) {
		printf("Unable to SSL_CTX_use_certificate_chain_file\n");
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "crts/Server.key", SSL_FILETYPE_PEM) <= 0 ) {
		printf("Unable to SSL_CTX_use_PrivateKey_file\n");
		return NULL;
	}
	return ctx;
}

int main(int argc, char **argv)
{
	struct sockaddr_in addr;
	int len, opt_len = 0;
	char msg[200];
	SSL_CTX *ctx;
	int sd, c_sd;
	SSL *ssl;

	if (argc != 2) {
		printf("%s PORT\n", argv[0]);
		return -1;
	}

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		printf("Unable to create socket\n");
		return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[1]));
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		printf("Unable to bind\n");
		return -1;
	}
	if (listen(sd, 1) < 0) {
		printf("Unable to listen\n");
		return -1;
	}
	c_sd = accept(sd, (struct sockaddr*)&addr, &len);
	if (c_sd < 0) {
		printf("Unable to accept\n");
		return -1;
	}
	printf("Accept new socket successfully\n");

	ctx = create_context();
	if (!ctx) {
		printf("Unable to create_context\n");
		return -1;
	}
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, c_sd);

	if (SSL_accept(ssl) < 0) {
		printf("Unable to SSL_accept\n");
		return -1;
	}
	printf("Accept new ssl successfully\n");

	strcpy(msg, "AAAAAAAAAA");
	len = SSL_write(ssl, msg, strlen(msg));
	if (len < 0) {
		printf("Unable to send\n");
		return -1;
	}
	strcpy(msg, "BBBBBBBBBB");
	len = SSL_write(ssl, msg, strlen(msg));
	if (len < 0) {
		printf("Unable to send\n");
		return -1;
	}
	strcpy(msg, "CCCCCCCCCC");
	len = SSL_write(ssl, msg, strlen(msg));
	if (len < 0) {
		printf("Unable to send\n");
		return -1;
	}

	while(1) {
		len = SSL_read(ssl, msg, sizeof(msg));
		if (len < 0) {
			printf("Unable to recv\n");
			return -1;
		}
		msg[len] = '\0';
		printf("App data from client %d %s\n", len, msg);
		opt_len += len;
		if (opt_len >= 30)
			break;
	}

	sleep(5);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(c_sd);
	close(sd);
	SSL_CTX_free(ctx);
}
