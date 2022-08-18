#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLS_client_method();
	ctx = SSL_CTX_new(method);
	if (!ctx)
		return NULL;

	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
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
	struct sockaddr_in saddr;
	int len, opt_len = 0, sd;
	char msg[200];
	SSL_CTX *ctx;
	SSL *ssl;

	if (argc != 2) {
		printf("%s PORT\n", argv[0]);
		return -1;
	}

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd < 0){
		printf("Unable to create socket\n");
		return -1;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(atoi(argv[1]));
	saddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	if (connect(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
		printf("Unable to connect\n");
		return -1;
	}
	printf("Connected with server successfully\n");

	ctx = create_context();
	if (!ctx) {
		printf("Unable to create_context\n");
		return -1;
	}
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sd);

	if (SSL_connect(ssl) < 0) {
		printf("Unable to SSL_connect\n");
		return -1;
	}
	printf("connect ssl successfully\n");

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
	SSL_free(ssl);
	close(sd);
	SSL_CTX_free(ctx);
}
