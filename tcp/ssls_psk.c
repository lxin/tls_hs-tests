#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

const unsigned char tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };
char *psk_key = "5ac851e04710692cdb8da27668839d60";
static SSL_SESSION *psksess = NULL;
static char *psk_identity = "13aa";

static unsigned int psk_server_cb(SSL *ssl, const char *identity,
				  unsigned char *psk, unsigned int max_psk_len)
{
	return 0;
}

static int psk_find_session_cb(SSL *ssl, const unsigned char *identity,
			       size_t identity_len, SSL_SESSION **sess)
{
	const SSL_CIPHER *cipher;
	SSL_SESSION *tmpsess;
	unsigned char *key;
	long key_len;

	if (strlen(psk_identity) != identity_len ||
	    memcmp(psk_identity, identity, identity_len) != 0) {
		*sess = NULL;
		return 1;
	}
	if (psksess) {
		SSL_SESSION_up_ref(psksess);
		*sess = psksess;
		return 1;
	}

	key = OPENSSL_hexstr2buf(psk_key, &key_len);
	if (!key) {
		printf("Could not convert PSK key '%s' to buffer\n", psk_key);
		return 0;
	}

	cipher = SSL_CIPHER_find(ssl, tls13_aes128gcmsha256_id);
	if (!cipher) {
		printf("Error finding suitable ciphersuite\n");
		OPENSSL_free(key);
		return 0;
	}
	tmpsess = SSL_SESSION_new();
	if (!tmpsess || !SSL_SESSION_set1_master_key(tmpsess, key, key_len) ||
	    !SSL_SESSION_set_cipher(tmpsess, cipher) ||
	    !SSL_SESSION_set_protocol_version(tmpsess, SSL_version(ssl))) {
		OPENSSL_free(key);
		return 0;
	}
	SSL_SESSION_set_max_early_data(tmpsess, 65535);
	OPENSSL_free(key);
	*sess = tmpsess;

	return 1;
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLS_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		printf("Unable to create SSL context\n");
		return NULL;
	}
	SSL_CTX_set_psk_server_callback(ctx, psk_server_cb);
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_psk_find_session_callback(ctx, psk_find_session_cb);
	SSL_CTX_set_max_early_data(ctx, 65535);

	return ctx;
}

int main(int argc, char **argv)
{
	int ret = SSL_READ_EARLY_DATA_ERROR;
	long unsigned int len, opt_len = 0;
	struct sockaddr_in addr;
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
	len = sizeof(addr);
	c_sd = accept(sd, (struct sockaddr*)&addr, (unsigned int *)&len);
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

	while (ret != SSL_READ_EARLY_DATA_FINISH) {
		for (;;) {
			ret = SSL_read_early_data(ssl, msg, sizeof(msg), &len);
			if (ret != SSL_READ_EARLY_DATA_ERROR)
				break;

			switch (SSL_get_error(ssl, 0)) {
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_WANT_ASYNC:
			case SSL_ERROR_WANT_READ:
				continue;
			default:
				printf("Error reading early data %d\n", ret);
				return -1;
			}
		}
		opt_len += len;
		if (len > 0) {
			msg[len] = '\0';
			printf("Early data from client %d %s\n", opt_len, msg);
		}
	}
	printf("Early Data rcv done\n");

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
