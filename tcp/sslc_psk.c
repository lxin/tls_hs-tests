#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

const unsigned char tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };
char *psk_key = "5ac851e04710692cdb8da27668839d60";
static SSL_SESSION *psksess = NULL;
static char *psk_identity = "13aa";

static int psk_use_session_cb(SSL *s, const EVP_MD *md, const unsigned char **id,
			      size_t *idlen, SSL_SESSION **sess)
{
	SSL_SESSION *usesess = NULL;
	const SSL_CIPHER *cipher = NULL;

	if (psksess != NULL) {
		SSL_SESSION_up_ref(psksess);
		usesess = psksess;
	} else {
		unsigned char *key;
		long key_len;

		key = OPENSSL_hexstr2buf(psk_key, &key_len);
		if (key == NULL) {
			printf("Could not convert PSK key '%s' to buffer\n", psk_key);
			return 0;
		}

		cipher = SSL_CIPHER_find(s, tls13_aes128gcmsha256_id);
		if (cipher == NULL) {
			printf("Error finding suitable ciphersuite\n");
			OPENSSL_free(key);
			return 0;
		}

		usesess = SSL_SESSION_new();
		if (usesess == NULL
				|| !SSL_SESSION_set1_master_key(usesess, key, key_len)
				|| !SSL_SESSION_set_cipher(usesess, cipher)
				|| !SSL_SESSION_set_protocol_version(usesess, TLS1_3_VERSION)) {
			OPENSSL_free(key);
			goto err;
		}
		SSL_SESSION_set_max_early_data(usesess, 65535);
		OPENSSL_free(key);
	}

	cipher = SSL_SESSION_get0_cipher(usesess);
	if (cipher == NULL)
		goto err;

	if (md != NULL && SSL_CIPHER_get_handshake_digest(cipher) != md) {
		*id = NULL;
		*idlen = 0;
		*sess = NULL;
		SSL_SESSION_free(usesess);
	} else {
		*sess = usesess;
		*id = (unsigned char *)psk_identity;
		*idlen = strlen(psk_identity);
	}

	return 1;
err:
	SSL_SESSION_free(usesess);
	return 0;
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLS_client_method();
	ctx = SSL_CTX_new(method);
	if (!ctx)
		return NULL;

	SSL_CTX_set_cipher_list(ctx, "AES128-SHA256");
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_psk_use_session_callback(ctx, psk_use_session_cb);
	SSL_CTX_set_max_early_data(ctx, 65535);
	return ctx;
}

int main(int argc, char **argv)
{
	long unsigned int len, opt_len = 0;
	struct sockaddr_in saddr;
	char msg[200];
	SSL_CTX *ctx;
	int ret, sd;
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

	strcpy(msg, "AAAAAAAAAA");
	while (!SSL_write_early_data(ssl, msg, strlen(msg), &len)) {
		ret = SSL_get_error(ssl, 0);
		switch (ret) {
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_ASYNC:
		case SSL_ERROR_WANT_READ:
			continue;
		default:
			printf("Error writing early data %d\n", ret);
			return -1;
		}
	}
	if (SSL_connect(ssl) < 0) {
		printf("Unable to SSL_connect\n");
		return -1;
	}
	printf("connect ssl successfully\n");
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
	return 0;
}
