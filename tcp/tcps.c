#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/tcp.h>

int main(int argc, char *argv[])
{
	char flag, s_msg[200] = {'\0'}, c_msg[200] = {'\0'};
	int sd, c_sd, addr_len, opt_len, len;
	struct sockaddr_in saddr, caddr;

	if (argc != 3 || (strcmp(argv[1], "crt") && strcmp(argv[1], "psk"))) {
		printf("%s psk | crt PORT\n", argv[0]);
		return -1;
	}

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd < 0){
		printf("Error while creating socket\n");
		return -1;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(atoi(argv[2]));
	saddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	if (bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("Couldn't bind to the port\n");
		return -1;
	}

	if(listen(sd, 1) < 0){
		printf("Error while listening\n");
		return -1;
	}
	printf("Listening for incoming connections.....\n");

	addr_len = sizeof(caddr);
	c_sd = accept(sd, (struct sockaddr*)&caddr, &addr_len);
	if (c_sd < 0){
		printf("Can't accept\n");
		return -1;
	}
	printf("Client connected at IP: %s and port: %i\n", inet_ntoa(caddr.sin_addr),
	       ntohs(caddr.sin_port));

	flag = !strcmp(argv[1], "psk") ? (0x1 + 0x2) /* TLS_F_SERV + TLS_F_PSK */
				       : (0x1 + 0x4 + 0x8); /* TLS_F_SERV + TLS_F_CRT + TLS_F_CRT_REQ */
	s_msg[0] = flag;
	strcpy(&s_msg[5], "AAAAAAAAAA");
	*((int *)(&s_msg[1])) = strlen(&s_msg[5]);
	opt_len = sizeof(s_msg);
	if (getsockopt(c_sd, SOL_TCP, 38, s_msg, &opt_len) < 0) {
		perror("Couldn't getsockopt\n");
		return -1;
	}
	if (opt_len) {
		s_msg[opt_len] = '\0';
		printf("Early data from client %d %s\n", opt_len, s_msg);
	}

	strcpy(s_msg, "BBBBBBBBBB");
	len = send(c_sd, s_msg, strlen(s_msg), 0);
	if (len < 0){
		printf("can't send\n");
		return -1;
	}
	strcpy(s_msg, "CCCCCCCCCC");
	len = send(c_sd, s_msg, strlen(s_msg), 0);
	if (len < 0){
		printf("Couldn't send\n");
		return -1;
	}
	while (1) {
		len = recv(c_sd, c_msg, sizeof(c_msg), 0);
		if (len <= 0){
			printf("Couldn't receive\n");
			return -1;
		}
		opt_len += len;
		c_msg[len] = '\0';
		printf("App data from client: %d %s\n", len, c_msg);
		if (opt_len >= 30)
			break;
	}

	sleep(3);
	close(c_sd);
	close(sd);
	return 0;
}
