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
	char control[CMSG_SPACE(sizeof(char))], type;
	struct sockaddr_in saddr;
	struct cmsghdr *cmsg;
	int sd, opt_len, len;
	struct msghdr msg;
	struct iovec iv;

	if (argc != 3 || (strcmp(argv[1], "crt") && strcmp(argv[1], "psk"))) {
		printf("%s psk | crt PORT\n", argv[0]);
		return -1;
	}

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd < 0){
		printf("Unable to create socket\n");
		return -1;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(atoi(argv[2]));
	saddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	if (connect(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
		printf("Unable to connect\n");
		return -1;
	}
	printf("Connected with server successfully\n");

	flag = !strcmp(argv[1], "psk") ? (0x2) /* TLS_F_SERV + TLS_F_PSK */
				       : (0x4 + 0x8); /* TLS_F_SERV + TLS_F_CRT + TLS_F_CRT_REQ */
	c_msg[0] = flag;
	strcpy(&c_msg[5], "AAAAAAAAAA");
	*((int *)(&c_msg[1])) = strlen(&c_msg[5]);
	opt_len = sizeof(c_msg);
	if (getsockopt(sd, SOL_TCP, 38, c_msg, &opt_len) < 0) {
		perror("Couldn't getsockopt\n");
		return -1;
	}
	if (opt_len) {
		c_msg[opt_len] = '\0';
		printf("Early data from server: %d %s\n", opt_len, c_msg);
	}

	strcpy(c_msg, "BBBBBBBBBB");
	if(send(sd, c_msg, strlen(c_msg), 0) < 0){
		printf("Unable to send message\n");
		return -1;
	}
	strcpy(c_msg, "CCCCCCCCCC");
	if(send(sd, c_msg, strlen(c_msg), 0) < 0){
		printf("Unable to send message\n");
		return -1;
	}

	while (1) {
		memset(&msg, 0, sizeof(msg));
		iv.iov_base = s_msg;
		iv.iov_len = 200;
		msg.msg_iov = &iv;
		msg.msg_iovlen = 1;
		msg.msg_control = control;
		msg.msg_controllen = sizeof(control);

		len = recvmsg(sd, &msg, 0);
		if(len <= 0){
			perror("Error while receiving server's msg\n");
			return -1;
		}
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg) {
			type = *((char *)CMSG_DATA(cmsg));
			if (type == 23) {
				opt_len += len;
				s_msg[len] = '\0';
				printf("App data from server: %d %s\n", len, s_msg);
				if (opt_len >= 30)
					break;
			} else {
				printf("Msg from server type %d\n", type);
			}
		}
	}

	sleep(3);
	close(sd);
	return 0;
}
