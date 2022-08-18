// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2021
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "quic.h"

int get_token(char **buf)
{
	*buf = malloc(8);
	if (!(*buf))
		return -ENOMEM;
	memset(*buf, 0x1, 8);

	return 8;
}

int main(void)
{
	int sd, ad, ret, events, len, flags;
	struct sockaddr_in s_addr, c_addr;
	struct quic_evt_msg *es;
	struct quic_rcvinfo r;
	char *buf;

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_QUIC);

	memset(&s_addr, 0x00, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(1234);
	s_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (bind(sd, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0) {
		printf("Unable to bind\n");
		return -1;
	}

	len = get_token(&buf);
	if (setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_LOAD_TOKEN, buf, len) < 0) {
		printf("Unable to setsockopt token %d\n", errno);
		return -1;
	}

	if (listen(sd, 3)) {
		printf("Unable to listen\n");
		return -1;
	}

	len = get_file(&buf, "certs/cert.der");
	if (setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_CERT, buf, len) < 0) {
		printf("Unable to setsockopt cert %d\n", errno);
		return -1;
	}

	len = get_file(&buf, "certs/pkey.der");
	if (setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_PKEY, buf, len) < 0) {
		printf("Unable to setsockopt pkey %d\n", errno);
		return -1;
	}

	ad = accept(sd, (struct sockaddr *)&c_addr, &len);
	if (ad == -1) {
		printf("Unable to accept %d\n", errno);
		return -1;
	}

	events = (1 << QUIC_EVT_TOKEN);
	len = sizeof(events);
	ret = setsockopt(ad, SOL_QUIC, QUIC_SOCKOPT_EVENTS, &events, len);
	if (ret < 0) {
		printf("setsockopt %u %u\n", ret, errno);
		return 1;
	}

	len = sizeof(events);
	ret = getsockopt(ad, SOL_QUIC, QUIC_SOCKOPT_EVENTS, &events, &len);
	if (ret < 0) {
		printf("getsockopt %u %u\n", ret, errno);
		return 1;
	}
	sleep(2);

	if (setsockopt(ad, SOL_QUIC, QUIC_SOCKOPT_NEW_TOKEN, NULL, 0) < 0) {
		printf("Unable to setsockopt token %d\n", errno);
		return -1;
	}

	memset(msg, 0, sizeof(msg));
	flags = MSG_MORE;
	ret = quic_recvmsg(ad, msg, sizeof(msg), &r, &flags);
	if (ret == -1) {
		printf("recv %d %d\n", ret, errno);
		return 1;
	}
	if (flags & MSG_NOTIFICATION) {
		if (msg[0] == QUIC_EVT_TOKEN)  {
			es = (struct quic_evt_msg *)msg;
			printf("notification type %u, %u: %u, %u, %u\n",
			       es->evt_type, es->sub_type, es->value[0], es->value[1], es->value[2]);
			sleep(3);
			close(ad);
		}
	}

	ad = accept(sd, (struct sockaddr *)&c_addr, &len);
	if (ad == -1) {
		printf("Unable to accept %d\n", errno);
		return -1;
	}
	sleep(2);

	memset(msg, 's', sizeof(msg) - 1);
	ret = quic_sendmsg(ad, msg, strlen(msg), 0, 3);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return 1;
	}

	len = 0;
	while (1) {
		memset(msg, 0, sizeof(msg));
		ret = quic_recvmsg(ad, msg, sizeof(msg), &r, &flags);
		if (ret == -1) {
			printf("recv %d %d\n", ret, errno);
			return 1;
		}
		printf("recv %d %d %s\n", ret, r.stream_id, msg);
		len += ret;
		if (len >= MSG_LEN)
			break;
	}

	sleep(2);
	close(ad);
	close(sd);
	return 0;
}
