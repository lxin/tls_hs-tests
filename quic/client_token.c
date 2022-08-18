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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "quic.h"

int main(void)
{
	struct sockaddr_in s_addr, c_addr;
	int sd, ret, events, len, flags;
	struct quic_evt_msg *es;
	struct quic_rcvinfo r;
	char *buf;

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_QUIC);

	c_addr.sin_family = AF_INET;
	c_addr.sin_port = htons(4321);
	c_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (bind(sd, (struct sockaddr *)&c_addr, sizeof(c_addr)) < 0) {
		printf("Unable to bind\n");
		return -1;
	}

	events = (1 << QUIC_EVT_TOKEN);
	len = sizeof(events);
	ret = setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_EVENTS, &events, len);
	if (ret < 0) {
		printf("setsockopt %u %u\n", ret, errno);
		return 1;
	}

	len = sizeof(events);
	ret = getsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_EVENTS, &events, &len);
	if (ret < 0) {
		printf("getsockopt %u %u\n", ret, errno);
		return 1;
	}

	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(1234);
	s_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (connect(sd, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0) {
		printf("Unable to connect %d\n", errno);
		return -1;
	}
	sleep(2);

	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sd, msg, sizeof(msg), &r, &flags);
	if (ret == -1) {
		printf("recv %d %d\n", ret, errno);
		return 1;
	}
	if (flags & MSG_NOTIFICATION) {
		if (msg[0] == QUIC_EVT_TOKEN)  {
			es = (struct quic_evt_msg *)msg;
			printf("notification type %u, %u: %u, %u, %u\n",
			       es->evt_type, es->sub_type, es->value[0], es->value[1], es->value[2]);
			buf = es->data;
			len = es->value[0];
			sleep(3);
			close(sd);
		}
	}

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_QUIC);

	c_addr.sin_family = AF_INET;
	c_addr.sin_port = htons(4321);
	c_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (bind(sd, (struct sockaddr *)&c_addr, sizeof(c_addr)) < 0) {
		printf("Unable to bind\n");
		return -1;
	}

	if (setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_LOAD_TOKEN, buf, len) < 0) {
		printf("Unable to setsockopt token %d\n", errno);
		return -1;
	}

	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(1234);
	s_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (connect(sd, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0) {
		printf("Unable to connect %d\n", errno);
		return -1;
	}

	memset(msg, 'c', sizeof(msg) - 1);
	ret = quic_sendmsg(sd, msg, strlen(msg), 0, 0);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		sleep(100);
		return 1;
	}

	len = 0;
	while (1) {
		memset(msg, 0, sizeof(msg));
		ret = quic_recvmsg(sd, msg, sizeof(msg), &r, &flags);
		if (ret == -1) {
			printf("recv %d %d\n", ret, errno);
			return -1;
		}
		printf("recv %d %d %s\n", ret, r.stream_id, msg);
		len += ret;
		if (len >= MSG_LEN)
			break;
	}

	sleep(2);
	close(sd);
	return 0;
}
