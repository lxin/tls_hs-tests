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
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "quic.h"

int main(void)
{
	int sd, fd, ret, events, len, flags;
	struct sockaddr_in s_addr, c_addr;
	struct quic_evt_msg *es;
	struct quic_rcvinfo r;
	char name[32], *buf;

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_QUIC);

	c_addr.sin_family = AF_INET;
	c_addr.sin_port = htons(4321);
	c_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (bind(sd, (struct sockaddr *)&c_addr, sizeof(c_addr)) < 0) {
		printf("Unable to bind\n");
		return -1;
	}

	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(1234);
	s_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	events = (1 << QUIC_EVT_TICKET);
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

	if (connect(sd, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0) {
		printf("Unable to connect %d\n", errno);
		return -1;
	}
	memset(msg, 'c', sizeof(msg) - 1);
	ret = quic_sendmsg(sd, msg, strlen(msg), 0, 0);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}

	while (1) {
		memset(msg, 0, sizeof(msg));
		ret = quic_recvmsg(sd, msg, sizeof(msg), &r, &flags);
		if (ret == -1) {
			printf("recv %d %d\n", ret, errno);
			return -1;
		}
		if (!(flags & MSG_NOTIFICATION)) {
			printf("recv %d %d\n", ret, r.stream_id);
			continue;
		}

		if (msg[0] != QUIC_EVT_TICKET)
			continue;

		es = (struct quic_evt_msg *)msg;
		printf("notification type %u, %u: %u, %u, %u\n",
		       es->evt_type, es->sub_type, es->value[0], es->value[1], es->value[2]);

		strcpy(name, "psks/session.der");
		fd = open(name, O_RDWR | O_CREAT);
		if (fd == -1) {
			printf("open file %s error %d\n", name, errno);
			return -1;
		}
		len = es->value[0];
		len = write(fd, es->data, len);
		printf("write session file %s len %d\n", name, len);
		close(fd);
		break;
	}

	sleep(2);
	close(sd);
	printf("wait for 5 seconds\n");
	sleep(5);

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_QUIC);

	c_addr.sin_family = AF_INET;
	c_addr.sin_port = htons(4321);
	c_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (bind(sd, (struct sockaddr *)&c_addr, sizeof(c_addr)) < 0) {
		printf("Unable to bind\n");
		return -1;
	}

	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(1234);
	s_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	len = get_file(&buf, "psks/session.der");
	if (setsockopt(sd, SOL_QUIC, QUIC_SOCKOPT_LOAD_TICKET, buf, len) < 0) {
		printf("Unable to setsockopt PSK %d\n", errno);
		return -1;
	}
	memset(msg, 'c', sizeof(msg) - 1);
	ret = quic_sendto(sd, msg, strlen(msg), (struct sockaddr *)&s_addr,
			  sizeof(s_addr), 0, 0);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}
	while (1) {
		memset(msg, 0, sizeof(msg));
		ret = quic_recvmsg(sd, msg, sizeof(msg), &r, 0);
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
