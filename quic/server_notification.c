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

int main(void)
{
	int sd, ad, ret, sid, cid, len, flags;
	struct sockaddr_in s_addr, c_addr;
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
	if (listen(sd, 3)) {
		printf("Unable to listen\n");
		return -1;
	}

	len = get_file(&buf, "certs/cert.der");
	if (setsockopt(sd, SOL_QUIC, 0, buf, len) < 0) {
		printf("Unable to setsockopt cert %d\n", errno);
		return -1;
	}

	len = get_file(&buf, "certs/pkey.der");
	if (setsockopt(sd, SOL_QUIC, 1, buf, len) < 0) {
		printf("Unable to setsockopt pkey %d\n", errno);
		return -1;
	}

	ad = accept(sd, (struct sockaddr *)&c_addr, &len);
	if (ad == -1) {
		printf("Unable to accept %d\n", errno);
		return -1;
	}
	sleep(2);

	c_addr.sin_family = AF_INET;
	c_addr.sin_port = htons(3333);
	c_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	len = sizeof(c_addr);
	ret = setsockopt(ad, SOL_QUIC, QUIC_SOCKOPT_CUR_SADDR, &c_addr, len);
	if (ret < 0) {
		printf("setsockopt %u %u\n", ret, errno);
		return 1;
	}

	cid = 0;
	len = sizeof(cid);
	ret = setsockopt(ad, SOL_QUIC, QUIC_SOCKOPT_NEW_SCID, &cid, len);
	if (ret < 0) {
		printf("setsockopt %u %u\n", ret, errno);
		return 1;
	}

	sid = 1;
	len = sizeof(sid);
	ret = setsockopt(ad, SOL_QUIC, QUIC_SOCKOPT_RESET_STREAM, &sid, len);
	if (ret < 0) {
		printf("setsockopt %u %u\n", ret, errno);
		return 1;
	}

	memset(msg, 's', sizeof(msg) - 1);
	ret = quic_sendmsg(ad, msg, strlen(msg), MSG_EOR, 5);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return 1;
	}

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
