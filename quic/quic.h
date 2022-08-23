/* SPDX-License-Identifier: GPL-2.0-or-later WITH Linux-syscall-note */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2021
 *
 * This file is part of the SCTP kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#ifndef _UAPI_QUIC_H
#define _UAPI_QUIC_H

#include <linux/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>

struct quic_sndinfo {
	uint32_t stream_id;
};

struct quic_rcvinfo {
	uint32_t stream_id;
};

enum quic_cmsg_type {
	QUIC_SNDINFO,
	QUIC_RCVINFO,
};

struct quic_scc {
	uint32_t start;
	uint32_t cnt;
	uint32_t cur;
};

struct quic_idv {
	uint32_t id;
	uint32_t value;
};

enum quic_evt_type {
	QUIC_EVT_CIDS,		/* NEW, DEL, CUR */
	QUIC_EVT_STREAMS,	/* RESET, STOP, MAX, BLOCKED */
	QUIC_EVT_ADDRESS,	/* NEW */
	QUIC_EVT_TICKET,	/* NEW */
	QUIC_EVT_KEY,		/* NEW */
	QUIC_EVT_TOKEN,		/* NEW */
	QUIC_EVT_MAX,
};

enum quic_evt_stms_type {
	QUIC_EVT_STREAMS_RESET,
	QUIC_EVT_STREAMS_STOP,
	QUIC_EVT_STREAMS_MAX,
	QUIC_EVT_STREAMS_BLOCKED,
};

enum quic_evt_cids_type {
	QUIC_EVT_CIDS_NEW,
	QUIC_EVT_CIDS_DEL,
	QUIC_EVT_CIDS_CUR,
};

enum quic_evt_addr_type {
	QUIC_EVT_ADDRESS_NEW,
};

enum quic_evt_ticket_type {
	QUIC_EVT_TICKET_NEW,
};

enum quic_evt_key_type {
	QUIC_EVT_KEY_NEW,
};

enum quic_evt_token_type {
	QUIC_EVT_TOKEN_NEW,
};

struct quic_evt_msg {
	uint8_t evt_type;
	uint8_t sub_type;
	uint32_t value[3];
	uint8_t data[];
};

/* certificate and private key */
#define QUIC_SOCKOPT_CERT		0
#define QUIC_SOCKOPT_PKEY		1

/* connection id related */
#define QUIC_SOCKOPT_NEW_SCID		2
#define QUIC_SOCKOPT_DEL_DCID		3
#define QUIC_SOCKOPT_CUR_SCID		4
#define QUIC_SOCKOPT_CUR_DCID		5
#define QUIC_SOCKOPT_ALL_SCID		6
#define QUIC_SOCKOPT_ALL_DCID		7

/* connection migration related */
#define QUIC_SOCKOPT_CUR_SADDR		8

/* stream operation related */
#define QUIC_SOCKOPT_RESET_STREAM	9
#define QUIC_SOCKOPT_STOP_SENDING	10
#define QUIC_SOCKOPT_STREAM_STATE	11
#define QUIC_SOCKOPT_MAX_STREAMS	12

/* event */
#define QUIC_SOCKOPT_EVENT		13
#define QUIC_SOCKOPT_EVENTS		14

/* ticket */
#define QUIC_SOCKOPT_NEW_TICKET		15
#define QUIC_SOCKOPT_LOAD_TICKET	16

/* key */
#define QUIC_SOCKOPT_KEY_UPDATE		17

/* certificate chain */
#define QUIC_SOCKOPT_CERT_CHAIN		18
#define QUIC_SOCKOPT_ROOT_CA		19

/* token */
#define QUIC_SOCKOPT_NEW_TOKEN		20
#define QUIC_SOCKOPT_LOAD_TOKEN		21

#define QUIC_SOCKOPT_CERT_REQUEST	22

#define MSG_NOTIFICATION		0x8000

#define IPPROTO_QUIC	144
#define SOL_QUIC	144

int quic_recvmsg(int s, void *msg, size_t len, struct quic_rcvinfo *rinfo, int *msg_flags)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_rcvinfo))];
	struct cmsghdr *cmsg = NULL;
	struct msghdr inmsg;
	struct iovec iov;
	int error;

	memset(&inmsg, 0, sizeof(inmsg));

	iov.iov_base = msg;
	iov.iov_len = len;

	inmsg.msg_name = NULL;
	inmsg.msg_namelen = 0;
	inmsg.msg_iov = &iov;
	inmsg.msg_iovlen = 1;
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	error = recvmsg(s, &inmsg, 0);
	if (error < 0)
		return error;

	if (msg_flags)
		*msg_flags = inmsg.msg_flags;

	if (!rinfo)
		return error;

	for (cmsg = CMSG_FIRSTHDR(&inmsg); cmsg != NULL; cmsg = CMSG_NXTHDR(&inmsg, cmsg))
		if (SOL_QUIC == cmsg->cmsg_level && QUIC_RCVINFO == cmsg->cmsg_type)
			break;
	if (cmsg)
		memcpy(rinfo, CMSG_DATA(cmsg), sizeof(struct quic_rcvinfo));

	return error;
}

int quic_sendmsg(int s, const void *msg, size_t len, uint32_t flags, uint32_t stream_id)
{
	struct quic_sndinfo *sinfo;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char outcmsg[CMSG_SPACE(sizeof(*sinfo))];

	outmsg.msg_name = NULL;
	outmsg.msg_namelen = 0;
	outmsg.msg_iov = &iov;
	iov.iov_base = (void *)msg;
	iov.iov_len = len;
	outmsg.msg_iovlen = 1;

	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);
	outmsg.msg_flags = 0;

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = SOL_QUIC;
	cmsg->cmsg_type = 0;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct quic_sndinfo));

	outmsg.msg_controllen = cmsg->cmsg_len;
	sinfo = (struct quic_sndinfo *)CMSG_DATA(cmsg);
	memset(sinfo, 0, sizeof(struct quic_sndinfo));
	sinfo->stream_id = stream_id;

	return sendmsg(s, &outmsg, flags);
}

int get_file(char **buf, char *name)
{
	int fd = open(name, O_RDONLY);
	struct stat sb;

	if (fd == -1)
		return -1;
	if (stat(name, &sb) == -1)
		return -1;

	*buf = malloc(sb.st_size);
	if (!(*buf))
		return -ENOMEM;
	read(fd, *buf, sb.st_size);

	close(fd);
	return sb.st_size;
}

int quic_sendto(int s, const void *msg, size_t len, struct sockaddr *addr,
		uint32_t addr_len, uint32_t flags, uint32_t stream_id)
{
	struct quic_sndinfo *sinfo;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char outcmsg[CMSG_SPACE(sizeof(*sinfo))];

	outmsg.msg_name = addr;
	outmsg.msg_namelen = addr_len;
	outmsg.msg_iov = &iov;
	iov.iov_base = (void *)msg;
	iov.iov_len = len;
	outmsg.msg_iovlen = 1;

	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);
	outmsg.msg_flags = 0;

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = SOL_QUIC;
	cmsg->cmsg_type = 0;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct quic_sndinfo));

	outmsg.msg_controllen = cmsg->cmsg_len;
	sinfo = (struct quic_sndinfo *)CMSG_DATA(cmsg);
	memset(sinfo, 0, sizeof(struct quic_sndinfo));
	sinfo->stream_id = stream_id;

	return sendmsg(s, &outmsg, flags);
}

#define MSG_LEN	1999

char msg[MSG_LEN + 1];

#endif /* _UAPI_QUIC_H */
