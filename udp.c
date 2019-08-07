/* udp.c - UDP specific code for echo client */

/*
 * Copyright (c) 2017 Intel Corporation.
 * Copyright (c) 2018 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_DECLARE(net_echo_client_sample, LOG_LEVEL_DBG);

#include <zephyr.h>
#include <errno.h>
#include <stdio.h>

#include <net/socket.h>
#include <net/tls_credentials.h>

#include "common.h"
#include "ca_certificate.h"

#define RECV_BUF_SIZE 1280
#define UDP_SLEEP K_MSEC(150)
#define UDP_WAIT K_SECONDS(10)

char recv_buf[RECV_BUF_SIZE];

static int send_udp_data(struct data *data)
{
	int ret;

	do {
		data->udp.expecting = sys_rand32_get() % ipsum_len;
	} while (data->udp.expecting == 0U);

	ret = send(data->udp.sock, lorem_ipsum, data->udp.expecting, 0);

	printf("%s UDP: Sent %d bytes\n", data->proto, data->udp.expecting);

	k_delayed_work_submit(&data->udp.recv, UDP_WAIT);

	return ret < 0 ? -EIO : 0;
}

static int compare_udp_data(struct data *data, const char *buf, u32_t received)
{
	if (received != data->udp.expecting) {
		printf("Invalid amount of data received: UDP %s\n", data->proto);
		return -EIO;
	}

	if (memcmp(buf, lorem_ipsum, received) != 0) {
		printf("Invalid data received: UDP %s\n", data->proto);
		return -EIO;
	}

	return 0;
}

static void wait_reply(struct k_work *work)
{
	/* This means that we did not receive response in time. */
	struct data *data = CONTAINER_OF(work, struct data, udp.recv);

	printf("UDP %s: Data packet not received\n", data->proto);

	/* Send a new packet at this point */
	send_udp_data(data);
}

static void wait_transmit(struct k_work *work)
{
	struct data *data = CONTAINER_OF(work, struct data, udp.transmit);

	send_udp_data(data);
}

static int start_udp_proto(struct data *data, struct sockaddr *addr,
			   socklen_t addrlen)
{
	int ret;

	k_delayed_work_init(&data->udp.recv, wait_reply);
	k_delayed_work_init(&data->udp.transmit, wait_transmit);

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	printf("IPPROTO_DTLS_1_2\n");
	data->udp.sock = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_DTLS_1_2);
#else
	data->udp.sock = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
#endif
	if (data->udp.sock < 0) {
		printf("Failed to create UDP socket (%s): %d\n", data->proto,
			errno);
		return -errno;
	}

	printf("setting for HOSTNAME\n");
	sec_tag_t sec_tag_list[] = {
		CA_CERTIFICATE_TAG,
	};

	ret = setsockopt(data->udp.sock, SOL_TLS, TLS_SEC_TAG_LIST,
			 sec_tag_list, sizeof(sec_tag_list));
	if (ret < 0) {
		printf("Failed to set TLS_SEC_TAG_LIST option (%s): %d\n",
			data->proto, errno);
		ret = -errno;
	}

	// setting for HOSTNAME
	char hostname[100];
	gethostname(hostname, sizeof(hostname));
	printf("HOSTNAME=%s\n", &hostname);
	ret = zsock_setsockopt(data->udp.sock, SOL_TLS, TLS_HOSTNAME,
						   hostname, sizeof(hostname));
	if (ret < 0)
	{
		printf("Failed to set TLS_HOSTNAME option : %d\n", errno);
		ret = -errno;
	}
/*
	ret = setsockopt(data->udp.sock, SOL_TLS, TLS_HOSTNAME,
			 TLS_PEER_HOSTNAME, sizeof(TLS_PEER_HOSTNAME));
	if (ret < 0) {
		printf("Failed to set TLS_HOSTNAME option (%s): %d ret = %d\n",
			data->proto, errno,ret);
		ret = -errno;
	} */

	/* Call connect so we can use send and recv. */
	ret = connect(data->udp.sock, addr, addrlen);
	if (ret < 0) {
		printf("Cannot connect to UDP remote (%s): %d", data->proto,
			errno);
		ret = -errno;
	}

	return ret;
}

static int process_udp_proto(struct data *data)
{
	int ret, received;

	received = recv(data->udp.sock, recv_buf, sizeof(recv_buf),
			MSG_DONTWAIT);

	if (received == 0) {
		return -EIO;
	}
	if (received < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = 0;
		} else {
			ret = -errno;
		}
		return ret;
	}

	ret = compare_udp_data(data, recv_buf, received);
	if (ret != 0) {
		printf("%s UDP: Received and compared %d bytes, data "
			"mismatch\n", data->proto, received);
		return 0;
	}

	/* Correct response received */
	printf("%s UDP: Received and compared %d bytes, all ok\n",
		data->proto, received);

	if (++data->udp.counter % 1000 == 0U) {
		printf("%s UDP: Exchanged %u packets\n", data->proto,
			   data->udp.counter);
	}

	k_delayed_work_cancel(&data->udp.recv);

	/* Do not flood the link if we have also TCP configured */
	if (IS_ENABLED(CONFIG_NET_TCP)) {
		k_delayed_work_submit(&data->udp.transmit, UDP_SLEEP);
		ret = 0;
	} else {
		ret = send_udp_data(data);
	}

	return ret;
}

int start_udp(void)
{
	int ret = 0;
	struct sockaddr_in6 addr6;

	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(PEER_PORT);
	inet_pton(AF_INET6, "fdf9:3dba:e602::1",
			  &addr6.sin6_addr);

	ret = start_udp_proto(&conf.ipv6, (struct sockaddr *)&addr6,
			      sizeof(addr6));
	if (ret < 0) {
		return ret;
	}

	ret = send_udp_data(&conf.ipv6);
	if (ret < 0) {
		return ret;
	}

	return ret;
}

int process_udp(void)
{
	int ret = 0;

	ret = process_udp_proto(&conf.ipv6);
	if (ret < 0) {
		return ret;
	}

	return ret;
}

void stop_udp(void)
{
	k_delayed_work_cancel(&conf.ipv6.udp.recv);
	k_delayed_work_cancel(&conf.ipv6.udp.transmit);

	if (conf.ipv6.udp.sock > 0) {
		(void)close(conf.ipv6.udp.sock);
	}
}
