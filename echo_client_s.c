/* echo-client.c - Networking echo client */

/*
 * Copyright (c) 2017 Intel Corporation.
 * Copyright (c) 2018 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * The echo-client application is acting as a client that is run in Zephyr OS,
 * and echo-server is run in the host acting as a server. The client will send
 * either unicast or multicast packets to the server which will reply the packet
 * back to the originator.
 *
 * In this sample application we create four threads that start to send data.
 * This might not be what you want to do in your app so caveat emptor.
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(net_echo_client_sample, LOG_LEVEL_DBG);

#include <zephyr.h>
#include <errno.h>
#include <stdio.h>

#include <net/socket.h>
#include <net/tls_credentials.h>

#include "common.h"
#include "ca_certificate.h"

#define APP_BANNER "Run echo client"

#define INVALID_SOCK (-1)

/* Generated by http://www.lipsum.com/
 * 2 paragraphs, 179 words, 1160 bytes of Lorem Ipsum
 */
const char lorem_ipsum[] =
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque "
	"sodales lorem lorem, sed congue enim vehicula a. Sed finibus diam sed "
	"odio ultrices pharetra. Nullam dictum arcu ultricies turpis congue, "
	"vel venenatis turpis venenatis. Nam tempus arcu eros, ac congue libero "
	"tristique congue. Proin velit lectus, euismod sit amet quam in, "
	"maximus condimentum urna. Cras vel erat luctus, mattis orci ut, varius "
	"urna. Nam eu lobortis velit."
	"\n"
	"Nullam sit amet diam vel odio sodales cursus vehicula eu arcu. Proin "
	"fringilla, enim nec consectetur mollis, lorem orci interdum nisi, "
	"vitae suscipit nisi mauris eu mi. Proin diam enim, mollis ac rhoncus "
	"vitae, placerat et eros. Suspendisse convallis, ipsum nec rhoncus "
	"aliquam, ex augue ultrices nisl, id aliquet mi diam quis ante. "
	"Pellentesque venenatis ornare ultrices. Quisque et porttitor lectus. "
	"Ut venenatis nunc et urna imperdiet porttitor non laoreet massa. Donec "
	"eleifend eros in mi sagittis egestas. Sed et mi nunc. Nunc vulputate, "
	"mauris non ullamcorper viverra, lorem nulla vulputate diam, et congue "
	"dui velit non erat. Duis interdum leo et ipsum tempor consequat. In "
	"faucibus enim quis purus vulputate nullam."
	"\n";

const int ipsum_len = sizeof(lorem_ipsum) - 1;

struct configs conf = {
	.ipv4 = {
		.proto = "IPv4",
		.udp.sock = INVALID_SOCK,
		.tcp.sock = INVALID_SOCK,
	},
	.ipv6 = {
		.proto = "IPv6",
		.udp.sock = INVALID_SOCK,
		.tcp.sock = INVALID_SOCK,
	},
};

struct pollfd fds[4];
int nfds;

static void prepare_fds(void)
{
	if (conf.ipv4.udp.sock >= 0)
	{
		fds[nfds].fd = conf.ipv4.udp.sock;
		fds[nfds].events = POLLIN;
		nfds++;
	}

	if (conf.ipv4.tcp.sock >= 0)
	{
		fds[nfds].fd = conf.ipv4.tcp.sock;
		fds[nfds].events = POLLIN;
		nfds++;
	}

	if (conf.ipv6.udp.sock >= 0)
	{
		fds[nfds].fd = conf.ipv6.udp.sock;
		fds[nfds].events = POLLIN;
		nfds++;
	}

	if (conf.ipv6.tcp.sock >= 0)
	{
		fds[nfds].fd = conf.ipv6.tcp.sock;
		fds[nfds].events = POLLIN;
		nfds++;
	}
}

static void wait(void)
{
	/* Wait for event on any socket used. Once event occurs,
	 * we'll check them all.
	 */
	if (poll(fds, nfds, K_FOREVER) < 0)
	{
		printf("Error in poll:%d", errno);
	}
}

static void init_app(void)
{
	LOG_INF(APP_BANNER);

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	int err = tls_credential_add(CA_CERTIFICATE_TAG,
								 TLS_CREDENTIAL_CA_CERTIFICATE,
								 ca_certificate,
								 sizeof(ca_certificate));
	if (err < 0)
	{
		printf("Failed to register public certificate: %d", err);
	}
#endif

	init_vlan();
}

void echo_client_s(void)
{
	int ret;

	init_app();

	ret = start_udp();
	if (ret < 0)
	{
		goto quit;
	}

	prepare_fds();

	while (true)
	{
		ret = process_udp();
		if (ret < 0)
		{
			goto quit;
		}

		wait();
	}

quit:
	LOG_INF("Stopping...");

	if (IS_ENABLED(CONFIG_NET_UDP))
	{
		stop_udp();
	}
}
