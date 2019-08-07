#include <errno.h>
#include <zephyr.h>
#include "py/nlr.h"
#include "py/obj.h"
#include "py/runtime.h"
#include "py/binary.h"

#include <stdio.h>
#include <string.h>

#include <net/socket.h>
#include <net/net_mgmt.h>
#include <net/net_ip.h>
#include <net/udp.h>
#include <net/coap.h>
#include <net/tls_credentials.h>

#include "ca_certificate.h"
#include "degu_utils.h"

#define RAISE_ERRNO(x) { int _err = x; if (_err < 0) mp_raise_OSError(-_err); }
#define RAISE_SYSCALL_ERRNO(x) { if ((int)(x) == -1) mp_raise_OSError(errno); }
#define CONFIG_NET_CONFIG_PEER_IPV6_ADDR "fdf9:3dba:e602::1"
#define P_PORT 8194
#define TLS_PEER_HOSTNAME "localhost"

typedef struct _mp_obj_coap_t {
	mp_obj_base_t base;
	int sock;
} mp_obj_coap_t;

u16_t sport = 0;

STATIC const mp_obj_type_t coap_type;

STATIC void parse_inet_addr(mp_obj_coap_t *coap, mp_obj_t addr_in, struct sockaddr *sockaddr) {
    // We employ the fact that port and address offsets are the same for IPv4 & IPv6
	struct sockaddr_in6 *sockaddr_in = (struct sockaddr_in6 *)sockaddr;

	mp_obj_t *addr_items;
    mp_obj_get_array_fixed_n(addr_in, 2, &addr_items);
	sockaddr_in->sin6_family = net_context_get_family((void *)coap->sock);
	//const char *objstr = mp_obj_str_get_str(addr_items[0]);
	// sockaddr_in->sin_family = 43716;
	//int itest = net_addr_pton(sockaddr_in->sin_family, objstr, &sockaddr_in->sin_addr);
	int itest = net_addr_pton(sockaddr_in->sin6_family, "fdf9:3dba:e602::1", &sockaddr_in->sin6_addr);
    RAISE_ERRNO(itest);
	sockaddr_in->sin6_port = htons(mp_obj_get_int(addr_items[1]));
}

STATIC mp_obj_t coap_client_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {

	struct sockaddr *sockaddr;
	int ret;
	struct in_addr addr;

/*
	addr6.sin6_family = AF_INET6;							// プロトコル設定
	addr6.sin6_port = htons(P_PORT);						// ポート番号設定
	inet_pton(AF_INET6, CONFIG_NET_CONFIG_PEER_IPV6_ADDR,	// IPアドレス設定
			  &addr6.sin6_addr);
	sockaddr = (struct sockaddr *)&addr6; */

	mp_obj_coap_t *client = m_new_obj_with_finaliser(mp_obj_coap_t);
	parse_inet_addr(client, args[0], sockaddr);
	client->base.type = (mp_obj_t)&coap_type;

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	int err = tls_credential_add(CA_CERTIFICATE_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, ca_certificate, sizeof(ca_certificate));
	if (err < 0)
	{
		printf("Failed to register public certificate: %d\n", err);
	}
#endif

	client->sock = socket(sockaddr->sa_family, SOCK_DGRAM, IPPROTO_DTLS_1_2);
	if (client->sock < 0)
	{
		perror("socket");
		return 1;
	}

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	sec_tag_t sec_tag_list[] = {
		CA_CERTIFICATE_TAG,
	};

	ret = setsockopt(client->sock, SOL_TLS, TLS_SEC_TAG_LIST,
					 sec_tag_list, sizeof(sec_tag_list));
	if (ret < 0)
	{
		printf("Failed to set TLS_SEC_TAG_LIST option : %d\n", errno);
		ret = -errno;
	}
	/*
	// char hostname[100];
	char hostname[] = "armadillo";
	// gethostname(hostname, sizeof(hostname));
	// hostname[99] = 0;
	printf("HOSTNAME=%s\n",&hostname);
//	ret = setsockopt(client->sock, SOL_TLS, TLS_HOSTNAME,
//					 hostname, sizeof(hostname));
	ret = setsockopt(client->sock, SOL_TLS, TLS_HOSTNAME,
					 TLS_PEER_HOSTNAME, sizeof(TLS_PEER_HOSTNAME)); // 今エラーが出るのはここ
	if (ret < 0)
	{
		printf("Failed to set TLS_HOSTNAME option : %d\n", errno);
		ret = -errno;
	} */

#endif
	printf("connect\n");
	ret = connect(client->sock, &sockaddr, sizeof(sockaddr));
	RAISE_SYSCALL_ERRNO(ret);
	printf("send\n");
	ret = send(client->sock, &sockaddr, strlen(&sockaddr), 0);
	printf("send end\n");
	// ret = send(client->sock, &sockaddr, sizeof(sockaddr), 0);
	RAISE_SYSCALL_ERRNO(ret);

	return MP_OBJ_FROM_PTR(client);
}

STATIC mp_obj_t coap_dump(void) {
	printf("dump\n");
	return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(coap_dump_obj, coap_dump);

#define MAX_COAP_MSG_LEN 256
#define COAP_TYPE_CON 0 //Confirmable
#define COAP_TYPE_NCON 1 //non-Confirmable
#define COAP_TYPE_ACK 2 //Acknowledgement
#define COAP_TYPE_RST 3 //Reset

STATIC mp_obj_t coap_request_post(mp_obj_t self_in, mp_obj_t path, mp_obj_t payload) {
	mp_obj_coap_t *client = self_in;
	int r;
	struct coap_packet request;
	u8_t *data;

	data = (u8_t *)m_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		printf("can't malloc\n");
		RAISE_SYSCALL_ERRNO(-1);
	}

	r = coap_packet_init(&request, data, MAX_COAP_MSG_LEN,
			     1, COAP_TYPE_CON, 8, coap_next_token(),
			     COAP_METHOD_POST, coap_next_id());
	if (r < 0) {
		printf("Unable to init CoAP packet\n");
		goto end;
	}

	r = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
				      (u8_t *)mp_obj_str_get_str(path),
				      strlen(mp_obj_str_get_str(path)));
	if (r < 0) {
		printf("Unable to add option to request\n");
		goto end;
	}

	r = coap_packet_append_payload_marker(&request);
	if (r < 0) {
		printf("Unable to append payload maker\n");
		goto end;
	}
	r = coap_packet_append_payload(&request, (u8_t *)mp_obj_str_get_str(payload),
				       strlen(mp_obj_str_get_str(payload)));
	if (r < 0) {
		printf("Unable to append payload\n");
		goto end;
	}

	r = send(client->sock, request.data, request.offset, 0);
	if (r < 0) {
		printf("Unable to send packet\n");
		goto end;
	}

end:
	m_free(data);

	return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(coap_request_post_obj, coap_request_post);

STATIC mp_obj_t coap_request_get(mp_obj_t self_in, mp_obj_t path) {
	mp_obj_coap_t *client = self_in;
	int r;
	int rcvd;
	struct coap_packet request;
	struct coap_packet reply;
	u8_t *data;
	const u8_t *payload;
	u16_t payload_len;

	data = (u8_t *)m_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		printf("can't malloc to send packet\n");
		RAISE_SYSCALL_ERRNO(-1);
	}

	r = coap_packet_init(&request, data, MAX_COAP_MSG_LEN,
			     1, COAP_TYPE_CON, 8, coap_next_token(),
			     COAP_METHOD_GET, coap_next_id());
	if (r < 0) {
		printf("Unable to init CoAP packet\n");
		goto err;
	}

	r = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
				      (u8_t *)mp_obj_str_get_str(path),
				      strlen(mp_obj_str_get_str(path)));
	if (r < 0) {
		printf("Unable to add option to request\n");
		goto err;
	}

	r = send(client->sock, request.data, request.offset, 0);
	if (r < 0) {
		printf("Unable to send CoAP packet\n");
		goto err;
	}

	rcvd = recv(client->sock, data, MAX_COAP_MSG_LEN, ZSOCK_MSG_DONTWAIT);
	if (rcvd <= 0) {
		printf("Unable to receive packet\n");
		goto err;
	}

	r = coap_packet_parse(&reply, data, rcvd, NULL, 0);
	if (r < 0) {
		printf("Unable to parse recieved packet\n");
		goto err;
	}

	payload = coap_packet_get_payload(&reply, &payload_len);

	m_free(data);
	return mp_obj_new_str(payload, payload_len);

err:
	m_free(data);
	return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(coap_request_get_obj, coap_request_get);

STATIC mp_obj_t coap_close(mp_obj_t self_in) {
	mp_obj_coap_t *self = self_in;
	close(self->sock);
	return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(coap_close_obj, coap_close);

STATIC mp_obj_t coap_eui64(void) {
	char eui64[17];
	get_eui64(eui64);
	eui64[16] = '\0';
	return mp_obj_new_str(eui64, strlen(eui64));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(coap_eui64_obj, coap_eui64);

STATIC mp_obj_t coap_gw_addr(void) {
	char gw_addr[NET_IPV6_ADDR_LEN];
	strcpy(gw_addr, get_gw_addr(64));

	if (gw_addr != NULL) {
		return mp_obj_new_str(gw_addr, strlen(gw_addr));
	}
	else {
		return mp_const_none;
	}
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(coap_gw_addr_obj, coap_gw_addr);

STATIC const mp_rom_map_elem_t coap_locals_dict_table[] = {
	{ MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&coap_close_obj) },
	{ MP_ROM_QSTR(MP_QSTR_close), MP_ROM_PTR(&coap_close_obj) },
	{ MP_ROM_QSTR(MP_QSTR_dump), MP_ROM_PTR(&coap_dump_obj) },
	{ MP_ROM_QSTR(MP_QSTR_request_post), MP_ROM_PTR(&coap_request_post_obj) },
	{ MP_ROM_QSTR(MP_QSTR_request_get), MP_ROM_PTR(&coap_request_get_obj) },
};

STATIC MP_DEFINE_CONST_DICT(coap_locals_dict, coap_locals_dict_table);

STATIC const mp_obj_type_t coap_type = {
    { &mp_type_type },
    .name = MP_QSTR_client,
    .make_new = coap_client_make_new,
    .locals_dict = (void*)&coap_locals_dict,
};

STATIC const mp_rom_map_elem_t zcoap_globals_table[] = {
	{MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_zcoap) },
	{MP_ROM_QSTR(MP_QSTR_client), MP_ROM_PTR(&coap_type) },
	{MP_ROM_QSTR(MP_QSTR_eui64), MP_ROM_PTR(&coap_eui64_obj) },
	{MP_ROM_QSTR(MP_QSTR_gw_addr), MP_ROM_PTR(&coap_gw_addr_obj) },
};

STATIC MP_DEFINE_CONST_DICT (mp_module_zcoap_globals, zcoap_globals_table);

const mp_obj_module_t mp_module_zcoap = {
	.base = { &mp_type_module },
	.globals = (mp_obj_dict_t*)&mp_module_zcoap_globals,
};
