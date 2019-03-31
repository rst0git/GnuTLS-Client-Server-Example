#include "common.h"

int tcp_client_connect(const char *address, int port)
{
	int fd;
	int ret;
	struct sockaddr_in serv_addr;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket()");
		return -1;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	ret = inet_pton(AF_INET, address, &serv_addr.sin_addr);
	if (ret != 1) {
		perror("inet_pton()");
		exit(-1);
	}

	ret = connect(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if (ret < 0) {
		perror("connect()");
		exit(-1);
	}

	return fd;
}

int main(int argc, char *argv[])
{
	int fd;
	int ret;
	char buf[100];

	gnutls_session_t session;
	gnutls_psk_client_credentials_t cred;
	gnutls_datum_t key;

	ret = gnutls_init(&session, GNUTLS_CLIENT);
	if (ret != GNUTLS_E_SUCCESS)
		fail("gnutls_init()", ret);

	ret = gnutls_psk_allocate_client_credentials(&cred);
	if (ret != 0)
		fail("gnutls_psk_allocate_client_credentials()", ret);

	key.size = strlen(KEY);
	key.data = malloc(key.size);
	memcpy(key.data, KEY, key.size);
	ret = gnutls_psk_set_client_credentials(cred, USR, &key, GNUTLS_PSK_KEY_RAW);

	memset(key.data, 0, key.size);
	free(key.data);
	key.data = NULL;
	key.size = 0;

	if (ret != 0)
		fail("gnutls_psk_set_client_credentials()", ret);

	ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);
	if (ret != 0)
		fail("gnutls_credentials_set()", ret);

	ret = tls_set_priority(&session);
	if (ret)
		fail("failed to set priority", ret);

	fd = tcp_client_connect(ADDRESS, PORT);

	int *connfdPtr = malloc(sizeof(int));
	*connfdPtr = fd;
	gnutls_transport_set_ptr(session, connfdPtr);

	gnutls_transport_set_push_function(session, _tls_data_push_cb);
	gnutls_transport_set_pull_function(session, _tls_data_pull_cb);

	do {
		ret = gnutls_handshake(session);
	} while (ret != 0 && !gnutls_error_is_fatal(ret));

	if (gnutls_error_is_fatal(ret))
		fail("Fatal error during handshake", ret);

	ret = gnutls_record_recv(session, buf, sizeof(buf));
	while (ret != 0) {
		if (ret == GNUTLS_E_REHANDSHAKE) {
			fail("re-handshake not supported", ret);
		} else if (gnutls_error_is_fatal(ret)) {
			fail("Fatal error during read", ret);
		} else if (ret > 0) {
			fwrite(buf, 1, ret, stdout);
			fflush(stdout);
		}
		ret = gnutls_record_recv(session, buf, sizeof(buf));
	}

	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	gnutls_deinit(session);
	close(fd);
	gnutls_psk_free_client_credentials(cred);
	gnutls_global_deinit();

	printf("All done!\n");
	return 0;
}
