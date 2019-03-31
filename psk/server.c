#include "common.h"

int psk_creds(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
	key->size = strlen(KEY);
	key->data = gnutls_malloc(key->size);
	if (key->data == NULL) {
		return -1;
	}
	memcpy(key->data, KEY, key->size);
	return 0;
}

int accept_one_connection(int port)
{
	int ret;
	struct sockaddr_in serv_addr;
	int listenfd, connfd;
	int one = 1;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd < 0) {
		perror("socket() failed.\n");
		exit(-1);
	}

	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)) == -1){
		perror("setsockopt() failed");
		exit(-1);
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);

	ret = bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if (ret < 0) {
		perror("bind() failed");
		exit(-1);
	}

	ret = listen(listenfd, 10);
	if (ret < 0) {
		perror("listen() failed.\n");
		exit(-1);
	}

	printf("Waiting for a connection...\n");

	connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
	if (connfd < 0) {
		perror("accept() failed.\n");
		exit(-1);
	}

	printf("A client connected!\n");
	close(listenfd);

	return connfd;
}

void error_exit(const char *msg)
{
	printf("ERROR: %s", msg);
	exit(1);
}

int main(int argc, char **argv)
{
	int fd;
	int ret;

	gnutls_session_t session;
	gnutls_psk_server_credentials_t cred;

	gnutls_global_init();

	ret = gnutls_init(&session, GNUTLS_SERVER);
	if (ret != GNUTLS_E_SUCCESS)
		fail("gnutls_init()", ret);

	ret = gnutls_psk_allocate_server_credentials(&cred);
	if (ret != 0)
		fail("gnutls_psk_allocate_server_credentials() failed", ret);

	gnutls_psk_set_server_credentials_function(cred, psk_creds);

	ret = gnutls_credentials_set(session, GNUTLS_CRD_PSK, cred);
	if (ret != 0)
		fail("gnutls_credentials_set()", ret);

	ret = tls_set_priority(&session);
	if (ret)
		fail("failed to set priority", ret);

	fd = accept_one_connection(PORT);

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

	char buf[100];
	for (int i = 1; i <= 10; i++) {
		sprintf(buf, "Server %d\r\n", i);
		do {
			ret = gnutls_record_send(session, buf, strlen(buf));
		} while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);

		if (gnutls_error_is_fatal(ret))
			fail("Fatal error during send", ret);
	}

	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	gnutls_deinit(session);
	close(fd);
	gnutls_psk_free_server_credentials(cred);
	gnutls_priority_deinit(priority_cache);
	gnutls_global_deinit();

	printf("All done!\n");
	return 0;
}
