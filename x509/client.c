#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/* A very basic TLS client, with X.509 authentication and server certificate
 * verification. Note that error recovery is minimal for simplicity.
 */

#define CHECK(x) assert((x)>=0)
#define LOOP_CHECK(rval, cmd) \
	do { \
		rval = cmd; \
	} while(rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED); \
	assert(rval >= 0)

#define MAX_BUF 1024
#define MSG "GET / HTTP/1.0\r\n\r\n"

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

int main(void)
{
	int ret, sd, ii;
	int type;
	unsigned status;
	char buffer[MAX_BUF + 1], *desc;

	gnutls_datum_t out;
	gnutls_session_t session;
	gnutls_certificate_credentials_t x509_cred;

	CHECK(gnutls_certificate_allocate_credentials(&x509_cred));

	CHECK(gnutls_certificate_set_x509_system_trust(x509_cred));

	gnutls_certificate_set_x509_key_file(x509_cred, "cert.pem", "key.pem", GNUTLS_X509_FMT_PEM);

	CHECK(gnutls_init(&session, GNUTLS_CLIENT));

	CHECK(gnutls_set_default_priority(session));

	CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred));
	gnutls_certificate_set_x509_trust_file(x509_cred, "ca_cert.pem", GNUTLS_X509_FMT_PEM);
	gnutls_session_set_verify_cert(session, NULL, 0);

	sd = tcp_client_connect("127.0.0.1", 5556);

	gnutls_transport_set_int(session, sd);
	gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	do {
		ret = gnutls_handshake(session);
	}
	while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	if (ret < 0) {
		if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
			/* check certificate verification status */
			type = gnutls_certificate_type_get(session);
			status = gnutls_session_get_verify_cert_status(session);
			CHECK(gnutls_certificate_verification_status_print(status, type, &out, 0));
			printf("cert verify output:\n%s\n", out.data);
			gnutls_free(out.data);
		}
		fprintf(stderr, "*** Handshake failed: %s\n", gnutls_strerror(ret));
		goto end;
	} else {
		desc = gnutls_session_get_desc(session);
		printf("- Session info: %s\n", desc);
		gnutls_free(desc);
	}

	/* send data */
	LOOP_CHECK(ret, gnutls_record_send(session, MSG, strlen(MSG)));
	LOOP_CHECK(ret, gnutls_record_recv(session, buffer, MAX_BUF));
	if (ret == 0) {
		printf("- Peer has closed the TLS connection\n");
		goto end;
	} else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
		fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
	} else if (ret < 0) {
		fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
		goto end;
	}

	if (ret > 0) {
		printf("- Received %d bytes: ", ret);
		for (ii = 0; ii < ret; ii++) {
			fputc(buffer[ii], stdout);
		}
		fputs("\n", stdout);
	}
	CHECK(gnutls_bye(session, GNUTLS_SHUT_RDWR));
end:
	close(sd);
	gnutls_deinit(session);
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_global_deinit();

	return 0;
}
