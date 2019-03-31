#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <assert.h>

#define KEYFILE "key.pem"
#define CERTFILE "cert.pem"
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"
#define CRLFILE "crl.pem"

#define CHECK(x) assert((x)>=0)
#define LOOP_CHECK(rval, cmd) \
	do { \
		rval = cmd; \
	} while(rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)

#define MAX_BUF 1024
#define PORT 5556

int setup_tcp_server()
{
	int listen_sd;
	struct sockaddr_in sa_serv;
	int optval = 1;

	listen_sd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(PORT); /* Server Port number */

	setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof(int));
	bind(listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv));
	listen(listen_sd, 1024);

	printf("Server ready. Listening to port '%d'.\n\n", PORT);
	return listen_sd;
}

int main(void)
{
	int listen_sd;
	struct sockaddr_in sa_cli;

	int sd, ret;
	socklen_t client_len;
	char topbuf[512];
	char buffer[MAX_BUF + 1];

	gnutls_certificate_credentials_t x509_cred;
	gnutls_priority_t priority_cache;
	gnutls_session_t session;

	CHECK(gnutls_certificate_allocate_credentials(&x509_cred));
	CHECK(gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM));
	CHECK(gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE, GNUTLS_X509_FMT_PEM));
	CHECK(gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM));
	CHECK(gnutls_priority_init(&priority_cache, NULL, NULL));

	/* Instead of the default options as shown above one could specify
	 * additional options such as server precedence in ciphersuite selection
	 * as follows:
	 * gnutls_priority_init2(&priority_cache,
	 *			 "%SERVER_PRECEDENCE",
	 *			 NULL, GNUTLS_PRIORITY_INIT_DEF_APPEND);
	 */

	listen_sd = setup_tcp_server();

	client_len = sizeof(sa_cli);
	for (;;) {
		CHECK(gnutls_init(&session, GNUTLS_SERVER));
		CHECK(gnutls_priority_set(session, priority_cache));
		CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred));

		gnutls_certificate_set_x509_trust_file(x509_cred, "ca_cert.pem", GNUTLS_X509_FMT_PEM);
		gnutls_session_set_verify_cert(session, NULL, 0);

		gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
		gnutls_certificate_send_x509_rdn_sequence(session, 1);
		gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

		sd = accept(listen_sd, (struct sockaddr *) &sa_cli, &client_len);

		printf("- connection from %s, port %d\n",
				inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf,
					sizeof(topbuf)), ntohs(sa_cli.sin_port));

		gnutls_transport_set_int(session, sd);

		LOOP_CHECK(ret, gnutls_handshake(session));
		if (ret < 0) {
			close(sd);
			gnutls_deinit(session);
			fprintf(stderr,
					"*** Handshake has failed (%s)\n\n",
					gnutls_strerror(ret));
			continue;
		}
		printf("- Handshake was completed\n");

		/* see the Getting peer's information example */
		/* print_info(session); */

		for (;;) {
			LOOP_CHECK(ret, gnutls_record_recv(session, buffer, MAX_BUF));

			if (ret == 0) {
				printf
					("\n- Peer has closed the GnuTLS connection\n");
				break;
			} else if (ret < 0
					&& gnutls_error_is_fatal(ret) == 0) {
				fprintf(stderr, "*** Warning: %s\n",
						gnutls_strerror(ret));
			} else if (ret < 0) {
				fprintf(stderr, "\n*** Received corrupted "
						"data(%d). Closing the connection.\n\n",
						ret);
				break;
			} else if (ret > 0) {
				/* echo data back to the client
				*/
				CHECK(gnutls_record_send(session, buffer, ret));
			}
		}
		printf("\n");
		/* do not wait for the peer to close the connection.
		*/
		LOOP_CHECK(ret, gnutls_bye(session, GNUTLS_SHUT_WR));

		close(sd);
		gnutls_deinit(session);

	}
	close(listen_sd);

	gnutls_certificate_free_credentials(x509_cred);
	gnutls_priority_deinit(priority_cache);

	gnutls_global_deinit();

	return 0;

}
