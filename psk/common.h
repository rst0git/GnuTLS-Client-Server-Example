#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <gnutls/gnutls.h>

#define LOG_LEVEL 0

#define USR "USER"
#define KEY "SECRET PRE-SHARED KEY"

#define ADDRESS "127.0.0.1"
#define PORT 1234

gnutls_priority_t priority_cache;

int tls_set_priority(gnutls_session_t *session)
{
	int ret;

	ret = gnutls_priority_init(&priority_cache, "NORMAL:+PSK:+ECDHE-PSK:+DHE-PSK", NULL);
	if (!ret)
		ret = gnutls_priority_set(*session, priority_cache);

	return ret;
}

void fail(const char *msg, int ret)
{
	printf("ERROR: %s: %s\n", msg, gnutls_strerror(ret));
	exit(1);
}

ssize_t _tls_data_push_cb(gnutls_transport_ptr_t ptr, const void* data, size_t len)
{
	int sockfd = *(int *)(ptr);
	return send(sockfd, data, len, 0);
}

ssize_t _tls_data_pull_cb(gnutls_transport_ptr_t ptr, void* data, size_t maxlen)
{
	int sockfd = *(int *)(ptr);
	return recv(sockfd, data, maxlen, 0);
}
