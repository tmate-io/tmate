#include <event2/dns.h>
#include <event2/util.h>
#include <event2/event.h>

#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "tmate.h"

#define TMATE_DNS_RETRY_TIMEOUT 10

struct tmate_session tmate_session;

static struct evdns_base *ev_dnsbase;
static struct event ev_dns_retry;
static void lookup_and_connect(void);

static void on_dns_retry(evutil_socket_t fd, short what, void *arg)
{
	lookup_and_connect();
}

static void dns_cb(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
	struct tmate_ssh_client *client;
	struct evutil_addrinfo *ai;
	struct timeval tv;
	const char *host = ptr;

	if (errcode) {
		tmate_status_message("%s lookup failure. Retrying in %d seconds (%s)",
				     host, TMATE_DNS_RETRY_TIMEOUT,
				     evutil_gai_strerror(errcode));

		tv.tv_sec = TMATE_DNS_RETRY_TIMEOUT;
		tv.tv_usec = 0;

		evtimer_assign(&ev_dns_retry, ev_base, on_dns_retry, NULL);
		evtimer_add(&ev_dns_retry, &tv);

		return;
	}

	tmate_status_message("Connecting to %s...", host);

	for (ai = addr; ai; ai = ai->ai_next) {
		char buf[128];
		const char *ip = NULL;
		if (ai->ai_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
			ip = evutil_inet_ntop(AF_INET, &sin->sin_addr, buf, 128);
		} else if (ai->ai_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
			ip = evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, buf, 128);
		}

		tmate_debug("Trying server %s", ip);

		/*
		 * Note: We don't deal with the client list. Clients manage it
		 * and free client structs when necessary.
		 */
		(void)tmate_ssh_client_alloc(&tmate_session, ip);
	}

	evutil_freeaddrinfo(addr);

	/*
	 * XXX For some reason, freeing the DNS resolver makes MacOSX flip out...
	 * not sure what's going on...
	 * evdns_base_free(ev_dnsbase, 0);
	 * ev_dnsbase = NULL;
	 */
}

static void lookup_and_connect(void)
{
	struct evutil_addrinfo hints;
	const char *tmate_server_host;

	if (!ev_dnsbase)
		ev_dnsbase = evdns_base_new(ev_base, 1);
	if (!ev_dnsbase)
		tmate_fatal("Cannot initialize the DNS lookup service");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = 0;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	tmate_server_host = options_get_string(&global_s_options,
					       "tmate-server-host");
	tmate_info("Looking up %s...", tmate_server_host);
	(void)evdns_getaddrinfo(ev_dnsbase, tmate_server_host, NULL,
				&hints, dns_cb, tmate_server_host);
}

static void ssh_log_function(int priority, const char *function,
			     const char *buffer, void *userdata)
{
	tmate_debug("[%d] [%s] %s", priority, function, buffer);
}

void tmate_session_init(void)
{
	ssh_set_log_callback(ssh_log_function);
	tmate_catch_sigsegv();

	tmate_encoder_init(&tmate_session.encoder);
	tmate_decoder_init(&tmate_session.decoder);

	TAILQ_INIT(&tmate_session.clients);

	tmate_session.need_passphrase = 0;
	tmate_session.passphrase = NULL;

	/* The header will be written as soon as the first client connects */
	tmate_write_header();
}

void tmate_session_start(void)
{
	/* We split init and start because:
	 * - We need to process the tmux config file during the connection as
	 *   we are setting up the tmate identity.
	 * - While we are parsing the config file, we need to be able to
	 *   serialize it, and so we need a worker encoder.
	 */
	lookup_and_connect();
}
