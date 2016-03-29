#include <event2/dns.h>
#include <event2/util.h>
#include <event2/event.h>

#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "tmate.h"

#define TMATE_DNS_RETRY_TIMEOUT 2
#define TMATE_RECONNECT_RETRY_TIMEOUT 2

struct tmate_session tmate_session;

static void lookup_and_connect(void);

static void on_dns_retry(__unused evutil_socket_t fd, __unused short what,
			 __unused void *arg)
{
	lookup_and_connect();
}

static void dns_cb(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
	struct evutil_addrinfo *ai;
	struct timeval tv;
	const char *host = ptr;

	if (errcode) {
		tmate_status_message("%s lookup failure. Retrying in %d seconds (%s)",
				     host, TMATE_DNS_RETRY_TIMEOUT,
				     evutil_gai_strerror(errcode));

		tv.tv_sec = TMATE_DNS_RETRY_TIMEOUT;
		tv.tv_usec = 0;

		evtimer_assign(&tmate_session.ev_dns_retry, tmate_session.ev_base,
			       on_dns_retry, NULL);
		evtimer_add(&tmate_session.ev_dns_retry, &tv);

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
	 * evdns_base_free(tmate_session.ev_dnsbase, 0);
	 * tmate_session.ev_dnsbase = NULL;
	 */
}

static void lookup_and_connect(void)
{
	struct evutil_addrinfo hints;
	const char *tmate_server_host;

	if (!tmate_session.ev_dnsbase)
		tmate_session.ev_dnsbase = evdns_base_new(tmate_session.ev_base, 1);
	if (!tmate_session.ev_dnsbase)
		tmate_fatal("Cannot initialize the DNS lookup service");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	tmate_server_host = options_get_string(global_options,
					       "tmate-server-host");
	tmate_info("Looking up %s...", tmate_server_host);
	(void)evdns_getaddrinfo(tmate_session.ev_dnsbase, tmate_server_host, NULL,
				&hints, dns_cb, (void *)tmate_server_host);
}

static void __tmate_session_init(struct tmate_session *session,
				 struct event_base *base)
{
	memset(session, 0, sizeof(*session));

	session->ev_base = base;

	/*
	 * Early initialization of encoder because we need to parse
	 * config files to get the server configs, but while we are parsing
	 * config files, we need to buffer bind commands and all for the
	 * slave.
	 * Decoder is setup later.
	 */
	tmate_encoder_init(&session->encoder, NULL, &tmate_session);

	session->min_sx = -1;
	session->min_sy = -1;

	TAILQ_INIT(&session->clients);
}

void tmate_session_init(struct event_base *base)
{
	__tmate_session_init(&tmate_session, base);
	tmate_write_header();
}

void tmate_session_start(void)
{
	/*
	 * We split init and start because:
	 * - We need to process the tmux config file during the connection as
	 *   we are setting up the tmate identity.
	 * - While we are parsing the config file, we need to be able to
	 *   serialize it, and so we need a worker encoder.
	 */
	lookup_and_connect();
}

static void on_reconnect_retry(__unused evutil_socket_t fd, __unused short what, void *arg)
{
	struct tmate_session *session = arg;

	if (session->last_server_ip) {
		/*
		 * We have a previous server ip. Let's try that again first,
		 * but then connect to any server if it fails again.
		 */
		(void)tmate_ssh_client_alloc(&tmate_session, session->last_server_ip);
		free(session->last_server_ip);
		session->last_server_ip = NULL;
	} else {
		lookup_and_connect();
	}
}

void tmate_reconnect_session(struct tmate_session *session, const char *message)
{
	/*
	 * We no longer have an SSH connection. Time to reconnect.
	 * We'll reuse some of the session information if we can,
	 * and we'll try to reconnect to the same server if possible,
	 * to avoid an SSH connection string change.
	 */
	struct timeval tv = { .tv_sec = TMATE_RECONNECT_RETRY_TIMEOUT, .tv_usec = 0 };

	evtimer_assign(&session->ev_connection_retry, session->ev_base,
		       on_reconnect_retry, session);
	evtimer_add(&session->ev_connection_retry, &tv);

	if (message)
		tmate_status_message("Reconnecting... (%s)", message);
	else
		tmate_status_message("Reconnecting...");

	/*
	 * This says that we'll need to send a snapshot of the current state.
	 * Until we have persisted logs...
	 */
	session->reconnected = true;
}
