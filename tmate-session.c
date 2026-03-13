#include <event2/dns.h>
#include <event2/util.h>
#include <event2/event.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include <errno.h>
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
			 void *arg)
{
	struct tmate_session *session = arg;

	assert(session->ev_dns_retry);
	event_free(session->ev_dns_retry);
	session->ev_dns_retry = NULL;

	lookup_and_connect();
}

static void dns_cb(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
	struct evutil_addrinfo *ai;
	const char *host = ptr;

	evdns_base_free(tmate_session.ev_dnsbase, 0);
	tmate_session.ev_dnsbase = NULL;

	if (errcode) {
		struct tmate_session *session = &tmate_session;

		if (session->ev_dns_retry)
			return;

		struct timeval tv = { .tv_sec = TMATE_DNS_RETRY_TIMEOUT, .tv_usec = 0 };

		session->ev_dns_retry = evtimer_new(session->ev_base, on_dns_retry, session);
		if (!session->ev_dns_retry)
			tmate_fatal("out of memory");
		evtimer_add(session->ev_dns_retry, &tv);

		tmate_status_message("%s lookup failure. Retrying in %d seconds (%s)",
				     host, TMATE_DNS_RETRY_TIMEOUT,
				     evutil_gai_strerror(errcode));
		return;
	}

	tmate_status_message("Connecting to %s...", host);

	int i, num_clients = 0;
	for (ai = addr; ai; ai = ai->ai_next)
		num_clients++;

	struct tmate_ssh_client *ssh_clients[num_clients];

	for (ai = addr, i = 0; ai; ai = ai->ai_next, i++) {
		char buf[128];
		const char *ip = NULL;
		if (ai->ai_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
			ip = evutil_inet_ntop(AF_INET, &sin->sin_addr, buf, 128);
		} else if (ai->ai_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->ai_addr;
			ip = evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, buf, 128);
		}

		ssh_clients[i] = tmate_ssh_client_alloc(&tmate_session, ip);
	}

	for (i = 0; i < num_clients; i++)
		connect_ssh_client(ssh_clients[i]);

	evutil_freeaddrinfo(addr);
}

static void lookup_and_connect(void)
{
	struct evutil_addrinfo hints;
	const char *tmate_server_host;

	assert(!tmate_session.ev_dnsbase);
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
	tmate_debug("Looking up %s...", tmate_server_host);
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

static void send_authorized_keys(void)
{
	char *path;
	path = options_get_string(global_options, "tmate-authorized-keys");
	if (strlen(path) == 0)
		return;

	path = xstrdup(path);
	tmate_info("Using %s for access control", path);

	FILE *f;
	char *line;
	size_t len;

	if (path[0] == '~' && path[1] == '/') {
		const char *home = find_home();
		if (home) {
			char *new_path;
			xasprintf(&new_path, "%s%s", home, &path[1]);
			free(path);
			path = new_path;
		}
	}

	if ((f = fopen(path, "r")) == NULL) {
		cfg_add_cause("%s: %s", path, strerror(errno));
		free(path);
		return;
	}

	while ((line = fparseln(f, &len, NULL, NULL, 0)) != NULL) {
		if (len == 0)
			continue;
		tmate_set_val("authorized_keys", line);
		free(line);
	}

	if (ferror(f))
		cfg_add_cause("%s: %s", path, strerror(errno));

	fclose(f);
	free(path);
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
	if (tmate_foreground) {
		tmate_set_val("foreground", "true");
	} else {
		cfg_add_cause("%s", "Tip: if you wish to use tmate only for remote access, run: tmate -F");
		cfg_add_cause("%s", "To see the following messages again, run in a tmate session: tmate show-messages");
		cfg_add_cause("%s", "Press <q> or <ctrl-c> to continue");
		cfg_add_cause("%s", "---------------------------------------------------------------------");
	}

	send_authorized_keys();
	tmate_write_uname();
	tmate_write_ready();
	lookup_and_connect();
}

static void on_reconnect_retry(__unused evutil_socket_t fd, __unused short what, void *arg)
{
	struct tmate_session *session = arg;

	assert(session->ev_connection_retry);
	event_free(session->ev_connection_retry);
	session->ev_connection_retry = NULL;

	if (session->last_server_ip) {
		/*
		 * We have a previous server ip. Let's try that again first,
		 * but then connect to any server if it fails again.
		 */
		struct tmate_ssh_client *c = tmate_ssh_client_alloc(session,
						session->last_server_ip);
		connect_ssh_client(c);
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

	if (session->ev_connection_retry)
		return;

	session->ev_connection_retry = evtimer_new(session->ev_base, on_reconnect_retry, session);
	if (!session->ev_connection_retry)
		tmate_fatal("out of memory");
	evtimer_add(session->ev_connection_retry, &tv);

	if (message && !tmate_foreground)
		tmate_status_message("Reconnecting... (%s)", message);
	else
		tmate_status_message("Reconnecting...");

	/*
	 * This says that we'll need to send a snapshot of the current state.
	 */
	session->reconnected = true;
}
