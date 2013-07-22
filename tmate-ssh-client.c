#include <sys/socket.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <event.h>
#include <assert.h>

#include "tmate.h"

static void consume_channel(struct tmate_ssh_client *client);
static void flush_input_stream(struct tmate_ssh_client *client);
static void __flush_input_stream(evutil_socket_t fd, short what, void *arg);
static void __on_session_event(evutil_socket_t fd, short what, void *arg);
static void printflike2 disconnect_session(struct tmate_ssh_client *client,
					   const char *fmt, ...);
static void printflike2 reconnect_session(struct tmate_ssh_client *client,
					  const char *fmt, ...);

static void log_function(ssh_session session, int priority,
		  const char *message, void *userdata)
{
	struct tmate_ssh_client *client = userdata;
	tmate_debug("[%s] [%d] %s", client->server_ip, priority, message);
}

static void register_session_fd_event(struct tmate_ssh_client *client)
{
	if (!event_initialized(&client->ev_ssh)) {
		int flag = 1;
		setsockopt(ssh_get_fd(client->session), IPPROTO_TCP,
			   TCP_NODELAY, &flag, sizeof(flag));

		event_assign(&client->ev_ssh, ev_base, ssh_get_fd(client->session),
			     EV_READ | EV_PERSIST, __on_session_event, client);
		event_add(&client->ev_ssh, NULL);
	}
}

static void register_input_stream_event(struct tmate_ssh_client *client)
{
	struct tmate_encoder *encoder = &client->tmate_session->encoder;

	if (!event_initialized(&encoder->ev_readable)) {
		event_assign(&encoder->ev_readable, ev_base, -1,
			     EV_READ | EV_PERSIST, __flush_input_stream, client);
		event_add(&encoder->ev_readable, NULL);
		client->has_encoder = 1;
	}
}

static void consume_channel(struct tmate_ssh_client *client)
{
	struct tmate_decoder *decoder = &client->tmate_session->decoder;
	char *buf;
	ssize_t len;

	for (;;) {
		tmate_decoder_get_buffer(decoder, &buf, &len);
		len = ssh_channel_read_nonblocking(client->channel, buf, len, 0);
		if (len < 0) {
			reconnect_session(client, "Error reading from channel: %s",
					  ssh_get_error(client->session));
			break;
		}

		if (len == 0)
			break;

		tmate_decoder_commit(decoder, len);
	}
}

static void connection_complete(struct tmate_ssh_client *connected_client)
{
	struct tmate_session *session = connected_client->tmate_session;
	struct tmate_ssh_client *client, *tmp_client;

	TAILQ_FOREACH_SAFE(client, &session->clients, node, tmp_client) {
		if (client == connected_client)
			continue;

		assert(!client->has_encoder);
		tmate_ssh_client_free(client);
	}
}

static char *get_identity(void)
{
	char *identity;

	identity = options_get_string(&global_s_options, "tmate-identity");
	if (!strlen(identity))
		return NULL;

	if (strchr(identity, '/'))
		identity = xstrdup(identity);
	else
		xasprintf(&identity, "%%d/%s", identity);

	return identity;
}

static void on_session_event(struct tmate_ssh_client *client)
{
	char *identity;
	ssh_key pubkey;
	int key_type;
	unsigned char *hash;
	ssize_t hash_len;
	char *hash_str;
	int match;

	int verbosity = SSH_LOG_NOLOG + debug_level;
	int port = TMATE_PORT;

	ssh_session session = client->session;
	ssh_channel channel = client->channel;

	switch (client->state) {
	case SSH_INIT:
		client->session = session = ssh_new();
		if (!session) {
			tmate_fatal("cannot initialize");
			return;
		}

		ssh_set_callbacks(session, &client->ssh_callbacks);

		client->channel = channel = ssh_channel_new(session);
		if (!channel) {
			tmate_fatal("cannot initialize");
			return;
		}

		ssh_set_blocking(session, 0);
		ssh_options_set(session, SSH_OPTIONS_HOST, client->server_ip);
		ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
		ssh_options_set(session, SSH_OPTIONS_PORT, &port);
		ssh_options_set(session, SSH_OPTIONS_USER, "tmate");
		ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "yes");

		if ((identity = get_identity())) {
			ssh_options_set(session, SSH_OPTIONS_IDENTITY, identity);
			free(identity);
		}

		client->state = SSH_CONNECT;
		/* fall through */

	case SSH_CONNECT:
		switch (ssh_connect(session)) {
		case SSH_AGAIN:
			register_session_fd_event(client);
			return;
		case SSH_ERROR:
			reconnect_session(client, "Error connecting: %s",
					  ssh_get_error(session));
			return;
		case SSH_OK:
			register_session_fd_event(client);
			tmate_debug("Establishing connection to %s", client->server_ip);
			client->state = SSH_AUTH_SERVER;
			/* fall through */
		}

	case SSH_AUTH_SERVER:
		if ((hash_len = ssh_get_pubkey_hash(session, &hash)) < 0) {
			disconnect_session(client, "Cannot authenticate server");
			return;
		}

		hash_str = ssh_get_hexa(hash, hash_len);
		if (!hash_str)
			tmate_fatal("malloc failed");

		if (ssh_get_publickey(session, &pubkey) < 0)
			tmate_fatal("ssh_get_publickey");

#ifdef DEVENV
		match = 1;
#else
		key_type = ssh_key_type(pubkey);
		switch (key_type) {
		case SSH_KEYTYPE_DSS:
			match = !strcmp(hash_str, TMATE_HOST_DSA_KEY);
			break;
		case SSH_KEYTYPE_RSA:
			match = !strcmp(hash_str, TMATE_HOST_RSA_KEY);
			break;
		case SSH_KEYTYPE_ECDSA:
			match = !strcmp(hash_str, TMATE_HOST_ECDSA_KEY);
			break;
		default:
			match = 0;
		}
#endif

		ssh_key_free(pubkey);
		ssh_clean_pubkey_hash(&hash);
		free(hash_str);

		if (!match) {
			disconnect_session(client, "Cannot authenticate server");
			return;
		}

		/*
		 * At this point, we abort other connection attempts to the
		 * other tmate servers, since we have reached the fastest one.
		 * We need to do it before we ask the user its passphrase,
		 * otherwise the speed test would be biased.
		 */
		tmate_debug("Connected to %s", client->server_ip);
		connection_complete(client);
		client->state = SSH_AUTH_CLIENT;

		/* fall through */

	case SSH_AUTH_CLIENT:
		switch (ssh_userauth_autopubkey(session, NULL)) {
		case SSH_AUTH_AGAIN:
			return;
		case SSH_AUTH_PARTIAL:
		case SSH_AUTH_INFO:
		case SSH_AUTH_DENIED:
			disconnect_session(client, "Access denied. Check your SSH keys "
					           "(passphrases are not supported yet).");
			return;
		case SSH_AUTH_ERROR:
			reconnect_session(client, "Auth error: %s",
					  ssh_get_error(session));
			return;
		case SSH_AUTH_SUCCESS:
			tmate_debug("Auth successful");
			client->state = SSH_OPEN_CHANNEL;
			/* fall through */
		}

	case SSH_OPEN_CHANNEL:
		switch (ssh_channel_open_session(channel)) {
		case SSH_AGAIN:
			return;
		case SSH_ERROR:
			reconnect_session(client, "Error opening channel: %s",
					  ssh_get_error(session));
			return;
		case SSH_OK:
			tmate_debug("Session opened, initalizing tmate");
			client->state = SSH_BOOTSTRAP;
			/* fall through */
		}

	case SSH_BOOTSTRAP:
		switch (ssh_channel_request_subsystem(channel, "tmate")) {
		case SSH_AGAIN:
			return;
		case SSH_ERROR:
			reconnect_session(client, "Error initializing tmate: %s",
					  ssh_get_error(session));
			return;
		case SSH_OK:
			tmate_debug("Ready");

			/* Writes are now performed in a blocking fashion */
			ssh_set_blocking(session, 1);

			client->state = SSH_READY;
			register_input_stream_event(client);
			flush_input_stream(client);
			/* fall through */
		}

	case SSH_READY:
		consume_channel(client);
		if (!ssh_is_connected(session)) {
			reconnect_session(client, "Disconnected");
			return;
		}
	}
}

static void flush_input_stream(struct tmate_ssh_client *client)
{
	struct tmate_encoder *encoder = &client->tmate_session->encoder;
	struct evbuffer *evb = encoder->buffer;
	ssize_t len, written;
	char *buf;

	if (client->state < SSH_READY)
		return;

	for (;;) {
		len = evbuffer_get_length(evb);
		if (!len)
			break;

		buf = evbuffer_pullup(evb, -1);

		written = ssh_channel_write(client->channel, buf, len);
		if (written < 0) {
			reconnect_session(client, "Error writing to channel: %s",
					  ssh_get_error(client->session));
			return;
		}

		evbuffer_drain(evb, written);
	}
}

static void __flush_input_stream(evutil_socket_t fd, short what, void *arg)
{
	flush_input_stream(arg);
}

static void __on_session_event(evutil_socket_t fd, short what, void *arg)
{
	on_session_event(arg);
}

static void __disconnect_session(struct tmate_ssh_client *client,
				 const char *fmt, va_list va)
{
	struct tmate_encoder *encoder;

	if (fmt)
		__tmate_status_message(fmt, va);
	else
		tmate_debug("Disconnecting %s", client->server_ip);

	if (event_initialized(&client->ev_ssh)) {
		event_del(&client->ev_ssh);
		client->ev_ssh.ev_flags = 0;
	}

	if (client->has_encoder) {
		encoder = &client->tmate_session->encoder;
		event_del(&encoder->ev_readable);
		encoder->ev_readable.ev_flags = 0;
		client->has_encoder = 0;
	}

	if (client->session) {
		/* ssh_free() also frees the associated channels. */
		ssh_free(client->session);
		client->session = NULL;
		client->channel = NULL;
	}

	client->state = SSH_NONE;
}

static void printflike2 disconnect_session(struct tmate_ssh_client *client,
					   const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__disconnect_session(client, fmt, ap);
	va_end(ap);
}

static void connect_session(struct tmate_ssh_client *client)
{
	if (!client->session) {
		client->state = SSH_INIT;
		on_session_event(client);
	}
}

static void on_reconnect_timer(evutil_socket_t fd, short what, void *arg)
{
	connect_session(arg);
}

static void printflike2 reconnect_session(struct tmate_ssh_client *client,
					  const char *fmt, ...)
{
	struct timeval tv;
	va_list ap;

	va_start(ap, fmt);
	__disconnect_session(client, fmt, ap);
	va_end(ap);

	/* Not yet implemented... */
#if 0
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	evtimer_add(&client->ev_ssh_reconnect, &tv);
#endif
}


struct tmate_ssh_client *tmate_ssh_client_alloc(struct tmate_session *session,
						const char *server_ip)
{
	struct tmate_ssh_client *client;
	client = xmalloc(sizeof(*client));

	ssh_callbacks_init(&client->ssh_callbacks);
	client->ssh_callbacks.log_function = log_function;
	client->ssh_callbacks.userdata = client;

	client->tmate_session = session;
	TAILQ_INSERT_TAIL(&session->clients, client, node);

	client->server_ip = xstrdup(server_ip);
	client->state = SSH_NONE;
	client->session = NULL;
	client->channel = NULL;
	client->has_encoder = 0;

	evtimer_assign(&client->ev_ssh_reconnect, ev_base,
		       on_reconnect_timer, client);

	connect_session(client);

	return client;
}

void tmate_ssh_client_free(struct tmate_ssh_client *client)
{
	disconnect_session(client, NULL);
	TAILQ_REMOVE(&client->tmate_session->clients, client, node);
	free(client->server_ip);
	free(client);
}
