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
static void printflike2 kill_session(struct tmate_ssh_client *client,
				     const char *fmt, ...);
static void printflike2 reconnect_session(struct tmate_ssh_client *client,
					  const char *fmt, ...);
static void on_session_event(struct tmate_ssh_client *client);

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
		kill_session(client, NULL);
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

static int passphrase_callback(const char *prompt, char *buf, size_t len,
			       int echo, int verify, void *userdata)
{
	struct tmate_ssh_client *client = userdata;

	client->tmate_session->need_passphrase = 1;

	if (client->tmate_session->passphrase)
		strncpy(buf, client->tmate_session->passphrase, len);
	else
		strcpy(buf, "");

	return 0;
}

static void on_passphrase_read(const char *passphrase, void *private)
{
	struct tmate_ssh_client *client = private;

	client->tmate_session->passphrase = xstrdup(passphrase);
	on_session_event(client);
}

static void request_passphrase(struct tmate_ssh_client *client)
{
	struct window_pane *wp;
	struct window_copy_mode_data *data;

	/*
	 * We'll display the prompt on the first pane.
	 * It doesn't make much sense, but it's simpler to reuse the copy mode
	 * and its key parsing logic compared to rolling something on our own.
	 */
	wp = RB_MIN(window_pane_tree, &all_window_panes);

	if (wp->mode) {
		data = wp->modedata;
		if (data->inputtype == WINDOW_COPY_PASSWORD) {
			/* We are already requesting the passphrase */
			return;
		}
		window_pane_reset_mode(wp);
	}

	window_pane_set_mode(wp, &window_copy_mode);
	window_copy_init_from_pane(wp);
	data = wp->modedata;

	data->inputtype = WINDOW_COPY_PASSWORD;
	data->inputprompt = "SSH key passphrase";

	mode_key_init(&data->mdata, &mode_key_tree_vi_edit);

	window_copy_update_selection(wp);
	window_copy_redraw_screen(wp);

	data->password_cb = on_passphrase_read;
	data->password_cb_private = client;
}

static void on_session_event(struct tmate_ssh_client *client)
{
	char *identity;
	ssh_key pubkey;
	int key_type;
	unsigned char *hash;
	ssize_t hash_len;
	char *hash_str;
	char *server_hash_str;
	int match;

	int verbosity = SSH_LOG_NOLOG + debug_level;
	int port = options_get_number(&global_s_options, "tmate-server-port");

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
			/*
			 * FIXME libssh will continue with the next set of
			 * keys if the identity has a passphrase and the
			 * regular one doesn't.
			 */
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
			kill_session(client, "Cannot authenticate server");
			return;
		}

		hash_str = ssh_get_hexa(hash, hash_len);
		if (!hash_str)
			tmate_fatal("malloc failed");

		if (ssh_get_publickey(session, &pubkey) < 0)
			tmate_fatal("ssh_get_publickey");

		key_type = ssh_key_type(pubkey);

		switch (key_type) {
		case SSH_KEYTYPE_DSS:
			server_hash_str = options_get_string(&global_s_options,
						"tmate-server-dsa-fingerprint");
			break;
		case SSH_KEYTYPE_RSA:
			server_hash_str = options_get_string(&global_s_options,
						"tmate-server-rsa-fingerprint");
			break;
		case SSH_KEYTYPE_ECDSA:
			server_hash_str = options_get_string(&global_s_options,
						"tmate-server-ecdsa-fingerprint");
			break;
		default:
			server_hash_str = "";
		}

		match = !strcmp(hash_str, server_hash_str);

		ssh_key_free(pubkey);
		ssh_clean_pubkey_hash(&hash);
		free(hash_str);

		if (!match) {
			kill_session(client, "Cannot authenticate server");
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
		client->tried_passphrase = client->tmate_session->passphrase;
		switch (ssh_userauth_autopubkey(session, client->tried_passphrase)) {
		case SSH_AUTH_AGAIN:
			return;
		case SSH_AUTH_PARTIAL:
		case SSH_AUTH_INFO:
		case SSH_AUTH_DENIED:
			if (client->tmate_session->need_passphrase &&
			    !client->tried_passphrase)
				request_passphrase(client);
			else
				kill_session(client, "Access denied. Check your SSH keys.");
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

static void __kill_session(struct tmate_ssh_client *client,
			   const char *fmt, va_list va)
{
	struct tmate_encoder *encoder;

	if (fmt && TAILQ_EMPTY(&client->tmate_session->clients))
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

static void printflike2 kill_session(struct tmate_ssh_client *client,
				     const char *fmt, ...)
{
	va_list ap;

	TAILQ_REMOVE(&client->tmate_session->clients, client, node);

	va_start(ap, fmt);
	__kill_session(client, fmt, ap);
	va_end(ap);

	free(client->server_ip);
	free(client);
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

#if 1
	TAILQ_REMOVE(&client->tmate_session->clients, client, node);
#endif

	va_start(ap, fmt);
	__kill_session(client, fmt, ap);
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

	memset(&client->ssh_callbacks, 0, sizeof(client->ssh_callbacks));
	ssh_callbacks_init(&client->ssh_callbacks);
	client->ssh_callbacks.userdata = client;
	client->ssh_callbacks.auth_function = passphrase_callback;

	client->tmate_session = session;
	TAILQ_INSERT_TAIL(&session->clients, client, node);

	client->server_ip = xstrdup(server_ip);
	client->state = SSH_NONE;
	client->session = NULL;
	client->channel = NULL;
	client->has_encoder = 0;

	client->ev_ssh.ev_flags = 0;

	evtimer_assign(&client->ev_ssh_reconnect, ev_base,
		       on_reconnect_timer, client);

	connect_session(client);

	return client;
}
