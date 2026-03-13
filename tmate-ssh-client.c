#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <event.h>
#include <assert.h>

#include "tmate.h"
#include "window-copy.h"

static void on_ssh_client_event(struct tmate_ssh_client *client);
static void __on_ssh_client_event(evutil_socket_t fd, short what, void *arg);

static void printflike(2, 3) kill_ssh_client(struct tmate_ssh_client *client,
					     const char *fmt, ...);
static void printflike(2, 3) kill_ssh_client(struct tmate_ssh_client *client,
						  const char *fmt, ...);

static void read_channel(struct tmate_ssh_client *client)
{
	struct tmate_decoder *decoder = &client->tmate_session->decoder;
	char *buf;
	ssize_t len;

	for (;;) {
		tmate_decoder_get_buffer(decoder, &buf, &len);
		len = ssh_channel_read_nonblocking(client->channel, buf, len, 0);
		if (len < 0) {
			kill_ssh_client(client, "Error reading from channel: %s",
					ssh_get_error(client->session));
			break;
		}

		if (len == 0)
			break;

		tmate_decoder_commit(decoder, len);
	}
}

static void on_decoder_read(void *userdata, struct tmate_unpacker *uk)
{
	struct tmate_ssh_client *client = userdata;
	tmate_dispatch_slave_message(client->tmate_session, uk);
}

static void on_encoder_write(void *userdata, struct evbuffer *buffer)
{
	struct tmate_ssh_client *client = userdata;
	ssize_t len, written;
	unsigned char *buf;

	if (!client->channel)
		return;

	for(;;) {
		len = evbuffer_get_length(buffer);
		if (!len)
			break;

		buf = evbuffer_pullup(buffer, -1);

		written = ssh_channel_write(client->channel, buf, len);
		if (written < 0) {
			kill_ssh_client(client, "Error writing to channel: %s",
					ssh_get_error(client->session));
			break;
		}

		evbuffer_drain(buffer, written);
	}
}

static void on_ssh_auth_server_complete(struct tmate_ssh_client *connected_client)
{
	/*
	 * The first ssh connection succeeded. Hopefully this one offers the
	 * best latency. We can now kill the other ssh clients that are trying
	 * to connect.
	 */
	struct tmate_session *session = connected_client->tmate_session;
	struct tmate_ssh_client *client, *tmp_client;

	TAILQ_FOREACH_SAFE(client, &session->clients, node, tmp_client) {
		if (client == connected_client)
			continue;

		kill_ssh_client(client, NULL);
	}
}

static char *get_identity(void)
{
	char *identity;

	identity = options_get_string(global_options, "tmate-identity");
	if (!strlen(identity))
		return NULL;

	if (strchr(identity, '/'))
		identity = xstrdup(identity);
	else
		xasprintf(&identity, "%%d/%s", identity);

	return identity;
}

static int passphrase_callback(__unused const char *prompt, char *buf, size_t len,
			       __unused int echo, __unused int verify, void *userdata)
{
	struct tmate_ssh_client *client = userdata;

	client->tmate_session->need_passphrase = 1;

	if (client->tmate_session->passphrase)
		strlcpy(buf, client->tmate_session->passphrase, len);
	else
		strcpy(buf, "");

	return 0;
}

static void on_passphrase_read(const char *passphrase, void *private)
{
	struct tmate_ssh_client *client = private;

	client->tmate_session->passphrase = xstrdup(passphrase);
	on_ssh_client_event(client);
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
	window_copy_init_from_pane(wp, 0);
	data = wp->modedata;

	data->inputtype = WINDOW_COPY_PASSWORD;
	data->inputprompt = "SSH key passphrase";

	mode_key_init(&data->mdata, &mode_key_tree_vi_edit);

	window_copy_update_selection(wp, 1);
	window_copy_redraw_screen(wp);

	data->password_cb = on_passphrase_read;
	data->password_cb_private = client;
}

#define KEEPALIVE_IDLE		30
#define KEEPALIVE_CNT		4
#define KEEPALIVE_INTVL		11
#define WRITE_TIMEOUT		80

static void tune_socket_opts(int fd)
{
#define SSO(level, optname, val) ({							\
	int _flag = val;								\
	if (setsockopt(fd, level, optname, &(_flag), sizeof(int)) < 0) {		\
		/* If the connection has been closed, we'll get EINVAL */		\
		if (errno != EINVAL)							\
			tmate_info("setsockopt(" #level ", " #optname ", %d) failed %s", val, strerror(errno));	\
	}										\
})

	SSO(IPPROTO_IP, IP_TOS, 0x10); /* IPTOS_LOWDELAY */
	SSO(IPPROTO_TCP, TCP_NODELAY, 1);
	SSO(SOL_SOCKET, SO_KEEPALIVE, 1);
#ifdef TCP_KEEPALIVE
	/*
	 * The TCP_KEEPALIVE options enable to specify the amount of time, in
	 * seconds, that the connection must be idle before keepalive probes
	 * (if enabled) are sent.
	 */
	SSO(IPPROTO_TCP, TCP_KEEPALIVE, KEEPALIVE_IDLE);
#endif
#ifdef TCP_KEEPIDLE
	/*
	 * Same as TCP_KEEPALIVE, but on different systems
	 */
	SSO(IPPROTO_TCP, TCP_KEEPIDLE, KEEPALIVE_IDLE);
#endif
#ifdef TCP_KEEPCNT
	/*
	 * When keepalive probes are enabled, this option will set the number
	 * of times a keepalive probe should be repeated if the peer is not
	 * responding. After this many probes, the connection will be closed.
	 */
	SSO(IPPROTO_TCP, TCP_KEEPCNT, KEEPALIVE_CNT);
#endif
#ifdef TCP_KEEPINTVL
	/*
	 * When keepalive probes are enabled, this option will set the amount
	 * of time in seconds between successive keepalives sent to probe an
	 * unresponsive peer.
	 */
	SSO(IPPROTO_TCP, TCP_KEEPINTVL, KEEPALIVE_INTVL);
#endif
#ifdef TCP_USER_TIMEOUT
	/*
	 * This option takes an unsigned int as an argument.  When the
	 * value is greater than 0, it specifies the maximum amount of
	 * time in milliseconds that transmitted data may remain
	 * unacknowledged before TCP will forcibly close the
	 * corresponding connection and return ETIMEDOUT to the
	 * application.
	 */
	SSO(IPPROTO_TCP, TCP_USER_TIMEOUT, 1000*WRITE_TIMEOUT);
#endif
#undef SSO
}

static void init_conn_fd(struct tmate_ssh_client *client)
{
	int fd;

	if (client->ev_ssh)
		return;

	if ((fd = ssh_get_fd(client->session)) < 0)
		return;

	tune_socket_opts(fd);

	client->ev_ssh = event_new(client->tmate_session->ev_base, fd,
				   EV_READ | EV_PERSIST,
				   __on_ssh_client_event, client);
	if (!client->ev_ssh)
		tmate_fatal("out of memory");
	event_add(client->ev_ssh, NULL);
}

static const size_t MAX_ACCOUNT_LEN = 30;

static void on_ssh_client_event(struct tmate_ssh_client *client)
{
	ssh_session session = client->session;
	ssh_channel channel = client->channel;

	switch (client->state) {
	case SSH_INIT: {
		client->session = session = ssh_new();
		if (!session) {
			tmate_fatal("cannot ssh_new()");
			return;
		}

		ssh_set_callbacks(session, &client->ssh_callbacks);

		int verbosity = SSH_LOG_NOLOG + log_get_level();
		int port = options_get_number(global_options, "tmate-server-port");

		ssh_set_blocking(session, 0);
		ssh_options_set(session, SSH_OPTIONS_HOST, client->server_ip);
		ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
		ssh_options_set(session, SSH_OPTIONS_PORT, &port);
		char* tmate_user = options_get_string(global_options,
						"tmate-user");
		size_t tmate_user_len = strlen(tmate_user);

		if (tmate_user_len > MAX_ACCOUNT_LEN)
		{
			tmate_fatal("Invalid tmate-user");
		}

		ssh_options_set(session, SSH_OPTIONS_USER, tmate_user);
		ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "yes");

		char *identity;
		if ((identity = get_identity())) {
			/*
			 * FIXME libssh will continue with the next set of
			 * keys if the identity has a passphrase and the
			 * regular one doesn't.
			 */
			ssh_options_set(session, SSH_OPTIONS_IDENTITY, identity);

			/* Do not use keys from ssh-agent. */
			unsetenv("SSH_AUTH_SOCK");
			free(identity);
		}

		client->state = SSH_CONNECT;
	}
	// fall through

	case SSH_CONNECT:
		switch (ssh_connect(session)) {
		case SSH_AGAIN:
			init_conn_fd(client);
			return;
		case SSH_ERROR:
			kill_ssh_client(client, "Error connecting: %s",
					ssh_get_error(session));
			return;
		case SSH_OK:
			init_conn_fd(client);

			tmate_debug("Establishing connection to %s", client->server_ip);
			client->state = SSH_AUTH_SERVER;
		}
		// fall through

	case SSH_AUTH_SERVER: {
		ssh_key pubkey;
		enum ssh_keytypes_e key_type;
		unsigned char *hash;
		ssize_t hash_len;
		char *hash_str;
		const char *server_hash_str;
		int match;

#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 9, 0)
		if (ssh_get_server_publickey(session, &pubkey) < 0)
			tmate_fatal("ssh_get_server_publickey");
#else
		if (ssh_get_publickey(session, &pubkey) < 0)
			tmate_fatal("ssh_get_publickey");
#endif

		if (ssh_get_publickey_hash(pubkey, SSH_PUBLICKEY_HASH_SHA256,
					   &hash, &hash_len) < 0) {
			kill_ssh_client(client, "Failed to get server fingerprint");
			return;
		}

		hash_str = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256,
						    hash, hash_len);
		if (!hash_str)
			tmate_fatal("malloc failed");

		key_type = ssh_key_type(pubkey);

		switch (key_type) {
		case SSH_KEYTYPE_RSA:
			server_hash_str = options_get_string(global_options,
						"tmate-server-rsa-fingerprint");
			break;
		case SSH_KEYTYPE_ECDSA:
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 9, 0)
		case SSH_KEYTYPE_ECDSA_P256:
		case SSH_KEYTYPE_ECDSA_P384:
		case SSH_KEYTYPE_ECDSA_P521:
#endif
			server_hash_str = options_get_string(global_options,
						"tmate-server-ecdsa-fingerprint");
			break;
		case SSH_KEYTYPE_ED25519:
			server_hash_str = options_get_string(global_options,
						"tmate-server-ed25519-fingerprint");
			break;
		default:
			server_hash_str = "";
		}

		match = !strcmp(hash_str, server_hash_str);
		if (!match) {
			kill_ssh_client(client, "Server fingerprint not recognized: "
				"`%s', expected `%s'", server_hash_str, hash_str);
		}

		ssh_key_free(pubkey);
		ssh_clean_pubkey_hash(&hash);
		free(hash_str);

		if (!match)
			return;

		/*
		 * At this point, we abort other connection attempts to the
		 * other tmate servers, since we have reached the fastest one.
		 * We need to do it before we ask the user its passphrase,
		 * otherwise the speed test would be biased.
		 */
		tmate_debug("Connected to %s", client->server_ip);
		on_ssh_auth_server_complete(client);

		client->state = SSH_AUTH_CLIENT_NONE;
	}
		// fall through

	case SSH_AUTH_CLIENT_NONE:
		switch (ssh_userauth_none(session, NULL)) {
		case SSH_AUTH_AGAIN:
			return;
		case SSH_AUTH_ERROR:
			kill_ssh_client(client, "Auth error: %s", ssh_get_error(session));
			return;
		case SSH_AUTH_SUCCESS:
			tmate_debug("Auth successful via none method");
			client->state = SSH_NEW_CHANNEL;
			goto SSH_NEW_CHANNEL;
		case SSH_AUTH_PARTIAL:
		case SSH_AUTH_DENIED:
			client->state = SSH_AUTH_CLIENT_PUBKEY;
		}
		// fall through

	case SSH_AUTH_CLIENT_PUBKEY:
		client->tried_passphrase = client->tmate_session->passphrase;
		switch (ssh_userauth_publickey_auto(session, NULL, client->tried_passphrase)) {
		case SSH_AUTH_AGAIN:
			return;
		case SSH_AUTH_PARTIAL:
		case SSH_AUTH_INFO:
		case SSH_AUTH_DENIED:
			if (client->tmate_session->need_passphrase) {
				request_passphrase(client);
			} else {
				kill_ssh_client(client, "SSH keys not found."
				" Run 'ssh-keygen' to create keys.");
				return;
			}

			if (client->tried_passphrase)
				tmate_status_message("Can't load SSH key."
				" Try typing passphrase again in case of typo. ctrl-c to abort.");
			return;
		case SSH_AUTH_ERROR:
			kill_ssh_client(client, "Auth error: %s", ssh_get_error(session));
			return;
		case SSH_AUTH_SUCCESS:
			tmate_debug("Auth successful with pubkey");
			client->state = SSH_NEW_CHANNEL;
		}
		// fall through

SSH_NEW_CHANNEL:
	case SSH_NEW_CHANNEL:
		client->channel = channel = ssh_channel_new(session);
		if (!channel) {
			tmate_fatal("cannot ssh_channel_new()");
			return;
		}
		client->state = SSH_OPEN_CHANNEL;
		// fall through

	case SSH_OPEN_CHANNEL:
		switch (ssh_channel_open_session(channel)) {
		case SSH_AGAIN:
			return;
		case SSH_ERROR:
			kill_ssh_client(client, "Error opening channel: %s",
					ssh_get_error(session));
			return;
		case SSH_OK:
			tmate_debug("Session opened, initializing tmate");
			client->state = SSH_BOOTSTRAP;
		}
		// fall through

	case SSH_BOOTSTRAP:
		switch (ssh_channel_request_subsystem(channel, "tmate")) {
		case SSH_AGAIN:
			return;
		case SSH_ERROR:
			kill_ssh_client(client, "Error initializing tmate: %s",
					ssh_get_error(session));
			return;
		case SSH_OK:
			tmate_debug("Ready");

			/* Writes are now performed in a blocking fashion */
			ssh_set_blocking(session, 1);

			client->state = SSH_READY;

			if (client->tmate_session->reconnected)
				tmate_send_reconnection_state(client->tmate_session);

			tmate_encoder_set_ready_callback(&client->tmate_session->encoder,
							 on_encoder_write, client);
			tmate_decoder_init(&client->tmate_session->decoder,
					   on_decoder_read, client);

			free(client->tmate_session->last_server_ip);
			client->tmate_session->last_server_ip = xstrdup(client->server_ip);
		}
		// fall through

	case SSH_READY:
		read_channel(client);
	}
}

static void __on_ssh_client_event(__unused evutil_socket_t fd, __unused short what, void *arg)
{
	on_ssh_client_event(arg);
}

static void kill_ssh_client(struct tmate_ssh_client *client,
			    const char *fmt, ...)
{
	bool last_client;
	va_list ap;
	char *message = NULL;

	TAILQ_REMOVE(&client->tmate_session->clients, client, node);
	last_client = TAILQ_EMPTY(&client->tmate_session->clients);

	if (fmt && last_client) {
		va_start(ap, fmt);
		xvasprintf(&message, fmt, ap);
		va_end(ap);
		tmate_status_message("%s", message);
	}

	tmate_debug("SSH client killed (%s)", client->server_ip);

	if (client->ev_ssh) {
		event_del(client->ev_ssh);
		event_free(client->ev_ssh);
		client->ev_ssh = NULL;
	}

	if (client->state == SSH_READY) {
		tmate_encoder_set_ready_callback(&client->tmate_session->encoder, NULL, NULL);
		tmate_decoder_destroy(&client->tmate_session->decoder);

		client->tmate_session->min_sx = -1;
		client->tmate_session->min_sy = -1;
		recalculate_sizes();
	}

	if (client->session) {
		/* ssh_free() also frees the associated channels. */
		ssh_free(client->session);
		client->session = NULL;
		client->channel = NULL;
	}

	if (last_client)
		tmate_reconnect_session(client->tmate_session, message);

	free(client->server_ip);
	free(client);
}

void connect_ssh_client(struct tmate_ssh_client *client)
{
	assert(!client->session);
	client->state = SSH_INIT;
	on_ssh_client_event(client);
}

static void ssh_log_function(int priority, const char *function,
			     const char *buffer, __unused void *userdata)
{
	tmate_debug("[%d] [%s] %s", priority, function, buffer);
}

struct tmate_ssh_client *tmate_ssh_client_alloc(struct tmate_session *session,
						const char *server_ip)
 
{
	struct tmate_ssh_client *client;
	client = xmalloc(sizeof(*client));
	memset(client, 0, sizeof(*client));

	ssh_set_log_callback(ssh_log_function);

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

	return client;
}
