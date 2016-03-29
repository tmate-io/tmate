#ifndef TMATE_H
#define TMATE_H

#include <sys/types.h>
#include <msgpack.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <event.h>

#include "tmux.h"

#define tmate_debug(...) log_debug("[tmate] D " __VA_ARGS__)
#define tmate_warn(...)  log_debug("[tmate] W " __VA_ARGS__)
#define tmate_info(...)  log_debug("[tmate] I " __VA_ARGS__)
#define tmate_fatal(...)    fatalx("[tmate] " __VA_ARGS__)

/* tmate-msgpack.c */

typedef void tmate_encoder_write_cb(void *userdata, struct evbuffer *buffer);

struct tmate_encoder {
	msgpack_packer pk;
	tmate_encoder_write_cb *ready_callback;
	void *userdata;
	struct evbuffer *buffer;
	struct event ev_buffer;
	bool ev_active;
};

extern void tmate_encoder_init(struct tmate_encoder *encoder,
			       tmate_encoder_write_cb *callback,
			       void *userdata);
extern void tmate_encoder_destroy(struct tmate_encoder *encoder);
extern void tmate_encoder_set_ready_callback(struct tmate_encoder *encoder,
					     tmate_encoder_write_cb *callback,
					     void *userdata);

extern void msgpack_pack_string(msgpack_packer *pk, const char *str);
extern void msgpack_pack_boolean(msgpack_packer *pk, bool value);

#define _pack(enc, what, ...) msgpack_pack_##what(&(enc)->pk, ##__VA_ARGS__)

struct tmate_unpacker;
struct tmate_decoder;
typedef void tmate_decoder_reader(void *userdata, struct tmate_unpacker *uk);

struct tmate_decoder {
	struct msgpack_unpacker unpacker;
	tmate_decoder_reader *reader;
	void *userdata;
};

extern void tmate_decoder_init(struct tmate_decoder *decoder, tmate_decoder_reader *reader, void *userdata);
extern void tmate_decoder_destroy(struct tmate_decoder *decoder);
extern void tmate_decoder_get_buffer(struct tmate_decoder *decoder, char **buf, size_t *len);
extern void tmate_decoder_commit(struct tmate_decoder *decoder, size_t len);

struct tmate_unpacker {
	int argc;
	msgpack_object *argv;
};

extern void init_unpacker(struct tmate_unpacker *uk, msgpack_object obj);
extern void tmate_decoder_error(void);
extern int64_t unpack_int(struct tmate_unpacker *uk);
extern bool unpack_bool(struct tmate_unpacker *uk);
extern void unpack_buffer(struct tmate_unpacker *uk, const char **buf, size_t *len);
extern char *unpack_string(struct tmate_unpacker *uk);
extern void unpack_array(struct tmate_unpacker *uk, struct tmate_unpacker *nested);

#define unpack_each(nested_uk, tmp_uk, uk)						\
	for (unpack_array(uk, tmp_uk);							\
	     (tmp_uk)->argc > 0 && (init_unpacker(nested_uk, (tmp_uk)->argv[0]), 1);	\
	     (tmp_uk)->argv++, (tmp_uk)->argc--)

/* tmate-encoder.c */

#define TMATE_PROTOCOL_VERSION 6

struct tmate_session;

extern void tmate_write_header(void);
extern void tmate_write_ready(void);
extern void tmate_sync_layout(void);
extern void tmate_pty_data(struct window_pane *wp, const char *buf, size_t len);
extern int tmate_should_replicate_cmd(const struct cmd_entry *cmd);
extern void tmate_exec_cmd_args(int argc, const char **argv);
extern void tmate_exec_cmd(struct cmd *cmd);
extern void tmate_failed_cmd(int client_id, const char *cause);
extern void tmate_status(const char *left, const char *right);
extern void tmate_sync_copy_mode(struct window_pane *wp);
extern void tmate_write_copy_mode(struct window_pane *wp, const char *str);
extern void tmate_write_fin(void);
extern void tmate_send_reconnection_state(struct tmate_session *session);

/* tmate-decoder.c */

struct tmate_session;
extern void tmate_dispatch_slave_message(struct tmate_session *session,
					 struct tmate_unpacker *uk);

/* tmate-ssh-client.c */

enum tmate_ssh_client_state_types {
	SSH_NONE,
	SSH_INIT,
	SSH_CONNECT,
	SSH_AUTH_SERVER,
	SSH_AUTH_CLIENT,
	SSH_OPEN_CHANNEL,
	SSH_BOOTSTRAP,
	SSH_READY,
};

struct tmate_ssh_client {
	/* XXX The "session" word is used for three things:
	 * - the ssh session
	 * - the tmate sesssion
	 * - the tmux session
	 * A tmux session is associated 1:1 with a tmate session.
	 * An ssh session belongs to a tmate session, and a tmate session
	 * has one ssh session, except during bootstrapping where
	 * there is one ssh session per tmate server, and the first one wins.
	 */
	struct tmate_session *tmate_session;
	TAILQ_ENTRY(tmate_ssh_client) node;

	char *server_ip;

	int has_encoder;
	int state;

	/*
	 * ssh_callbacks is allocated because the libssh API sucks (userdata
	 * has to be in the struct itself).
	 */
	struct ssh_callbacks_struct ssh_callbacks;
	char *tried_passphrase;
	ssh_session session;
	ssh_channel channel;

	bool has_init_conn_fd;
	struct event ev_ssh;
};
TAILQ_HEAD(tmate_ssh_clients, tmate_ssh_client);

extern struct tmate_ssh_client *tmate_ssh_client_alloc(struct tmate_session *session,
						       const char *server_ip);

/* tmate-session.c */

struct tmate_session {
	struct event_base *ev_base;
	struct evdns_base *ev_dnsbase;
	struct event ev_dns_retry;

	struct tmate_encoder encoder;
	struct tmate_decoder decoder;

	/* True when the slave has sent all the environment variables */
	int tmate_env_ready;

	int min_sx;
	int min_sy;

	/*
	 * This list contains one connection per IP. The first connected
	 * client wins, and saved in *client. When we have a winner, the
	 * losers are disconnected and killed.
	 */
	struct tmate_ssh_clients clients;
	int need_passphrase;
	char *passphrase;

	bool reconnected;
	struct event ev_connection_retry;
	char *last_server_ip;
	char *reconnection_data;
	/*
	 * When we reconnect, instead of serializing the key bindings and
	 * options, we replay all the tmux commands we replicated.
	 * It may be a little innacurate to replicate the state, but
	 * it's much easier.
	 */
	struct {
		unsigned int capacity;
		unsigned int tail;
		struct {
			int argc;
			char **argv;
		} *cmds;
	} saved_tmux_cmds;
};

extern struct tmate_session tmate_session;
extern void tmate_session_init(struct event_base *base);
extern void tmate_session_start(void);
extern void tmate_reconnect_session(struct tmate_session *session, const char *message);

/* tmate-debug.c */
extern void tmate_print_stack_trace(void);
extern void tmate_catch_sigsegv(void);

/* tmate-msg.c */

extern void __tmate_status_message(const char *fmt, va_list ap);
extern void printflike(1, 2) tmate_status_message(const char *fmt, ...);

/* tmate-env.c */

extern int tmate_has_received_env(void);
extern void tmate_set_env(const char *name, const char *value);
extern void tmate_format(struct format_tree *ft);

#endif
