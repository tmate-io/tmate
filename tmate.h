#ifndef TMATE_H
#define TMATE_H

#include <sys/types.h>
#include <msgpack.h>
#include <event.h>

#include "tmux.h"

#define tmate_debug(...) log_debug("[tmate] " __VA_ARGS__)
#define tmate_warn(...)   log_warn("[tmate] " __VA_ARGS__)
#define tmate_info(...)   log_info("[tmate] " __VA_ARGS__)
#define tmate_fatal(...) log_fatal("[tmate] " __VA_ARGS__)

/* tmate-encoder.c */

#define TMATE_MAX_MESSAGE_SIZE (16*1024)

#define TMATE_PROTOCOL_VERSION 1

enum tmate_commands {
	TMATE_HEADER,
	TMATE_SYNC_LAYOUT,
	TMATE_PTY_DATA,
	TMATE_EXEC_CMD,
	TMATE_FAILED_CMD,
	TMATE_STATUS,
	TMATE_SYNC_COPY_MODE,
};

struct tmate_encoder {
	msgpack_packer pk;
	struct evbuffer *buffer;
	struct event ev_readable;
};

extern void tmate_encoder_init(struct tmate_encoder *encoder);

extern void tmate_write_header(void);
extern void tmate_sync_layout(void);
extern void tmate_pty_data(struct window_pane *wp, const char *buf, size_t len);
extern int tmate_should_replicate_cmd(const struct cmd_entry *cmd);
extern void tmate_exec_cmd(const char *cmd);
extern void tmate_failed_cmd(int client_id, const char *cause);
extern void tmate_status(const char *left, const char *right);
extern void tmate_sync_copy_mode(struct window_pane *wp);

/* tmate-decoder.c */

enum tmate_client_commands {
	TMATE_NOTIFY,
	TMATE_CLIENT_PANE_KEY,
	TMATE_CLIENT_RESIZE,
	TMATE_CLIENT_EXEC_CMD,
};

struct tmate_decoder {
	struct msgpack_unpacker unpacker;
};

extern int tmate_sx;
extern int tmate_sy;

extern void tmate_decoder_init(struct tmate_decoder *decoder);
extern void tmate_decoder_get_buffer(struct tmate_decoder *decoder,
				     char **buf, size_t *len);
extern void tmate_decoder_commit(struct tmate_decoder *decoder, size_t len);

/* tmate-ssh-client.c */

#ifdef DEVENV
#define TMATE_HOST "localhost"
#define TMATE_PORT 2200
#else
#define TMATE_HOST "master.tmate.io"
#define TMATE_PORT 22
#define TMATE_HOST_DSA_KEY   "f5:26:31:c3:8a:78:6e:5c:77:74:0f:41:5b:5f:21:88"
#define TMATE_HOST_RSA_KEY   "af:2d:81:c1:fe:49:70:2d:7f:09:a9:d7:4b:32:e3:be"
#define TMATE_HOST_ECDSA_KEY "c7:a1:51:36:d2:bb:35:4b:0a:1a:c0:43:97:74:ea:42"
#endif

typedef struct ssh_session_struct* ssh_session;
typedef struct ssh_channel_struct* ssh_channel;

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
	int state;
	ssh_session session;
	ssh_channel channel;

	struct tmate_encoder *encoder;
	struct tmate_decoder *decoder;

	struct event ev_ssh;
	struct event ev_ssh_reconnect;
};

extern void tmate_ssh_client_init(struct tmate_ssh_client *client,
				  struct tmate_encoder *encoder,
				  struct tmate_decoder *decoder);

/* tmate.c */

extern struct tmate_encoder *tmate_encoder;
extern void tmate_client_start(void);

/* tmate-debug.c */
extern void tmate_print_trace (void);

/* tmate-msg.c */

extern void __tmate_status_message(const char *fmt, va_list ap);
extern void printflike1 tmate_status_message(const char *fmt, ...);

#endif
