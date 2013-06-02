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
	TMATE_SYNC_WINDOW,
	TMATE_PTY_DATA,
};

struct tmate_encoder {
	msgpack_packer pk;
	struct evbuffer *buffer;
	struct event ev_readable;
};

extern void tmate_encoder_init(struct tmate_encoder *encoder);

extern void tmate_write_header(void);
extern void tmate_sync_window(struct window *w);
extern void tmate_pty_data(struct window_pane *wp, const char *buf, size_t len);

/* tmate-decoder.c */

enum tmate_notifications {
	TMATE_CLIENT_KEY,
	TMATE_CLIENT_RESIZE,
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

typedef struct ssh_session_struct* ssh_session;
typedef struct ssh_channel_struct* ssh_channel;

enum tmate_ssh_client_state_types {
	SSH_NONE,
	SSH_INIT,
	SSH_CONNECT,
	SSH_AUTH,
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

#endif
