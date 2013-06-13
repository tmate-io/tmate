#include "tmate.h"

int tmate_sx = -1;
int tmate_sy = -1;

struct tmate_unpacker {
	msgpack_object *argv;
	int argc;
};

static void decoder_error(void)
{
	/* TODO Don't kill the session, disconnect */
	tmate_fatal("Received a bad message");
}

static void init_unpacker(struct tmate_unpacker *uk,
			  msgpack_object obj)
{
	if (obj.type != MSGPACK_OBJECT_ARRAY)
		decoder_error();

	uk->argv = obj.via.array.ptr;
	uk->argc = obj.via.array.size;
}

static int64_t unpack_int(struct tmate_unpacker *uk)
{
	int64_t val;

	if (uk->argc == 0)
		decoder_error();

	if (uk->argv[0].type != MSGPACK_OBJECT_POSITIVE_INTEGER &&
	    uk->argv[0].type != MSGPACK_OBJECT_NEGATIVE_INTEGER)
		decoder_error();

	val = uk->argv[0].via.i64;

	uk->argv++;
	uk->argc--;

	return val;
}

static void unpack_raw(struct tmate_unpacker *uk,
		       const char **buf, size_t *len)
{
	if (uk->argc == 0)
		decoder_error();

	if (uk->argv[0].type != MSGPACK_OBJECT_RAW)
		decoder_error();

	*len = uk->argv[0].via.raw.size;
	*buf = uk->argv[0].via.raw.ptr;

	uk->argv++;
	uk->argc--;
}

static char *unpack_string(struct tmate_unpacker *uk)
{
	const char *buf;
	char *alloc_buf;
	size_t len;

	unpack_raw(uk, &buf, &len);

	alloc_buf = xmalloc(len + 1);
	memcpy(alloc_buf, buf, len);
	alloc_buf[len] = '\0';

	return alloc_buf;
}

static void tmate_reply_header(struct tmate_unpacker *uk)
{
	unsigned long flags = unpack_int(uk);
	char *remote_session = unpack_string(uk);

	tmate_status_message("Remote session: %s", remote_session);
}

static void tmate_client_pane_key(struct tmate_unpacker *uk)
{
	struct session *s;
	struct window *w;
	struct window_pane *wp;

	int key = unpack_int(uk);

	s = RB_MIN(sessions, &sessions);
	if (!s)
		return;

	w = s->curw->window;
	if (!w)
		return;

	wp = w->active;
	if (!wp)
		return;

	window_pane_key(wp, s, key);
}

static void tmate_client_resize(struct tmate_unpacker *uk)
{
	/* TODO This is sad, we might want our own client. */
	tmate_sx = unpack_int(uk);
	tmate_sy = unpack_int(uk);
	recalculate_sizes();

	/* TODO Handle reconnection cases */
}

static void tmate_client_exec_cmd(struct tmate_unpacker *uk)
{
	struct cmd_q *cmd_q;
	struct cmd_list *cmdlist;
	char *cause;

	int client_id = unpack_int(uk);
	char *cmd_str = unpack_string(uk);

	if (cmd_string_parse(cmd_str, &cmdlist, NULL, 0, &cause) != 0) {
		tmate_failed_cmd(client_id, cause);
		free(cause);
		goto out;
	}

	/* error messages land in cfg_causes */
	ARRAY_FREE(&cfg_causes);

	cmd_q = cmdq_new(NULL);
	cmdq_run(cmd_q, cmdlist);
	cmd_list_free(cmdlist);
	cmdq_free(cmd_q);

	if (!ARRAY_EMPTY(&cfg_causes)) {
		cause = ARRAY_ITEM(&cfg_causes, 0);
		tmate_failed_cmd(client_id, cause);
		free(cause);
		ARRAY_FREE(&cfg_causes);
	}

out:
	free(cmd_str);
}

static void handle_message(msgpack_object obj)
{
	struct tmate_unpacker _uk;
	struct tmate_unpacker *uk = &_uk;

	init_unpacker(uk, obj);

	switch (unpack_int(uk)) {
	case TMATE_REPLY_HEADER:	tmate_reply_header(uk); break;
	case TMATE_CLIENT_PANE_KEY:	tmate_client_pane_key(uk); break;
	case TMATE_CLIENT_RESIZE:	tmate_client_resize(uk); break;
	case TMATE_CLIENT_EXEC_CMD:	tmate_client_exec_cmd(uk); break;
	default:			decoder_error();
	}
}

void tmate_decoder_commit(struct tmate_decoder *decoder, size_t len)
{
	msgpack_unpacked result;

	msgpack_unpacker_buffer_consumed(&decoder->unpacker, len);

	msgpack_unpacked_init(&result);
	while (msgpack_unpacker_next(&decoder->unpacker, &result)) {
		handle_message(result.data);
	}
	msgpack_unpacked_destroy(&result);

	if (msgpack_unpacker_message_size(&decoder->unpacker) >
						TMATE_MAX_MESSAGE_SIZE) {
		tmate_fatal("Message too big");
	}
}

void tmate_decoder_get_buffer(struct tmate_decoder *decoder,
			      char **buf, size_t *len)
{
	/* rewind the buffer if possible */
	if (msgpack_unpacker_buffer_capacity(&decoder->unpacker) <
						TMATE_MAX_MESSAGE_SIZE) {
		msgpack_unpacker_expand_buffer(&decoder->unpacker, 0);
	}

	*buf = msgpack_unpacker_buffer(&decoder->unpacker);
	*len = msgpack_unpacker_buffer_capacity(&decoder->unpacker);
}

void tmate_decoder_init(struct tmate_decoder *decoder)
{
	if (!msgpack_unpacker_init(&decoder->unpacker, 2*TMATE_MAX_MESSAGE_SIZE))
		tmate_fatal("cannot initialize the unpacker");
}
