#include "tmate.h"

static int msgpack_write(void *data, const char *buf, unsigned int len)
{
	struct tmate_encoder *encoder = data;

	evbuffer_add(encoder->buffer, buf, len);

	if ((encoder->ev_readable.ev_flags & EVLIST_INSERTED) &&
	    !(encoder->ev_readable.ev_flags & EVLIST_ACTIVE)) {
		event_active(&encoder->ev_readable, EV_READ, 0);
	}

	return 0;
}

void tmate_encoder_init(struct tmate_encoder *encoder)
{
	msgpack_packer_init(&encoder->pk, encoder, &msgpack_write);
	encoder->buffer = evbuffer_new();
}

#define msgpack_pack_string(pk, str) do {		\
	int __strlen = strlen(str);			\
	msgpack_pack_raw(pk, __strlen);			\
	msgpack_pack_raw_body(pk, str, __strlen);	\
} while(0)

#define pack(what, ...) msgpack_pack_##what(&tmate_encoder->pk, __VA_ARGS__)

void tmate_write_header(void)
{
	pack(array, 2);
	pack(int, TMATE_HEADER);
	pack(int, TMATE_PROTOCOL_VERSION);
}

void tmate_sync_layout(void)
{
	struct session *s;
	struct winlink *wl;
	struct window *w;
	struct window_pane *wp;
	int num_panes = 0;
	int num_windows = 0;
	int active_pane_id = -1;
	int active_window_id = -1;

	/*
	 * We only allow one session, it makes our lives easier.
	 * Especially when the HTML5 client will come along.
	 * We make no distinction between a winlink and its window.
	 * TODO send the winlink in the current session stack order.
	 */

	s = RB_MIN(sessions, &sessions);
	if (!s)
		return;

	num_windows = 0;
	RB_FOREACH(wl, winlinks, &s->windows) {
		if (wl->window)
			num_windows++;
	}

	if (!num_windows)
		return;

	pack(array, 5);
	pack(int, TMATE_SYNC_LAYOUT);

	pack(int, s->sx);
	pack(int, s->sy);

	pack(array, num_windows);
	RB_FOREACH(wl, winlinks, &s->windows) {
		w = wl->window;
		if (!w)
			continue;

		pack(array, 4);
		pack(int, w->id);
		pack(string, w->name);

		num_panes = 0;
		TAILQ_FOREACH(wp, &w->panes, entry)
			num_panes++;

		pack(array, num_panes);
		TAILQ_FOREACH(wp, &w->panes, entry) {
			pack(array, 5);
			pack(int, wp->id);
			pack(int, wp->sx);
			pack(int, wp->sy);
			pack(int, wp->xoff);
			pack(int, wp->yoff);

			if (wp == w->active)
				active_pane_id = wp->id;
		}
		pack(int, active_pane_id);

		if (wl == s->curw)
			active_window_id = w->id;
	}

	if (active_window_id == -1) {
		wl = RB_MIN(winlinks, &s->windows);
		active_window_id = wl->window->id;
	}

	pack(int, active_window_id);
}

void tmate_pty_data(struct window_pane *wp, const char *buf, size_t len)
{
	size_t max_write, to_write;

	max_write = TMATE_MAX_MESSAGE_SIZE - 4;
	while (len > 0) {
		to_write = len < max_write ? len : max_write;

		pack(array, 3);
		pack(int, TMATE_PTY_DATA);
		pack(int, wp->id);
		pack(raw, to_write);
		pack(raw_body, buf, to_write);

		buf += to_write;
		len -= to_write;
	}
}

static const struct cmd_entry *replicated_cmds[] = {
	&cmd_bind_key_entry,
	&cmd_unbind_key_entry,
	&cmd_set_option_entry,
	&cmd_set_window_option_entry,
	NULL
};

int tmate_should_replicate_cmd(const struct cmd_entry *cmd)
{
	const struct cmd_entry **ptr;

	for (ptr = replicated_cmds; *ptr; ptr++)
		if (*ptr == cmd)
			return 1;
	return 0;
}

void tmate_cmd(const char *cmd)
{
	pack(array, 2);
	pack(int, TMATE_CMD);
	pack(string, cmd);
}

void tmate_status(const char *left, const char *right)
{
	static char *old_left, *old_right;

	if (old_left  && !strcmp(old_left,  left) &&
	    old_right && !strcmp(old_right, right))
		return;

	pack(array, 3);
	pack(int, TMATE_STATUS);
	pack(string, left);
	pack(string, right);

	free(old_left);
	free(old_right);
	old_left = xstrdup(left);
	old_right = xstrdup(right);
}
