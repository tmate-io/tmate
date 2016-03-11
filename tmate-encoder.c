#include "tmate.h"
#include "tmate-protocol.h"
#include "window-copy.h"

#define pack(what, ...) _pack(&tmate_session.encoder, what, __VA_ARGS__)

void tmate_write_header(void)
{
	pack(array, 3);
	pack(int, TMATE_OUT_HEADER);
	pack(int, TMATE_PROTOCOL_VERSION);
	pack(string, VERSION);
}

void tmate_write_ready(void)
{
	pack(array, 1);
	pack(int, TMATE_OUT_READY);
}

void tmate_sync_layout(void)
{
	struct session *s;
	struct winlink *wl;
	struct window *w;
	struct window_pane *wp;
	int num_panes = 0;
	int num_windows = 0;
	int active_pane_id;
	int active_window_idx = -1;

	/*
	 * TODO this can get a little heavy.
	 * We are shipping the full layout whenever a window name changes,
	 * that is, at every shell command.
	 * Might be better to do something incremental.
	 */

	/*
	 * We only allow one session, it makes our lives easier.
	 * Especially when the HTML5 client will come along.
	 * We make no distinction between a winlink and its window except
	 * that we send the winlink idx to draw the status bar properly.
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
	pack(int, TMATE_OUT_SYNC_LAYOUT);

	pack(int, s->sx);
	pack(int, s->sy);

	pack(array, num_windows);
	RB_FOREACH(wl, winlinks, &s->windows) {
		w = wl->window;
		if (!w)
			continue;

		w->tmate_last_sync_active_pane = NULL;
		active_pane_id = -1;

		if (active_window_idx == -1)
			active_window_idx = wl->idx;

		pack(array, 4);
		pack(int, wl->idx);
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

			if (wp == w->active) {
				w->tmate_last_sync_active_pane = wp;
				active_pane_id = wp->id;
			}

		}
		pack(int, active_pane_id);
	}

	if (s->curw)
		active_window_idx = s->curw->idx;

	pack(int, active_window_idx);
}

/* TODO add a buffer for pty_data ? */

void tmate_pty_data(struct window_pane *wp, const char *buf, size_t len)
{
	size_t max_write, to_write;

	max_write = TMATE_MAX_MESSAGE_SIZE - 16;
	while (len > 0) {
		to_write = len < max_write ? len : max_write;

		pack(array, 3);
		pack(int, TMATE_OUT_PTY_DATA);
		pack(int, wp->id);
		pack(str, to_write);
		pack(str_body, buf, to_write);

		buf += to_write;
		len -= to_write;
	}
}

extern const struct cmd_entry cmd_bind_key_entry;
extern const struct cmd_entry cmd_unbind_key_entry;
extern const struct cmd_entry cmd_set_option_entry;
extern const struct cmd_entry cmd_set_window_option_entry;

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

void tmate_exec_cmd(const char *cmd)
{
	pack(array, 2);
	pack(int, TMATE_OUT_EXEC_CMD);
	pack(string, cmd);
}

void tmate_failed_cmd(int client_id, const char *cause)
{
	pack(array, 3);
	pack(int, TMATE_OUT_FAILED_CMD);
	pack(int, client_id);
	pack(string, cause);
}

void tmate_status(const char *left, const char *right)
{
	static char *old_left, *old_right;

	if (old_left  && !strcmp(old_left,  left) &&
	    old_right && !strcmp(old_right, right))
		return;

	pack(array, 3);
	pack(int, TMATE_OUT_STATUS);
	pack(string, left);
	pack(string, right);

	free(old_left);
	free(old_right);
	old_left = xstrdup(left);
	old_right = xstrdup(right);
}

void tmate_sync_copy_mode(struct window_pane *wp)
{
	struct window_copy_mode_data *data = wp->modedata;

	pack(array, 3);
	pack(int, TMATE_OUT_SYNC_COPY_MODE);

	pack(int, wp->id);

	if (wp->mode != &window_copy_mode ||
	    data->inputtype == WINDOW_COPY_PASSWORD) {
		pack(array, 0);
		return;
	}
	pack(array, 6);
	pack(int, data->backing == &wp->base);

	pack(int, data->oy);
	pack(int, data->cx);
	pack(int, data->cy);

	if (data->screen.sel.flag) {
		pack(array, 3);
		pack(int, data->selx);
		pack(int, -data->sely + screen_hsize(data->backing)
				      + screen_size_y(data->backing) - 1);
		pack(int, data->rectflag);
	} else
		pack(array, 0);

	if (data->inputprompt) {
		pack(array, 3);
		pack(int, data->inputtype);
		pack(string, data->inputprompt);
		pack(string, data->inputstr);
	} else
		pack(array, 0);
}

void tmate_write_copy_mode(struct window_pane *wp, const char *str)
{
	pack(array, 3);
	pack(int, TMATE_OUT_WRITE_COPY_MODE);
	pack(int, wp->id);
	pack(string, str);
}

void tmate_write_fin(void)
{
	pack(array, 1);
	pack(int, TMATE_OUT_FIN);
}
