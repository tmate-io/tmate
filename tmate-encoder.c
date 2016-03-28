#include "tmate.h"
#include "tmate-protocol.h"
#include "window-copy.h"

#define pack(what, ...) _pack(&tmate_session.encoder, what, ##__VA_ARGS__)

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

#define TMATE_MAX_PTY_SIZE (16*1024)

void tmate_pty_data(struct window_pane *wp, const char *buf, size_t len)
{
	size_t to_write;

	while (len > 0) {
		to_write = len < TMATE_MAX_PTY_SIZE ? len : TMATE_MAX_PTY_SIZE;

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

#define sc (&session->saved_tmux_cmds)
#define SAVED_TMUX_CMD_INITIAL_SIZE 256
static void __tmate_exec_cmd_args(int argc, const char **argv);

static void append_saved_cmd(struct tmate_session *session,
			     int argc, const char **argv)
{
	if (!sc->cmds) {
		sc->capacity = SAVED_TMUX_CMD_INITIAL_SIZE;
		sc->cmds = xmalloc(sizeof(*sc->cmds) * sc->capacity);
		sc->tail = 0;
	}

	if (sc->tail == sc->capacity) {
		sc->capacity *= 2;
		sc->cmds = xrealloc(sc->cmds, sizeof(*sc->cmds) * sc->capacity);
	}

	sc->cmds[sc->tail].argc = argc;
	sc->cmds[sc->tail].argv = cmd_copy_argv(argc, (char **)argv);

	sc->tail++;
}

static void replay_saved_cmd(struct tmate_session *session)
{
	unsigned int i;
	for (i = 0; i < sc->tail; i++)
		__tmate_exec_cmd_args(sc->cmds[i].argc, (const char **)sc->cmds[i].argv);
}
#undef sc

struct args_entry {
	u_char			 flag;
	char			*value;
	RB_ENTRY(args_entry)	 entry;
};

static void extract_cmd(struct cmd *cmd, int *_argc, char ***_argv)
{
	struct args_entry *entry;
	struct args* args = cmd->args;
	int argc = 0;
	char **argv;
	int next = 0, i;

	argc++; /* cmd name */
	RB_FOREACH(entry, args_tree, &args->tree) {
		argc++;
		if (entry->value != NULL)
			argc++;
	}
	argc += args->argc;
	argv = xmalloc(sizeof(char *) * argc);

	argv[next++] = xstrdup(cmd->entry->name);

	RB_FOREACH(entry, args_tree, &args->tree) {
		xasprintf(&argv[next++], "-%c", entry->flag);
		if (entry->value != NULL)
			argv[next++] = xstrdup(entry->value);
	}

	for (i = 0; i < args->argc; i++)
		argv[next++] = xstrdup(args->argv[i]);

	*_argc = argc;
	*_argv = argv;
}

static void __tmate_exec_cmd_args(int argc, const char **argv)
{
	int i;

	pack(array, argc + 1);
	pack(int, TMATE_OUT_EXEC_CMD);

	for (i = 0; i < argc; i++)
		pack(string, argv[i]);
}

void tmate_exec_cmd_args(int argc, const char **argv)
{
	__tmate_exec_cmd_args(argc, argv);
	append_saved_cmd(&tmate_session, argc, argv);
}

void tmate_exec_cmd(struct cmd *cmd)
{
	int argc;
	char **argv;

	extract_cmd(cmd, &argc, &argv);
	tmate_exec_cmd_args(argc, (const char **)argv);
	cmd_free_argv(argc, argv);
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

static void do_snapshot_grid(struct grid *grid, unsigned int max_history_lines)
{
	struct grid_line *line;
	struct grid_cell gc;
	unsigned int line_i, i;
	unsigned int max_lines;
	size_t str_len;

	max_lines = max_history_lines + grid->sy;

#define grid_num_lines(grid) (grid->hsize + grid->sy)

	if (grid_num_lines(grid) > max_lines)
		line_i = grid_num_lines(grid) - max_lines;
	else
		line_i = 0;

	pack(array, grid_num_lines(grid) - line_i);
	for (; line_i < grid_num_lines(grid); line_i++) {
		line = &grid->linedata[line_i];

		pack(array, 2);
		str_len = 0;
		for (i = 0; i < line->cellsize; i++) {
			grid_get_cell(grid, i, line_i, &gc);
			str_len += gc.data.size;
		}

		pack(str, str_len);
		for (i = 0; i < line->cellsize; i++) {
			grid_get_cell(grid, i, line_i, &gc);
			pack(str_body, gc.data.data, gc.data.size);
		}

		pack(array, line->cellsize);
		for (i = 0; i < line->cellsize; i++) {
			grid_get_cell(grid, i, line_i, &gc);
			pack(unsigned_int, ((gc.flags << 24) |
					    (gc.attr  << 16) |
					    (gc.bg    << 8)  |
					     gc.fg        ));
		}
	}

}

static void do_snapshot_pane(struct window_pane *wp, unsigned int max_history_lines)
{
	struct screen *screen = &wp->base;

	pack(array, 4);
	pack(int, wp->id);

	pack(unsigned_int, screen->mode);

	pack(array, 3);
	pack(int, screen->cx);
	pack(int, screen->cy);
	do_snapshot_grid(screen->grid, max_history_lines);

	if (wp->saved_grid) {
		pack(array, 3);
		pack(int, wp->saved_cx);
		pack(int, wp->saved_cy);
		do_snapshot_grid(wp->saved_grid, max_history_lines);
	} else {
		pack(nil);
	}
}

static void tmate_send_session_snapshot(unsigned int max_history_lines)
{
	struct session *s;
	struct winlink *wl;
	struct window *w;
	struct window_pane *pane;
	int num_panes;

	pack(array, 2);
	pack(int, TMATE_OUT_SNAPSHOT);

	s = RB_MIN(sessions, &sessions);
	if (!s)
		tmate_fatal("no session?");

	num_panes = 0;
	RB_FOREACH(wl, winlinks, &s->windows) {
		w = wl->window;
		if (!w)
			continue;

		TAILQ_FOREACH(pane, &w->panes, entry)
			num_panes++;
	}

	pack(array, num_panes);
	RB_FOREACH(wl, winlinks, &s->windows) {
		w = wl->window;
		if (!w)
			continue;

		TAILQ_FOREACH(pane, &w->panes, entry)
			do_snapshot_pane(pane, max_history_lines);
	}
}

static void tmate_send_reconnection_data(struct tmate_session *session)
{
	if (!session->reconnection_data)
		return;

	pack(array, 2);
	pack(int, TMATE_OUT_RECONNECT);
	pack(string, session->reconnection_data);
}

#define RECONNECTION_MAX_HISTORY_LINE 300

void tmate_send_reconnection_state(struct tmate_session *session)
{
	/* Start with a fresh encoder */
	tmate_encoder_destroy(&session->encoder);
	tmate_encoder_init(&session->encoder, NULL, session);

	tmate_write_header();
	tmate_send_reconnection_data(session);
	replay_saved_cmd(session);
	/* TODO send all option variables */
	tmate_write_ready();

	tmate_sync_layout();
	tmate_send_session_snapshot(RECONNECTION_MAX_HISTORY_LINE);
}
