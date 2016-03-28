#include "tmate.h"
#include "tmate-protocol.h"

static void handle_notify(__unused struct tmate_session *session,
			  struct tmate_unpacker *uk)
{
	char *msg = unpack_string(uk);
	tmate_status_message("%s", msg);
	free(msg);
}

static void handle_legacy_pane_key(__unused struct tmate_session *_session,
				   struct tmate_unpacker *uk)
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

	window_pane_key(wp, NULL, s, key, NULL);
}

static struct window_pane *find_window_pane(struct session *s, int pane_id)
{
	struct window *w;

	if (pane_id != -1)
		return window_pane_find_by_id(pane_id);

	w = s->curw->window;
	if (!w)
		return NULL;

	return w->active;
}

static void handle_pane_key(__unused struct tmate_session *_session,
			    struct tmate_unpacker *uk)
{
	struct session *s;
	struct window_pane *wp;

	int pane_id = unpack_int(uk);
	key_code key = unpack_int(uk);

	s = RB_MIN(sessions, &sessions);
	if (!s)
		return;

	wp = find_window_pane(s, pane_id);
	if (!wp)
		return;

	window_pane_key(wp, NULL, s, key, NULL);
}

static void handle_resize(struct tmate_session *session,
			  struct tmate_unpacker *uk)
{
	session->min_sx = unpack_int(uk);
	session->min_sy = unpack_int(uk);
	recalculate_sizes();
}

extern char		**cfg_causes;
extern u_int		  cfg_ncauses;

static void handle_exec_cmd_str(__unused struct tmate_session *session,
				struct tmate_unpacker *uk)
{
	struct cmd_q *cmd_q;
	struct cmd_list *cmdlist;
	char *cause;
	u_int i;

	int client_id = unpack_int(uk);
	char *cmd_str = unpack_string(uk);

	if (cmd_string_parse(cmd_str, &cmdlist, NULL, 0, &cause) != 0) {
		tmate_failed_cmd(client_id, cause);
		free(cause);
		goto out;
	}

	cmd_q = cmdq_new(NULL);
	cmdq_run(cmd_q, cmdlist, NULL);
	cmd_list_free(cmdlist);
	cmdq_free(cmd_q);

	/* error messages land in cfg_causes */
	for (i = 0; i < cfg_ncauses; i++) {
		tmate_failed_cmd(client_id, cfg_causes[i]);
		free(cfg_causes[i]);
	}

	free(cfg_causes);
	cfg_causes = NULL;
	cfg_ncauses = 0;

out:
	free(cmd_str);
}

static void handle_exec_cmd(__unused struct tmate_session *session,
			    struct tmate_unpacker *uk)
{
	struct cmd_q *cmd_q;
	struct cmd_list *cmdlist;
	struct cmd *cmd;
	char *cause;
	u_int i;
	unsigned int argc;
	char **argv;

	int client_id = unpack_int(uk);

	argc = uk->argc;
	argv = xmalloc(sizeof(char *) * argc);
	for (i = 0; i < argc; i++)
		argv[i] = unpack_string(uk);

	cmd = cmd_parse(argc, argv, NULL, 0, &cause);
	if (!cmd) {
		tmate_failed_cmd(client_id, cause);
		free(cause);
		goto out;
	}

	cmdlist = xcalloc(1, sizeof *cmdlist);
	cmdlist->references = 1;
	TAILQ_INIT(&cmdlist->list);
	TAILQ_INSERT_TAIL(&cmdlist->list, cmd, qentry);

	cmd_q = cmdq_new(NULL);
	cmdq_run(cmd_q, cmdlist, NULL);
	cmd_list_free(cmdlist);
	cmdq_free(cmd_q);

	/* error messages land in cfg_causes */
	for (i = 0; i < cfg_ncauses; i++) {
		tmate_failed_cmd(client_id, cfg_causes[i]);
		free(cfg_causes[i]);
	}

	free(cfg_causes);
	cfg_causes = NULL;
	cfg_ncauses = 0;

out:
	cmd_free_argv(argc, argv);
}

static void maybe_save_reconnection_data(struct tmate_session *session,
				const char *name, const char *value)
{
	if (!strcmp(name, "tmate_reconnection_data")) {
		free(session->reconnection_data);
		session->reconnection_data = xstrdup(value);
	}
}

static void handle_set_env(struct tmate_session *session,
			   struct tmate_unpacker *uk)
{
	char *name = unpack_string(uk);
	char *value = unpack_string(uk);

	tmate_set_env(name, value);
	maybe_save_reconnection_data(session, name, value);

	free(name);
	free(value);
}

static void handle_ready(struct tmate_session *session,
			 __unused struct tmate_unpacker *uk)
{
	session->tmate_env_ready = 1;
	signal_waiting_clients("tmate-ready");
}

void tmate_dispatch_slave_message(struct tmate_session *session,
				  struct tmate_unpacker *uk)
{
	int cmd = unpack_int(uk);
	switch (cmd) {
#define dispatch(c, f) case c: f(session, uk); break
	dispatch(TMATE_IN_NOTIFY,		handle_notify);
	dispatch(TMATE_IN_LEGACY_PANE_KEY,	handle_legacy_pane_key);
	dispatch(TMATE_IN_RESIZE,		handle_resize);
	dispatch(TMATE_IN_EXEC_CMD_STR,		handle_exec_cmd_str);
	dispatch(TMATE_IN_SET_ENV,		handle_set_env);
	dispatch(TMATE_IN_READY,		handle_ready);
	dispatch(TMATE_IN_PANE_KEY,		handle_pane_key);
	dispatch(TMATE_IN_EXEC_CMD,		handle_exec_cmd);
	default: tmate_info("Bad message type: %d", cmd);
	}
}
