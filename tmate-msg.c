#include <time.h>
#include "tmate.h"

void status_message_callback(int, short, void *);

/* Very similar to status.c:status_message_set */

static void tmate_status_message_client(struct client *c, const char *message)
{
	struct timeval		 tv;
	struct message_entry	*msg, *msg1;
	int			 delay;
	u_int			 limit;

	limit = options_get_number(global_options, "message-limit");
	delay = options_get_number(c->session ? c->session->options : global_s_options,
				   "tmate-display-time");

	status_prompt_clear(c);
	status_message_clear(c);

	xasprintf(&c->message_string, "[tmate] %s", message);

	msg = xcalloc(1, sizeof *msg);
	msg->msg_time = time(NULL);
	msg->msg_num = c->message_next++;
	msg->msg = xstrdup(c->message_string);
	TAILQ_INSERT_TAIL(&c->message_log, msg, entry);

	TAILQ_FOREACH_SAFE(msg, &c->message_log, entry, msg1) {
		if (msg->msg_num + limit >= c->message_next)
			break;
		free(msg->msg);
		TAILQ_REMOVE(&c->message_log, msg, entry);
		free(msg);
	}

	if (delay > 0) {
		tv.tv_sec = delay / 1000;
		tv.tv_usec = (delay % 1000) * 1000L;

		if (event_initialized(&c->message_timer))
			evtimer_del(&c->message_timer);
		evtimer_set(&c->message_timer, status_message_callback, c);
		evtimer_add(&c->message_timer, &tv);
	}

	c->flags |= CLIENT_STATUS | CLIENT_FORCE_STATUS;

	recalculate_sizes();
}

void __tmate_status_message(const char *fmt, va_list ap)
{
	struct client *c;
	char *message;

	xvasprintf(&message, fmt, ap);
	tmate_debug("%s", message);

	TAILQ_FOREACH(c, &clients, entry) {
		if (c && !(c->flags & CLIENT_READONLY))
			tmate_status_message_client(c, message);
	}

	free(message);
}

void tmate_status_message(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__tmate_status_message(fmt, ap);
	va_end(ap);
}
