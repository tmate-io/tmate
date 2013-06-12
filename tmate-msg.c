#include <time.h>
#include "tmate.h"

void status_message_callback(int, short, void *);

/* Very similar to status.c:status_message_set */

static void tmate_status_message_client(struct client *c, const char *message)
{
	struct timeval		 tv;
	struct session		*s = c->session;
	struct message_entry	*msg;
	int			 delay;
	u_int			 i, limit;

	status_prompt_clear(c);
	status_message_clear(c);

	xasprintf(&c->message_string, "tmate: %s", message);

	ARRAY_EXPAND(&c->message_log, 1);
	msg = &ARRAY_LAST(&c->message_log);
	msg->msg_time = time(NULL);
	msg->msg = xstrdup(c->message_string);

	if (!s)
		return;

	limit = options_get_number(&s->options, "message-limit");
	if (ARRAY_LENGTH(&c->message_log) > limit) {
		limit = ARRAY_LENGTH(&c->message_log) - limit;
		for (i = 0; i < limit; i++) {
			msg = &ARRAY_FIRST(&c->message_log);
			free(msg->msg);
			ARRAY_REMOVE(&c->message_log, 0);
		}
	}

	delay = options_get_number(&c->session->options, "tmate-display-time");
	tv.tv_sec = delay / 1000;
	tv.tv_usec = (delay % 1000) * 1000L;

	if (event_initialized (&c->message_timer))
		evtimer_del(&c->message_timer);
	evtimer_set(&c->message_timer, status_message_callback, c);
	evtimer_add(&c->message_timer, &tv);

	c->flags |= CLIENT_STATUS | CLIENT_FORCE_STATUS;

	recalculate_sizes();
}

void __tmate_status_message(const char *fmt, va_list ap)
{
	struct client *c;
	unsigned int i;
	char *message;

	xvasprintf(&message, fmt, ap);
	tmate_debug("%s", message);

	for (i = 0; i < ARRAY_LENGTH(&clients); i++) {
		c = ARRAY_ITEM(&clients, i);
		if (c && !(c->flags & CLIENT_READONLY))
			tmate_status_message_client(c, message);
	}

	free(message);
}

void printflike1 tmate_status_message(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__tmate_status_message(fmt, ap);
	va_end(ap);
}
