/* $OpenBSD$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicholas.marriott@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tmux.h"

static FILE	*log_file;
static int	 log_level;

static void	 log_event_cb(int, const char *);
static void	 log_vwrite(const char *, va_list);

static int is_log_stdout(void)
{
	return fileno(log_file) <= 2;
}

/* Log callback for libevent. */
static void
log_event_cb(__unused int severity, const char *msg)
{
	log_debug("%s", msg);
}

/* Increment log level. */
void
log_add_level(void)
{
	log_level++;
}

/* Get log level. */
int
log_get_level(void)
{
	return (log_level);
}

void
log_open_fp(FILE *f)
{
	if (log_file == f)
		return;

	if (log_file != NULL && !is_log_stdout())
		fclose(log_file);

	log_file = f;

	setvbuf(log_file, NULL, _IOLBF, 0);
	event_set_log_callback(log_event_cb);
}

/* Open logging to file. */
void
log_open(const char *name)
{
	char	*path;

	if (log_level == 0)
		return;

	xasprintf(&path, "tmate-%s-%ld.log", name, (long)getpid());
	FILE *f = fopen(path, "w");
	free(path);
	if (f)
		log_open_fp(f);
}

/* Close logging. */
void
log_close(void)
{
	if (log_file != NULL && !is_log_stdout())
		fclose(log_file);
	log_file = NULL;

	event_set_log_callback(NULL);
}

/* Write a log message. */
__attribute__((__format__(__printf__, 1, 0)))
static void
log_vwrite(const char *msg, va_list ap)
{
	char		*fmt, *out;
	struct timeval	 tv;

	if (log_file == NULL)
		return;

	if (vasprintf(&fmt, msg, ap) == -1)
		exit(1);
	if (stravis(&out, fmt, VIS_OCTAL|VIS_CSTYLE|VIS_TAB|VIS_NL) == -1)
		exit(1);

	gettimeofday(&tv, NULL);

	if (is_log_stdout()) {
		if (fprintf(log_file, "%s\n", out) == -1)
			exit(1);
	} else {
		if (fprintf(log_file, "%lld.%06d %s\n", (long long)tv.tv_sec,
			    (int)tv.tv_usec, out) == -1)
			exit(1);
	}

	fflush(log_file);

	free(out);
	free(fmt);
}

/* Log a debug message. */
void
log_emit(int level, const char *msg, ...)
{
	va_list	ap;

	if (log_level < level)
		return;

	va_start(ap, msg);
	log_vwrite(msg, ap);
	va_end(ap);
}

/* Log a critical error with error string and die. */
__attribute__((__format__(__printf__, 1, 0)))
__dead void
fatal(const char *msg, ...)
{
	char	*fmt;
	va_list	 ap;

	va_start(ap, msg);
	if (asprintf(&fmt, "fatal: %s: %s", msg, strerror(errno)) == -1)
		exit(1);
	msg = fmt;
	log_vwrite(msg, ap);
	exit(1);
}

/* Log a critical error and die. */
__attribute__((__format__(__printf__, 1, 0)))
__dead void
fatalx(const char *msg, ...)
{
	char	*fmt;
	va_list	 ap;

	va_start(ap, msg);
	if (asprintf(&fmt, "fatal: %s", msg) == -1)
		exit(1);
	msg = fmt;
	log_vwrite(msg, ap);
	exit(1);
}
