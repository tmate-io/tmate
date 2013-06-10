/*
 * log.c - logging and debugging functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008      by Aris Adamantiadis
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#ifndef _WIN32
#include <sys/time.h>
#else
#include <sys/utime.h>
#endif
#include <time.h>

#include "libssh/priv.h"
#include "libssh/misc.h"
#include "libssh/session.h"

/**
 * @defgroup libssh_log The SSH logging functions.
 * @ingroup libssh
 *
 * Logging functions for debugging and problem resolving.
 *
 * @{
 */

static int current_timestring(int hires, char *buf, size_t len)
{
    char tbuf[64];
    struct timeval tv;
    struct tm *tm;
    time_t t;

    gettimeofday(&tv, NULL);
    t = (time_t) tv.tv_sec;

    tm = localtime(&t);
    if (tm == NULL) {
        return -1;
    }

    if (hires) {
        strftime(tbuf, sizeof(tbuf) - 1, "%Y/%m/%d %H:%M:%S", tm);
        snprintf(buf, len, "%s.%06ld", tbuf, tv.tv_usec);
    } else {
        strftime(tbuf, sizeof(tbuf) - 1, "%Y/%m/%d %H:%M:%S", tm);
        snprintf(buf, len, "%s", tbuf);
    }

    return 0;
}

void ssh_log_function(int verbosity,
                      const char *function,
                      const char *buffer)
{
    char date[64] = {0};
    int rc;

    rc = current_timestring(1, date, sizeof(date));
    if (rc == 0) {
        fprintf(stderr, "[%s, %d] %s", date, verbosity, function);
    } else {
        fprintf(stderr, "[%d] %s", verbosity, function);
    }
    fprintf(stderr, "  %s\n", buffer);
}

/** @internal
 * @brief do the actual work of logging an event
 */

static void do_ssh_log(struct ssh_common_struct *common,
                       int verbosity,
                       const char *function,
                       const char *buffer) {
    if (common->callbacks && common->callbacks->log_function) {
        char buf[1024];

        snprintf(buf, sizeof(buf), "%s: %s", function, buffer);

        common->callbacks->log_function((ssh_session)common,
                                        verbosity,
                                        buf,
                                        common->callbacks->userdata);
        return;
    }

    ssh_log_function(verbosity, function, buffer);
}

/* legacy function */
void ssh_log(ssh_session session,
             int verbosity,
             const char *format, ...)
{
  char buffer[1024];
  va_list va;

  if (verbosity <= session->common.log_verbosity) {
    va_start(va, format);
    vsnprintf(buffer, sizeof(buffer), format, va);
    va_end(va);
    do_ssh_log(&session->common, verbosity, "", buffer);
  }
}

/** @internal
 * @brief log a SSH event with a common pointer
 * @param common       The SSH/bind session.
 * @param verbosity     The verbosity of the event.
 * @param format        The format string of the log entry.
 */
void ssh_log_common(struct ssh_common_struct *common,
                    int verbosity,
                    const char *function,
                    const char *format, ...)
{
    char buffer[1024];
    va_list va;

    if (verbosity <= common->log_verbosity) {
        va_start(va, format);
        vsnprintf(buffer, sizeof(buffer), format, va);
        va_end(va);
        do_ssh_log(common, verbosity, function, buffer);
    }
}

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
