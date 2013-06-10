/*
 * callbacks.c - callback functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009      by Andreas Schneider <mail@cynapses.org>
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

#include "config.h"

#include "libssh/callbacks.h"
#include "libssh/session.h"

int ssh_set_callbacks(ssh_session session, ssh_callbacks cb) {
  if (session == NULL || cb == NULL) {
    return SSH_ERROR;
  }
  enter_function();
  if(cb->size <= 0 || cb->size > 1024 * sizeof(void *)){
  	ssh_set_error(session,SSH_FATAL,
  			"Invalid callback passed in (badly initialized)");
  	leave_function();
  	return SSH_ERROR;
  }
  session->common.callbacks = cb;
  leave_function();
  return 0;
}

int ssh_set_channel_callbacks(ssh_channel channel, ssh_channel_callbacks cb) {
  ssh_session session = NULL;
  if (channel == NULL || cb == NULL) {
    return SSH_ERROR;
  }
  session = channel->session;
  enter_function();
  if(cb->size <= 0 || cb->size > 1024 * sizeof(void *)){
  	ssh_set_error(session,SSH_FATAL,
  			"Invalid channel callback passed in (badly initialized)");
  	leave_function();
  	return SSH_ERROR;
  }
  channel->callbacks = cb;
  leave_function();
  return 0;
}
