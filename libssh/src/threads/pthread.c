/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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
#include <libssh/callbacks.h>

#ifdef HAVE_PTHREAD

#include <errno.h>
#include <stdlib.h>
#include <pthread.h>

/** @brief Defines the needed callbacks for pthread. Use this if your
 * OS supports libpthread and want to use it for threading.
 * @code
 * #include <libssh/callbacks.h>
 * #include <errno.h>
 * #include <pthread.h>
 * SSH_THREADS_PTHREAD(ssh_pthread_callbacks);
 * int main(){
 *   ssh_init_set_threads_callbacks(&ssh_pthread_callbacks);
 *   ssh_init();
 *   ...
 * }
 * @endcode
 * @param name name of the structure to be declared, containing the
 * callbacks for threading
 *
 */

static int ssh_pthread_mutex_init (void **priv){
  int err = 0;
  *priv = malloc (sizeof (pthread_mutex_t));
  if (*priv==NULL)
    return ENOMEM;
  err = pthread_mutex_init (*priv, NULL);
  if (err != 0){
    free (*priv);
    *priv=NULL;
  }
  return err;
}

static int ssh_pthread_mutex_destroy (void **lock) {
  int err = pthread_mutex_destroy (*lock);
  free (*lock);
  *lock=NULL;
  return err;
}

static int ssh_pthread_mutex_lock (void **lock) {
  return pthread_mutex_lock (*lock);
}

static int ssh_pthread_mutex_unlock (void **lock){
  return pthread_mutex_unlock (*lock);
}

static unsigned long ssh_pthread_thread_id (void){
#if _WIN32
    return (unsigned long) pthread_self().p;
#else
    return (unsigned long) pthread_self();
#endif
}

static struct ssh_threads_callbacks_struct ssh_threads_pthread =
{
		.type="threads_pthread",
    .mutex_init=ssh_pthread_mutex_init,
    .mutex_destroy=ssh_pthread_mutex_destroy,
    .mutex_lock=ssh_pthread_mutex_lock,
    .mutex_unlock=ssh_pthread_mutex_unlock,
    .thread_id=ssh_pthread_thread_id
};

struct ssh_threads_callbacks_struct *ssh_threads_get_pthread(void) {
	return &ssh_threads_pthread;
}

#endif /* HAVE_PTHREAD */
