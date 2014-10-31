/*
 * connect.c - handles connections to ssh servers
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2013 by Aris Adamantiadis
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libssh/libssh.h"
#include "libssh/misc.h"

#ifdef _WIN32
/*
 * Only use Windows API functions available on Windows 2000 SP4 or later.
 * The available constants are in <sdkddkver.h>.
 *  http://msdn.microsoft.com/en-us/library/aa383745.aspx
 *  http://blogs.msdn.com/oldnewthing/archive/2007/04/11/2079137.aspx
 */
#undef _WIN32_WINNT
#ifdef HAVE_WSPIAPI_H
#define _WIN32_WINNT 0x0500 /* _WIN32_WINNT_WIN2K */
#undef NTDDI_VERSION
#define NTDDI_VERSION 0x05000400 /* NTDDI_WIN2KSP4 */
#else
#define _WIN32_WINNT 0x0501 /* _WIN32_WINNT_WINXP */
#undef NTDDI_VERSION
#define NTDDI_VERSION 0x05010000 /* NTDDI_WINXP */
#endif

#if _MSC_VER >= 1400
#include <io.h>
#undef close
#define close _close
#endif /* _MSC_VER */
#include <winsock2.h>
#include <ws2tcpip.h>

/* <wspiapi.h> is necessary for getaddrinfo before Windows XP, but it isn't
 * available on some platforms like MinGW. */
#ifdef HAVE_WSPIAPI_H
#include <wspiapi.h>
#endif

#else /* _WIN32 */

#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#endif /* _WIN32 */

#include "libssh/priv.h"
#include "libssh/socket.h"
#include "libssh/channels.h"
#include "libssh/session.h"
#include "libssh/poll.h"

#ifndef HAVE_GETADDRINFO
#error "Your system must have getaddrinfo()"
#endif

#ifdef _WIN32
#ifndef gai_strerror
char WSAAPI *gai_strerrorA(int code) {
  static char buf[256];

  snprintf(buf, sizeof(buf), "Undetermined error code (%d)", code);

  return buf;
}
#endif /* gai_strerror */
#endif /* _WIN32 */

static int ssh_connect_socket_close(socket_t s){
#ifdef _WIN32
  return closesocket(s);
#else
  return close(s);
#endif
}


static int getai(const char *host, int port, struct addrinfo **ai) {
  const char *service = NULL;
  struct addrinfo hints;
  char s_port[10];

  ZERO_STRUCT(hints);

  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (port == 0) {
    hints.ai_flags = AI_PASSIVE;
  } else {
    snprintf(s_port, sizeof(s_port), "%hu", (unsigned short)port);
    service = s_port;
#ifdef AI_NUMERICSERV
    hints.ai_flags=AI_NUMERICSERV;
#endif
  }

  if (ssh_is_ipaddr(host)) {
    /* this is an IP address */
    SSH_LOG(SSH_LOG_PACKET,"host %s matches an IP address",host);
    hints.ai_flags |= AI_NUMERICHOST;
  }

  return getaddrinfo(host, service, &hints, ai);
}

static int ssh_connect_ai_timeout(ssh_session session, const char *host,
    int port, struct addrinfo *ai, long timeout, long usec, socket_t s) {
  int timeout_ms;
  ssh_pollfd_t fds;
  int rc = 0;
  int ret;
  socklen_t len = sizeof(rc);

  /* I know we're losing some precision. But it's not like poll-like family
   * type of mechanisms are precise up to the microsecond.
   */
  timeout_ms=timeout * 1000 + usec / 1000;

  rc = ssh_socket_set_nonblocking(s);
  if (rc < 0) {
      ssh_set_error(session, SSH_FATAL,
          "Failed to set socket non-blocking for %s:%d", host, port);
      ssh_connect_socket_close(s);
      return -1;
  }

  SSH_LOG(SSH_LOG_RARE, "Trying to connect to host: %s:%d with "
      "timeout %d ms", host, port, timeout_ms);

  /* The return value is checked later */
  connect(s, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(ai);

  fds.fd=s;
  fds.revents=0;
  fds.events=POLLOUT;
#ifdef _WIN32
  fds.events |= POLLWRNORM;
#endif
  rc = ssh_poll(&fds,1,timeout_ms);

  if (rc == 0) {
    /* timeout */
    ssh_set_error(session, SSH_FATAL,
        "Timeout while connecting to %s:%d", host, port);
    ssh_connect_socket_close(s);

    return -1;
  }

  if (rc < 0) {
    ssh_set_error(session, SSH_FATAL,
        "poll error: %s", strerror(errno));
    ssh_connect_socket_close(s);

    return -1;
  }
  rc = -1;

  /* Get connect(2) return code. Zero means no error */
  ret = getsockopt(s, SOL_SOCKET, SO_ERROR,(char *) &rc, &len);
  if (ret < 0 || rc != 0) {
    ssh_set_error(session, SSH_FATAL,
        "Connect to %s:%d failed: %s", host, port, strerror(rc));
    ssh_connect_socket_close(s);

    return -1;
  }

  /* s is connected ? */
  SSH_LOG(SSH_LOG_PACKET, "Socket connected with timeout\n");
  ret = ssh_socket_set_blocking(s);
  if (ret < 0) {
      ssh_set_error(session, SSH_FATAL,
          "Failed to set socket as blocking connecting to %s:%d failed: %s",
          host, port, strerror(errno));
      ssh_connect_socket_close(s);
      return -1;
  }

  return s;
}

/**
 * @internal
 *
 * @brief Connect to an IPv4 or IPv6 host specified by its IP address or
 * hostname.
 *
 * @returns A file descriptor, < 0 on error.
 */
socket_t ssh_connect_host(ssh_session session, const char *host,
    const char *bind_addr, int port, long timeout, long usec) {
  socket_t s = -1;
  int rc;
  struct addrinfo *ai;
  struct addrinfo *itr;

  rc = getai(host, port, &ai);
  if (rc != 0) {
    ssh_set_error(session, SSH_FATAL,
        "Failed to resolve hostname %s (%s)", host, gai_strerror(rc));

    return -1;
  }

  for (itr = ai; itr != NULL; itr = itr->ai_next){
    /* create socket */
    s = socket(itr->ai_family, itr->ai_socktype, itr->ai_protocol);
    if (s < 0) {
      ssh_set_error(session, SSH_FATAL,
          "Socket create failed: %s", strerror(errno));
      continue;
    }

    if (bind_addr) {
      struct addrinfo *bind_ai;
      struct addrinfo *bind_itr;

      SSH_LOG(SSH_LOG_PACKET, "Resolving %s\n", bind_addr);

      rc = getai(bind_addr, 0, &bind_ai);
      if (rc != 0) {
        ssh_set_error(session, SSH_FATAL,
            "Failed to resolve bind address %s (%s)",
            bind_addr,
            gai_strerror(rc));
        freeaddrinfo(ai);
        close(s);

        return -1;
      }

      for (bind_itr = bind_ai; bind_itr != NULL; bind_itr = bind_itr->ai_next) {
        if (bind(s, bind_itr->ai_addr, bind_itr->ai_addrlen) < 0) {
          ssh_set_error(session, SSH_FATAL,
              "Binding local address: %s", strerror(errno));
          continue;
        } else {
          break;
        }
      }
      freeaddrinfo(bind_ai);

      /* Cannot bind to any local addresses */
      if (bind_itr == NULL) {
        ssh_connect_socket_close(s);
        s = -1;
        continue;
      }
    }

    if (timeout || usec) {
      socket_t ret = ssh_connect_ai_timeout(session, host, port, itr,
          timeout, usec, s);

      return ret;
    }

    if (connect(s, itr->ai_addr, itr->ai_addrlen) < 0) {
      ssh_set_error(session, SSH_FATAL, "Connect failed: %s", strerror(errno));
      ssh_connect_socket_close(s);
      s = -1;
      continue;
    } else {
      /* We are connected */
      break;
    }
  }

  freeaddrinfo(ai);

  return s;
}

/**
 * @internal
 *
 * @brief Launches a nonblocking connect to an IPv4 or IPv6 host
 * specified by its IP address or hostname.
 *
 * @returns A file descriptor, < 0 on error.
 * @warning very ugly !!!
 */
socket_t ssh_connect_host_nonblocking(ssh_session session, const char *host,
    const char *bind_addr, int port) {
  socket_t s = -1;
  int rc;
  struct addrinfo *ai;
  struct addrinfo *itr;

  rc = getai(host, port, &ai);
  if (rc != 0) {
    ssh_set_error(session, SSH_FATAL,
        "Failed to resolve hostname %s (%s)", host, gai_strerror(rc));

    return -1;
  }

  for (itr = ai; itr != NULL; itr = itr->ai_next){
    /* create socket */
    s = socket(itr->ai_family, itr->ai_socktype, itr->ai_protocol);
    if (s < 0) {
      ssh_set_error(session, SSH_FATAL,
          "Socket create failed: %s", strerror(errno));
      continue;
    }

    if (bind_addr) {
      struct addrinfo *bind_ai;
      struct addrinfo *bind_itr;

      SSH_LOG(SSH_LOG_PACKET, "Resolving %s\n", bind_addr);

      rc = getai(bind_addr, 0, &bind_ai);
      if (rc != 0) {
        ssh_set_error(session, SSH_FATAL,
            "Failed to resolve bind address %s (%s)",
            bind_addr,
            gai_strerror(rc));
        ssh_connect_socket_close(s);
        s=-1;
        break;
      }

      for (bind_itr = bind_ai; bind_itr != NULL; bind_itr = bind_itr->ai_next) {
        if (bind(s, bind_itr->ai_addr, bind_itr->ai_addrlen) < 0) {
          ssh_set_error(session, SSH_FATAL,
              "Binding local address: %s", strerror(errno));
          continue;
        } else {
          break;
        }
      }
      freeaddrinfo(bind_ai);

      /* Cannot bind to any local addresses */
      if (bind_itr == NULL) {
        ssh_connect_socket_close(s);
        s = -1;
        continue;
      }
    }

    rc = ssh_socket_set_nonblocking(s);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL,
            "Failed to set socket non-blocking for %s:%d", host, port);
        ssh_connect_socket_close(s);
        s = -1;
        continue;
    }

    rc = connect(s, itr->ai_addr, itr->ai_addrlen);
    if (rc == -1 && (errno != EINPROGRESS)) {
      ssh_set_error(session, SSH_FATAL,
          "Failed to connect: %s", strerror(errno));
      ssh_connect_socket_close(s);
      s = -1;
      continue;
    }

    break;
  }

  freeaddrinfo(ai);

  return s;
}

/**
 * @addtogroup libssh_session
 *
 * @{
 */

static int ssh_select_cb (socket_t fd, int revents, void *userdata){
  fd_set *set = (fd_set *)userdata;
  if(revents & POLLIN)
    FD_SET(fd, set);
  return 0;
}

/**
 * @brief A wrapper for the select syscall
 *
 * This functions acts more or less like the select(2) syscall.\n
 * There is no support for writing or exceptions.\n
 *
 * @param[in]  channels Arrays of channels pointers terminated by a NULL.
 *                      It is never rewritten.
 *
 * @param[out] outchannels Arrays of same size that "channels", there is no need
 *                         to initialize it.
 *
 * @param[in]  maxfd    Maximum +1 file descriptor from readfds.
 *
 * @param[in]  readfds  A fd_set of file descriptors to be select'ed for
 *                      reading.
 *
 * @param[in]  timeout  The timeout in milliseconds.
 *
 * @return              SSH_OK on success,
 *                      SSH_ERROR on error,
 *                      SSH_EINTR if it was interrupted. In that case,
 *                      just restart it.
 *
 * @warning libssh is not reentrant here. That means that if a signal is caught
 *          during the processing of this function, you cannot call libssh
 *          functions on sessions that are busy with ssh_select().
 *
 * @see select(2)
 */
int ssh_select(ssh_channel *channels, ssh_channel *outchannels, socket_t maxfd,
    fd_set *readfds, struct timeval *timeout) {
  fd_set origfds;
  socket_t fd;
  int i,j;
  int rc;
  int base_tm, tm;
  struct ssh_timestamp ts;
  ssh_event event = ssh_event_new();
  int firstround=1;

  base_tm = tm=timeout->tv_sec * 1000 + timeout->tv_usec/1000;
  for (i=0 ; channels[i] != NULL; ++i){
    ssh_event_add_session(event, channels[i]->session);
  }

  FD_ZERO(&origfds);
  for (fd = 0; fd < maxfd ; fd++) {
      if (FD_ISSET(fd, readfds)) {
          ssh_event_add_fd(event, fd, POLLIN, ssh_select_cb, readfds);
          FD_SET(fd, &origfds);
      }
  }
  outchannels[0] = NULL;
  FD_ZERO(readfds);
  ssh_timestamp_init(&ts);
  do {
    /* Poll every channel */
    j = 0;
    for (i = 0; channels[i]; i++) {
      if(ssh_channel_poll(channels[i], 0) != 0) {
        outchannels[j] = channels[i];
        j++;
      } else if(ssh_channel_poll(channels[i], 1) != 0) {
        outchannels[j] = channels[i];
        j++;
      }
    }
    outchannels[j] = NULL;
    if(j != 0)
      break;
    /* watch if a user socket was triggered */
    for (fd = 0; fd < maxfd; fd++) {
        if (FD_ISSET(fd, readfds)) {
            goto out;
        }
    }

    /* If the timeout is elapsed, we should go out */
    if(!firstround && ssh_timeout_elapsed(&ts, base_tm))
      goto out;
    /* since there's nothing, let's fire the polling */
    rc = ssh_event_dopoll(event,tm);
    if (rc == SSH_ERROR){
      goto out;
    }
    tm = ssh_timeout_update(&ts, base_tm);
    firstround=0;
  } while (1);
out:
  for (fd = 0; fd < maxfd; fd++) {
    if (FD_ISSET(fd, &origfds)) {
      ssh_event_remove_fd(event, fd);
    }
  }
  ssh_event_free(event);
  return SSH_OK;
}

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
