/*
 * sftp.c - Secure FTP functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2005-2008 by Aris Adamantiadis
 * Copyright (c) 2008-2009 by Andreas Schneider <asn@cryptomilk.org>
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

/* This file contains code written by Nick Zitzmann */

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#define S_IFSOCK 0140000
#define S_IFLNK  0120000

#ifdef _MSC_VER
#define S_IFBLK  0060000
#define S_IFIFO  0010000
#endif
#endif

#include "libssh/priv.h"
#include "libssh/ssh2.h"
#include "libssh/sftp.h"
#include "libssh/buffer.h"
#include "libssh/channels.h"
#include "libssh/session.h"
#include "libssh/misc.h"

#ifdef WITH_SFTP

struct sftp_ext_struct {
  unsigned int count;
  char **name;
  char **data;
};

/* functions */
static int sftp_enqueue(sftp_session session, sftp_message msg);
static void sftp_message_free(sftp_message msg);
static void sftp_set_error(sftp_session sftp, int errnum);
static void status_msg_free(sftp_status_message status);

static sftp_ext sftp_ext_new(void) {
  sftp_ext ext;

  ext = malloc(sizeof(struct sftp_ext_struct));
  if (ext == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(ext);

  return ext;
}

static void sftp_ext_free(sftp_ext ext) {
  unsigned int i;

  if (ext == NULL) {
    return;
  }

  if (ext->count) {
    for (i = 0; i < ext->count; i++) {
      SAFE_FREE(ext->name[i]);
      SAFE_FREE(ext->data[i]);
    }
    SAFE_FREE(ext->name);
    SAFE_FREE(ext->data);
  }

  SAFE_FREE(ext);
}

sftp_session sftp_new(ssh_session session){
  sftp_session sftp;

  if (session == NULL) {
    return NULL;
  }

  sftp = malloc(sizeof(struct sftp_session_struct));
  if (sftp == NULL) {
    ssh_set_error_oom(session);

    return NULL;
  }
  ZERO_STRUCTP(sftp);

  sftp->ext = sftp_ext_new();
  if (sftp->ext == NULL) {
    ssh_set_error_oom(session);
    SAFE_FREE(sftp);

    return NULL;
  }

  sftp->session = session;
  sftp->channel = ssh_channel_new(session);
  if (sftp->channel == NULL) {
    SAFE_FREE(sftp);

    return NULL;
  }

  if (ssh_channel_open_session(sftp->channel)) {
    ssh_channel_free(sftp->channel);
    SAFE_FREE(sftp);

    return NULL;
  }

  if (ssh_channel_request_sftp(sftp->channel)) {
    sftp_free(sftp);

    return NULL;
  }

  return sftp;
}

sftp_session sftp_new_channel(ssh_session session, ssh_channel channel){
  sftp_session sftp;

  if (session == NULL) {
    return NULL;
  }

  sftp = malloc(sizeof(struct sftp_session_struct));
  if (sftp == NULL) {
    ssh_set_error_oom(session);

    return NULL;
  }
  ZERO_STRUCTP(sftp);

  sftp->ext = sftp_ext_new();
  if (sftp->ext == NULL) {
    ssh_set_error_oom(session);
    SAFE_FREE(sftp);

    return NULL;
  }

  sftp->session = session;
  sftp->channel = channel;

  return sftp;
}

#ifdef WITH_SERVER
sftp_session sftp_server_new(ssh_session session, ssh_channel chan){
  sftp_session sftp = NULL;

  sftp = malloc(sizeof(struct sftp_session_struct));
  if (sftp == NULL) {
    ssh_set_error_oom(session);
    return NULL;
  }
  ZERO_STRUCTP(sftp);

  sftp->session = session;
  sftp->channel = chan;

  return sftp;
}

int sftp_server_init(sftp_session sftp){
  ssh_session session = sftp->session;
  sftp_packet packet = NULL;
  ssh_buffer reply = NULL;
  uint32_t version;

  packet = sftp_packet_read(sftp);
  if (packet == NULL) {
    return -1;
  }

  if (packet->type != SSH_FXP_INIT) {
    ssh_set_error(session, SSH_FATAL,
        "Packet read of type %d instead of SSH_FXP_INIT",
        packet->type);

    sftp_packet_free(packet);
    return -1;
  }

  SSH_LOG(SSH_LOG_PACKET, "Received SSH_FXP_INIT");

  buffer_get_u32(packet->payload, &version);
  version = ntohl(version);
  SSH_LOG(SSH_LOG_PACKET, "Client version: %d", version);
  sftp->client_version = version;

  sftp_packet_free(packet);

  reply = ssh_buffer_new();
  if (reply == NULL) {
    ssh_set_error_oom(session);
    return -1;
  }

  if (buffer_add_u32(reply, ntohl(LIBSFTP_VERSION)) < 0) {
    ssh_set_error_oom(session);
    ssh_buffer_free(reply);
    return -1;
  }

  if (sftp_packet_write(sftp, SSH_FXP_VERSION, reply) < 0) {
    ssh_buffer_free(reply);
    return -1;
  }
  ssh_buffer_free(reply);

  SSH_LOG(SSH_LOG_RARE, "Server version sent");

  if (version > LIBSFTP_VERSION) {
    sftp->version = LIBSFTP_VERSION;
  } else {
    sftp->version=version;
  }

  return 0;
}
#endif /* WITH_SERVER */

void sftp_free(sftp_session sftp){
  sftp_request_queue ptr;

  if (sftp == NULL) {
    return;
  }

  ssh_channel_send_eof(sftp->channel);
  ptr = sftp->queue;
  while(ptr) {
    sftp_request_queue old;
    sftp_message_free(ptr->message);
    old = ptr->next;
    SAFE_FREE(ptr);
    ptr = old;
  }

  ssh_channel_free(sftp->channel);

  SAFE_FREE(sftp->handles);

  sftp_ext_free(sftp->ext);
  ZERO_STRUCTP(sftp);

  SAFE_FREE(sftp);
}

int sftp_packet_write(sftp_session sftp, uint8_t type, ssh_buffer payload){
  int size;

  if (buffer_prepend_data(payload, &type, sizeof(uint8_t)) < 0) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  size = htonl(buffer_get_rest_len(payload));
  if (buffer_prepend_data(payload, &size, sizeof(uint32_t)) < 0) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  size = ssh_channel_write(sftp->channel, buffer_get_rest(payload),
      buffer_get_rest_len(payload));
  if (size < 0) {
    return -1;
  } else if((uint32_t) size != buffer_get_rest_len(payload)) {
    SSH_LOG(SSH_LOG_PACKET,
        "Had to write %d bytes, wrote only %d",
        buffer_get_rest_len(payload),
        size);
  }

  return size;
}

sftp_packet sftp_packet_read(sftp_session sftp) {
  unsigned char buffer[MAX_BUF_SIZE];
  sftp_packet packet = NULL;
  uint32_t size;
  int r;

  packet = malloc(sizeof(struct sftp_packet_struct));
  if (packet == NULL) {
    ssh_set_error_oom(sftp->session);
    return NULL;
  }
  packet->sftp = sftp;
  packet->payload = ssh_buffer_new();
  if (packet->payload == NULL) {
    ssh_set_error_oom(sftp->session);
    SAFE_FREE(packet);
    return NULL;
  }

  r=ssh_channel_read(sftp->channel, buffer, 4, 0);
  if (r < 0) {
    ssh_buffer_free(packet->payload);
    SAFE_FREE(packet);
    return NULL;
  }
  ssh_buffer_add_data(packet->payload, buffer, r);
  if (buffer_get_u32(packet->payload, &size) != sizeof(uint32_t)) {
    ssh_set_error(sftp->session, SSH_FATAL, "Short sftp packet!");
    ssh_buffer_free(packet->payload);
    SAFE_FREE(packet);
    return NULL;
  }

  size = ntohl(size);
  r=ssh_channel_read(sftp->channel, buffer, 1, 0);
  if (r <= 0) {
    /* TODO: check if there are cases where an error needs to be set here */
    ssh_buffer_free(packet->payload);
    SAFE_FREE(packet);
    return NULL;
  }
  ssh_buffer_add_data(packet->payload, buffer, r);
  buffer_get_u8(packet->payload, &packet->type);
  size=size-1;
  while (size>0){
    r=ssh_channel_read(sftp->channel,buffer,
        sizeof(buffer)>size ? size:sizeof(buffer),0);

    if(r <= 0) {
      /* TODO: check if there are cases where an error needs to be set here */
      ssh_buffer_free(packet->payload);
      SAFE_FREE(packet);
      return NULL;
    }
    if (ssh_buffer_add_data(packet->payload, buffer, r) == SSH_ERROR) {
      ssh_buffer_free(packet->payload);
      SAFE_FREE(packet);
      ssh_set_error_oom(sftp->session);
      return NULL;
    }
    size -= r;
  }

  return packet;
}

static void sftp_set_error(sftp_session sftp, int errnum) {
  if (sftp != NULL) {
    sftp->errnum = errnum;
  }
}

/* Get the last sftp error */
int sftp_get_error(sftp_session sftp) {
  if (sftp == NULL) {
    return -1;
  }

  return sftp->errnum;
}

static sftp_message sftp_message_new(sftp_session sftp){
  sftp_message msg = NULL;

  msg = malloc(sizeof(struct sftp_message_struct));
  if (msg == NULL) {
    ssh_set_error_oom(sftp->session);
    return NULL;
  }
  ZERO_STRUCTP(msg);

  msg->payload = ssh_buffer_new();
  if (msg->payload == NULL) {
    ssh_set_error_oom(sftp->session);
    SAFE_FREE(msg);
    return NULL;
  }
  msg->sftp = sftp;

  return msg;
}

static void sftp_message_free(sftp_message msg) {
  if (msg == NULL) {
    return;
  }

  ssh_buffer_free(msg->payload);
  SAFE_FREE(msg);
}

static sftp_message sftp_get_message(sftp_packet packet) {
  sftp_session sftp = packet->sftp;
  sftp_message msg = NULL;
  int rc;

  msg = sftp_message_new(sftp);
  if (msg == NULL) {
    return NULL;
  }

  msg->sftp = packet->sftp;
  msg->packet_type = packet->type;

  if ((packet->type != SSH_FXP_STATUS) && (packet->type!=SSH_FXP_HANDLE) &&
      (packet->type != SSH_FXP_DATA) && (packet->type != SSH_FXP_ATTRS) &&
      (packet->type != SSH_FXP_NAME) && (packet->type != SSH_FXP_EXTENDED_REPLY)) {
    ssh_set_error(packet->sftp->session, SSH_FATAL,
        "Unknown packet type %d", packet->type);
    sftp_message_free(msg);
    return NULL;
  }

  rc = ssh_buffer_unpack(packet->payload, "d", &msg->id);
  if (rc != SSH_OK) {
    ssh_set_error(packet->sftp->session, SSH_FATAL,
        "Invalid packet %d: no ID", packet->type);
    sftp_message_free(msg);
    return NULL;
  }

  SSH_LOG(SSH_LOG_PACKET,
      "Packet with id %d type %d",
      msg->id,
      msg->packet_type);

  if (ssh_buffer_add_data(msg->payload, buffer_get_rest(packet->payload),
        buffer_get_rest_len(packet->payload)) < 0) {
    ssh_set_error_oom(sftp->session);
    sftp_message_free(msg);
    return NULL;
  }

  return msg;
}

static int sftp_read_and_dispatch(sftp_session sftp) {
  sftp_packet packet = NULL;
  sftp_message msg = NULL;

  packet = sftp_packet_read(sftp);
  if (packet == NULL) {
    return -1; /* something nasty happened reading the packet */
  }

  msg = sftp_get_message(packet);
  sftp_packet_free(packet);
  if (msg == NULL) {
    return -1;
  }

  if (sftp_enqueue(sftp, msg) < 0) {
    sftp_message_free(msg);
    return -1;
  }

  return 0;
}

void sftp_packet_free(sftp_packet packet) {
  if (packet == NULL) {
    return;
  }

  ssh_buffer_free(packet->payload);
  free(packet);
}

/* Initialize the sftp session with the server. */
int sftp_init(sftp_session sftp) {
  sftp_packet packet = NULL;
  ssh_buffer buffer = NULL;
  char *ext_name = NULL;
  char *ext_data = NULL;
  uint32_t version;
  int rc;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  rc = ssh_buffer_pack(buffer, "d", LIBSFTP_VERSION);
  if (rc != SSH_OK) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return -1;
  }
  if (sftp_packet_write(sftp, SSH_FXP_INIT, buffer) < 0) {
    ssh_buffer_free(buffer);
    return -1;
  }
  ssh_buffer_free(buffer);

  packet = sftp_packet_read(sftp);
  if (packet == NULL) {
    return -1;
  }

  if (packet->type != SSH_FXP_VERSION) {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received a %d messages instead of SSH_FXP_VERSION", packet->type);
    sftp_packet_free(packet);
    return -1;
  }

  /* TODO: are we sure there are 4 bytes ready? */
  rc = ssh_buffer_unpack(packet->payload, "d", &version);
  if (rc != SSH_OK){
      return -1;
  }
  SSH_LOG(SSH_LOG_RARE,
      "SFTP server version %d",
      version);
  rc = ssh_buffer_unpack(packet->payload, "s", &ext_name);
  while (rc == SSH_OK) {
    int count = sftp->ext->count;

    rc = ssh_buffer_unpack(packet->payload, "s", &ext_data);
    if (rc == SSH_ERROR) {
      break;
    }

    SSH_LOG(SSH_LOG_RARE,
        "SFTP server extension: %s, version: %s",
        ext_name, ext_data);

    count++;
    sftp->ext->name = realloc(sftp->ext->name, count * sizeof(char *));
    if (sftp->ext->name == NULL) {
      ssh_set_error_oom(sftp->session);
      SAFE_FREE(ext_name);
      SAFE_FREE(ext_data);
      return -1;
    }
    sftp->ext->name[count - 1] = ext_name;

    sftp->ext->data = realloc(sftp->ext->data, count * sizeof(char *));
    if (sftp->ext->data == NULL) {
      ssh_set_error_oom(sftp->session);
      SAFE_FREE(ext_name);
      SAFE_FREE(ext_data);
      return -1;
    }
    sftp->ext->data[count - 1] = ext_data;

    sftp->ext->count = count;

    rc = ssh_buffer_unpack(packet->payload, "s", &ext_name);
  }

  sftp_packet_free(packet);

  sftp->version = sftp->server_version = version;


  return 0;
}

unsigned int sftp_extensions_get_count(sftp_session sftp) {
  if (sftp == NULL || sftp->ext == NULL) {
    return 0;
  }

  return sftp->ext->count;
}

const char *sftp_extensions_get_name(sftp_session sftp, unsigned int idx) {
  if (sftp == NULL)
    return NULL;
  if (sftp->ext == NULL || sftp->ext->name == NULL) {
    ssh_set_error_invalid(sftp->session);
    return NULL;
  }

  if (idx > sftp->ext->count) {
    ssh_set_error_invalid(sftp->session);
    return NULL;
  }

  return sftp->ext->name[idx];
}

const char *sftp_extensions_get_data(sftp_session sftp, unsigned int idx) {
  if (sftp == NULL)
    return NULL;
  if (sftp->ext == NULL || sftp->ext->name == NULL) {
    ssh_set_error_invalid(sftp->session);
    return NULL;
  }

  if (idx > sftp->ext->count) {
    ssh_set_error_invalid(sftp->session);
    return NULL;
  }

  return sftp->ext->data[idx];
}

int sftp_extension_supported(sftp_session sftp, const char *name,
    const char *data) {
  int i, n;

  if (sftp == NULL || name == NULL || data == NULL) {
    return 0;
  }

  n = sftp_extensions_get_count(sftp);
  for (i = 0; i < n; i++) {
    const char *ext_name = sftp_extensions_get_name(sftp, i);
    const char *ext_data = sftp_extensions_get_data(sftp, i);

    if (ext_name != NULL && ext_data != NULL &&
        strcmp(ext_name, name) == 0 &&
        strcmp(ext_data, data) == 0) {
      return 1;
    }
  }

  return 0;
}

static sftp_request_queue request_queue_new(sftp_message msg) {
  sftp_request_queue queue = NULL;

  queue = malloc(sizeof(struct sftp_request_queue_struct));
  if (queue == NULL) {
    ssh_set_error_oom(msg->sftp->session);
    return NULL;
  }
  ZERO_STRUCTP(queue);

  queue->message = msg;

  return queue;
}

static void request_queue_free(sftp_request_queue queue) {
  if (queue == NULL) {
    return;
  }

  ZERO_STRUCTP(queue);
  SAFE_FREE(queue);
}

static int sftp_enqueue(sftp_session sftp, sftp_message msg) {
  sftp_request_queue queue = NULL;
  sftp_request_queue ptr;

  queue = request_queue_new(msg);
  if (queue == NULL) {
    return -1;
  }

  SSH_LOG(SSH_LOG_PACKET,
      "Queued msg type %d id %d",
      msg->id, msg->packet_type);

  if(sftp->queue == NULL) {
    sftp->queue = queue;
  } else {
    ptr = sftp->queue;
    while(ptr->next) {
      ptr=ptr->next; /* find end of linked list */
    }
    ptr->next = queue; /* add it on bottom */
  }

  return 0;
}

/*
 * Pulls of a message from the queue based on the ID.
 * Returns NULL if no message has been found.
 */
static sftp_message sftp_dequeue(sftp_session sftp, uint32_t id){
  sftp_request_queue prev = NULL;
  sftp_request_queue queue;
  sftp_message msg;

  if(sftp->queue == NULL) {
    return NULL;
  }

  queue = sftp->queue;
  while (queue) {
    if(queue->message->id == id) {
      /* remove from queue */
      if (prev == NULL) {
        sftp->queue = queue->next;
      } else {
        prev->next = queue->next;
      }
      msg = queue->message;
      request_queue_free(queue);
      SSH_LOG(SSH_LOG_PACKET,
          "Dequeued msg id %d type %d",
          msg->id,
          msg->packet_type);
      return msg;
    }
    prev = queue;
    queue = queue->next;
  }

  return NULL;
}

/*
 * Assigns a new SFTP ID for new requests and assures there is no collision
 * between them.
 * Returns a new ID ready to use in a request
 */
static inline uint32_t sftp_get_new_id(sftp_session session) {
  return ++session->id_counter;
}

static sftp_status_message parse_status_msg(sftp_message msg){
  sftp_status_message status;
  int rc;

  if (msg->packet_type != SSH_FXP_STATUS) {
    ssh_set_error(msg->sftp->session, SSH_FATAL,
        "Not a ssh_fxp_status message passed in!");
    return NULL;
  }

  status = malloc(sizeof(struct sftp_status_message_struct));
  if (status == NULL) {
    ssh_set_error_oom(msg->sftp->session);
    return NULL;
  }
  ZERO_STRUCTP(status);

  status->id = msg->id;
  rc = ssh_buffer_unpack(msg->payload, "d",
          &status->status);
  if (rc != SSH_OK){
    SAFE_FREE(status);
    ssh_set_error(msg->sftp->session, SSH_FATAL,
        "Invalid SSH_FXP_STATUS message");
    return NULL;
  }
  rc = ssh_buffer_unpack(msg->payload, "ss",
          &status->errormsg,
          &status->langmsg);

  if(rc != SSH_OK && msg->sftp->version >=3){
      /* These are mandatory from version 3 */
      SAFE_FREE(status);
      ssh_set_error(msg->sftp->session, SSH_FATAL,
        "Invalid SSH_FXP_STATUS message");
      return NULL;
  }
  if (status->errormsg == NULL)
    status->errormsg = strdup("No error message in packet");
  if (status->langmsg == NULL)
    status->langmsg = strdup("");
  if (status->errormsg == NULL || status->langmsg == NULL) {
    ssh_set_error_oom(msg->sftp->session);
    status_msg_free(status);
    return NULL;
  }

  return status;
}

static void status_msg_free(sftp_status_message status){
  if (status == NULL) {
    return;
  }

  SAFE_FREE(status->errormsg);
  SAFE_FREE(status->langmsg);
  SAFE_FREE(status);
}

static sftp_file parse_handle_msg(sftp_message msg){
  sftp_file file;

  if(msg->packet_type != SSH_FXP_HANDLE) {
    ssh_set_error(msg->sftp->session, SSH_FATAL,
        "Not a ssh_fxp_handle message passed in!");
    return NULL;
  }

  file = malloc(sizeof(struct sftp_file_struct));
  if (file == NULL) {
    ssh_set_error_oom(msg->sftp->session);
    return NULL;
  }
  ZERO_STRUCTP(file);

  file->handle = buffer_get_ssh_string(msg->payload);
  if (file->handle == NULL) {
    ssh_set_error(msg->sftp->session, SSH_FATAL,
        "Invalid SSH_FXP_HANDLE message");
    SAFE_FREE(file);
    return NULL;
  }

  file->sftp = msg->sftp;
  file->offset = 0;
  file->eof = 0;

  return file;
}

/* Open a directory */
sftp_dir sftp_opendir(sftp_session sftp, const char *path){
  sftp_message msg = NULL;
  sftp_file file = NULL;
  sftp_dir dir = NULL;
  sftp_status_message status;
  ssh_string path_s;
  ssh_buffer payload;
  uint32_t id;

  payload = ssh_buffer_new();
  if (payload == NULL) {
    ssh_set_error_oom(sftp->session);
    return NULL;
  }

  path_s = ssh_string_from_char(path);
  if (path_s == NULL) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(payload);
    return NULL;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(payload, htonl(id)) < 0 ||
      buffer_add_ssh_string(payload, path_s) < 0) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(payload);
    ssh_string_free(path_s);
    return NULL;
  }
  ssh_string_free(path_s);

  if (sftp_packet_write(sftp, SSH_FXP_OPENDIR, payload) < 0) {
    ssh_buffer_free(payload);
    return NULL;
  }
  ssh_buffer_free(payload);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      /* something nasty has happened */
      return NULL;
    }
    msg = sftp_dequeue(sftp, id);
  }

  switch (msg->packet_type) {
    case SSH_FXP_STATUS:
      status = parse_status_msg(msg);
      sftp_message_free(msg);
      if (status == NULL) {
        return NULL;
      }
      sftp_set_error(sftp, status->status);
      ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
          "SFTP server: %s", status->errormsg);
      status_msg_free(status);
      return NULL;
    case SSH_FXP_HANDLE:
      file = parse_handle_msg(msg);
      sftp_message_free(msg);
      if (file != NULL) {
        dir = malloc(sizeof(struct sftp_dir_struct));
        if (dir == NULL) {
          ssh_set_error_oom(sftp->session);
          free(file);
          return NULL;
        }
        ZERO_STRUCTP(dir);

        dir->sftp = sftp;
        dir->name = strdup(path);
        if (dir->name == NULL) {
          SAFE_FREE(dir);
          SAFE_FREE(file);
          return NULL;
        }
        dir->handle = file->handle;
        SAFE_FREE(file);
      }
      return dir;
    default:
      ssh_set_error(sftp->session, SSH_FATAL,
          "Received message %d during opendir!", msg->packet_type);
      sftp_message_free(msg);
  }

  return NULL;
}

/*
 * Parse the attributes from a payload from some messages. It is coded on
 * baselines from the protocol version 4.
 * This code is more or less dead but maybe we need it in future.
 */
static sftp_attributes sftp_parse_attr_4(sftp_session sftp, ssh_buffer buf,
    int expectnames) {
  sftp_attributes attr;
  ssh_string owner = NULL;
  ssh_string group = NULL;
  uint32_t flags = 0;
  int ok = 0;

  /* unused member variable */
  (void) expectnames;

  attr = malloc(sizeof(struct sftp_attributes_struct));
  if (attr == NULL) {
    ssh_set_error_oom(sftp->session);
    return NULL;
  }
  ZERO_STRUCTP(attr);

  /* This isn't really a loop, but it is like a try..catch.. */
  do {
    if (buffer_get_u32(buf, &flags) != 4) {
      break;
    }

    flags = ntohl(flags);
    attr->flags = flags;

    if (flags & SSH_FILEXFER_ATTR_SIZE) {
      if (buffer_get_u64(buf, &attr->size) != 8) {
        break;
      }
      attr->size = ntohll(attr->size);
    }

    if (flags & SSH_FILEXFER_ATTR_OWNERGROUP) {
      owner = buffer_get_ssh_string(buf);
      if (owner == NULL) {
        break;
      }
      attr->owner = ssh_string_to_char(owner);
      ssh_string_free(owner);
      if (attr->owner == NULL) {
        break;
      }

      group = buffer_get_ssh_string(buf);
      if (group == NULL) {
        break;
      }
      attr->group = ssh_string_to_char(group);
      ssh_string_free(group);
      if (attr->group == NULL) {
        break;
      }
    }

    if (flags & SSH_FILEXFER_ATTR_PERMISSIONS) {
      if (buffer_get_u32(buf, &attr->permissions) != 4) {
        break;
      }
      attr->permissions = ntohl(attr->permissions);

      /* FIXME on windows! */
      switch (attr->permissions & S_IFMT) {
        case S_IFSOCK:
        case S_IFBLK:
        case S_IFCHR:
        case S_IFIFO:
          attr->type = SSH_FILEXFER_TYPE_SPECIAL;
          break;
        case S_IFLNK:
          attr->type = SSH_FILEXFER_TYPE_SYMLINK;
          break;
        case S_IFREG:
          attr->type = SSH_FILEXFER_TYPE_REGULAR;
          break;
        case S_IFDIR:
          attr->type = SSH_FILEXFER_TYPE_DIRECTORY;
          break;
        default:
          attr->type = SSH_FILEXFER_TYPE_UNKNOWN;
          break;
      }
    }

    if (flags & SSH_FILEXFER_ATTR_ACCESSTIME) {
      if (buffer_get_u64(buf, &attr->atime64) != 8) {
        break;
      }
      attr->atime64 = ntohll(attr->atime64);
    }

    if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) {
      if (buffer_get_u32(buf, &attr->atime_nseconds) != 4) {
        break;
      }
      attr->atime_nseconds = ntohl(attr->atime_nseconds);
    }

    if (flags & SSH_FILEXFER_ATTR_CREATETIME) {
      if (buffer_get_u64(buf, &attr->createtime) != 8) {
        break;
      }
      attr->createtime = ntohll(attr->createtime);
    }

    if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) {
      if (buffer_get_u32(buf, &attr->createtime_nseconds) != 4) {
        break;
      }
      attr->createtime_nseconds = ntohl(attr->createtime_nseconds);
    }

    if (flags & SSH_FILEXFER_ATTR_MODIFYTIME) {
      if (buffer_get_u64(buf, &attr->mtime64) != 8) {
        break;
      }
      attr->mtime64 = ntohll(attr->mtime64);
    }

    if (flags & SSH_FILEXFER_ATTR_SUBSECOND_TIMES) {
      if (buffer_get_u32(buf, &attr->mtime_nseconds) != 4) {
        break;
      }
      attr->mtime_nseconds = ntohl(attr->mtime_nseconds);
    }

    if (flags & SSH_FILEXFER_ATTR_ACL) {
      if ((attr->acl = buffer_get_ssh_string(buf)) == NULL) {
        break;
      }
    }

    if (flags & SSH_FILEXFER_ATTR_EXTENDED) {
      if (buffer_get_u32(buf,&attr->extended_count) != 4) {
        break;
      }
      attr->extended_count = ntohl(attr->extended_count);

      while(attr->extended_count &&
          (attr->extended_type = buffer_get_ssh_string(buf)) &&
          (attr->extended_data = buffer_get_ssh_string(buf))){
        attr->extended_count--;
      }

      if (attr->extended_count) {
        break;
      }
    }
    ok = 1;
  } while (0);

  if (ok == 0) {
    /* break issued somewhere */
    ssh_string_free(attr->acl);
    ssh_string_free(attr->extended_type);
    ssh_string_free(attr->extended_data);
    SAFE_FREE(attr->owner);
    SAFE_FREE(attr->group);
    SAFE_FREE(attr);

    ssh_set_error(sftp->session, SSH_FATAL, "Invalid ATTR structure");

    return NULL;
  }

  return attr;
}

enum sftp_longname_field_e {
  SFTP_LONGNAME_PERM = 0,
  SFTP_LONGNAME_FIXME,
  SFTP_LONGNAME_OWNER,
  SFTP_LONGNAME_GROUP,
  SFTP_LONGNAME_SIZE,
  SFTP_LONGNAME_DATE,
  SFTP_LONGNAME_TIME,
  SFTP_LONGNAME_NAME,
};

static char *sftp_parse_longname(const char *longname,
        enum sftp_longname_field_e longname_field) {
    const char *p, *q;
    size_t len, field = 0;
    char *x;

    p = longname;
    /* Find the beginning of the field which is specified by sftp_longanme_field_e. */
    while(field != longname_field) {
        if(isspace(*p)) {
            field++;
            p++;
            while(*p && isspace(*p)) {
                p++;
            }
        } else {
            p++;
        }
    }

    q = p;
    while (! isspace(*q)) {
        q++;
    }

    /* There is no strndup on windows */
    len = q - p + 1;
    x = malloc(len);
    if (x == NULL) {
      return NULL;
    }

    snprintf(x, len, "%s", p);

    return x;
}

/* sftp version 0-3 code. It is different from the v4 */
/* maybe a paste of the draft is better than the code */
/*
        uint32   flags
        uint64   size           present only if flag SSH_FILEXFER_ATTR_SIZE
        uint32   uid            present only if flag SSH_FILEXFER_ATTR_UIDGID
        uint32   gid            present only if flag SSH_FILEXFER_ATTR_UIDGID
        uint32   permissions    present only if flag SSH_FILEXFER_ATTR_PERMISSIONS
        uint32   atime          present only if flag SSH_FILEXFER_ACMODTIME
        uint32   mtime          present only if flag SSH_FILEXFER_ACMODTIME
        uint32   extended_count present only if flag SSH_FILEXFER_ATTR_EXTENDED
        string   extended_type
        string   extended_data
        ...      more extended data (extended_type - extended_data pairs),
                   so that number of pairs equals extended_count              */
static sftp_attributes sftp_parse_attr_3(sftp_session sftp, ssh_buffer buf,
        int expectname) {
    sftp_attributes attr;
    int rc;

    attr = malloc(sizeof(struct sftp_attributes_struct));
    if (attr == NULL) {
        ssh_set_error_oom(sftp->session);
        return NULL;
    }
    ZERO_STRUCTP(attr);

    if (expectname) {
        rc = ssh_buffer_unpack(buf, "ss",
                &attr->name,
                &attr->longname);
        if (rc != SSH_OK){
            goto error;
        }
        SSH_LOG(SSH_LOG_RARE, "Name: %s", attr->name);

        /* Set owner and group if we talk to openssh and have the longname */
        if (ssh_get_openssh_version(sftp->session)) {
            attr->owner = sftp_parse_longname(attr->longname, SFTP_LONGNAME_OWNER);
            if (attr->owner == NULL) {
                goto error;
            }

            attr->group = sftp_parse_longname(attr->longname, SFTP_LONGNAME_GROUP);
            if (attr->group == NULL) {
                goto error;
            }
        }
    }

    rc = ssh_buffer_unpack(buf, "d", &attr->flags);
    if (rc != SSH_OK){
        goto error;
    }
    SSH_LOG(SSH_LOG_RARE,
            "Flags: %.8lx\n", (long unsigned int) attr->flags);

    if (attr->flags & SSH_FILEXFER_ATTR_SIZE) {
        rc = ssh_buffer_unpack(buf, "q", &attr->size);
        if(rc != SSH_OK) {
            goto error;
        }
        SSH_LOG(SSH_LOG_RARE,
                "Size: %llu\n",
                (long long unsigned int) attr->size);
    }

    if (attr->flags & SSH_FILEXFER_ATTR_UIDGID) {
        rc = ssh_buffer_unpack(buf, "dd",
                &attr->uid,
                &attr->gid);
        if (rc != SSH_OK){
            goto error;
        }
    }

    if (attr->flags & SSH_FILEXFER_ATTR_PERMISSIONS) {
        rc = ssh_buffer_unpack(buf, "d", &attr->permissions);
        if (rc != SSH_OK){
            goto error;
        }

        switch (attr->permissions & S_IFMT) {
        case S_IFSOCK:
        case S_IFBLK:
        case S_IFCHR:
        case S_IFIFO:
            attr->type = SSH_FILEXFER_TYPE_SPECIAL;
            break;
        case S_IFLNK:
            attr->type = SSH_FILEXFER_TYPE_SYMLINK;
            break;
        case S_IFREG:
            attr->type = SSH_FILEXFER_TYPE_REGULAR;
            break;
        case S_IFDIR:
            attr->type = SSH_FILEXFER_TYPE_DIRECTORY;
            break;
        default:
            attr->type = SSH_FILEXFER_TYPE_UNKNOWN;
            break;
        }
    }

    if (attr->flags & SSH_FILEXFER_ATTR_ACMODTIME) {
        rc = ssh_buffer_unpack(buf, "dd",
                &attr->atime,
                &attr->mtime);
        if (rc != SSH_OK){
            goto error;
        }
    }

    if (attr->flags & SSH_FILEXFER_ATTR_EXTENDED) {
        rc = ssh_buffer_unpack(buf, "d", &attr->extended_count);
        if (rc != SSH_OK){
            goto error;
        }

        if (attr->extended_count > 0){
            rc = ssh_buffer_unpack(buf, "ss",
                    &attr->extended_type,
                    &attr->extended_data);
            if (rc != SSH_OK){
                goto error;
            }
            attr->extended_count--;
        }
        /* just ignore the remaining extensions */

        while (attr->extended_count > 0){
            ssh_string tmp1,tmp2;
            rc = ssh_buffer_unpack(buf, "SS", &tmp1, &tmp2);
            if (rc != SSH_OK){
                goto error;
            }
            SAFE_FREE(tmp1);
            SAFE_FREE(tmp2);
            attr->extended_count--;
        }
    }

    return attr;

    error:
    ssh_string_free(attr->extended_type);
    ssh_string_free(attr->extended_data);
    SAFE_FREE(attr->name);
    SAFE_FREE(attr->longname);
    SAFE_FREE(attr->owner);
    SAFE_FREE(attr->group);
    SAFE_FREE(attr);
    ssh_set_error(sftp->session, SSH_FATAL, "Invalid ATTR structure");

    return NULL;
}

/* FIXME is this really needed as a public function? */
int buffer_add_attributes(ssh_buffer buffer, sftp_attributes attr) {
  uint32_t flags = (attr ? attr->flags : 0);
  int rc;

  flags &= (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID |
      SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME);

  rc = ssh_buffer_pack(buffer, "d", flags);
  if (rc != SSH_OK) {
    return -1;
  }

  if (attr != NULL) {
    if (flags & SSH_FILEXFER_ATTR_SIZE) {
      rc = ssh_buffer_pack(buffer, "q", attr->size);
      if (rc != SSH_OK) {
        return -1;
      }
    }

    if (flags & SSH_FILEXFER_ATTR_UIDGID) {
      rc = ssh_buffer_pack(buffer, "dd", attr->uid, attr->gid);
      if (rc != SSH_OK) {
        return -1;
      }
    }

    if (flags & SSH_FILEXFER_ATTR_PERMISSIONS) {
      rc = ssh_buffer_pack(buffer, "d", attr->permissions);
      if (rc != SSH_OK) {
        return -1;
      }
    }

    if (flags & SSH_FILEXFER_ATTR_ACMODTIME) {
      rc = ssh_buffer_pack(buffer, "dd", attr->atime, attr->mtime);
      if (rc != SSH_OK) {
        return -1;
      }
    }
  }
  return 0;
}


sftp_attributes sftp_parse_attr(sftp_session session, ssh_buffer buf,
    int expectname) {
  switch(session->version) {
    case 4:
      return sftp_parse_attr_4(session, buf, expectname);
    case 3:
    case 2:
    case 1:
    case 0:
      return sftp_parse_attr_3(session, buf, expectname);
    default:
      ssh_set_error(session->session, SSH_FATAL,
          "Version %d unsupported by client", session->server_version);
      return NULL;
  }

  return NULL;
}

/* Get the version of the SFTP protocol supported by the server */
int sftp_server_version(sftp_session sftp) {
  return sftp->server_version;
}

/* Get a single file attributes structure of a directory. */
sftp_attributes sftp_readdir(sftp_session sftp, sftp_dir dir) {
  sftp_message msg = NULL;
  sftp_status_message status;
  sftp_attributes attr;
  ssh_buffer payload;
  uint32_t id;

  if (dir->buffer == NULL) {
    payload = ssh_buffer_new();
    if (payload == NULL) {
      ssh_set_error_oom(sftp->session);
      return NULL;
    }

    id = sftp_get_new_id(sftp);
    if (buffer_add_u32(payload, htonl(id)) < 0 ||
        buffer_add_ssh_string(payload, dir->handle) < 0) {
      ssh_set_error_oom(sftp->session);
      ssh_buffer_free(payload);
      return NULL;
    }

    if (sftp_packet_write(sftp, SSH_FXP_READDIR, payload) < 0) {
      ssh_buffer_free(payload);
      return NULL;
    }
    ssh_buffer_free(payload);

    SSH_LOG(SSH_LOG_PACKET,
        "Sent a ssh_fxp_readdir with id %d", id);

    while (msg == NULL) {
      if (sftp_read_and_dispatch(sftp) < 0) {
        /* something nasty has happened */
        return NULL;
      }
      msg = sftp_dequeue(sftp, id);
    }

    switch (msg->packet_type){
      case SSH_FXP_STATUS:
        status = parse_status_msg(msg);
        sftp_message_free(msg);
        if (status == NULL) {
          return NULL;
        }
        sftp_set_error(sftp, status->status);
        switch (status->status) {
          case SSH_FX_EOF:
            dir->eof = 1;
            status_msg_free(status);
            return NULL;
          default:
            break;
        }

        ssh_set_error(sftp->session, SSH_FATAL,
            "Unknown error status: %d", status->status);
        status_msg_free(status);

        return NULL;
      case SSH_FXP_NAME:
        buffer_get_u32(msg->payload, &dir->count);
        dir->count = ntohl(dir->count);
        dir->buffer = msg->payload;
        msg->payload = NULL;
        sftp_message_free(msg);
        break;
      default:
        ssh_set_error(sftp->session, SSH_FATAL,
            "Unsupported message back %d", msg->packet_type);
        sftp_message_free(msg);

        return NULL;
    }
  }

  /* now dir->buffer contains a buffer and dir->count != 0 */
  if (dir->count == 0) {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Count of files sent by the server is zero, which is invalid, or "
        "libsftp bug");
    return NULL;
  }

  SSH_LOG(SSH_LOG_RARE, "Count is %d", dir->count);

  attr = sftp_parse_attr(sftp, dir->buffer, 1);
  if (attr == NULL) {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Couldn't parse the SFTP attributes");
    return NULL;
  }

  dir->count--;
  if (dir->count == 0) {
    ssh_buffer_free(dir->buffer);
    dir->buffer = NULL;
  }

  return attr;
}

/* Tell if the directory has reached EOF (End Of File). */
int sftp_dir_eof(sftp_dir dir) {
  return dir->eof;
}

/* Free a SFTP_ATTRIBUTE handle */
void sftp_attributes_free(sftp_attributes file){
  if (file == NULL) {
    return;
  }

  ssh_string_free(file->acl);
  ssh_string_free(file->extended_data);
  ssh_string_free(file->extended_type);

  SAFE_FREE(file->name);
  SAFE_FREE(file->longname);
  SAFE_FREE(file->group);
  SAFE_FREE(file->owner);

  SAFE_FREE(file);
}

static int sftp_handle_close(sftp_session sftp, ssh_string handle) {
  sftp_status_message status;
  sftp_message msg = NULL;
  ssh_buffer buffer = NULL;
  uint32_t id;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, htonl(id)) < 0 ||
      buffer_add_ssh_string(buffer, handle) < 0) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return -1;
  }
  if (sftp_packet_write(sftp, SSH_FXP_CLOSE ,buffer) < 0) {
    ssh_buffer_free(buffer);
    return -1;
  }
  ssh_buffer_free(buffer);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      /* something nasty has happened */
      return -1;
    }
    msg = sftp_dequeue(sftp,id);
  }

  switch (msg->packet_type) {
    case SSH_FXP_STATUS:
      status = parse_status_msg(msg);
      sftp_message_free(msg);
      if(status == NULL) {
        return -1;
      }
      sftp_set_error(sftp, status->status);
      switch (status->status) {
        case SSH_FX_OK:
          status_msg_free(status);
          return 0;
          break;
        default:
          break;
      }
      ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
          "SFTP server: %s", status->errormsg);
      status_msg_free(status);
      return -1;
    default:
      ssh_set_error(sftp->session, SSH_FATAL,
          "Received message %d during sftp_handle_close!", msg->packet_type);
      sftp_message_free(msg);
  }

  return -1;
}

/* Close an open file handle. */
int sftp_close(sftp_file file){
  int err = SSH_NO_ERROR;

  SAFE_FREE(file->name);
  if (file->handle){
    err = sftp_handle_close(file->sftp,file->handle);
    ssh_string_free(file->handle);
  }
  /* FIXME: check server response and implement errno */
  SAFE_FREE(file);

  return err;
}

/* Close an open directory. */
int sftp_closedir(sftp_dir dir){
  int err = SSH_NO_ERROR;

  SAFE_FREE(dir->name);
  if (dir->handle) {
    err = sftp_handle_close(dir->sftp, dir->handle);
    ssh_string_free(dir->handle);
  }
  /* FIXME: check server response and implement errno */
  ssh_buffer_free(dir->buffer);
  SAFE_FREE(dir);

  return err;
}

/* Open a file on the server. */
sftp_file sftp_open(sftp_session sftp, const char *file, int flags,
    mode_t mode) {
  sftp_message msg = NULL;
  sftp_status_message status;
  struct sftp_attributes_struct attr;
  sftp_file handle;
  ssh_string filename;
  ssh_buffer buffer;
  uint32_t sftp_flags = 0;
  uint32_t id;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return NULL;
  }

  filename = ssh_string_from_char(file);
  if (filename == NULL) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return NULL;
  }

  ZERO_STRUCT(attr);
  attr.permissions = mode;
  attr.flags = SSH_FILEXFER_ATTR_PERMISSIONS;

  if (flags == O_RDONLY)
    sftp_flags |= SSH_FXF_READ; /* if any of the other flag is set,
                                   READ should not be set initialy */
  if (flags & O_WRONLY)
    sftp_flags |= SSH_FXF_WRITE;
  if (flags & O_RDWR)
    sftp_flags |= (SSH_FXF_WRITE | SSH_FXF_READ);
  if (flags & O_CREAT)
    sftp_flags |= SSH_FXF_CREAT;
  if (flags & O_TRUNC)
    sftp_flags |= SSH_FXF_TRUNC;
  if (flags & O_EXCL)
    sftp_flags |= SSH_FXF_EXCL;
  SSH_LOG(SSH_LOG_PACKET,"Opening file %s with sftp flags %x",file,sftp_flags);
  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, htonl(id)) < 0 ||
      buffer_add_ssh_string(buffer, filename) < 0) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    ssh_string_free(filename);
    return NULL;
  }
  ssh_string_free(filename);

  if (buffer_add_u32(buffer, htonl(sftp_flags)) < 0 ||
      buffer_add_attributes(buffer, &attr) < 0) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return NULL;
  }
  if (sftp_packet_write(sftp, SSH_FXP_OPEN, buffer) < 0) {
    ssh_buffer_free(buffer);
    return NULL;
  }
  ssh_buffer_free(buffer);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      /* something nasty has happened */
      return NULL;
    }
    msg = sftp_dequeue(sftp, id);
  }

  switch (msg->packet_type) {
    case SSH_FXP_STATUS:
      status = parse_status_msg(msg);
      sftp_message_free(msg);
      if (status == NULL) {
        return NULL;
      }
      sftp_set_error(sftp, status->status);
      ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
          "SFTP server: %s", status->errormsg);
      status_msg_free(status);

      return NULL;
    case SSH_FXP_HANDLE:
      handle = parse_handle_msg(msg);
      sftp_message_free(msg);
      return handle;
    default:
      ssh_set_error(sftp->session, SSH_FATAL,
          "Received message %d during open!", msg->packet_type);
      sftp_message_free(msg);
  }

  return NULL;
}

void sftp_file_set_nonblocking(sftp_file handle){
    handle->nonblocking=1;
}
void sftp_file_set_blocking(sftp_file handle){
    handle->nonblocking=0;
}

/* Read from a file using an opened sftp file handle. */
ssize_t sftp_read(sftp_file handle, void *buf, size_t count) {
  sftp_session sftp = handle->sftp;
  sftp_message msg = NULL;
  sftp_status_message status;
  ssh_string datastring;
  ssh_buffer buffer;
  int id;
  int rc;

  if (handle->eof) {
    return 0;
  }

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  id = sftp_get_new_id(handle->sftp);

  rc = ssh_buffer_pack(buffer,
                       "dSqd",
                       id,
                       handle->handle,
                       handle->offset,
                       count);
  if (rc != SSH_OK){
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return -1;
  }
  if (sftp_packet_write(handle->sftp, SSH_FXP_READ, buffer) < 0) {
    ssh_buffer_free(buffer);
    return -1;
  }
  ssh_buffer_free(buffer);

  while (msg == NULL) {
    if (handle->nonblocking) {
      if (ssh_channel_poll(handle->sftp->channel, 0) == 0) {
        /* we cannot block */
        return 0;
      }
    }
    if (sftp_read_and_dispatch(handle->sftp) < 0) {
      /* something nasty has happened */
      return -1;
    }
    msg = sftp_dequeue(handle->sftp, id);
  }

  switch (msg->packet_type) {
    case SSH_FXP_STATUS:
      status = parse_status_msg(msg);
      sftp_message_free(msg);
      if (status == NULL) {
        return -1;
      }
      sftp_set_error(sftp, status->status);
      switch (status->status) {
        case SSH_FX_EOF:
          handle->eof = 1;
          status_msg_free(status);
          return 0;
        default:
          break;
      }
      ssh_set_error(sftp->session,SSH_REQUEST_DENIED,
          "SFTP server: %s", status->errormsg);
      status_msg_free(status);
      return -1;
    case SSH_FXP_DATA:
      datastring = buffer_get_ssh_string(msg->payload);
      sftp_message_free(msg);
      if (datastring == NULL) {
        ssh_set_error(sftp->session, SSH_FATAL,
            "Received invalid DATA packet from sftp server");
        return -1;
      }

      if (ssh_string_len(datastring) > count) {
        ssh_set_error(sftp->session, SSH_FATAL,
            "Received a too big DATA packet from sftp server: "
            "%" PRIdS " and asked for %" PRIdS,
            ssh_string_len(datastring), count);
        ssh_string_free(datastring);
        return -1;
      }
      count = ssh_string_len(datastring);
      handle->offset += count;
      memcpy(buf, ssh_string_data(datastring), count);
      ssh_string_free(datastring);
      return count;
    default:
      ssh_set_error(sftp->session, SSH_FATAL,
          "Received message %d during read!", msg->packet_type);
      sftp_message_free(msg);
      return -1;
  }

  return -1; /* not reached */
}

/* Start an asynchronous read from a file using an opened sftp file handle. */
int sftp_async_read_begin(sftp_file file, uint32_t len){
  sftp_session sftp = file->sftp;
  ssh_buffer buffer;
  uint32_t id;
  int rc;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  id = sftp_get_new_id(sftp);

  rc = ssh_buffer_pack(buffer,
                       "dSqd",
                       id,
                       file->handle,
                       file->offset,
                       len);
  if (rc != SSH_OK) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return -1;
  }
  if (sftp_packet_write(sftp, SSH_FXP_READ, buffer) < 0) {
    ssh_buffer_free(buffer);
    return -1;
  }
  ssh_buffer_free(buffer);

  file->offset += len; /* assume we'll read len bytes */

  return id;
}

/* Wait for an asynchronous read to complete and save the data. */
int sftp_async_read(sftp_file file, void *data, uint32_t size, uint32_t id){
  sftp_session sftp;
  sftp_message msg = NULL;
  sftp_status_message status;
  ssh_string datastring;
  int err = SSH_OK;
  uint32_t len;

  if (file == NULL) {
    return SSH_ERROR;
  }
  sftp = file->sftp;

  if (file->eof) {
    return 0;
  }

  /* handle an existing request */
  while (msg == NULL) {
    if (file->nonblocking){
      if (ssh_channel_poll(sftp->channel, 0) == 0) {
        /* we cannot block */
        return SSH_AGAIN;
      }
    }

    if (sftp_read_and_dispatch(sftp) < 0) {
      /* something nasty has happened */
      return SSH_ERROR;
    }

    msg = sftp_dequeue(sftp,id);
  }

  switch (msg->packet_type) {
    case SSH_FXP_STATUS:
      status = parse_status_msg(msg);
      sftp_message_free(msg);
      if (status == NULL) {
        return -1;
      }
      sftp_set_error(sftp, status->status);
      if (status->status != SSH_FX_EOF) {
        ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
            "SFTP server : %s", status->errormsg);
        err = SSH_ERROR;
      } else {
        file->eof = 1;
      }
      status_msg_free(status);
      return err;
    case SSH_FXP_DATA:
      datastring = buffer_get_ssh_string(msg->payload);
      sftp_message_free(msg);
      if (datastring == NULL) {
        ssh_set_error(sftp->session, SSH_FATAL,
            "Received invalid DATA packet from sftp server");
        return SSH_ERROR;
      }
      if (ssh_string_len(datastring) > size) {
        ssh_set_error(sftp->session, SSH_FATAL,
            "Received a too big DATA packet from sftp server: "
            "%" PRIdS " and asked for %u",
            ssh_string_len(datastring), size);
        ssh_string_free(datastring);
        return SSH_ERROR;
      }
      len = ssh_string_len(datastring);
      /* Update the offset with the correct value */
      file->offset = file->offset - (size - len);
      memcpy(data, ssh_string_data(datastring), len);
      ssh_string_free(datastring);
      return len;
    default:
      ssh_set_error(sftp->session,SSH_FATAL,"Received message %d during read!",msg->packet_type);
      sftp_message_free(msg);
      return SSH_ERROR;
  }

  return SSH_ERROR;
}

ssize_t sftp_write(sftp_file file, const void *buf, size_t count) {
  sftp_session sftp = file->sftp;
  sftp_message msg = NULL;
  sftp_status_message status;
  ssh_buffer buffer;
  uint32_t id;
  int len;
  int packetlen;
  int rc;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  id = sftp_get_new_id(file->sftp);

  rc = ssh_buffer_pack(buffer,
                       "dSqdP",
                       id,
                       file->handle,
                       file->offset,
                       count, /* len of datastring */
                       (size_t)count, buf);
  if (rc != SSH_OK){
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return -1;
  }
  packetlen=buffer_get_rest_len(buffer);
  len = sftp_packet_write(file->sftp, SSH_FXP_WRITE, buffer);
  ssh_buffer_free(buffer);
  if (len < 0) {
    return -1;
  } else  if (len != packetlen) {
    SSH_LOG(SSH_LOG_PACKET,
        "Could not write as much data as expected");
  }

  while (msg == NULL) {
    if (sftp_read_and_dispatch(file->sftp) < 0) {
      /* something nasty has happened */
      return -1;
    }
    msg = sftp_dequeue(file->sftp, id);
  }

  switch (msg->packet_type) {
    case SSH_FXP_STATUS:
      status = parse_status_msg(msg);
      sftp_message_free(msg);
      if (status == NULL) {
        return -1;
      }
      sftp_set_error(sftp, status->status);
      switch (status->status) {
        case SSH_FX_OK:
          file->offset += count;
          status_msg_free(status);
          return count;
        default:
          break;
      }
      ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
          "SFTP server: %s", status->errormsg);
      file->offset += count;
      status_msg_free(status);
      return -1;
    default:
      ssh_set_error(sftp->session, SSH_FATAL,
          "Received message %d during write!", msg->packet_type);
      sftp_message_free(msg);
      return -1;
  }

  return -1; /* not reached */
}

/* Seek to a specific location in a file. */
int sftp_seek(sftp_file file, uint32_t new_offset) {
  if (file == NULL) {
    return -1;
  }

  file->offset = new_offset;
  file->eof = 0;

  return 0;
}

int sftp_seek64(sftp_file file, uint64_t new_offset) {
  if (file == NULL) {
    return -1;
  }

  file->offset = new_offset;
  file->eof = 0;

  return 0;
}

/* Report current byte position in file. */
unsigned long sftp_tell(sftp_file file) {
  return (unsigned long)file->offset;
}
/* Report current byte position in file. */
uint64_t sftp_tell64(sftp_file file) {
  return (uint64_t) file->offset;
}

/* Rewinds the position of the file pointer to the beginning of the file.*/
void sftp_rewind(sftp_file file) {
  file->offset = 0;
  file->eof = 0;
}

/* code written by Nick */
int sftp_unlink(sftp_session sftp, const char *file) {
  sftp_status_message status = NULL;
  sftp_message msg = NULL;
  ssh_buffer buffer;
  uint32_t id;
  int rc;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  id = sftp_get_new_id(sftp);

  rc = ssh_buffer_pack(buffer,
                       "ds",
                       id,
                       file);
  if (rc != SSH_OK) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return -1;
  }

  if (sftp_packet_write(sftp, SSH_FXP_REMOVE, buffer) < 0) {
    ssh_buffer_free(buffer);
    return -1;
  }
  ssh_buffer_free(buffer);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp)) {
      return -1;
    }
    msg = sftp_dequeue(sftp, id);
  }

  if (msg->packet_type == SSH_FXP_STATUS) {
    /* by specification, this command's only supposed to return SSH_FXP_STATUS */
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return -1;
    }
    sftp_set_error(sftp, status->status);
    switch (status->status) {
      case SSH_FX_OK:
        status_msg_free(status);
        return 0;
      default:
        break;
    }

    /*
     * The status should be SSH_FX_OK if the command was successful, if it
     * didn't, then there was an error
     */
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return -1;
  } else {
    ssh_set_error(sftp->session,SSH_FATAL,
        "Received message %d when attempting to remove file", msg->packet_type);
    sftp_message_free(msg);
  }

  return -1;
}

/* code written by Nick */
int sftp_rmdir(sftp_session sftp, const char *directory) {
  sftp_status_message status = NULL;
  sftp_message msg = NULL;
  ssh_buffer buffer;
  uint32_t id;
  int rc;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  id = sftp_get_new_id(sftp);

  rc = ssh_buffer_pack(buffer,
                       "ds",
                       id,
                       directory);
  if (rc != SSH_OK) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return -1;
  }
  if (sftp_packet_write(sftp, SSH_FXP_RMDIR, buffer) < 0) {
    ssh_buffer_free(buffer);
    return -1;
  }
  ssh_buffer_free(buffer);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return -1;
    }
    msg = sftp_dequeue(sftp, id);
  }

  /* By specification, this command returns SSH_FXP_STATUS */
  if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return -1;
    }
    sftp_set_error(sftp, status->status);
    switch (status->status) {
      case SSH_FX_OK:
        status_msg_free(status);
        return 0;
        break;
      default:
        break;
    }
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return -1;
  } else {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to remove directory",
        msg->packet_type);
    sftp_message_free(msg);
  }

  return -1;
}

/* Code written by Nick */
int sftp_mkdir(sftp_session sftp, const char *directory, mode_t mode) {
  sftp_status_message status = NULL;
  sftp_message msg = NULL;
  sftp_attributes errno_attr = NULL;
  struct sftp_attributes_struct attr;
  ssh_buffer buffer;
  ssh_string path;
  uint32_t id;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  path = ssh_string_from_char(directory);
  if (path == NULL) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return -1;
  }

  ZERO_STRUCT(attr);
  attr.permissions = mode;
  attr.flags = SSH_FILEXFER_ATTR_PERMISSIONS;

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, htonl(id)) < 0 ||
      buffer_add_ssh_string(buffer, path) < 0 ||
      buffer_add_attributes(buffer, &attr) < 0 ||
      sftp_packet_write(sftp, SSH_FXP_MKDIR, buffer) < 0) {
    ssh_buffer_free(buffer);
    ssh_string_free(path);
    return -1;
  }
  ssh_buffer_free(buffer);
  ssh_string_free(path);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return -1;
    }
    msg = sftp_dequeue(sftp, id);
  }

  /* By specification, this command only returns SSH_FXP_STATUS */
  if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return -1;
    }
    sftp_set_error(sftp, status->status);
    switch (status->status) {
      case SSH_FX_FAILURE:
        /*
         * mkdir always returns a failure, even if the path already exists.
         * To be POSIX conform and to be able to map it to EEXIST a stat
         * call is needed here.
         */
        errno_attr = sftp_lstat(sftp, directory);
        if (errno_attr != NULL) {
          SAFE_FREE(errno_attr);
          sftp_set_error(sftp, SSH_FX_FILE_ALREADY_EXISTS);
        }
        break;
      case SSH_FX_OK:
        status_msg_free(status);
        return 0;
        break;
      default:
        break;
    }
    /*
     * The status should be SSH_FX_OK if the command was successful, if it
     * didn't, then there was an error
     */
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return -1;
  } else {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to make directory",
        msg->packet_type);
    sftp_message_free(msg);
  }

  return -1;
}

/* code written by nick */
int sftp_rename(sftp_session sftp, const char *original, const char *newname) {
  sftp_status_message status = NULL;
  sftp_message msg = NULL;
  ssh_buffer buffer;
  uint32_t id;
  int rc;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  id = sftp_get_new_id(sftp);

  rc = ssh_buffer_pack(buffer,
                       "dss",
                       id,
                       original,
                       newname);
  if (rc != SSH_OK) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return -1;
  }

  if (sftp->version >= 4){
      /* POSIX rename atomically replaces newpath, we should do the same
       * only available on >=v4 */
      buffer_add_u32(buffer, SSH_FXF_RENAME_OVERWRITE);
  }

  if (sftp_packet_write(sftp, SSH_FXP_RENAME, buffer) < 0) {
    ssh_buffer_free(buffer);
    return -1;
  }
  ssh_buffer_free(buffer);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return -1;
    }
    msg = sftp_dequeue(sftp, id);
  }

  /* By specification, this command only returns SSH_FXP_STATUS */
  if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return -1;
    }
    sftp_set_error(sftp, status->status);
    switch (status->status) {
      case SSH_FX_OK:
        status_msg_free(status);
        return 0;
      default:
        break;
    }
    /*
     * Status should be SSH_FX_OK if the command was successful, if it didn't,
     * then there was an error
     */
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return -1;
  } else {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to rename",
        msg->packet_type);
    sftp_message_free(msg);
  }

  return -1;
}

/* Code written by Nick */
/* Set file attributes on a file, directory or symbolic link. */
int sftp_setstat(sftp_session sftp, const char *file, sftp_attributes attr) {
  uint32_t id;
  ssh_buffer buffer;
  ssh_string path;
  sftp_message msg = NULL;
  sftp_status_message status = NULL;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  path = ssh_string_from_char(file);
  if (path == NULL) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return -1;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, htonl(id)) < 0 ||
      buffer_add_ssh_string(buffer, path) < 0 ||
      buffer_add_attributes(buffer, attr) < 0) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    ssh_string_free(path);
    return -1;
  }
  if (sftp_packet_write(sftp, SSH_FXP_SETSTAT, buffer) < 0) {
    ssh_buffer_free(buffer);
    ssh_string_free(path);
    return -1;
  }
  ssh_buffer_free(buffer);
  ssh_string_free(path);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return -1;
    }
    msg = sftp_dequeue(sftp, id);
  }

  /* By specification, this command only returns SSH_FXP_STATUS */
  if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return -1;
    }
    sftp_set_error(sftp, status->status);
    switch (status->status) {
      case SSH_FX_OK:
        status_msg_free(status);
        return 0;
      default:
        break;
    }
    /*
     * The status should be SSH_FX_OK if the command was successful, if it
     * didn't, then there was an error
     */
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return -1;
  } else {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to set stats", msg->packet_type);
    sftp_message_free(msg);
  }

  return -1;
}

/* Change the file owner and group */
int sftp_chown(sftp_session sftp, const char *file, uid_t owner, gid_t group) {
	struct sftp_attributes_struct attr;
  ZERO_STRUCT(attr);

  attr.uid = owner;
  attr.gid = group;

  attr.flags = SSH_FILEXFER_ATTR_UIDGID;

  return sftp_setstat(sftp, file, &attr);
}

/* Change permissions of a file */
int sftp_chmod(sftp_session sftp, const char *file, mode_t mode) {
	struct sftp_attributes_struct attr;
  ZERO_STRUCT(attr);
  attr.permissions = mode;
  attr.flags = SSH_FILEXFER_ATTR_PERMISSIONS;

  return sftp_setstat(sftp, file, &attr);
}

/* Change the last modification and access time of a file. */
int sftp_utimes(sftp_session sftp, const char *file,
    const struct timeval *times) {
	struct sftp_attributes_struct attr;
  ZERO_STRUCT(attr);

  attr.atime = times[0].tv_sec;
  attr.atime_nseconds = times[0].tv_usec;

  attr.mtime = times[1].tv_sec;
  attr.mtime_nseconds = times[1].tv_usec;

  attr.flags |= SSH_FILEXFER_ATTR_ACCESSTIME | SSH_FILEXFER_ATTR_MODIFYTIME |
    SSH_FILEXFER_ATTR_SUBSECOND_TIMES;

  return sftp_setstat(sftp, file, &attr);
}

int sftp_symlink(sftp_session sftp, const char *target, const char *dest) {
  sftp_status_message status = NULL;
  sftp_message msg = NULL;
  ssh_buffer buffer;
  uint32_t id;
  int rc;

  if (sftp == NULL)
    return -1;
  if (target == NULL || dest == NULL) {
    ssh_set_error_invalid(sftp->session);
    return -1;
  }

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return -1;
  }

  id = sftp_get_new_id(sftp);

  /* TODO check for version number if they ever fix it. */
  if (ssh_get_openssh_version(sftp->session)) {
      rc = ssh_buffer_pack(buffer,
                           "dss",
                           id,
                           target,
                           dest);
  } else {
      rc = ssh_buffer_pack(buffer,
                           "dss",
                           id,
                           dest,
                           target);
  }
  if (rc != SSH_OK){
      ssh_set_error_oom(sftp->session);
      ssh_buffer_free(buffer);
      return -1;
  }

  if (sftp_packet_write(sftp, SSH_FXP_SYMLINK, buffer) < 0) {
    ssh_buffer_free(buffer);
    return -1;
  }
  ssh_buffer_free(buffer);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return -1;
    }
    msg = sftp_dequeue(sftp, id);
  }

  /* By specification, this command only returns SSH_FXP_STATUS */
  if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return -1;
    }
    sftp_set_error(sftp, status->status);
    switch (status->status) {
      case SSH_FX_OK:
        status_msg_free(status);
        return 0;
      default:
        break;
    }
    /*
     * The status should be SSH_FX_OK if the command was successful, if it
     * didn't, then there was an error
     */
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return -1;
  } else {
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to set stats", msg->packet_type);
    sftp_message_free(msg);
  }

  return -1;
}

char *sftp_readlink(sftp_session sftp, const char *path) {
  sftp_status_message status = NULL;
  sftp_message msg = NULL;
  ssh_string path_s = NULL;
  ssh_string link_s = NULL;
  ssh_buffer buffer;
  char *lnk;
  uint32_t ignored;
  uint32_t id;

  if (sftp == NULL)
    return NULL;
  if (path == NULL) {
    ssh_set_error_invalid(sftp);
    return NULL;
  }
  if (sftp->version < 3){
    ssh_set_error(sftp,SSH_REQUEST_DENIED,"sftp version %d does not support sftp_readlink",sftp->version);
    return NULL;
  }
  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return NULL;
  }

  path_s = ssh_string_from_char(path);
  if (path_s == NULL) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return NULL;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, htonl(id)) < 0 ||
      buffer_add_ssh_string(buffer, path_s) < 0) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    ssh_string_free(path_s);
    return NULL;
  }
  if (sftp_packet_write(sftp, SSH_FXP_READLINK, buffer) < 0) {
    ssh_buffer_free(buffer);
    ssh_string_free(path_s);
    return NULL;
  }
  ssh_buffer_free(buffer);
  ssh_string_free(path_s);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return NULL;
    }
    msg = sftp_dequeue(sftp, id);
  }

  if (msg->packet_type == SSH_FXP_NAME) {
    /* we don't care about "count" */
    buffer_get_u32(msg->payload, &ignored);
    /* we only care about the file name string */
    link_s = buffer_get_ssh_string(msg->payload);
    sftp_message_free(msg);
    if (link_s == NULL) {
      /* TODO: what error to set here? */
      return NULL;
    }
    lnk = ssh_string_to_char(link_s);
    ssh_string_free(link_s);

    return lnk;
  } else if (msg->packet_type == SSH_FXP_STATUS) { /* bad response (error) */
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return NULL;
    }
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
  } else { /* this shouldn't happen */
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to set stats", msg->packet_type);
    sftp_message_free(msg);
  }

  return NULL;
}

static sftp_statvfs_t sftp_parse_statvfs(sftp_session sftp, ssh_buffer buf) {
  sftp_statvfs_t  statvfs;
  int rc;

  statvfs = malloc(sizeof(struct sftp_statvfs_struct));
  if (statvfs == NULL) {
    ssh_set_error_oom(sftp->session);
    return NULL;
  }
  ZERO_STRUCTP(statvfs);

  rc = ssh_buffer_unpack(buf, "qqqqqqqqqqq",
          &statvfs->f_bsize,  /* file system block size */
          &statvfs->f_frsize, /* fundamental fs block size */
          &statvfs->f_blocks, /* number of blocks (unit f_frsize) */
          &statvfs->f_bfree,  /* free blocks in file system */
          &statvfs->f_bavail, /* free blocks for non-root */
          &statvfs->f_files,  /* total file inodes */
          &statvfs->f_ffree,  /* free file inodes */
          &statvfs->f_favail, /* free file inodes for to non-root */
          &statvfs->f_fsid,   /* file system id */
          &statvfs->f_flag,   /* bit mask of f_flag values */
          &statvfs->f_namemax/* maximum filename length */
          );
  if (rc != SSH_OK) {
    SAFE_FREE(statvfs);
    ssh_set_error(sftp->session, SSH_FATAL, "Invalid statvfs structure");
    return NULL;
  }

  return statvfs;
}

sftp_statvfs_t sftp_statvfs(sftp_session sftp, const char *path) {
  sftp_status_message status = NULL;
  sftp_message msg = NULL;
  ssh_string pathstr;
  ssh_string ext;
  ssh_buffer buffer;
  uint32_t id;

  if (sftp == NULL)
    return NULL;
  if (path == NULL) {
    ssh_set_error_invalid(sftp->session);
    return NULL;
  }
  if (sftp->version < 3){
    ssh_set_error(sftp,SSH_REQUEST_DENIED,"sftp version %d does not support sftp_statvfs",sftp->version);
    return NULL;
  }

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return NULL;
  }

  ext = ssh_string_from_char("statvfs@openssh.com");
  if (ext == NULL) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return NULL;
  }

  pathstr = ssh_string_from_char(path);
  if (pathstr == NULL) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    ssh_string_free(ext);
    return NULL;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, htonl(id)) < 0 ||
      buffer_add_ssh_string(buffer, ext) < 0 ||
      buffer_add_ssh_string(buffer, pathstr) < 0) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    ssh_string_free(ext);
    ssh_string_free(pathstr);
    return NULL;
  }
  if (sftp_packet_write(sftp, SSH_FXP_EXTENDED, buffer) < 0) {
    ssh_buffer_free(buffer);
    ssh_string_free(ext);
    ssh_string_free(pathstr);
    return NULL;
  }
  ssh_buffer_free(buffer);
  ssh_string_free(ext);
  ssh_string_free(pathstr);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return NULL;
    }
    msg = sftp_dequeue(sftp, id);
  }

  if (msg->packet_type == SSH_FXP_EXTENDED_REPLY) {
  	sftp_statvfs_t  buf = sftp_parse_statvfs(sftp, msg->payload);
    sftp_message_free(msg);
    if (buf == NULL) {
      return NULL;
    }

    return buf;
  } else if (msg->packet_type == SSH_FXP_STATUS) { /* bad response (error) */
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return NULL;
    }
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
  } else { /* this shouldn't happen */
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to get statvfs", msg->packet_type);
    sftp_message_free(msg);
  }

  return NULL;
}

sftp_statvfs_t sftp_fstatvfs(sftp_file file) {
  sftp_status_message status = NULL;
  sftp_message msg = NULL;
  sftp_session sftp;
  ssh_string ext;
  ssh_buffer buffer;
  uint32_t id;

  if (file == NULL) {
    return NULL;
  }
  sftp = file->sftp;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return NULL;
  }

  ext = ssh_string_from_char("fstatvfs@openssh.com");
  if (ext == NULL) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return NULL;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, htonl(id)) < 0 ||
      buffer_add_ssh_string(buffer, ext) < 0 ||
      buffer_add_ssh_string(buffer, file->handle) < 0) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    ssh_string_free(ext);
    return NULL;
  }
  if (sftp_packet_write(sftp, SSH_FXP_EXTENDED, buffer) < 0) {
    ssh_buffer_free(buffer);
    ssh_string_free(ext);
    return NULL;
  }
  ssh_buffer_free(buffer);
  ssh_string_free(ext);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return NULL;
    }
    msg = sftp_dequeue(sftp, id);
  }

  if (msg->packet_type == SSH_FXP_EXTENDED_REPLY) {
  	sftp_statvfs_t buf = sftp_parse_statvfs(sftp, msg->payload);
    sftp_message_free(msg);
    if (buf == NULL) {
      return NULL;
    }

    return buf;
  } else if (msg->packet_type == SSH_FXP_STATUS) { /* bad response (error) */
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return NULL;
    }
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
  } else { /* this shouldn't happen */
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to set stats", msg->packet_type);
    sftp_message_free(msg);
  }

  return NULL;
}

void sftp_statvfs_free(sftp_statvfs_t statvfs) {
  if (statvfs == NULL) {
    return;
  }

  SAFE_FREE(statvfs);
}

/* another code written by Nick */
char *sftp_canonicalize_path(sftp_session sftp, const char *path) {
  sftp_status_message status = NULL;
  sftp_message msg = NULL;
  ssh_string name = NULL;
  ssh_string pathstr;
  ssh_buffer buffer;
  char *cname;
  uint32_t ignored;
  uint32_t id;

  if (sftp == NULL)
    return NULL;
  if (path == NULL) {
    ssh_set_error_invalid(sftp->session);
    return NULL;
  }

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return NULL;
  }

  pathstr = ssh_string_from_char(path);
  if (pathstr == NULL) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return NULL;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, htonl(id)) < 0 ||
      buffer_add_ssh_string(buffer, pathstr) < 0) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    ssh_string_free(pathstr);
    return NULL;
  }
  if (sftp_packet_write(sftp, SSH_FXP_REALPATH, buffer) < 0) {
    ssh_buffer_free(buffer);
    ssh_string_free(pathstr);
    return NULL;
  }
  ssh_buffer_free(buffer);
  ssh_string_free(pathstr);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return NULL;
    }
    msg = sftp_dequeue(sftp, id);
  }

  if (msg->packet_type == SSH_FXP_NAME) {
    /* we don't care about "count" */
    buffer_get_u32(msg->payload, &ignored);
    /* we only care about the file name string */
    name = buffer_get_ssh_string(msg->payload);
    sftp_message_free(msg);
    if (name == NULL) {
      /* TODO: error message? */
      return NULL;
    }
    cname = ssh_string_to_char(name);
    ssh_string_free(name);
    if (cname == NULL) {
      ssh_set_error_oom(sftp->session);
    }
    return cname;
  } else if (msg->packet_type == SSH_FXP_STATUS) { /* bad response (error) */
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return NULL;
    }
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
  } else { /* this shouldn't happen */
    ssh_set_error(sftp->session, SSH_FATAL,
        "Received message %d when attempting to set stats", msg->packet_type);
    sftp_message_free(msg);
  }

  return NULL;
}

static sftp_attributes sftp_xstat(sftp_session sftp, const char *path,
    int param) {
  sftp_status_message status = NULL;
  sftp_message msg = NULL;
  ssh_string pathstr;
  ssh_buffer buffer;
  uint32_t id;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(sftp->session);
    return NULL;
  }

  pathstr = ssh_string_from_char(path);
  if (pathstr == NULL) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    return NULL;
  }

  id = sftp_get_new_id(sftp);
  if (buffer_add_u32(buffer, htonl(id)) < 0 ||
      buffer_add_ssh_string(buffer, pathstr) < 0) {
    ssh_set_error_oom(sftp->session);
    ssh_buffer_free(buffer);
    ssh_string_free(pathstr);
    return NULL;
  }
  if (sftp_packet_write(sftp, param, buffer) < 0) {
    ssh_buffer_free(buffer);
    ssh_string_free(pathstr);
    return NULL;
  }
  ssh_buffer_free(buffer);
  ssh_string_free(pathstr);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(sftp) < 0) {
      return NULL;
    }
    msg = sftp_dequeue(sftp, id);
  }

  if (msg->packet_type == SSH_FXP_ATTRS) {
    sftp_attributes attr = sftp_parse_attr(sftp, msg->payload, 0);
    sftp_message_free(msg);

    return attr;
  } else if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return NULL;
    }
    sftp_set_error(sftp, status->status);
    ssh_set_error(sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);
    return NULL;
  }
  ssh_set_error(sftp->session, SSH_FATAL,
      "Received mesg %d during stat()", msg->packet_type);
  sftp_message_free(msg);

  return NULL;
}

sftp_attributes sftp_stat(sftp_session session, const char *path) {
  return sftp_xstat(session, path, SSH_FXP_STAT);
}

sftp_attributes sftp_lstat(sftp_session session, const char *path) {
  return sftp_xstat(session, path, SSH_FXP_LSTAT);
}

sftp_attributes sftp_fstat(sftp_file file) {
  sftp_status_message status = NULL;
  sftp_message msg = NULL;
  ssh_buffer buffer;
  uint32_t id;

  buffer = ssh_buffer_new();
  if (buffer == NULL) {
    ssh_set_error_oom(file->sftp->session);
    return NULL;
  }

  id = sftp_get_new_id(file->sftp);
  if (buffer_add_u32(buffer, htonl(id)) < 0 ||
      buffer_add_ssh_string(buffer, file->handle) < 0) {
    ssh_set_error_oom(file->sftp->session);
    ssh_buffer_free(buffer);
    return NULL;
  }
  if (sftp_packet_write(file->sftp, SSH_FXP_FSTAT, buffer) < 0) {
    ssh_buffer_free(buffer);
    return NULL;
  }
  ssh_buffer_free(buffer);

  while (msg == NULL) {
    if (sftp_read_and_dispatch(file->sftp) < 0) {
      return NULL;
    }
    msg = sftp_dequeue(file->sftp, id);
  }

  if (msg->packet_type == SSH_FXP_ATTRS){
    return sftp_parse_attr(file->sftp, msg->payload, 0);
  } else if (msg->packet_type == SSH_FXP_STATUS) {
    status = parse_status_msg(msg);
    sftp_message_free(msg);
    if (status == NULL) {
      return NULL;
    }
    ssh_set_error(file->sftp->session, SSH_REQUEST_DENIED,
        "SFTP server: %s", status->errormsg);
    status_msg_free(status);

    return NULL;
  }
  ssh_set_error(file->sftp->session, SSH_FATAL,
      "Received msg %d during fstat()", msg->packet_type);
  sftp_message_free(msg);

  return NULL;
}

#endif /* WITH_SFTP */
/* vim: set ts=2 sw=2 et cindent: */
