/*
 * kex.c - key exchange
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/dh.h"
#include "libssh/kex.h"
#include "libssh/session.h"
#include "libssh/ssh2.h"
#include "libssh/string.h"
#include "libssh/curve25519.h"

#ifdef HAVE_LIBGCRYPT
# define BLOWFISH "blowfish-cbc,"
# define AES "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,"
# define DES "3des-cbc,des-cbc-ssh1"
#elif defined(HAVE_LIBCRYPTO)
# ifdef HAVE_OPENSSL_BLOWFISH_H
#  define BLOWFISH "blowfish-cbc,"
# else
#  define BLOWFISH ""
# endif
# ifdef HAVE_OPENSSL_AES_H
#  ifdef BROKEN_AES_CTR
#   define AES "aes256-cbc,aes192-cbc,aes128-cbc,"
#  else
#   define AES "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,"
#  endif /* BROKEN_AES_CTR */
# else
#  define AES ""
#  endif
# define DES "3des-cbc,des-cbc-ssh1"
#endif

#ifdef WITH_ZLIB
#define ZLIB "none,zlib,zlib@openssh.com"
#else
#define ZLIB "none"
#endif

#ifdef HAVE_CURVE25519
#define CURVE25519 "curve25519-sha256@libssh.org,"
#else
#define CURVE25519 ""
#endif

#ifdef HAVE_ECDH
#define ECDH "ecdh-sha2-nistp256,"
#define HOSTKEYS "ecdsa-sha2-nistp256,ssh-rsa,ssh-dss"
#else
#define HOSTKEYS "ssh-rsa,ssh-dss"
#define ECDH ""
#endif

#define KEY_EXCHANGE CURVE25519 ECDH "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
#define KEX_METHODS_SIZE 10

/* NOTE: This is a fixed API and the index is defined by ssh_kex_types_e */
static const char *default_methods[] = {
  KEY_EXCHANGE,
  HOSTKEYS,
  AES BLOWFISH DES,
  AES BLOWFISH DES,
  "hmac-sha1",
  "hmac-sha1",
  "none",
  "none",
  "",
  "",
  NULL
};

/* NOTE: This is a fixed API and the index is defined by ssh_kex_types_e */
static const char *supported_methods[] = {
  KEY_EXCHANGE,
  HOSTKEYS,
  AES BLOWFISH DES,
  AES BLOWFISH DES,
  "hmac-sha1",
  "hmac-sha1",
  ZLIB,
  ZLIB,
  "",
  "",
  NULL
};

/* descriptions of the key exchange packet */
static const char *ssh_kex_descriptions[] = {
  "kex algos",
  "server host key algo",
  "encryption client->server",
  "encryption server->client",
  "mac algo client->server",
  "mac algo server->client",
  "compression algo client->server",
  "compression algo server->client",
  "languages client->server",
  "languages server->client",
  NULL
};

/* tokenize will return a token of strings delimited by ",". the first element has to be freed */
static char **tokenize(const char *chain){
    char **tokens;
    int n=1;
    int i=0;
    char *tmp;
    char *ptr;

    tmp = strdup(chain);
    if (tmp == NULL) {
      return NULL;
    }
    ptr = tmp;
    while(*ptr){
        if(*ptr==','){
            n++;
            *ptr=0;
        }
        ptr++;
    }
    /* now n contains the number of tokens, the first possibly empty if the list was empty too e.g. "" */
    tokens=malloc(sizeof(char *) * (n+1) ); /* +1 for the null */
    if (tokens == NULL) {
      SAFE_FREE(tmp);
      return NULL;
    }
    ptr=tmp;
    for(i=0;i<n;i++){
        tokens[i]=ptr;
        while(*ptr)
            ptr++; // find a zero
        ptr++; // then go one step further
    }
    tokens[i]=NULL;
    return tokens;
}

/* same as tokenize(), but with spaces instead of ',' */
/* TODO FIXME rewrite me! */
char **space_tokenize(const char *chain){
    char **tokens;
    int n=1;
    int i=0;
    char *tmp;
    char *ptr;

    tmp = strdup(chain);
    if (tmp == NULL) {
      return NULL;
    }
    ptr = tmp;

    while(*ptr==' ')
        ++ptr; /* skip initial spaces */
    while(*ptr){
        if(*ptr==' '){
            n++; /* count one token per word */
            *ptr=0;
            while(*(ptr+1)==' '){ /* don't count if the tokens have more than 2 spaces */
                *(ptr++)=0;
            }
        }
        ptr++;
    }
    /* now n contains the number of tokens, the first possibly empty if the list was empty too e.g. "" */
    tokens = malloc(sizeof(char *) * (n + 1)); /* +1 for the null */
    if (tokens == NULL) {
      SAFE_FREE(tmp);
      return NULL;
    }
    ptr=tmp; /* we don't pass the initial spaces because the "tmp" pointer is needed by the caller */
                    /* function to free the tokens. */
    for(i=0;i<n;i++){
        tokens[i]=ptr;
        if(i!=n-1){
            while(*ptr)
                ptr++; // find a zero
            while(!*(ptr+1))
                ++ptr; /* if the zero is followed by other zeros, go through them */
            ptr++; // then go one step further
        }
    }
    tokens[i]=NULL;
    return tokens;
}

const char *ssh_kex_get_supported_method(uint32_t algo) {
  if (algo >= KEX_METHODS_SIZE) {
    return NULL;
  }

  return supported_methods[algo];
}

const char *ssh_kex_get_description(uint32_t algo) {
  if (algo >= KEX_METHODS_SIZE) {
    return NULL;
  }

  return ssh_kex_descriptions[algo];
}

/* find_matching gets 2 parameters : a list of available objects (available_d), separated by colons,*/
/* and a list of preferred objects (preferred_d) */
/* it will return a strduped pointer on the first preferred object found in the available objects list */

char *ssh_find_matching(const char *available_d, const char *preferred_d){
    char ** tok_available, **tok_preferred;
    int i_avail, i_pref;
    char *ret;

    if ((available_d == NULL) || (preferred_d == NULL)) {
      return NULL; /* don't deal with null args */
    }

    tok_available = tokenize(available_d);
    if (tok_available == NULL) {
      return NULL;
    }

    tok_preferred = tokenize(preferred_d);
    if (tok_preferred == NULL) {
      SAFE_FREE(tok_available[0]);
      SAFE_FREE(tok_available);
      return NULL;
    }

    for(i_pref=0; tok_preferred[i_pref] ; ++i_pref){
      for(i_avail=0; tok_available[i_avail]; ++i_avail){
        if(strcmp(tok_available[i_avail],tok_preferred[i_pref]) == 0){
          /* match */
          ret=strdup(tok_available[i_avail]);
          /* free the tokens */
          SAFE_FREE(tok_available[0]);
          SAFE_FREE(tok_preferred[0]);
          SAFE_FREE(tok_available);
          SAFE_FREE(tok_preferred);
          return ret;
        }
      }
    }
    SAFE_FREE(tok_available[0]);
    SAFE_FREE(tok_preferred[0]);
    SAFE_FREE(tok_available);
    SAFE_FREE(tok_preferred);
    return NULL;
}

SSH_PACKET_CALLBACK(ssh_packet_kexinit){
	int server_kex=session->server;
  ssh_string str = NULL;
  char *strings[KEX_METHODS_SIZE];
  int i;

  (void)type;
  (void)user;
  memset(strings, 0, sizeof(strings));
  if (session->session_state == SSH_SESSION_STATE_AUTHENTICATED){
      SSH_LOG(SSH_LOG_WARNING, "Other side initiating key re-exchange");
  } else if(session->session_state != SSH_SESSION_STATE_INITIAL_KEX){
  	ssh_set_error(session,SSH_FATAL,"SSH_KEXINIT received in wrong state");
  	goto error;
  }
  if (server_kex) {
      if (buffer_get_data(packet,session->next_crypto->client_kex.cookie,16) != 16) {
        ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: no cookie in packet");
        goto error;
      }

      if (hashbufin_add_cookie(session, session->next_crypto->client_kex.cookie) < 0) {
        ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: adding cookie failed");
        goto error;
      }
  } else {
      if (buffer_get_data(packet,session->next_crypto->server_kex.cookie,16) != 16) {
        ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: no cookie in packet");
        goto error;
      }

      if (hashbufin_add_cookie(session, session->next_crypto->server_kex.cookie) < 0) {
        ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: adding cookie failed");
        goto error;
      }
  }

  for (i = 0; i < KEX_METHODS_SIZE; i++) {
    str = buffer_get_ssh_string(packet);
    if (str == NULL) {
      break;
    }

    if (buffer_add_ssh_string(session->in_hashbuf, str) < 0) {
    	ssh_set_error(session, SSH_FATAL, "Error adding string in hash buffer");
      goto error;
    }

    strings[i] = ssh_string_to_char(str);
    if (strings[i] == NULL) {
    	ssh_set_error_oom(session);
      goto error;
    }
    ssh_string_free(str);
    str = NULL;
  }

  /* copy the server kex info into an array of strings */
  if (server_kex) {
    for (i = 0; i < SSH_KEX_METHODS; i++) {
      session->next_crypto->client_kex.methods[i] = strings[i];
    }
  } else { /* client */
    for (i = 0; i < SSH_KEX_METHODS; i++) {
      session->next_crypto->server_kex.methods[i] = strings[i];
    }
  }

  session->session_state=SSH_SESSION_STATE_KEXINIT_RECEIVED;
  session->dh_handshake_state=DH_STATE_INIT;
  session->ssh_connection_callback(session);
  return SSH_PACKET_USED;
error:
  ssh_string_free(str);
  for (i = 0; i < SSH_KEX_METHODS; i++) {
    SAFE_FREE(strings[i]);
  }

  session->session_state = SSH_SESSION_STATE_ERROR;

  return SSH_PACKET_USED;
}

void ssh_list_kex(struct ssh_kex_struct *kex) {
  int i = 0;

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("session cookie", kex->cookie, 16);
#endif

  for(i = 0; i < SSH_KEX_METHODS; i++) {
    if (kex->methods[i] == NULL) {
      continue;
    }
    SSH_LOG(SSH_LOG_FUNCTIONS, "%s: %s",
        ssh_kex_descriptions[i], kex->methods[i]);
  }
}

/**
 * @brief sets the key exchange parameters to be sent to the server,
 *        in function of the options and available methods.
 */
int set_client_kex(ssh_session session){
    struct ssh_kex_struct *client= &session->next_crypto->client_kex;
    const char *wanted;
    int i;

    ssh_get_random(client->cookie, 16, 0);

    memset(client->methods, 0, KEX_METHODS_SIZE * sizeof(char **));
    for (i = 0; i < KEX_METHODS_SIZE; i++) {
        wanted = session->opts.wanted_methods[i];
        if (wanted == NULL)
            wanted = default_methods[i];
        client->methods[i] = strdup(wanted);
    }

    return SSH_OK;
}

/** @brief Select the different methods on basis of client's and
 * server's kex messages, and watches out if a match is possible.
 */
int ssh_kex_select_methods (ssh_session session){
    struct ssh_kex_struct *server = &session->next_crypto->server_kex;
    struct ssh_kex_struct *client = &session->next_crypto->client_kex;
    int i;

    for (i = 0; i < KEX_METHODS_SIZE; i++) {
        session->next_crypto->kex_methods[i]=ssh_find_matching(server->methods[i],client->methods[i]);
        if(session->next_crypto->kex_methods[i] == NULL && i < SSH_LANG_C_S){
            ssh_set_error(session,SSH_FATAL,"kex error : no match for method %s: server [%s], client [%s]",
                    ssh_kex_descriptions[i],server->methods[i],client->methods[i]);
            return SSH_ERROR;
        } else if ((i >= SSH_LANG_C_S) && (session->next_crypto->kex_methods[i] == NULL)) {
            /* we can safely do that for languages */
            session->next_crypto->kex_methods[i] = strdup("");
        }
    }
    if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group1-sha1") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP1_SHA1;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group14-sha1") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP14_SHA1;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "ecdh-sha2-nistp256") == 0){
      session->next_crypto->kex_type=SSH_KEX_ECDH_SHA2_NISTP256;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "curve25519-sha256@libssh.org") == 0){
      session->next_crypto->kex_type=SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG;
    }

    return SSH_OK;
}


/* this function only sends the predefined set of kex methods */
int ssh_send_kex(ssh_session session, int server_kex) {
  struct ssh_kex_struct *kex = (server_kex ? &session->next_crypto->server_kex :
      &session->next_crypto->client_kex);
  ssh_string str = NULL;
  int i;

  if (buffer_add_u8(session->out_buffer, SSH2_MSG_KEXINIT) < 0) {
    goto error;
  }
  if (buffer_add_data(session->out_buffer, kex->cookie, 16) < 0) {
    goto error;
  }

  if (hashbufout_add_cookie(session) < 0) {
    goto error;
  }

  ssh_list_kex(kex);

  for (i = 0; i < KEX_METHODS_SIZE; i++) {
    str = ssh_string_from_char(kex->methods[i]);
    if (str == NULL) {
      goto error;
    }

    if (buffer_add_ssh_string(session->out_hashbuf, str) < 0) {
      goto error;
    }
    if (buffer_add_ssh_string(session->out_buffer, str) < 0) {
      goto error;
    }
    ssh_string_free(str);
    str = NULL;
  }

  if (buffer_add_u8(session->out_buffer, 0) < 0) {
    goto error;
  }
  if (buffer_add_u32(session->out_buffer, 0) < 0) {
    goto error;
  }

  if (packet_send(session) == SSH_ERROR) {
    return -1;
  }

  return 0;
error:
  buffer_reinit(session->out_buffer);
  buffer_reinit(session->out_hashbuf);
  ssh_string_free(str);

  return -1;
}

/* returns 1 if at least one of the name algos is in the default algorithms table */
int verify_existing_algo(int algo, const char *name){
    char *ptr;
    if(algo>9 || algo <0)
        return -1;
    ptr=ssh_find_matching(supported_methods[algo],name);
    if(ptr){
        free(ptr);
        return 1;
    }
    return 0;
}

/* vim: set ts=2 sw=2 et cindent: */
