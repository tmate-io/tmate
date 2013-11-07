/*
 * knownhosts.c
 * This file contains an example of how verify the identity of a
 * SSH server using libssh
 */

/*
Copyright 2003-2009 Aris Adamantiadis

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libssh/libssh.h>
#include "examples_common.h"

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

int verify_knownhost(ssh_session session){
  char *hexa;
  int state;
  char buf[10];
  unsigned char *hash = NULL;
  size_t hlen;
  ssh_key srv_pubkey;
  int rc;

  state=ssh_is_server_known(session);

  rc = ssh_get_publickey(session, &srv_pubkey);
  if (rc < 0) {
      return -1;
  }

  rc = ssh_get_publickey_hash(srv_pubkey,
                              SSH_PUBLICKEY_HASH_SHA1,
                              &hash,
                              &hlen);
  ssh_key_free(srv_pubkey);
  if (rc < 0) {
      return -1;
  }

  switch(state){
    case SSH_SERVER_KNOWN_OK:
      break; /* ok */
    case SSH_SERVER_KNOWN_CHANGED:
      fprintf(stderr,"Host key for server changed : server's one is now :\n");
      ssh_print_hexa("Public key hash",hash, hlen);
      ssh_clean_pubkey_hash(&hash);
      fprintf(stderr,"For security reason, connection will be stopped\n");
      return -1;
    case SSH_SERVER_FOUND_OTHER:
      fprintf(stderr,"The host key for this server was not found but an other type of key exists.\n");
      fprintf(stderr,"An attacker might change the default server key to confuse your client"
          "into thinking the key does not exist\n"
          "We advise you to rerun the client with -d or -r for more safety.\n");
      return -1;
    case SSH_SERVER_FILE_NOT_FOUND:
      fprintf(stderr,"Could not find known host file. If you accept the host key here,\n");
      fprintf(stderr,"the file will be automatically created.\n");
      /* fallback to SSH_SERVER_NOT_KNOWN behavior */
    case SSH_SERVER_NOT_KNOWN:
      hexa = ssh_get_hexa(hash, hlen);
      fprintf(stderr,"The server is unknown. Do you trust the host key ?\n");
      fprintf(stderr, "Public key hash: %s\n", hexa);
      ssh_string_free_char(hexa);
      if (fgets(buf, sizeof(buf), stdin) == NULL) {
	    ssh_clean_pubkey_hash(&hash);
        return -1;
      }
      if(strncasecmp(buf,"yes",3)!=0){
	    ssh_clean_pubkey_hash(&hash);
        return -1;
      }
      fprintf(stderr,"This new key will be written on disk for further usage. do you agree ?\n");
      if (fgets(buf, sizeof(buf), stdin) == NULL) {
	    ssh_clean_pubkey_hash(&hash);
        return -1;
      }
      if(strncasecmp(buf,"yes",3)==0){
        if (ssh_write_knownhost(session) < 0) {
          ssh_clean_pubkey_hash(&hash);
          fprintf(stderr, "error %s\n", strerror(errno));
          return -1;
        }
      }

      break;
    case SSH_SERVER_ERROR:
      ssh_clean_pubkey_hash(&hash);
      fprintf(stderr,"%s",ssh_get_error(session));
      return -1;
  }
  ssh_clean_pubkey_hash(&hash);
  return 0;
}
