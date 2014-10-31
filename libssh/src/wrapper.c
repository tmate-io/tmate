/*
 * wrapper.c - wrapper for crytpo functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2013   by Aris Adamantiadis
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

/*
 * Why a wrapper?
 *
 * Let's say you want to port libssh from libcrypto of openssl to libfoo
 * you are going to spend hours to remove every references to SHA1_Update()
 * to libfoo_sha1_update after the work is finished, you're going to have
 * only this file to modify it's not needed to say that your modifications
 * are welcome.
 */

#include "config.h"


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/crypto.h"
#include "libssh/wrapper.h"
#include "libssh/pki.h"

static struct ssh_hmac_struct ssh_hmac_tab[] = {
  { "hmac-sha1",     SSH_HMAC_SHA1 },
  { "hmac-sha2-256", SSH_HMAC_SHA256 },
  { "hmac-sha2-384", SSH_HMAC_SHA384 },
  { "hmac-sha2-512", SSH_HMAC_SHA512 },
  { "hmac-md5",      SSH_HMAC_MD5 },
  { NULL,            0}
};

struct ssh_hmac_struct *ssh_get_hmactab(void) {
  return ssh_hmac_tab;
}

size_t hmac_digest_len(enum ssh_hmac_e type) {
  switch(type) {
    case SSH_HMAC_SHA1:
      return SHA_DIGEST_LEN;
    case SSH_HMAC_SHA256:
      return SHA256_DIGEST_LEN;
    case SSH_HMAC_SHA384:
      return SHA384_DIGEST_LEN;
    case SSH_HMAC_SHA512:
      return SHA512_DIGEST_LEN;
    case SSH_HMAC_MD5:
      return MD5_DIGEST_LEN;
    default:
      return 0;
  }
}

const char *ssh_hmac_type_to_string(enum ssh_hmac_e hmac_type)
{
  int i = 0;
  struct ssh_hmac_struct *ssh_hmactab = ssh_get_hmactab();
  while (ssh_hmactab[i].name && (ssh_hmactab[i].hmac_type != hmac_type)) {
    i++;
  }
  return ssh_hmactab[i].name;
}

/* it allocates a new cipher structure based on its offset into the global table */
static struct ssh_cipher_struct *cipher_new(int offset) {
  struct ssh_cipher_struct *cipher = NULL;

  cipher = malloc(sizeof(struct ssh_cipher_struct));
  if (cipher == NULL) {
    return NULL;
  }

  /* note the memcpy will copy the pointers : so, you shouldn't free them */
  memcpy(cipher, &ssh_get_ciphertab()[offset], sizeof(*cipher));

  return cipher;
}

static void cipher_free(struct ssh_cipher_struct *cipher) {
#ifdef HAVE_LIBGCRYPT
  unsigned int i;
#endif

  if (cipher == NULL) {
    return;
  }

  if(cipher->key) {
#ifdef HAVE_LIBGCRYPT
    for (i = 0; i < (cipher->keylen / sizeof(gcry_cipher_hd_t)); i++) {
      gcry_cipher_close(cipher->key[i]);
    }
#elif defined HAVE_LIBCRYPTO
    /* destroy the key */
    memset(cipher->key, 0, cipher->keylen);
#endif
    SAFE_FREE(cipher->key);
  }
  SAFE_FREE(cipher);
}

struct ssh_crypto_struct *crypto_new(void) {
   struct ssh_crypto_struct *crypto;

  crypto = malloc(sizeof(struct ssh_crypto_struct));
  if (crypto == NULL) {
    return NULL;
  }
  ZERO_STRUCTP(crypto);
  return crypto;
}

void crypto_free(struct ssh_crypto_struct *crypto){
  int i;
  if (crypto == NULL) {
    return;
  }

  SAFE_FREE(crypto->server_pubkey);

  cipher_free(crypto->in_cipher);
  cipher_free(crypto->out_cipher);

  bignum_free(crypto->e);
  bignum_free(crypto->f);
  bignum_free(crypto->x);
  bignum_free(crypto->y);
  bignum_free(crypto->k);
#ifdef HAVE_ECDH
  SAFE_FREE(crypto->ecdh_client_pubkey);
  SAFE_FREE(crypto->ecdh_server_pubkey);
#endif
  if(crypto->session_id != NULL){
    memset(crypto->session_id, '\0', crypto->digest_len);
    SAFE_FREE(crypto->session_id);
  }
  if(crypto->secret_hash != NULL){
    memset(crypto->secret_hash, '\0', crypto->digest_len);
    SAFE_FREE(crypto->secret_hash);
  }
#ifdef WITH_ZLIB
  if (crypto->compress_out_ctx &&
      (deflateEnd(crypto->compress_out_ctx) != 0)) {
    inflateEnd(crypto->compress_out_ctx);
  }
  SAFE_FREE(crypto->compress_out_ctx);

  if (crypto->compress_in_ctx &&
      (deflateEnd(crypto->compress_in_ctx) != 0)) {
    inflateEnd(crypto->compress_in_ctx);
  }
  SAFE_FREE(crypto->compress_in_ctx);
#endif /* WITH_ZLIB */
  if(crypto->encryptIV)
    SAFE_FREE(crypto->encryptIV);
  if(crypto->decryptIV)
    SAFE_FREE(crypto->decryptIV);
  if(crypto->encryptMAC)
    SAFE_FREE(crypto->encryptMAC);
  if(crypto->decryptMAC)
    SAFE_FREE(crypto->decryptMAC);
  if(crypto->encryptkey){
    memset(crypto->encryptkey, 0, crypto->digest_len);
    SAFE_FREE(crypto->encryptkey);
  }
  if(crypto->decryptkey){
    memset(crypto->decryptkey, 0, crypto->digest_len);
    SAFE_FREE(crypto->decryptkey);
  }

  for (i = 0; i < SSH_KEX_METHODS; i++) {
      SAFE_FREE(crypto->client_kex.methods[i]);
      SAFE_FREE(crypto->server_kex.methods[i]);
      SAFE_FREE(crypto->kex_methods[i]);
  }

  BURN_BUFFER(crypto, sizeof(struct ssh_crypto_struct));

  SAFE_FREE(crypto);
}

static int crypt_set_algorithms2(ssh_session session){
  const char *wanted;
  int i = 0;
  struct ssh_cipher_struct *ssh_ciphertab=ssh_get_ciphertab();
  struct ssh_hmac_struct *ssh_hmactab=ssh_get_hmactab();

  /* we must scan the kex entries to find crypto algorithms and set their appropriate structure */
  /* out */
  wanted = session->next_crypto->kex_methods[SSH_CRYPT_C_S];
  while (ssh_ciphertab[i].name && strcmp(wanted, ssh_ciphertab[i].name)) {
    i++;
  }

  if (ssh_ciphertab[i].name == NULL) {
    ssh_set_error(session, SSH_FATAL,
        "crypt_set_algorithms2: no crypto algorithm function found for %s",
        wanted);
      return SSH_ERROR;
  }
  SSH_LOG(SSH_LOG_PACKET, "Set output algorithm to %s", wanted);

  session->next_crypto->out_cipher = cipher_new(i);
  if (session->next_crypto->out_cipher == NULL) {
      ssh_set_error_oom(session);
      return SSH_ERROR;
  }
  i = 0;

  /* we must scan the kex entries to find hmac algorithms and set their appropriate structure */
  /* out */
  wanted = session->next_crypto->kex_methods[SSH_MAC_C_S];
  while (ssh_hmactab[i].name && strcmp(wanted, ssh_hmactab[i].name)) {
    i++;
  }

  if (ssh_hmactab[i].name == NULL) {
    ssh_set_error(session, SSH_FATAL,
        "crypt_set_algorithms2: no hmac algorithm function found for %s",
        wanted);
      return SSH_ERROR;
  }
  SSH_LOG(SSH_LOG_PACKET, "Set HMAC output algorithm to %s", wanted);

  session->next_crypto->out_hmac = ssh_hmactab[i].hmac_type;
  i = 0;

  /* in */
  wanted = session->next_crypto->kex_methods[SSH_CRYPT_S_C];
  while (ssh_ciphertab[i].name && strcmp(wanted, ssh_ciphertab[i].name)) {
    i++;
  }

  if (ssh_ciphertab[i].name == NULL) {
      ssh_set_error(session, SSH_FATAL,
          "Crypt_set_algorithms: no crypto algorithm function found for %s",
          wanted);
      return SSH_ERROR;
  }
  SSH_LOG(SSH_LOG_PACKET, "Set input algorithm to %s", wanted);

  session->next_crypto->in_cipher = cipher_new(i);
  if (session->next_crypto->in_cipher == NULL) {
      ssh_set_error_oom(session);
      return SSH_ERROR;
  }
  i = 0;

  /* we must scan the kex entries to find hmac algorithms and set their appropriate structure */
  wanted = session->next_crypto->kex_methods[SSH_MAC_S_C];
  while (ssh_hmactab[i].name && strcmp(wanted, ssh_hmactab[i].name)) {
    i++;
  }

  if (ssh_hmactab[i].name == NULL) {
    ssh_set_error(session, SSH_FATAL,
        "crypt_set_algorithms2: no hmac algorithm function found for %s",
        wanted);
      return SSH_ERROR;
  }
  SSH_LOG(SSH_LOG_PACKET, "Set HMAC output algorithm to %s", wanted);

  session->next_crypto->in_hmac = ssh_hmactab[i].hmac_type;
  i = 0;

  /* compression */
  if (strcmp(session->next_crypto->kex_methods[SSH_COMP_C_S], "zlib") == 0) {
    session->next_crypto->do_compress_out = 1;
  }
  if (strcmp(session->next_crypto->kex_methods[SSH_COMP_S_C], "zlib") == 0) {
    session->next_crypto->do_compress_in = 1;
  }
  if (strcmp(session->next_crypto->kex_methods[SSH_COMP_C_S], "zlib@openssh.com") == 0) {
    session->next_crypto->delayed_compress_out = 1;
  }
  if (strcmp(session->next_crypto->kex_methods[SSH_COMP_S_C], "zlib@openssh.com") == 0) {
    session->next_crypto->delayed_compress_in = 1;
  }

  return SSH_OK;
}

static int crypt_set_algorithms1(ssh_session session, enum ssh_des_e des_type) {
  int i = 0;
  struct ssh_cipher_struct *ssh_ciphertab=ssh_get_ciphertab();

  /* right now, we force 3des-cbc to be taken */
  while (ssh_ciphertab[i].name && strcmp(ssh_ciphertab[i].name,
        des_type == SSH_DES ? "des-cbc-ssh1" : "3des-cbc-ssh1")) {
    i++;
  }

  if (ssh_ciphertab[i].name == NULL) {
    ssh_set_error(session, SSH_FATAL, "cipher 3des-cbc-ssh1 or des-cbc-ssh1 not found!");
    return SSH_ERROR;
  }

  session->next_crypto->out_cipher = cipher_new(i);
  if (session->next_crypto->out_cipher == NULL) {
    ssh_set_error_oom(session);
    return SSH_ERROR;
  }

  session->next_crypto->in_cipher = cipher_new(i);
  if (session->next_crypto->in_cipher == NULL) {
    ssh_set_error_oom(session);
    return SSH_ERROR;
  }

  return SSH_OK;
}

int crypt_set_algorithms(ssh_session session, enum ssh_des_e des_type) {
  return (session->version == 1) ? crypt_set_algorithms1(session, des_type) :
    crypt_set_algorithms2(session);
}

#ifdef WITH_SERVER
int crypt_set_algorithms_server(ssh_session session){
    char *method = NULL;
    int i = 0;
    struct ssh_cipher_struct *ssh_ciphertab=ssh_get_ciphertab();
    struct ssh_hmac_struct   *ssh_hmactab=ssh_get_hmactab();

    if (session == NULL) {
        return SSH_ERROR;
    }

    /*
     * We must scan the kex entries to find crypto algorithms and set their
     * appropriate structure
     */
    /* out */
    method = session->next_crypto->kex_methods[SSH_CRYPT_S_C];
    while(ssh_ciphertab[i].name && strcmp(method,ssh_ciphertab[i].name))
        i++;
    if(!ssh_ciphertab[i].name){
        ssh_set_error(session,SSH_FATAL,"crypt_set_algorithms_server : "
                "no crypto algorithm function found for %s",method);
        return SSH_ERROR;
    }
    SSH_LOG(SSH_LOG_PACKET,"Set output algorithm %s",method);

    session->next_crypto->out_cipher = cipher_new(i);
    if (session->next_crypto->out_cipher == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    i=0;
    /* in */
    method = session->next_crypto->kex_methods[SSH_CRYPT_C_S];
    while(ssh_ciphertab[i].name && strcmp(method,ssh_ciphertab[i].name))
        i++;
    if(!ssh_ciphertab[i].name){
        ssh_set_error(session,SSH_FATAL,"Crypt_set_algorithms_server :"
                "no crypto algorithm function found for %s",method);
        return SSH_ERROR;
    }
    SSH_LOG(SSH_LOG_PACKET,"Set input algorithm %s",method);

    session->next_crypto->in_cipher = cipher_new(i);
    if (session->next_crypto->in_cipher == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    i=0;

    /* HMAC algorithm selection */
    method = session->next_crypto->kex_methods[SSH_MAC_S_C];
    while (ssh_hmactab[i].name && strcmp(method, ssh_hmactab[i].name)) {
      i++;
    }

    if (ssh_hmactab[i].name == NULL) {
      ssh_set_error(session, SSH_FATAL,
          "crypt_set_algorithms_server: no hmac algorithm function found for %s",
          method);
        return SSH_ERROR;
    }
    SSH_LOG(SSH_LOG_PACKET, "Set HMAC output algorithm to %s", method);

    session->next_crypto->out_hmac = ssh_hmactab[i].hmac_type;
    i=0;

    method = session->next_crypto->kex_methods[SSH_MAC_C_S];
    while (ssh_hmactab[i].name && strcmp(method, ssh_hmactab[i].name)) {
      i++;
    }

    if (ssh_hmactab[i].name == NULL) {
      ssh_set_error(session, SSH_FATAL,
          "crypt_set_algorithms_server: no hmac algorithm function found for %s",
          method);
        return SSH_ERROR;
    }
    SSH_LOG(SSH_LOG_PACKET, "Set HMAC input algorithm to %s", method);

    session->next_crypto->in_hmac = ssh_hmactab[i].hmac_type;
    i=0;

    /* compression */
    method = session->next_crypto->kex_methods[SSH_COMP_C_S];
    if(strcmp(method,"zlib") == 0){
        SSH_LOG(SSH_LOG_PACKET,"enabling C->S compression");
        session->next_crypto->do_compress_in=1;
    }
    if(strcmp(method,"zlib@openssh.com") == 0){
        SSH_LOG(SSH_LOG_PACKET,"enabling C->S delayed compression");

        if (session->flags & SSH_SESSION_FLAG_AUTHENTICATED) {
            session->next_crypto->do_compress_in = 1;
        } else {
            session->next_crypto->delayed_compress_in = 1;
        }
    }

    method = session->next_crypto->kex_methods[SSH_COMP_S_C];
    if(strcmp(method,"zlib") == 0){
        SSH_LOG(SSH_LOG_PACKET, "enabling S->C compression\n");
        session->next_crypto->do_compress_out=1;
    }
    if(strcmp(method,"zlib@openssh.com") == 0){
        SSH_LOG(SSH_LOG_PACKET,"enabling S->C delayed compression\n");

        if (session->flags & SSH_SESSION_FLAG_AUTHENTICATED) {
            session->next_crypto->do_compress_out = 1;
        } else {
            session->next_crypto->delayed_compress_out = 1;
        }
    }

    method = session->next_crypto->kex_methods[SSH_HOSTKEYS];
    session->srv.hostkey = ssh_key_type_from_name(method);

    return SSH_OK;
}

#endif /* WITH_SERVER */
/* vim: set ts=2 sw=2 et cindent: */
