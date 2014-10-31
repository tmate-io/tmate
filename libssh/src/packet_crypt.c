/*
 * crypt.c - blowfish-cbc code
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003 by Aris Adamantiadis
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
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef OPENSSL_CRYPTO
#include <openssl/blowfish.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/wrapper.h"
#include "libssh/crypto.h"
#include "libssh/buffer.h"

uint32_t packet_decrypt_len(ssh_session session, char *crypted){
  uint32_t decrypted;

  if (session->current_crypto) {
    if (packet_decrypt(session, crypted,
          session->current_crypto->in_cipher->blocksize) < 0) {
      return 0;
    }
  }
  memcpy(&decrypted,crypted,sizeof(decrypted));
  return ntohl(decrypted);
}

int packet_decrypt(ssh_session session, void *data,uint32_t len) {
  struct ssh_cipher_struct *crypto = session->current_crypto->in_cipher;
  char *out = NULL;

  assert(len);

  if(len % session->current_crypto->in_cipher->blocksize != 0){
    ssh_set_error(session, SSH_FATAL, "Cryptographic functions must be set on at least one blocksize (received %d)",len);
    return SSH_ERROR;
  }
  out = malloc(len);
  if (out == NULL) {
    return -1;
  }

  if (crypto->set_decrypt_key(crypto, session->current_crypto->decryptkey,
        session->current_crypto->decryptIV) < 0) {
    SAFE_FREE(out);
    return -1;
  }
  crypto->decrypt(crypto,data,out,len);

  memcpy(data,out,len);
  BURN_BUFFER(out, len);
  SAFE_FREE(out);
  return 0;
}

unsigned char *packet_encrypt(ssh_session session, void *data, uint32_t len) {
  struct ssh_cipher_struct *crypto = NULL;
  HMACCTX ctx = NULL;
  char *out = NULL;
  unsigned int finallen;
  uint32_t seq;
  enum ssh_hmac_e type;

  assert(len);

  if (!session->current_crypto) {
    return NULL; /* nothing to do here */
  }
  if(len % session->current_crypto->in_cipher->blocksize != 0){
      ssh_set_error(session, SSH_FATAL, "Cryptographic functions must be set on at least one blocksize (received %d)",len);
      return NULL;
  }
  out = malloc(len);
  if (out == NULL) {
    return NULL;
  }

  type = session->current_crypto->out_hmac;
  seq = ntohl(session->send_seq);
  crypto = session->current_crypto->out_cipher;

  if (crypto->set_encrypt_key(crypto, session->current_crypto->encryptkey,
      session->current_crypto->encryptIV) < 0) {
    SAFE_FREE(out);
    return NULL;
  }

  if (session->version == 2) {
    ctx = hmac_init(session->current_crypto->encryptMAC, hmac_digest_len(type), type);
    if (ctx == NULL) {
      SAFE_FREE(out);
      return NULL;
    }
    hmac_update(ctx,(unsigned char *)&seq,sizeof(uint32_t));
    hmac_update(ctx,data,len);
    hmac_final(ctx,session->current_crypto->hmacbuf,&finallen);
#ifdef DEBUG_CRYPTO
    ssh_print_hexa("mac: ",data,hmac_digest_len(type));
    if (finallen != hmac_digest_len(type)) {
      printf("Final len is %d\n",finallen);
    }
    ssh_print_hexa("Packet hmac", session->current_crypto->hmacbuf, hmac_digest_len(type));
#endif
  }

  crypto->encrypt(crypto, data, out, len);

  memcpy(data, out, len);
  BURN_BUFFER(out, len);
  SAFE_FREE(out);

  if (session->version == 2) {
    return session->current_crypto->hmacbuf;
  }

  return NULL;
}

/**
 * @internal
 *
 * @brief Verify the hmac of a packet
 *
 * @param  session      The session to use.
 * @param  buffer       The buffer to verify the hmac from.
 * @param  mac          The mac to compare with the hmac.
 *
 * @return              0 if hmac and mac are equal, < 0 if not or an error
 *                      occurred.
 */
int packet_hmac_verify(ssh_session session, ssh_buffer buffer,
    unsigned char *mac, enum ssh_hmac_e type) {
  unsigned char hmacbuf[DIGEST_MAX_LEN] = {0};
  HMACCTX ctx;
  unsigned int len;
  uint32_t seq;

  ctx = hmac_init(session->current_crypto->decryptMAC, hmac_digest_len(type), type);
  if (ctx == NULL) {
    return -1;
  }

  seq = htonl(session->recv_seq);

  hmac_update(ctx, (unsigned char *) &seq, sizeof(uint32_t));
  hmac_update(ctx, buffer_get_rest(buffer), buffer_get_rest_len(buffer));
  hmac_final(ctx, hmacbuf, &len);

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("received mac",mac,len);
  ssh_print_hexa("Computed mac",hmacbuf,len);
  ssh_print_hexa("seq",(unsigned char *)&seq,sizeof(uint32_t));
#endif
  if (memcmp(mac, hmacbuf, len) == 0) {
    return 0;
  }

  return -1;
}

/* vim: set ts=2 sw=2 et cindent: */
