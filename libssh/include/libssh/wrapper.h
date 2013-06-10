/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef WRAPPER_H_
#define WRAPPER_H_

#include "config.h"
#include "libssh/libcrypto.h"
#include "libssh/libgcrypt.h"

enum ssh_mac_e {
  SSH_MAC_SHA1=1,
  SSH_MAC_SHA256,
  SSH_MAC_SHA384,
  SSH_MAC_SHA512
};

enum ssh_hmac_e {
  SSH_HMAC_SHA1 = 1,
  SSH_HMAC_MD5
};

enum ssh_des_e {
  SSH_3DES,
  SSH_DES
};

typedef struct ssh_mac_ctx_struct *ssh_mac_ctx;
MD5CTX md5_init(void);
void md5_update(MD5CTX c, const void *data, unsigned long len);
void md5_final(unsigned char *md,MD5CTX c);
SHACTX sha1_init(void);
void sha1_update(SHACTX c, const void *data, unsigned long len);
void sha1_final(unsigned char *md,SHACTX c);
void sha1(unsigned char *digest,int len,unsigned char *hash);
void sha256(unsigned char *digest, int len, unsigned char *hash);

void evp(int nid, unsigned char *digest, int len, unsigned char *hash, unsigned int *hlen);

ssh_mac_ctx ssh_mac_ctx_init(enum ssh_mac_e type);
void ssh_mac_update(ssh_mac_ctx ctx, const void *data, unsigned long len);
void ssh_mac_final(unsigned char *md, ssh_mac_ctx ctx);

HMACCTX hmac_init(const void *key,int len, enum ssh_hmac_e type);
void hmac_update(HMACCTX c, const void *data, unsigned long len);
void hmac_final(HMACCTX ctx,unsigned char *hashmacbuf,unsigned int *len);

int crypt_set_algorithms(ssh_session session, enum ssh_des_e des_type);
int crypt_set_algorithms_server(ssh_session session);
struct ssh_crypto_struct *crypto_new(void);
void crypto_free(struct ssh_crypto_struct *crypto);


#endif /* WRAPPER_H_ */
