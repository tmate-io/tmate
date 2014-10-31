/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/crypto.h"
#include "libssh/wrapper.h"

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>

struct ssh_mac_ctx_struct {
  enum ssh_mac_e mac_type;
  gcry_md_hd_t ctx;
};

static int alloc_key(struct ssh_cipher_struct *cipher) {
    cipher->key = malloc(cipher->keylen);
    if (cipher->key == NULL) {
      return -1;
    }

    return 0;
}

void ssh_reseed(void){
	}

SHACTX sha1_init(void) {
  SHACTX ctx = NULL;
  gcry_md_open(&ctx, GCRY_MD_SHA1, 0);

  return ctx;
}

void sha1_update(SHACTX c, const void *data, unsigned long len) {
  gcry_md_write(c, data, len);
}

void sha1_final(unsigned char *md, SHACTX c) {
  gcry_md_final(c);
  memcpy(md, gcry_md_read(c, 0), SHA_DIGEST_LEN);
  gcry_md_close(c);
}

void sha1(unsigned char *digest, int len, unsigned char *hash) {
  gcry_md_hash_buffer(GCRY_MD_SHA1, hash, digest, len);
}

SHA256CTX sha256_init(void) {
  SHA256CTX ctx = NULL;
  gcry_md_open(&ctx, GCRY_MD_SHA256, 0);

  return ctx;
}

void sha256_update(SHACTX c, const void *data, unsigned long len) {
  gcry_md_write(c, data, len);
}

void sha256_final(unsigned char *md, SHACTX c) {
  gcry_md_final(c);
  memcpy(md, gcry_md_read(c, 0), SHA256_DIGEST_LEN);
  gcry_md_close(c);
}

void sha256(unsigned char *digest, int len, unsigned char *hash){
  gcry_md_hash_buffer(GCRY_MD_SHA256, hash, digest, len);
}

SHA384CTX sha384_init(void) {
  SHA384CTX ctx = NULL;
  gcry_md_open(&ctx, GCRY_MD_SHA384, 0);

  return ctx;
}

void sha384_update(SHACTX c, const void *data, unsigned long len) {
  gcry_md_write(c, data, len);
}

void sha384_final(unsigned char *md, SHACTX c) {
  gcry_md_final(c);
  memcpy(md, gcry_md_read(c, 0), SHA384_DIGEST_LEN);
  gcry_md_close(c);
}

void sha384(unsigned char *digest, int len, unsigned char *hash) {
  gcry_md_hash_buffer(GCRY_MD_SHA384, hash, digest, len);
}

SHA512CTX sha512_init(void) {
  SHA512CTX ctx = NULL;
  gcry_md_open(&ctx, GCRY_MD_SHA512, 0);

  return ctx;
}

void sha512_update(SHACTX c, const void *data, unsigned long len) {
  gcry_md_write(c, data, len);
}

void sha512_final(unsigned char *md, SHACTX c) {
  gcry_md_final(c);
  memcpy(md, gcry_md_read(c, 0), SHA512_DIGEST_LEN);
  gcry_md_close(c);
}

void sha512(unsigned char *digest, int len, unsigned char *hash) {
  gcry_md_hash_buffer(GCRY_MD_SHA512, hash, digest, len);
}

MD5CTX md5_init(void) {
  MD5CTX c = NULL;
  gcry_md_open(&c, GCRY_MD_MD5, 0);

  return c;
}

void md5_update(MD5CTX c, const void *data, unsigned long len) {
    gcry_md_write(c,data,len);
}

void md5_final(unsigned char *md, MD5CTX c) {
  gcry_md_final(c);
  memcpy(md, gcry_md_read(c, 0), MD5_DIGEST_LEN);
  gcry_md_close(c);
}

ssh_mac_ctx ssh_mac_ctx_init(enum ssh_mac_e type){
  ssh_mac_ctx ctx = malloc(sizeof(struct ssh_mac_ctx_struct));
  if (ctx == NULL) {
    return NULL;
  }

  ctx->mac_type=type;
  switch(type){
    case SSH_MAC_SHA1:
      gcry_md_open(&ctx->ctx, GCRY_MD_SHA1, 0);
      break;
    case SSH_MAC_SHA256:
      gcry_md_open(&ctx->ctx, GCRY_MD_SHA256, 0);
      break;
    case SSH_MAC_SHA384:
      gcry_md_open(&ctx->ctx, GCRY_MD_SHA384, 0);
      break;
    case SSH_MAC_SHA512:
      gcry_md_open(&ctx->ctx, GCRY_MD_SHA512, 0);
      break;
    default:
      SAFE_FREE(ctx);
      return NULL;
  }
  return ctx;
}

void ssh_mac_update(ssh_mac_ctx ctx, const void *data, unsigned long len) {
  gcry_md_write(ctx->ctx,data,len);
}

void ssh_mac_final(unsigned char *md, ssh_mac_ctx ctx) {
  size_t len;
  switch(ctx->mac_type){
    case SSH_MAC_SHA1:
      len=SHA_DIGEST_LEN;
      break;
    case SSH_MAC_SHA256:
      len=SHA256_DIGEST_LEN;
      break;
    case SSH_MAC_SHA384:
      len=SHA384_DIGEST_LEN;
      break;
    case SSH_MAC_SHA512:
      len=SHA512_DIGEST_LEN;
      break;
  }
  gcry_md_final(ctx->ctx);
  memcpy(md, gcry_md_read(ctx->ctx, 0), len);
  gcry_md_close(ctx->ctx);
  SAFE_FREE(ctx);
}

HMACCTX hmac_init(const void *key, int len, enum ssh_hmac_e type) {
  HMACCTX c = NULL;

  switch(type) {
    case SSH_HMAC_SHA1:
      gcry_md_open(&c, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
      break;
    case SSH_HMAC_SHA256:
      gcry_md_open(&c, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
      break;
    case SSH_HMAC_SHA384:
      gcry_md_open(&c, GCRY_MD_SHA384, GCRY_MD_FLAG_HMAC);
      break;
    case SSH_HMAC_SHA512:
      gcry_md_open(&c, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
      break;
    case SSH_HMAC_MD5:
      gcry_md_open(&c, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);
      break;
    default:
      c = NULL;
  }

  gcry_md_setkey(c, key, len);

  return c;
}

void hmac_update(HMACCTX c, const void *data, unsigned long len) {
  gcry_md_write(c, data, len);
}

void hmac_final(HMACCTX c, unsigned char *hashmacbuf, unsigned int *len) {
  *len = gcry_md_get_algo_dlen(gcry_md_get_algo(c));
  memcpy(hashmacbuf, gcry_md_read(c, 0), *len);
  gcry_md_close(c);
}

/* the wrapper functions for blowfish */
static int blowfish_set_key(struct ssh_cipher_struct *cipher, void *key, void *IV){
  if (cipher->key == NULL) {
    if (alloc_key(cipher) < 0) {
      return -1;
    }

    if (gcry_cipher_open(&cipher->key[0], GCRY_CIPHER_BLOWFISH,
        GCRY_CIPHER_MODE_CBC, 0)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if (gcry_cipher_setkey(cipher->key[0], key, 16)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if (gcry_cipher_setiv(cipher->key[0], IV, 8)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
  }

  return 0;
}

static void blowfish_encrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
  gcry_cipher_encrypt(cipher->key[0], out, len, in, len);
}

static void blowfish_decrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
  gcry_cipher_decrypt(cipher->key[0], out, len, in, len);
}

static int aes_set_key(struct ssh_cipher_struct *cipher, void *key, void *IV) {
  int mode=GCRY_CIPHER_MODE_CBC;
  if (cipher->key == NULL) {
    if (alloc_key(cipher) < 0) {
      return -1;
    }
    if(strstr(cipher->name,"-ctr"))
      mode=GCRY_CIPHER_MODE_CTR;
    switch (cipher->keysize) {
      case 128:
        if (gcry_cipher_open(&cipher->key[0], GCRY_CIPHER_AES128,
              mode, 0)) {
          SAFE_FREE(cipher->key);
          return -1;
        }
        break;
      case 192:
        if (gcry_cipher_open(&cipher->key[0], GCRY_CIPHER_AES192,
              mode, 0)) {
          SAFE_FREE(cipher->key);
          return -1;
        }
        break;
      case 256:
        if (gcry_cipher_open(&cipher->key[0], GCRY_CIPHER_AES256,
              mode, 0)) {
          SAFE_FREE(cipher->key);
          return -1;
        }
        break;
    }
    if (gcry_cipher_setkey(cipher->key[0], key, cipher->keysize / 8)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if(mode == GCRY_CIPHER_MODE_CBC){
      if (gcry_cipher_setiv(cipher->key[0], IV, 16)) {

        SAFE_FREE(cipher->key);
        return -1;
      }
    } else {
      if(gcry_cipher_setctr(cipher->key[0],IV,16)){
        SAFE_FREE(cipher->key);
        return -1;
      }
    }
  }

  return 0;
}

static void aes_encrypt(struct ssh_cipher_struct *cipher, void *in, void *out,
    unsigned long len) {
  gcry_cipher_encrypt(cipher->key[0], out, len, in, len);
}

static void aes_decrypt(struct ssh_cipher_struct *cipher, void *in, void *out,
    unsigned long len) {
  gcry_cipher_decrypt(cipher->key[0], out, len, in, len);
}

static int des1_set_key(struct ssh_cipher_struct *cipher, void *key, void *IV){
  if(!cipher->key){
    if (alloc_key(cipher) < 0) {
      return -1;
    }
    if (gcry_cipher_open(&cipher->key[0], GCRY_CIPHER_DES,
          GCRY_CIPHER_MODE_CBC, 0)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if (gcry_cipher_setkey(cipher->key[0], key, 8)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if (gcry_cipher_setiv(cipher->key[0], IV, 8)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
  }
  return 0;
}

static int des3_set_key(struct ssh_cipher_struct *cipher, void *key, void *IV) {
  if (cipher->key == NULL) {
    if (alloc_key(cipher) < 0) {
      return -1;
    }
    if (gcry_cipher_open(&cipher->key[0], GCRY_CIPHER_3DES,
          GCRY_CIPHER_MODE_CBC, 0)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if (gcry_cipher_setkey(cipher->key[0], key, 24)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if (gcry_cipher_setiv(cipher->key[0], IV, 8)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
  }

  return 0;
}


static void des1_1_encrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
  gcry_cipher_encrypt(cipher->key[0], out, len, in, len);
}

static void des1_1_decrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
  gcry_cipher_decrypt(cipher->key[0], out, len, in, len);
}

static void des3_encrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
  gcry_cipher_encrypt(cipher->key[0], out, len, in, len);
}

static void des3_decrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
  gcry_cipher_decrypt(cipher->key[0], out, len, in, len);
}

static int des3_1_set_key(struct ssh_cipher_struct *cipher, void *key, void *IV) {
  if (cipher->key == NULL) {
    if (alloc_key(cipher) < 0) {
      return -1;
    }
    if (gcry_cipher_open(&cipher->key[0], GCRY_CIPHER_DES,
          GCRY_CIPHER_MODE_CBC, 0)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if (gcry_cipher_setkey(cipher->key[0], key, 8)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if (gcry_cipher_setiv(cipher->key[0], IV, 8)) {
      SAFE_FREE(cipher->key);
      return -1;
    }

    if (gcry_cipher_open(&cipher->key[1], GCRY_CIPHER_DES,
          GCRY_CIPHER_MODE_CBC, 0)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if (gcry_cipher_setkey(cipher->key[1], (unsigned char *)key + 8, 8)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if (gcry_cipher_setiv(cipher->key[1], (unsigned char *)IV + 8, 8)) {
      SAFE_FREE(cipher->key);
      return -1;
    }

    if (gcry_cipher_open(&cipher->key[2], GCRY_CIPHER_DES,
          GCRY_CIPHER_MODE_CBC, 0)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if (gcry_cipher_setkey(cipher->key[2], (unsigned char *)key + 16, 8)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
    if (gcry_cipher_setiv(cipher->key[2], (unsigned char *)IV + 16, 8)) {
      SAFE_FREE(cipher->key);
      return -1;
    }
  }

  return 0;
}

static void des3_1_encrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
  gcry_cipher_encrypt(cipher->key[0], out, len, in, len);
  gcry_cipher_decrypt(cipher->key[1], in, len, out, len);
  gcry_cipher_encrypt(cipher->key[2], out, len, in, len);
}

static void des3_1_decrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
  gcry_cipher_decrypt(cipher->key[2], out, len, in, len);
  gcry_cipher_encrypt(cipher->key[1], in, len, out, len);
  gcry_cipher_decrypt(cipher->key[0], out, len, in, len);
}

/* the table of supported ciphers */
static struct ssh_cipher_struct ssh_ciphertab[] = {
  {
    .name            = "blowfish-cbc",
    .blocksize       = 8,
    .keylen          = sizeof(gcry_cipher_hd_t),
    .key             = NULL,
    .keysize         = 128,
    .set_encrypt_key = blowfish_set_key,
    .set_decrypt_key = blowfish_set_key,
    .encrypt     = blowfish_encrypt,
    .decrypt     = blowfish_decrypt
  },
  {
    .name            = "aes128-ctr",
    .blocksize       = 16,
    .keylen          = sizeof(gcry_cipher_hd_t),
    .key             = NULL,
    .keysize         = 128,
    .set_encrypt_key = aes_set_key,
    .set_decrypt_key = aes_set_key,
    .encrypt     = aes_encrypt,
    .decrypt     = aes_encrypt
  },
  {
      .name            = "aes192-ctr",
      .blocksize       = 16,
      .keylen          = sizeof(gcry_cipher_hd_t),
      .key             = NULL,
      .keysize         = 192,
      .set_encrypt_key = aes_set_key,
      .set_decrypt_key = aes_set_key,
      .encrypt     = aes_encrypt,
      .decrypt     = aes_encrypt
  },
  {
      .name            = "aes256-ctr",
      .blocksize       = 16,
      .keylen          = sizeof(gcry_cipher_hd_t),
      .key             = NULL,
      .keysize         = 256,
      .set_encrypt_key = aes_set_key,
      .set_decrypt_key = aes_set_key,
      .encrypt     = aes_encrypt,
      .decrypt     = aes_encrypt
  },
  {
    .name            = "aes128-cbc",
    .blocksize       = 16,
    .keylen          = sizeof(gcry_cipher_hd_t),
    .key             = NULL,
    .keysize         = 128,
    .set_encrypt_key = aes_set_key,
    .set_decrypt_key = aes_set_key,
    .encrypt     = aes_encrypt,
    .decrypt     = aes_decrypt
  },
  {
    .name            = "aes192-cbc",
    .blocksize       = 16,
    .keylen          = sizeof(gcry_cipher_hd_t),
    .key             = NULL,
    .keysize         = 192,
    .set_encrypt_key = aes_set_key,
    .set_decrypt_key = aes_set_key,
    .encrypt     = aes_encrypt,
    .decrypt     = aes_decrypt
  },
  {
    .name            = "aes256-cbc",
    .blocksize       = 16,
    .keylen          = sizeof(gcry_cipher_hd_t),
    .key             = NULL,
    .keysize         = 256,
    .set_encrypt_key = aes_set_key,
    .set_decrypt_key = aes_set_key,
    .encrypt     = aes_encrypt,
    .decrypt     = aes_decrypt
  },
  {
    .name            = "3des-cbc",
    .blocksize       = 8,
    .keylen          = sizeof(gcry_cipher_hd_t),
    .key             = NULL,
    .keysize         = 192,
    .set_encrypt_key = des3_set_key,
    .set_decrypt_key = des3_set_key,
    .encrypt     = des3_encrypt,
    .decrypt     = des3_decrypt
  },
  {
    .name            = "3des-cbc-ssh1",
    .blocksize       = 8,
    .keylen          = sizeof(gcry_cipher_hd_t) * 3,
    .key             = NULL,
    .keysize         = 192,
    .set_encrypt_key = des3_1_set_key,
    .set_decrypt_key = des3_1_set_key,
    .encrypt     = des3_1_encrypt,
    .decrypt     = des3_1_decrypt
  },
  {
    .name            = "des-cbc-ssh1",
    .blocksize       = 8,
    .keylen          = sizeof(gcry_cipher_hd_t),
    .key             = NULL,
    .keysize         = 64,
    .set_encrypt_key = des1_set_key,
    .set_decrypt_key = des1_set_key,
    .encrypt     = des1_1_encrypt,
    .decrypt     = des1_1_decrypt
  },
  {
    .name            = NULL,
    .blocksize       = 0,
    .keylen          = 0,
    .key             = NULL,
    .keysize         = 0,
    .set_encrypt_key = NULL,
    .set_decrypt_key = NULL,
    .encrypt     = NULL,
    .decrypt     = NULL
  }
};

struct ssh_cipher_struct *ssh_get_ciphertab(void)
{
  return ssh_ciphertab;
}

#endif
