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
#include <sys/time.h>

#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/crypto.h"
#include "libssh/wrapper.h"
#include "libssh/libcrypto.h"

#ifdef HAVE_LIBCRYPTO

#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

#ifdef HAVE_OPENSSL_AES_H
#define HAS_AES
#include <openssl/aes.h>
#endif
#ifdef HAVE_OPENSSL_BLOWFISH_H
#define HAS_BLOWFISH
#include <openssl/blowfish.h>
#endif
#ifdef HAVE_OPENSSL_DES_H
#define HAS_DES
#include <openssl/des.h>
#endif

#if (OPENSSL_VERSION_NUMBER<0x00907000L)
#define OLD_CRYPTO
#endif

#include "libssh/crypto.h"

struct ssh_mac_ctx_struct {
  enum ssh_mac_e mac_type;
  union {
    SHACTX sha1_ctx;
    SHA256CTX sha256_ctx;
    SHA384CTX sha384_ctx;
    SHA512CTX sha512_ctx;
  } ctx;
};

static int alloc_key(struct ssh_cipher_struct *cipher) {
    cipher->key = malloc(cipher->keylen);
    if (cipher->key == NULL) {
      return -1;
    }

    return 0;
}

void ssh_reseed(void){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    RAND_add(&tv, sizeof(tv), 0.0);
}

SHACTX sha1_init(void) {
  SHACTX c = malloc(sizeof(*c));
  if (c == NULL) {
    return NULL;
  }
  SHA1_Init(c);

  return c;
}

void sha1_update(SHACTX c, const void *data, unsigned long len) {
  SHA1_Update(c,data,len);
}

void sha1_final(unsigned char *md, SHACTX c) {
  SHA1_Final(md, c);
  SAFE_FREE(c);
}

void sha1(unsigned char *digest, int len, unsigned char *hash) {
  SHA1(digest, len, hash);
}

#ifdef HAVE_OPENSSL_ECC
static const EVP_MD *nid_to_evpmd(int nid)
{
    switch (nid) {
        case NID_X9_62_prime256v1:
            return EVP_sha256();
        case NID_secp384r1:
            return EVP_sha384();
        case NID_secp521r1:
            return EVP_sha512();
        default:
            return NULL;
    }

    return NULL;
}

void evp(int nid, unsigned char *digest, int len, unsigned char *hash, unsigned int *hlen)
{
    const EVP_MD *evp_md = nid_to_evpmd(nid);
    EVP_MD_CTX md;

    EVP_DigestInit(&md, evp_md);
    EVP_DigestUpdate(&md, digest, len);
    EVP_DigestFinal(&md, hash, hlen);
}

EVPCTX evp_init(int nid)
{
    const EVP_MD *evp_md = nid_to_evpmd(nid);

    EVPCTX ctx = malloc(sizeof(EVP_MD_CTX));
    if (ctx == NULL) {
        return NULL;
    }

    EVP_DigestInit(ctx, evp_md);

    return ctx;
}

void evp_update(EVPCTX ctx, const void *data, unsigned long len)
{
    EVP_DigestUpdate(ctx, data, len);
}

void evp_final(EVPCTX ctx, unsigned char *md, unsigned int *mdlen)
{
    EVP_DigestFinal(ctx, md, mdlen);
}
#endif

SHA256CTX sha256_init(void){
  SHA256CTX c = malloc(sizeof(*c));
  if (c == NULL) {
    return NULL;
  }
  SHA256_Init(c);

  return c;
}

void sha256_update(SHA256CTX c, const void *data, unsigned long len){
  SHA256_Update(c,data,len);
}

void sha256_final(unsigned char *md, SHA256CTX c) {
  SHA256_Final(md, c);
  SAFE_FREE(c);
}

void sha256(unsigned char *digest, int len, unsigned char *hash) {
  SHA256(digest, len, hash);
}

SHA384CTX sha384_init(void){
  SHA384CTX c = malloc(sizeof(*c));
  if (c == NULL) {
    return NULL;
  }
  SHA384_Init(c);

  return c;
}

void sha384_update(SHA384CTX c, const void *data, unsigned long len){
  SHA384_Update(c,data,len);
}

void sha384_final(unsigned char *md, SHA384CTX c) {
  SHA384_Final(md, c);
  SAFE_FREE(c);
}

void sha384(unsigned char *digest, int len, unsigned char *hash) {
  SHA384(digest, len, hash);
}

SHA512CTX sha512_init(void){
  SHA512CTX c = malloc(sizeof(*c));
  if (c == NULL) {
    return NULL;
  }
  SHA512_Init(c);

  return c;
}

void sha512_update(SHA512CTX c, const void *data, unsigned long len){
  SHA512_Update(c,data,len);
}

void sha512_final(unsigned char *md, SHA512CTX c) {
  SHA512_Final(md, c);
  SAFE_FREE(c);
}

void sha512(unsigned char *digest, int len, unsigned char *hash) {
  SHA512(digest, len, hash);
}

MD5CTX md5_init(void) {
  MD5CTX c = malloc(sizeof(*c));
  if (c == NULL) {
    return NULL;
  }

  MD5_Init(c);

  return c;
}

void md5_update(MD5CTX c, const void *data, unsigned long len) {
  MD5_Update(c, data, len);
}

void md5_final(unsigned char *md, MD5CTX c) {
  MD5_Final(md,c);
  SAFE_FREE(c);
}

ssh_mac_ctx ssh_mac_ctx_init(enum ssh_mac_e type){
  ssh_mac_ctx ctx = malloc(sizeof(struct ssh_mac_ctx_struct));
  if (ctx == NULL) {
    return NULL;
  }

  ctx->mac_type=type;
  switch(type){
    case SSH_MAC_SHA1:
      ctx->ctx.sha1_ctx = sha1_init();
      return ctx;
    case SSH_MAC_SHA256:
      ctx->ctx.sha256_ctx = sha256_init();
      return ctx;
    case SSH_MAC_SHA384:
      ctx->ctx.sha384_ctx = sha384_init();
      return ctx;
    case SSH_MAC_SHA512:
      ctx->ctx.sha512_ctx = sha512_init();
      return ctx;
    default:
      SAFE_FREE(ctx);
      return NULL;
  }
}

void ssh_mac_update(ssh_mac_ctx ctx, const void *data, unsigned long len) {
  switch(ctx->mac_type){
    case SSH_MAC_SHA1:
      sha1_update(ctx->ctx.sha1_ctx, data, len);
      break;
    case SSH_MAC_SHA256:
      sha256_update(ctx->ctx.sha256_ctx, data, len);
      break;
    case SSH_MAC_SHA384:
      sha384_update(ctx->ctx.sha384_ctx, data, len);
      break;
    case SSH_MAC_SHA512:
      sha512_update(ctx->ctx.sha512_ctx, data, len);
      break;
    default:
      break;
  }
}

void ssh_mac_final(unsigned char *md, ssh_mac_ctx ctx) {
  switch(ctx->mac_type){
    case SSH_MAC_SHA1:
      sha1_final(md,ctx->ctx.sha1_ctx);
      break;
    case SSH_MAC_SHA256:
      sha256_final(md,ctx->ctx.sha256_ctx);
      break;
    case SSH_MAC_SHA384:
      sha384_final(md,ctx->ctx.sha384_ctx);
      break;
    case SSH_MAC_SHA512:
      sha512_final(md,ctx->ctx.sha512_ctx);
      break;
    default:
      break;
  }
  SAFE_FREE(ctx);
}

HMACCTX hmac_init(const void *key, int len, enum ssh_hmac_e type) {
  HMACCTX ctx = NULL;

  ctx = malloc(sizeof(*ctx));
  if (ctx == NULL) {
    return NULL;
  }

#ifndef OLD_CRYPTO
  HMAC_CTX_init(ctx); // openssl 0.9.7 requires it.
#endif

  switch(type) {
    case SSH_HMAC_SHA1:
      HMAC_Init(ctx, key, len, EVP_sha1());
      break;
    case SSH_HMAC_SHA256:
      HMAC_Init(ctx, key, len, EVP_sha256());
      break;
    case SSH_HMAC_SHA384:
      HMAC_Init(ctx, key, len, EVP_sha384());
      break;
    case SSH_HMAC_SHA512:
      HMAC_Init(ctx, key, len, EVP_sha512());
      break;
    case SSH_HMAC_MD5:
      HMAC_Init(ctx, key, len, EVP_md5());
      break;
    default:
      SAFE_FREE(ctx);
      ctx = NULL;
  }

  return ctx;
}

void hmac_update(HMACCTX ctx, const void *data, unsigned long len) {
  HMAC_Update(ctx, data, len);
}

void hmac_final(HMACCTX ctx, unsigned char *hashmacbuf, unsigned int *len) {
  HMAC_Final(ctx,hashmacbuf,len);

#ifndef OLD_CRYPTO
  HMAC_CTX_cleanup(ctx);
#else
  HMAC_cleanup(ctx);
#endif

  SAFE_FREE(ctx);
}

#ifdef HAS_BLOWFISH
/* the wrapper functions for blowfish */
static int blowfish_set_key(struct ssh_cipher_struct *cipher, void *key, void *IV){
  if (cipher->key == NULL) {
    if (alloc_key(cipher) < 0) {
      return -1;
    }
    BF_set_key(cipher->key, 16, key);
  }
  cipher->IV = IV;
  return 0;
}

static void blowfish_encrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
  BF_cbc_encrypt(in, out, len, cipher->key, cipher->IV, BF_ENCRYPT);
}

static void blowfish_decrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
  BF_cbc_encrypt(in, out, len, cipher->key, cipher->IV, BF_DECRYPT);
}
#endif /* HAS_BLOWFISH */

#ifdef HAS_AES
static int aes_set_encrypt_key(struct ssh_cipher_struct *cipher, void *key,
    void *IV) {
  if (cipher->key == NULL) {
    if (alloc_key(cipher) < 0) {
      return -1;
    }
    if (AES_set_encrypt_key(key,cipher->keysize,cipher->key) < 0) {
      SAFE_FREE(cipher->key);
      return -1;
    }
  }
  cipher->IV=IV;
  return 0;
}
static int aes_set_decrypt_key(struct ssh_cipher_struct *cipher, void *key,
    void *IV) {
  if (cipher->key == NULL) {
    if (alloc_key(cipher) < 0) {
      return -1;
    }
    if (AES_set_decrypt_key(key,cipher->keysize,cipher->key) < 0) {
      SAFE_FREE(cipher->key);
      return -1;
    }
  }
  cipher->IV=IV;
  return 0;
}

static void aes_encrypt(struct ssh_cipher_struct *cipher, void *in, void *out,
    unsigned long len) {
  AES_cbc_encrypt(in, out, len, cipher->key, cipher->IV, AES_ENCRYPT);
}

static void aes_decrypt(struct ssh_cipher_struct *cipher, void *in, void *out,
    unsigned long len) {
  AES_cbc_encrypt(in, out, len, cipher->key, cipher->IV, AES_DECRYPT);
}

#ifndef BROKEN_AES_CTR
/* OpenSSL until 0.9.7c has a broken AES_ctr128_encrypt implementation which
 * increments the counter from 2^64 instead of 1. It's better not to use it
 */

/** @internal
 * @brief encrypts/decrypts data with stream cipher AES_ctr128. 128 bits is actually
 * the size of the CTR counter and incidentally the blocksize, but not the keysize.
 * @param len[in] must be a multiple of AES128 block size.
 */
static void aes_ctr128_encrypt(struct ssh_cipher_struct *cipher, void *in, void *out,
    unsigned long len) {
  unsigned char tmp_buffer[128/8];
  unsigned int num=0;
  /* Some things are special with ctr128 :
   * In this case, tmp_buffer is not being used, because it is used to store temporary data
   * when an encryption is made on lengths that are not multiple of blocksize.
   * Same for num, which is being used to store the current offset in blocksize in CTR
   * function.
   */
  AES_ctr128_encrypt(in, out, len, cipher->key, cipher->IV, tmp_buffer, &num);
}
#endif /* BROKEN_AES_CTR */
#endif /* HAS_AES */

#ifdef HAS_DES
static int des3_set_key(struct ssh_cipher_struct *cipher, void *key,void *IV) {
  if (cipher->key == NULL) {
    if (alloc_key(cipher) < 0) {
      return -1;
    }

    DES_set_odd_parity(key);
    DES_set_odd_parity((void*)((uint8_t*)key + 8));
    DES_set_odd_parity((void*)((uint8_t*)key + 16));
    DES_set_key_unchecked(key, cipher->key);
    DES_set_key_unchecked((void*)((uint8_t*)key + 8), (void*)((uint8_t*)cipher->key + sizeof(DES_key_schedule)));
    DES_set_key_unchecked((void*)((uint8_t*)key + 16), (void*)((uint8_t*)cipher->key + 2 * sizeof(DES_key_schedule)));
  }
  cipher->IV=IV;
  return 0;
}

static void des3_encrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
  DES_ede3_cbc_encrypt(in, out, len, cipher->key,
      (void*)((uint8_t*)cipher->key + sizeof(DES_key_schedule)),
      (void*)((uint8_t*)cipher->key + 2 * sizeof(DES_key_schedule)),
      cipher->IV, 1);
}

static void des3_decrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
  DES_ede3_cbc_encrypt(in, out, len, cipher->key,
      (void*)((uint8_t*)cipher->key + sizeof(DES_key_schedule)),
      (void*)((uint8_t*)cipher->key + 2 * sizeof(DES_key_schedule)),
      cipher->IV, 0);
}

static void des3_1_encrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
#ifdef DEBUG_CRYPTO
  ssh_print_hexa("Encrypt IV before", cipher->IV, 24);
#endif
  DES_ncbc_encrypt(in, out, len, cipher->key, cipher->IV, 1);
  DES_ncbc_encrypt(out, in, len, (void*)((uint8_t*)cipher->key + sizeof(DES_key_schedule)),
      (void*)((uint8_t*)cipher->IV + 8), 0);
  DES_ncbc_encrypt(in, out, len, (void*)((uint8_t*)cipher->key + 2 * sizeof(DES_key_schedule)),
      (void*)((uint8_t*)cipher->IV + 16), 1);
#ifdef DEBUG_CRYPTO
  ssh_print_hexa("Encrypt IV after", cipher->IV, 24);
#endif
}

static void des3_1_decrypt(struct ssh_cipher_struct *cipher, void *in,
    void *out, unsigned long len) {
#ifdef DEBUG_CRYPTO
  ssh_print_hexa("Decrypt IV before", cipher->IV, 24);
#endif

  DES_ncbc_encrypt(in, out, len, (void*)((uint8_t*)cipher->key + 2 * sizeof(DES_key_schedule)),
      cipher->IV, 0);
  DES_ncbc_encrypt(out, in, len, (void*)((uint8_t*)cipher->key + sizeof(DES_key_schedule)),
      (void*)((uint8_t*)cipher->IV + 8), 1);
  DES_ncbc_encrypt(in, out, len, cipher->key, (void*)((uint8_t*)cipher->IV + 16), 0);

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("Decrypt IV after", cipher->IV, 24);
#endif
}

static int des1_set_key(struct ssh_cipher_struct *cipher, void *key, void *IV){
  if(!cipher->key){
    if (alloc_key(cipher) < 0) {
      return -1;
    }
    DES_set_odd_parity(key);
    DES_set_key_unchecked(key,cipher->key);
  }
  cipher->IV=IV;
  return 0;
}

static void des1_1_encrypt(struct ssh_cipher_struct *cipher, void *in, void *out,
                           unsigned long len){

  DES_ncbc_encrypt(in, out, len, cipher->key, cipher->IV, 1);
}

static void des1_1_decrypt(struct ssh_cipher_struct *cipher, void *in, void *out,
                           unsigned long len){

  DES_ncbc_encrypt(in,out,len, cipher->key, cipher->IV, 0);
}

#endif /* HAS_DES */

/*
 * The table of supported ciphers
 *
 * WARNING: If you modify ssh_cipher_struct, you must make sure the order is
 * correct!
 */
static struct ssh_cipher_struct ssh_ciphertab[] = {
#ifdef HAS_BLOWFISH
  {
    "blowfish-cbc",
    8,
    sizeof (BF_KEY),
    NULL,
    NULL,
    128,
    blowfish_set_key,
    blowfish_set_key,
    blowfish_encrypt,
    blowfish_decrypt
  },
#endif /* HAS_BLOWFISH */
#ifdef HAS_AES
#ifndef BROKEN_AES_CTR
  {
    "aes128-ctr",
    16,
    sizeof(AES_KEY),
    NULL,
    NULL,
    128,
    aes_set_encrypt_key,
    aes_set_encrypt_key,
    aes_ctr128_encrypt,
    aes_ctr128_encrypt
  },
  {
    "aes192-ctr",
    16,
    sizeof(AES_KEY),
    NULL,
    NULL,
    192,
    aes_set_encrypt_key,
    aes_set_encrypt_key,
    aes_ctr128_encrypt,
    aes_ctr128_encrypt
  },
  {
    "aes256-ctr",
    16,
    sizeof(AES_KEY),
    NULL,
    NULL,
    256,
    aes_set_encrypt_key,
    aes_set_encrypt_key,
    aes_ctr128_encrypt,
    aes_ctr128_encrypt
  },
#endif /* BROKEN_AES_CTR */
  {
    "aes128-cbc",
    16,
    sizeof(AES_KEY),
    NULL,
    NULL,
    128,
    aes_set_encrypt_key,
    aes_set_decrypt_key,
    aes_encrypt,
    aes_decrypt
  },
  {
    "aes192-cbc",
    16,
    sizeof(AES_KEY),
    NULL,
    NULL,
    192,
    aes_set_encrypt_key,
    aes_set_decrypt_key,
    aes_encrypt,
    aes_decrypt
  },
  {
    "aes256-cbc",
    16,
    sizeof(AES_KEY),
    NULL,
    NULL,
    256,
    aes_set_encrypt_key,
    aes_set_decrypt_key,
    aes_encrypt,
    aes_decrypt
  },
#endif /* HAS_AES */
#ifdef HAS_DES
  {
    "3des-cbc",
    8,
    sizeof(DES_key_schedule) * 3,
    NULL,
    NULL,
    192,
    des3_set_key,
    des3_set_key,
    des3_encrypt,
    des3_decrypt
  },
  {
    "3des-cbc-ssh1",
    8,
    sizeof(DES_key_schedule) * 3,
    NULL,
    NULL,
    192,
    des3_set_key,
    des3_set_key,
    des3_1_encrypt,
    des3_1_decrypt
  },
  {
    "des-cbc-ssh1",
    8,
    sizeof(DES_key_schedule),
    NULL,
    NULL,
    64,
    des1_set_key,
    des1_set_key,
    des1_1_encrypt,
    des1_1_decrypt
  },
#endif /* HAS_DES */
  {
    NULL,
    0,
    0,
    NULL,
    NULL,
    0,
    NULL,
    NULL,
    NULL,
    NULL
  }
};


struct ssh_cipher_struct *ssh_get_ciphertab(void)
{
  return ssh_ciphertab;
}

#endif /* LIBCRYPTO */

