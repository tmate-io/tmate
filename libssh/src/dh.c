/*
 * dh.c - Diffie-Helman algorithm code against SSH 2
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2013 by Aris Adamantiadis
 * Copyright (c) 2009-2013 by Andreas Schneider <asn@cryptomilk.org>
 * Copyright (c) 2012      by Dmitriy Kuznetsov <dk@yandex.ru>
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
 * Let us resume the dh protocol.
 * Each side computes a private prime number, x at client side, y at server
 * side.
 * g and n are two numbers common to every ssh software.
 * client's public key (e) is calculated by doing:
 * e = g^x mod p
 * client sends e to the server.
 * the server computes his own public key, f
 * f = g^y mod p
 * it sends it to the client
 * the common key K is calculated by the client by doing
 * k = f^x mod p
 * the server does the same with the client public key e
 * k' = e^y mod p
 * if everything went correctly, k and k' are equal
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/crypto.h"
#include "libssh/buffer.h"
#include "libssh/session.h"
#include "libssh/misc.h"
#include "libssh/dh.h"
#include "libssh/ssh2.h"
#include "libssh/pki.h"
#include "libssh/bignum.h"

/* todo: remove it */
#include "libssh/string.h"
#ifdef HAVE_LIBCRYPTO
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

static unsigned char p_group1_value[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
        0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
        0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
        0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
        0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
#define P_GROUP1_LEN 128	/* Size in bytes of the p number */


static unsigned char p_group14_value[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
        0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
        0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
        0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
        0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
        0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
        0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
        0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
        0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
        0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF};

#define P_GROUP14_LEN 256 /* Size in bytes of the p number for group 14 */

static unsigned long g_int = 2 ;	/* G is defined as 2 by the ssh2 standards */
static bignum g;
static bignum p_group1;
static bignum p_group14;
static int ssh_crypto_initialized;

static bignum select_p(enum ssh_key_exchange_e type) {
    return type == SSH_KEX_DH_GROUP14_SHA1 ? p_group14 : p_group1;
}

int ssh_get_random(void *where, int len, int strong){

#ifdef HAVE_LIBGCRYPT
  /* variable not used in gcrypt */
  (void) strong;
  /* not using GCRY_VERY_STRONG_RANDOM which is a bit overkill */
  gcry_randomize(where,len,GCRY_STRONG_RANDOM);

  return 1;
#elif defined HAVE_LIBCRYPTO
  if (strong) {
    return RAND_bytes(where,len);
  } else {
    return RAND_pseudo_bytes(where,len);
  }
#endif

  /* never reached */
  return 1;
}


/*
 * This inits the values g and p which are used for DH key agreement
 * FIXME: Make the function thread safe by adding a semaphore or mutex.
 */
int ssh_crypto_init(void) {
  if (ssh_crypto_initialized == 0) {
#ifdef HAVE_LIBGCRYPT
    gcry_check_version(NULL);
    if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P,0)) {
      gcry_control(GCRYCTL_INIT_SECMEM, 4096);
      gcry_control(GCRYCTL_INITIALIZATION_FINISHED,0);
    }
#endif

    g = bignum_new();
    if (g == NULL) {
      return -1;
    }
    bignum_set_word(g,g_int);

#ifdef HAVE_LIBGCRYPT
    bignum_bin2bn(p_group1_value, P_GROUP1_LEN, &p_group1);
    if (p_group1 == NULL) {
      bignum_free(g);
      g = NULL;
      return -1;
    }
    bignum_bin2bn(p_group14_value, P_GROUP14_LEN, &p_group14);
    if (p_group14 == NULL) {
      bignum_free(g);
      bignum_free(p_group1);
      g = NULL;
      p_group1 = NULL;
      return -1;
    }

#elif defined HAVE_LIBCRYPTO
    p_group1 = bignum_new();
    if (p_group1 == NULL) {
      bignum_free(g);
      g = NULL;
      return -1;
    }
    bignum_bin2bn(p_group1_value, P_GROUP1_LEN, p_group1);

    p_group14 = bignum_new();
    if (p_group14 == NULL) {
      bignum_free(g);
      bignum_free(p_group1);
      g = NULL;
      p_group1 = NULL;
      return -1;
    }
    bignum_bin2bn(p_group14_value, P_GROUP14_LEN, p_group14);

    OpenSSL_add_all_algorithms();

#endif

    ssh_crypto_initialized = 1;
  }

  return 0;
}

void ssh_crypto_finalize(void) {
  if (ssh_crypto_initialized) {
    bignum_free(g);
    g = NULL;
    bignum_free(p_group1);
    p_group1 = NULL;
    bignum_free(p_group14);
    p_group14 = NULL;
#ifdef HAVE_LIBGCRYPT
    gcry_control(GCRYCTL_TERM_SECMEM);
#elif defined HAVE_LIBCRYPTO
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
#endif
    ssh_crypto_initialized=0;
  }
}

int dh_generate_x(ssh_session session) {
  session->next_crypto->x = bignum_new();
  if (session->next_crypto->x == NULL) {
    return -1;
  }

#ifdef HAVE_LIBGCRYPT
  bignum_rand(session->next_crypto->x, 128);
#elif defined HAVE_LIBCRYPTO
  bignum_rand(session->next_crypto->x, 128, 0, -1);
#endif

  /* not harder than this */
#ifdef DEBUG_CRYPTO
  ssh_print_bignum("x", session->next_crypto->x);
#endif

  return 0;
}

/* used by server */
int dh_generate_y(ssh_session session) {
    session->next_crypto->y = bignum_new();
  if (session->next_crypto->y == NULL) {
    return -1;
  }

#ifdef HAVE_LIBGCRYPT
  bignum_rand(session->next_crypto->y, 128);
#elif defined HAVE_LIBCRYPTO
  bignum_rand(session->next_crypto->y, 128, 0, -1);
#endif

  /* not harder than this */
#ifdef DEBUG_CRYPTO
  ssh_print_bignum("y", session->next_crypto->y);
#endif

  return 0;
}

/* used by server */
int dh_generate_e(ssh_session session) {
#ifdef HAVE_LIBCRYPTO
  bignum_CTX ctx = bignum_ctx_new();
  if (ctx == NULL) {
    return -1;
  }
#endif

  session->next_crypto->e = bignum_new();
  if (session->next_crypto->e == NULL) {
#ifdef HAVE_LIBCRYPTO
    bignum_ctx_free(ctx);
#endif
    return -1;
  }

#ifdef HAVE_LIBGCRYPT
  bignum_mod_exp(session->next_crypto->e, g, session->next_crypto->x,
      select_p(session->next_crypto->kex_type));
#elif defined HAVE_LIBCRYPTO
  bignum_mod_exp(session->next_crypto->e, g, session->next_crypto->x,
      select_p(session->next_crypto->kex_type), ctx);
#endif

#ifdef DEBUG_CRYPTO
  ssh_print_bignum("e", session->next_crypto->e);
#endif

#ifdef HAVE_LIBCRYPTO
  bignum_ctx_free(ctx);
#endif

  return 0;
}

int dh_generate_f(ssh_session session) {
#ifdef HAVE_LIBCRYPTO
  bignum_CTX ctx = bignum_ctx_new();
  if (ctx == NULL) {
    return -1;
  }
#endif

  session->next_crypto->f = bignum_new();
  if (session->next_crypto->f == NULL) {
#ifdef HAVE_LIBCRYPTO
    bignum_ctx_free(ctx);
#endif
    return -1;
  }

#ifdef HAVE_LIBGCRYPT
  bignum_mod_exp(session->next_crypto->f, g, session->next_crypto->y,
      select_p(session->next_crypto->kex_type));
#elif defined HAVE_LIBCRYPTO
  bignum_mod_exp(session->next_crypto->f, g, session->next_crypto->y,
      select_p(session->next_crypto->kex_type), ctx);
#endif

#ifdef DEBUG_CRYPTO
  ssh_print_bignum("f", session->next_crypto->f);
#endif

#ifdef HAVE_LIBCRYPTO
  bignum_ctx_free(ctx);
#endif

  return 0;
}

ssh_string dh_get_e(ssh_session session) {
  return make_bignum_string(session->next_crypto->e);
}

/* used by server */
ssh_string dh_get_f(ssh_session session) {
  return make_bignum_string(session->next_crypto->f);
}

void dh_import_pubkey(ssh_session session, ssh_string pubkey_string) {
  session->next_crypto->server_pubkey = pubkey_string;
}

int dh_import_f(ssh_session session, ssh_string f_string) {
  session->next_crypto->f = make_string_bn(f_string);
  if (session->next_crypto->f == NULL) {
    return -1;
  }

#ifdef DEBUG_CRYPTO
  ssh_print_bignum("f",session->next_crypto->f);
#endif

  return 0;
}

/* used by the server implementation */
int dh_import_e(ssh_session session, ssh_string e_string) {
  session->next_crypto->e = make_string_bn(e_string);
  if (session->next_crypto->e == NULL) {
    return -1;
  }

#ifdef DEBUG_CRYPTO
    ssh_print_bignum("e",session->next_crypto->e);
#endif

  return 0;
}

int dh_build_k(ssh_session session) {
#ifdef HAVE_LIBCRYPTO
  bignum_CTX ctx = bignum_ctx_new();
  if (ctx == NULL) {
    return -1;
  }
#endif

  session->next_crypto->k = bignum_new();
  if (session->next_crypto->k == NULL) {
#ifdef HAVE_LIBCRYPTO
    bignum_ctx_free(ctx);
#endif
    return -1;
  }

    /* the server and clients don't use the same numbers */
#ifdef HAVE_LIBGCRYPT
  if(session->client) {
    bignum_mod_exp(session->next_crypto->k, session->next_crypto->f,
        session->next_crypto->x, select_p(session->next_crypto->kex_type));
  } else {
    bignum_mod_exp(session->next_crypto->k, session->next_crypto->e,
        session->next_crypto->y, select_p(session->next_crypto->kex_type));
  }
#elif defined HAVE_LIBCRYPTO
  if (session->client) {
    bignum_mod_exp(session->next_crypto->k, session->next_crypto->f,
        session->next_crypto->x, select_p(session->next_crypto->kex_type), ctx);
  } else {
    bignum_mod_exp(session->next_crypto->k, session->next_crypto->e,
        session->next_crypto->y, select_p(session->next_crypto->kex_type), ctx);
  }
#endif

#ifdef DEBUG_CRYPTO
    ssh_print_hexa("Session server cookie",
                   session->next_crypto->server_kex.cookie, 16);
    ssh_print_hexa("Session client cookie",
                   session->next_crypto->client_kex.cookie, 16);
    ssh_print_bignum("Shared secret key", session->next_crypto->k);
#endif

#ifdef HAVE_LIBCRYPTO
  bignum_ctx_free(ctx);
#endif

  return 0;
}

/** @internal
 * @brief Starts diffie-hellman-group1 key exchange
 */
int ssh_client_dh_init(ssh_session session){
  ssh_string e = NULL;
  int rc;

  if (dh_generate_x(session) < 0) {
    goto error;
  }
  if (dh_generate_e(session) < 0) {
    goto error;
  }

  e = dh_get_e(session);
  if (e == NULL) {
    goto error;
  }

  rc = ssh_buffer_pack(session->out_buffer, "bS", SSH2_MSG_KEXDH_INIT, e);
  if (rc != SSH_OK) {
    goto error;
  }

  ssh_string_burn(e);
  ssh_string_free(e);
  e=NULL;

  rc = packet_send(session);
  return rc;
  error:
  if(e != NULL){
    ssh_string_burn(e);
    ssh_string_free(e);
  }

  return SSH_ERROR;
}

int ssh_client_dh_reply(ssh_session session, ssh_buffer packet){
  ssh_string f;
  ssh_string pubkey = NULL;
  ssh_string signature = NULL;
  int rc;
  pubkey = buffer_get_ssh_string(packet);
  if (pubkey == NULL){
    ssh_set_error(session,SSH_FATAL, "No public key in packet");
    goto error;
  }
  dh_import_pubkey(session, pubkey);

  f = buffer_get_ssh_string(packet);
  if (f == NULL) {
    ssh_set_error(session,SSH_FATAL, "No F number in packet");
    goto error;
  }
  rc = dh_import_f(session, f);
  ssh_string_burn(f);
  ssh_string_free(f);
  if (rc < 0) {
    ssh_set_error(session, SSH_FATAL, "Cannot import f number");
    goto error;
  }

  signature = buffer_get_ssh_string(packet);
  if (signature == NULL) {
    ssh_set_error(session, SSH_FATAL, "No signature in packet");
    goto error;
  }
  session->next_crypto->dh_server_signature = signature;
  signature=NULL; /* ownership changed */
  if (dh_build_k(session) < 0) {
    ssh_set_error(session, SSH_FATAL, "Cannot build k number");
    goto error;
  }

  /* Send the MSG_NEWKEYS */
  if (buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS) < 0) {
    goto error;
  }

  rc=packet_send(session);
  SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_NEWKEYS sent");
  return rc;
error:
  return SSH_ERROR;
}

int make_sessionid(ssh_session session) {
    ssh_string num = NULL;
    ssh_buffer server_hash = NULL;
    ssh_buffer client_hash = NULL;
    ssh_buffer buf = NULL;
    int rc = SSH_ERROR;

    buf = ssh_buffer_new();
    if (buf == NULL) {
        return rc;
    }

    rc = ssh_buffer_pack(buf,
                         "ss",
                         session->clientbanner,
                         session->serverbanner);
    if (rc == SSH_ERROR) {
        goto error;
    }

    if (session->client) {
        server_hash = session->in_hashbuf;
        client_hash = session->out_hashbuf;
    } else {
        server_hash = session->out_hashbuf;
        client_hash = session->in_hashbuf;
    }

    /*
     * Handle the two final fields for the KEXINIT message (RFC 4253 7.1):
     *
     *      boolean      first_kex_packet_follows
     *      uint32       0 (reserved for future extension)
     */
    rc = buffer_add_u8(server_hash, 0);
    if (rc < 0) {
        goto error;
    }
    rc = buffer_add_u32(server_hash, 0);
    if (rc < 0) {
        goto error;
    }

    /* These fields are handled for the server case in ssh_packet_kexinit. */
    if (session->client) {
        rc = buffer_add_u8(client_hash, 0);
        if (rc < 0) {
            goto error;
        }
        rc = buffer_add_u32(client_hash, 0);
        if (rc < 0) {
            goto error;
        }
    }

    rc = ssh_buffer_pack(buf,
                         "dPdPS",
                         buffer_get_rest_len(client_hash),
                         buffer_get_rest_len(client_hash),
                         buffer_get_rest(client_hash),
                         buffer_get_rest_len(server_hash),
                         buffer_get_rest_len(server_hash),
                         buffer_get_rest(server_hash),
                         session->next_crypto->server_pubkey);

    if(rc != SSH_OK){
        goto error;
    }

    if (session->next_crypto->kex_type == SSH_KEX_DH_GROUP1_SHA1 ||
            session->next_crypto->kex_type == SSH_KEX_DH_GROUP14_SHA1) {
        rc = ssh_buffer_pack(buf,
                             "BB",
                             session->next_crypto->e,
                             session->next_crypto->f);
        if (rc != SSH_OK) {
            goto error;
        }

#ifdef HAVE_ECDH
    } else if (session->next_crypto->kex_type == SSH_KEX_ECDH_SHA2_NISTP256) {
        if (session->next_crypto->ecdh_client_pubkey == NULL ||
            session->next_crypto->ecdh_server_pubkey == NULL) {
            SSH_LOG(SSH_LOG_WARNING, "ECDH parameted missing");
            goto error;
        }
        rc = ssh_buffer_pack(buf,
                             "SS",
                             session->next_crypto->ecdh_client_pubkey,
                             session->next_crypto->ecdh_server_pubkey);
        if (rc != SSH_OK) {
            goto error;
        }
#endif
#ifdef HAVE_CURVE25519
    } else if (session->next_crypto->kex_type == SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG) {
        rc = ssh_buffer_pack(buf,
                             "dPdP",
                             CURVE25519_PUBKEY_SIZE,
                             (size_t)CURVE25519_PUBKEY_SIZE, session->next_crypto->curve25519_client_pubkey,
                             CURVE25519_PUBKEY_SIZE,
                             (size_t)CURVE25519_PUBKEY_SIZE, session->next_crypto->curve25519_server_pubkey);

        if (rc != SSH_OK) {
            goto error;
        }
#endif
    }
    rc = ssh_buffer_pack(buf, "B", session->next_crypto->k);
    if (rc != SSH_OK) {
        goto error;
    }

#ifdef DEBUG_CRYPTO
    ssh_print_hexa("hash buffer", ssh_buffer_get_begin(buf), ssh_buffer_get_len(buf));
#endif

    switch (session->next_crypto->kex_type) {
    case SSH_KEX_DH_GROUP1_SHA1:
    case SSH_KEX_DH_GROUP14_SHA1:
        session->next_crypto->digest_len = SHA_DIGEST_LENGTH;
        session->next_crypto->mac_type = SSH_MAC_SHA1;
        session->next_crypto->secret_hash = malloc(session->next_crypto->digest_len);
        if (session->next_crypto->secret_hash == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        sha1(buffer_get_rest(buf), buffer_get_rest_len(buf),
                                   session->next_crypto->secret_hash);
        break;
    case SSH_KEX_ECDH_SHA2_NISTP256:
    case SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG:
        session->next_crypto->digest_len = SHA256_DIGEST_LENGTH;
        session->next_crypto->mac_type = SSH_MAC_SHA256;
        session->next_crypto->secret_hash = malloc(session->next_crypto->digest_len);
        if (session->next_crypto->secret_hash == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        sha256(buffer_get_rest(buf), buffer_get_rest_len(buf),
                                     session->next_crypto->secret_hash);
        break;
    }
    /* During the first kex, secret hash and session ID are equal. However, after
     * a key re-exchange, a new secret hash is calculated. This hash will not replace
     * but complement existing session id.
     */
    if (!session->next_crypto->session_id) {
        session->next_crypto->session_id = malloc(session->next_crypto->digest_len);
        if (session->next_crypto->session_id == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        memcpy(session->next_crypto->session_id, session->next_crypto->secret_hash,
                session->next_crypto->digest_len);
    }
#ifdef DEBUG_CRYPTO
    printf("Session hash: \n");
    ssh_print_hexa("secret hash", session->next_crypto->secret_hash, session->next_crypto->digest_len);
    ssh_print_hexa("session id", session->next_crypto->session_id, session->next_crypto->digest_len);
#endif

    rc = SSH_OK;
error:
    ssh_buffer_free(buf);
    ssh_buffer_free(client_hash);
    ssh_buffer_free(server_hash);

    session->in_hashbuf = NULL;
    session->out_hashbuf = NULL;

    ssh_string_free(num);

    return rc;
}

int hashbufout_add_cookie(ssh_session session) {
  session->out_hashbuf = ssh_buffer_new();
  if (session->out_hashbuf == NULL) {
    return -1;
  }

  if (buffer_add_u8(session->out_hashbuf, 20) < 0) {
    ssh_buffer_reinit(session->out_hashbuf);
    return -1;
  }

  if (session->server) {
    if (ssh_buffer_add_data(session->out_hashbuf,
          session->next_crypto->server_kex.cookie, 16) < 0) {
      ssh_buffer_reinit(session->out_hashbuf);
      return -1;
    }
  } else {
    if (ssh_buffer_add_data(session->out_hashbuf,
          session->next_crypto->client_kex.cookie, 16) < 0) {
      ssh_buffer_reinit(session->out_hashbuf);
      return -1;
    }
  }

  return 0;
}

int hashbufin_add_cookie(ssh_session session, unsigned char *cookie) {
  session->in_hashbuf = ssh_buffer_new();
  if (session->in_hashbuf == NULL) {
    return -1;
  }

  if (buffer_add_u8(session->in_hashbuf, 20) < 0) {
    ssh_buffer_reinit(session->in_hashbuf);
    return -1;
  }
  if (ssh_buffer_add_data(session->in_hashbuf,cookie, 16) < 0) {
    ssh_buffer_reinit(session->in_hashbuf);
    return -1;
  }

  return 0;
}

static int generate_one_key(ssh_string k,
    struct ssh_crypto_struct *crypto, unsigned char **output, char letter, size_t requested_size) {
  ssh_mac_ctx ctx;
  unsigned char *tmp;
  size_t size = crypto->digest_len;
  ctx=ssh_mac_ctx_init(crypto->mac_type);

  if (ctx == NULL) {
    return -1;
  }

  ssh_mac_update(ctx, k, ssh_string_len(k) + 4);
  ssh_mac_update(ctx, crypto->secret_hash, crypto->digest_len);
  ssh_mac_update(ctx, &letter, 1);
  ssh_mac_update(ctx, crypto->session_id, crypto->digest_len);
  ssh_mac_final(*output, ctx);

  while(requested_size > size) {
    tmp = realloc(*output, size + crypto->digest_len);
    if (tmp == NULL) {
      return -1;
    }
    *output = tmp;

    ctx = ssh_mac_ctx_init(crypto->mac_type);
    if (ctx == NULL) {
      return -1;
    }
    ssh_mac_update(ctx, k, ssh_string_len(k) + 4);
    ssh_mac_update(ctx, crypto->secret_hash,
        crypto->digest_len);
    ssh_mac_update(ctx, tmp, size);
    ssh_mac_final(tmp + size, ctx);
    size += crypto->digest_len;
  }

  return 0;
}

int generate_session_keys(ssh_session session) {
  ssh_string k_string = NULL;
  struct ssh_crypto_struct *crypto = session->next_crypto;
  int rc = -1;

  k_string = make_bignum_string(crypto->k);
  if (k_string == NULL) {
    ssh_set_error_oom(session);
    goto error;
  }

  crypto->encryptIV = malloc(crypto->digest_len);
  crypto->decryptIV = malloc(crypto->digest_len);
  crypto->encryptkey = malloc(crypto->digest_len);
  crypto->decryptkey = malloc(crypto->digest_len);
  crypto->encryptMAC = malloc(crypto->digest_len);
  crypto->decryptMAC = malloc(crypto->digest_len);
  if(crypto->encryptIV == NULL || crypto->decryptIV == NULL ||
      crypto->encryptkey == NULL || crypto->decryptkey == NULL ||
      crypto->encryptMAC == NULL || crypto->decryptMAC == NULL){
    ssh_set_error_oom(session);
    goto error;
  }

  /* IV */
  if (session->client) {
    rc = generate_one_key(k_string, crypto, &crypto->encryptIV, 'A', crypto->digest_len);
    if (rc < 0) {
      goto error;
    }
    rc = generate_one_key(k_string, crypto, &crypto->decryptIV, 'B', crypto->digest_len);
    if (rc < 0) {
      goto error;
    }
  } else {
    rc = generate_one_key(k_string, crypto, &crypto->decryptIV, 'A', crypto->digest_len);
    if (rc < 0) {
      goto error;
    }
    rc = generate_one_key(k_string, crypto, &crypto->encryptIV, 'B', crypto->digest_len);
    if (rc < 0) {
      goto error;
    }
  }
  if (session->client) {
    rc = generate_one_key(k_string, crypto, &crypto->encryptkey, 'C', crypto->out_cipher->keysize / 8);
    if (rc < 0) {
      goto error;
    }
    rc = generate_one_key(k_string, crypto, &crypto->decryptkey, 'D', crypto->in_cipher->keysize / 8);
    if (rc < 0) {
      goto error;
    }
  } else {
    rc = generate_one_key(k_string, crypto, &crypto->decryptkey, 'C', crypto->in_cipher->keysize / 8);
    if (rc < 0) {
      goto error;
    }
    rc = generate_one_key(k_string, crypto, &crypto->encryptkey, 'D', crypto->out_cipher->keysize / 8);
    if (rc < 0) {
      goto error;
    }
  }

  if(session->client) {
    rc = generate_one_key(k_string, crypto, &crypto->encryptMAC, 'E', hmac_digest_len(crypto->out_hmac));
    if (rc < 0) {
      goto error;
    }
    rc = generate_one_key(k_string, crypto, &crypto->decryptMAC, 'F', hmac_digest_len(crypto->in_hmac));
    if (rc < 0) {
      goto error;
    }
  } else {
    rc = generate_one_key(k_string, crypto, &crypto->decryptMAC, 'E', hmac_digest_len(crypto->in_hmac));
    if (rc < 0) {
      goto error;
    }
    rc = generate_one_key(k_string, crypto, &crypto->encryptMAC, 'F', hmac_digest_len(crypto->out_hmac));
    if (rc < 0) {
      goto error;
    }
  }

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("Encrypt IV", crypto->encryptIV, crypto->digest_len);
  ssh_print_hexa("Decrypt IV", crypto->decryptIV, crypto->digest_len);
  ssh_print_hexa("Encryption key", crypto->encryptkey, crypto->out_cipher->keysize / 8);
  ssh_print_hexa("Decryption key", crypto->decryptkey, crypto->in_cipher->keysize / 8);
  ssh_print_hexa("Encryption MAC", crypto->encryptMAC, hmac_digest_len(crypto->out_hmac));
  ssh_print_hexa("Decryption MAC", crypto->decryptMAC, hmac_digest_len(crypto->in_hmac));
#endif

  rc = 0;
error:
  ssh_string_free(k_string);

  return rc;
}

/**
 * @addtogroup libssh_session
 *
 * @{
 */

/**
 * @deprecated Use ssh_get_publickey_hash()
 */
int ssh_get_pubkey_hash(ssh_session session, unsigned char **hash) {
  ssh_string pubkey;
  MD5CTX ctx;
  unsigned char *h;

  if (session == NULL || hash == NULL) {
    return SSH_ERROR;
  }
  *hash = NULL;
  if (session->current_crypto == NULL ||
      session->current_crypto->server_pubkey == NULL){
    ssh_set_error(session,SSH_FATAL,"No current cryptographic context");
    return SSH_ERROR;
  }

  h = malloc(sizeof(unsigned char) * MD5_DIGEST_LEN);
  if (h == NULL) {
    return SSH_ERROR;
  }

  ctx = md5_init();
  if (ctx == NULL) {
    SAFE_FREE(h);
    return SSH_ERROR;
  }

  pubkey = session->current_crypto->server_pubkey;

  md5_update(ctx, ssh_string_data(pubkey), ssh_string_len(pubkey));
  md5_final(h, ctx);

  *hash = h;

  return MD5_DIGEST_LEN;
}

/**
 * @brief Deallocate the hash obtained by ssh_get_pubkey_hash.
 *
 * This is required under Microsoft platform as this library might use a 
 * different C library than your software, hence a different heap.
 *
 * @param[in] hash      The buffer to deallocate.
 *
 * @see ssh_get_pubkey_hash()
 */
void ssh_clean_pubkey_hash(unsigned char **hash) {
  SAFE_FREE(*hash);
  *hash = NULL;
}

/**
 * @brief Get the server public key from a session.
 *
 * @param[in]  session  The session to get the key from.
 *
 * @param[out] key      A pointer to store the allocated key. You need to free
 *                      the key.
 *
 * @return              SSH_OK on success, SSH_ERROR on errror.
 *
 * @see ssh_key_free()
 */
int ssh_get_publickey(ssh_session session, ssh_key *key)
{
    if (session==NULL ||
        session->current_crypto ==NULL ||
        session->current_crypto->server_pubkey == NULL) {
        return SSH_ERROR;
    }

    return ssh_pki_import_pubkey_blob(session->current_crypto->server_pubkey,
                                      key);
}

/**
 * @brief Allocates a buffer with the hash of the public key.
 *
 * This function allows you to get a hash of the public key. You can then
 * print this hash in a human-readable form to the user so that he is able to
 * verify it. Use ssh_get_hexa() or ssh_print_hexa() to display it.
 *
 * @param[in]  key      The public key to create the hash for.
 *
 * @param[in]  type     The type of the hash you want.
 *
 * @param[in]  hash     A pointer to store the allocated buffer. It can be
 *                      freed using ssh_clean_pubkey_hash().
 *
 * @param[in]  hlen     The length of the hash.
 *
 * @return 0 on success, -1 if an error occured.
 *
 * @warning It is very important that you verify at some moment that the hash
 *          matches a known server. If you don't do it, cryptography wont help
 *          you at making things secure.
 *          OpenSSH uses SHA1 to print public key digests.
 *
 * @see ssh_is_server_known()
 * @see ssh_get_hexa()
 * @see ssh_print_hexa()
 * @see ssh_clean_pubkey_hash()
 */
int ssh_get_publickey_hash(const ssh_key key,
                           enum ssh_publickey_hash_type type,
                           unsigned char **hash,
                           size_t *hlen)
{
    ssh_string blob;
    unsigned char *h;
    int rc;

    rc = ssh_pki_export_pubkey_blob(key, &blob);
    if (rc < 0) {
        return rc;
    }

    switch (type) {
    case SSH_PUBLICKEY_HASH_SHA1:
        {
            SHACTX ctx;

            h = malloc(SHA_DIGEST_LEN);
            if (h == NULL) {
                rc = -1;
                goto out;
            }

            ctx = sha1_init();
            if (ctx == NULL) {
                free(h);
                rc = -1;
                goto out;
            }

            sha1_update(ctx, ssh_string_data(blob), ssh_string_len(blob));
            sha1_final(h, ctx);

            *hlen = SHA_DIGEST_LEN;
        }
        break;
    case SSH_PUBLICKEY_HASH_MD5:
        {
            MD5CTX ctx;

            h = malloc(MD5_DIGEST_LEN);
            if (h == NULL) {
                rc = -1;
                goto out;
            }

            ctx = md5_init();
            if (ctx == NULL) {
                free(h);
                rc = -1;
                goto out;
            }

            md5_update(ctx, ssh_string_data(blob), ssh_string_len(blob));
            md5_final(h, ctx);

            *hlen = MD5_DIGEST_LEN;
        }
        break;
    default:
        rc = -1;
        goto out;
    }

    *hash = h;
    rc = 0;
out:
    ssh_string_free(blob);
    return rc;
}

/**
 * @brief Convert a buffer into a colon separated hex string.
 * The caller has to free the memory.
 *
 * @param  what         What should be converted to a hex string.
 *
 * @param  len          Length of the buffer to convert.
 *
 * @return              The hex string or NULL on error.
 *
 * @see ssh_string_free_char()
 */
char *ssh_get_hexa(const unsigned char *what, size_t len) {
  const char h[] = "0123456789abcdef";
  char *hexa;
  size_t i;
  size_t hlen = len * 3;

  if (len > (UINT_MAX - 1) / 3) {
    return NULL;
  }

  hexa = malloc(hlen + 1);
  if (hexa == NULL) {
    return NULL;
  }

  for (i = 0; i < len; i++) {
      hexa[i * 3] = h[(what[i] >> 4) & 0xF];
      hexa[i * 3 + 1] = h[what[i] & 0xF];
      hexa[i * 3 + 2] = ':';
  }
  hexa[hlen - 1] = '\0';

  return hexa;
}

/**
 * @brief Print a buffer as colon separated hex string.
 *
 * @param  descr        Description printed in front of the hex string.
 *
 * @param  what         What should be converted to a hex string.
 *
 * @param  len          Length of the buffer to convert.
 */
void ssh_print_hexa(const char *descr, const unsigned char *what, size_t len) {
    char *hexa = ssh_get_hexa(what, len);

    if (hexa == NULL) {
      return;
    }
    printf("%s: %s\n", descr, hexa);

    free(hexa);
}

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
