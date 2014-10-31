/*
 * pki_gcrypt.c private and public key handling using gcrypt.
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 Aris Adamantiadis
 * Copyright (c) 2009-2011 Andreas Schneider <asn@cryptomilk.org>
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

#ifdef HAVE_LIBGCRYPT

#include <string.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <stdio.h>

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/session.h"
#include "libssh/wrapper.h"
#include "libssh/misc.h"
#include "libssh/pki.h"
#include "libssh/pki_priv.h"

#define MAXLINESIZE 80
#define RSA_HEADER_BEGIN "-----BEGIN RSA PRIVATE KEY-----"
#define RSA_HEADER_END "-----END RSA PRIVATE KEY-----"
#define DSA_HEADER_BEGIN "-----BEGIN DSA PRIVATE KEY-----"
#define DSA_HEADER_END "-----END DSA PRIVATE KEY-----"

#define MAX_KEY_SIZE 32
#define MAX_PASSPHRASE_SIZE 1024
#define ASN1_INTEGER 2
#define ASN1_SEQUENCE 48
#define PKCS5_SALT_LEN 8

static int load_iv(const char *header, unsigned char *iv, int iv_len) {
  int i;
  int j;
  int k;

  memset(iv, 0, iv_len);
  for (i = 0; i < iv_len; i++) {
    if ((header[2*i] >= '0') && (header[2*i] <= '9'))
      j = header[2*i] - '0';
    else if ((header[2*i] >= 'A') && (header[2*i] <= 'F'))
      j = header[2*i] - 'A' + 10;
    else if ((header[2*i] >= 'a') && (header[2*i] <= 'f'))
      j = header[2*i] - 'a' + 10;
    else
      return -1;
    if ((header[2*i+1] >= '0') && (header[2*i+1] <= '9'))
      k = header[2*i+1] - '0';
    else if ((header[2*i+1] >= 'A') && (header[2*i+1] <= 'F'))
      k = header[2*i+1] - 'A' + 10;
    else if ((header[2*i+1] >= 'a') && (header[2*i+1] <= 'f'))
      k = header[2*i+1] - 'a' + 10;
    else
      return -1;
    iv[i] = (j << 4) + k;
  }
  return 0;
}

static uint32_t char_to_u32(unsigned char *data, uint32_t size) {
  uint32_t ret;
  uint32_t i;

  for (i = 0, ret = 0; i < size; ret = ret << 8, ret += data[i++])
    ;
  return ret;
}

static uint32_t asn1_get_len(ssh_buffer buffer) {
  uint32_t len;
  unsigned char tmp[4];

  if (buffer_get_data(buffer,tmp,1) == 0) {
    return 0;
  }

  if (tmp[0] > 127) {
    len = tmp[0] & 127;
    if (len > 4) {
      return 0; /* Length doesn't fit in u32. Can this really happen? */
    }
    if (buffer_get_data(buffer,tmp,len) == 0) {
      return 0;
    }
    len = char_to_u32(tmp, len);
  } else {
    len = char_to_u32(tmp, 1);
  }

  return len;
}

static ssh_string asn1_get_int(ssh_buffer buffer) {
  ssh_string str;
  unsigned char type;
  uint32_t size;

  if (buffer_get_data(buffer, &type, 1) == 0 || type != ASN1_INTEGER) {
    return NULL;
  }
  size = asn1_get_len(buffer);
  if (size == 0) {
    return NULL;
  }

  str = ssh_string_new(size);
  if (str == NULL) {
    return NULL;
  }

  if (buffer_get_data(buffer, ssh_string_data(str), size) == 0) {
    ssh_string_free(str);
    return NULL;
  }

  return str;
}

static int asn1_check_sequence(ssh_buffer buffer) {
  unsigned char *j = NULL;
  unsigned char tmp;
  int i;
  uint32_t size;
  uint32_t padding;

  if (buffer_get_data(buffer, &tmp, 1) == 0 || tmp != ASN1_SEQUENCE) {
    return 0;
  }

  size = asn1_get_len(buffer);
  if ((padding = ssh_buffer_get_len(buffer) - buffer->pos - size) > 0) {
    for (i = ssh_buffer_get_len(buffer) - buffer->pos - size,
         j = (unsigned char*)ssh_buffer_get_begin(buffer) + size + buffer->pos;
         i;
         i--, j++)
    {
      if (*j != padding) {                   /* padding is allowed */
        return 0;                            /* but nothing else */
      }
    }
  }

  return 1;
}

static int passphrase_to_key(char *data, unsigned int datalen,
    unsigned char *salt, unsigned char *key, unsigned int keylen) {
  MD5CTX md;
  unsigned char digest[MD5_DIGEST_LEN] = {0};
  unsigned int i;
  unsigned int j;
  unsigned int md_not_empty;

  for (j = 0, md_not_empty = 0; j < keylen; ) {
    md = md5_init();
    if (md == NULL) {
      return -1;
    }

    if (md_not_empty) {
      md5_update(md, digest, MD5_DIGEST_LEN);
    } else {
      md_not_empty = 1;
    }

    md5_update(md, data, datalen);
    if (salt) {
      md5_update(md, salt, PKCS5_SALT_LEN);
    }
    md5_final(digest, md);

    for (i = 0; j < keylen && i < MD5_DIGEST_LEN; j++, i++) {
      if (key) {
        key[j] = digest[i];
      }
    }
  }

  return 0;
}

static int privatekey_decrypt(int algo, int mode, unsigned int key_len,
                       unsigned char *iv, unsigned int iv_len,
                       ssh_buffer data, ssh_auth_callback cb,
                       void *userdata,
                       const char *desc)
{
  char passphrase[MAX_PASSPHRASE_SIZE] = {0};
  unsigned char key[MAX_KEY_SIZE] = {0};
  unsigned char *tmp = NULL;
  gcry_cipher_hd_t cipher;
  int rc = -1;

  if (!algo) {
    return -1;
  }

  if (cb) {
    rc = (*cb)(desc, passphrase, MAX_PASSPHRASE_SIZE, 0, 0, userdata);
    if (rc < 0) {
      return -1;
    }
  } else if (cb == NULL && userdata != NULL) {
    snprintf(passphrase, MAX_PASSPHRASE_SIZE, "%s", (char *) userdata);
  }

  if (passphrase_to_key(passphrase, strlen(passphrase), iv, key, key_len) < 0) {
    return -1;
  }

  if (gcry_cipher_open(&cipher, algo, mode, 0)
      || gcry_cipher_setkey(cipher, key, key_len)
      || gcry_cipher_setiv(cipher, iv, iv_len)
      || (tmp = malloc(ssh_buffer_get_len(data) * sizeof (char))) == NULL
      || gcry_cipher_decrypt(cipher, tmp, ssh_buffer_get_len(data),
                       ssh_buffer_get_begin(data), ssh_buffer_get_len(data))) {
    gcry_cipher_close(cipher);
    return -1;
  }

  memcpy(ssh_buffer_get_begin(data), tmp, ssh_buffer_get_len(data));

  SAFE_FREE(tmp);
  gcry_cipher_close(cipher);

  return 0;
}

static int privatekey_dek_header(const char *header, unsigned int header_len,
    int *algo, int *mode, unsigned int *key_len, unsigned char **iv,
    unsigned int *iv_len) {
  unsigned int iv_pos;

  if (header_len > 13 && !strncmp("DES-EDE3-CBC", header, 12))
  {
    *algo = GCRY_CIPHER_3DES;
    iv_pos = 13;
    *mode = GCRY_CIPHER_MODE_CBC;
    *key_len = 24;
    *iv_len = 8;
  }
  else if (header_len > 8 && !strncmp("DES-CBC", header, 7))
  {
    *algo = GCRY_CIPHER_DES;
    iv_pos = 8;
    *mode = GCRY_CIPHER_MODE_CBC;
    *key_len = 8;
    *iv_len = 8;
  }
  else if (header_len > 12 && !strncmp("AES-128-CBC", header, 11))
  {
    *algo = GCRY_CIPHER_AES128;
    iv_pos = 12;
    *mode = GCRY_CIPHER_MODE_CBC;
    *key_len = 16;
    *iv_len = 16;
  }
  else if (header_len > 12 && !strncmp("AES-192-CBC", header, 11))
  {
    *algo = GCRY_CIPHER_AES192;
    iv_pos = 12;
    *mode = GCRY_CIPHER_MODE_CBC;
    *key_len = 24;
    *iv_len = 16;
  }
  else if (header_len > 12 && !strncmp("AES-256-CBC", header, 11))
  {
    *algo = GCRY_CIPHER_AES256;
    iv_pos = 12;
    *mode = GCRY_CIPHER_MODE_CBC;
    *key_len = 32;
    *iv_len = 16;
  } else {
    return -1;
  }

  *iv = malloc(*iv_len);
  if (*iv == NULL) {
    return -1;
  }

  return load_iv(header + iv_pos, *iv, *iv_len);
}

#define get_next_line(p, len) {                                         \
        while(p[len] == '\n' || p[len] == '\r') /* skip empty lines */  \
            len++;                                                      \
        if(p[len] == '\0')    /* EOL */                                 \
            len = -1;                                                   \
        else                  /* calculate length */                    \
            for(p += len, len = 0; p[len] && p[len] != '\n'             \
                                          && p[len] != '\r'; len++);    \
    }

static ssh_buffer privatekey_string_to_buffer(const char *pkey, int type,
                ssh_auth_callback cb, void *userdata, const char *desc) {
    ssh_buffer buffer = NULL;
    ssh_buffer out = NULL;
    const char *p;
    unsigned char *iv = NULL;
    const char *header_begin;
    const char *header_end;
    unsigned int header_begin_size;
    unsigned int header_end_size;
    unsigned int key_len = 0;
    unsigned int iv_len = 0;
    int algo = 0;
    int mode = 0;
    int len;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        return NULL;
    }

    switch(type) {
        case SSH_KEYTYPE_DSS:
            header_begin = DSA_HEADER_BEGIN;
            header_end = DSA_HEADER_END;
            break;
        case SSH_KEYTYPE_RSA:
            header_begin = RSA_HEADER_BEGIN;
            header_end = RSA_HEADER_END;
            break;
        default:
            ssh_buffer_free(buffer);
            return NULL;
    }

    header_begin_size = strlen(header_begin);
    header_end_size = strlen(header_end);

    p = pkey;
    len = 0;
    get_next_line(p, len);

    while(len > 0 && strncmp(p, header_begin, header_begin_size)) {
        /* skip line */
        get_next_line(p, len);
    }
    if(len < 0) {
        /* no header found */
        return NULL;
    }
    /* skip header line */
    get_next_line(p, len);

    if (len > 11 && strncmp("Proc-Type: 4,ENCRYPTED", p, 11) == 0) {
        /* skip line */
        get_next_line(p, len);

        if (len > 10 && strncmp("DEK-Info: ", p, 10) == 0) {
            p += 10;
            len = 0;
            get_next_line(p, len);
            if (privatekey_dek_header(p, len, &algo, &mode, &key_len,
                        &iv, &iv_len) < 0) {
                ssh_buffer_free(buffer);
                SAFE_FREE(iv);
                return NULL;
            }
        } else {
            ssh_buffer_free(buffer);
            SAFE_FREE(iv);
            return NULL;
        }
    } else {
        if(len > 0) {
            if (ssh_buffer_add_data(buffer, p, len) < 0) {
                ssh_buffer_free(buffer);
                SAFE_FREE(iv);
                return NULL;
            }
        }
    }

    get_next_line(p, len);
    while(len > 0 && strncmp(p, header_end, header_end_size) != 0) {
        if (ssh_buffer_add_data(buffer, p, len) < 0) {
            ssh_buffer_free(buffer);
            SAFE_FREE(iv);
            return NULL;
        }
        get_next_line(p, len);
    }

    if (len == -1 || strncmp(p, header_end, header_end_size) != 0) {
        ssh_buffer_free(buffer);
        SAFE_FREE(iv);
        return NULL;
    }

    if (ssh_buffer_add_data(buffer, "\0", 1) < 0) {
        ssh_buffer_free(buffer);
        SAFE_FREE(iv);
        return NULL;
    }

    out = base64_to_bin(ssh_buffer_get_begin(buffer));
    ssh_buffer_free(buffer);
    if (out == NULL) {
        SAFE_FREE(iv);
        return NULL;
    }

    if (algo) {
        if (privatekey_decrypt(algo, mode, key_len, iv, iv_len, out,
                    cb, userdata, desc) < 0) {
            ssh_buffer_free(out);
            SAFE_FREE(iv);
            return NULL;
        }
    }
    SAFE_FREE(iv);

    return out;
}

static int b64decode_rsa_privatekey(const char *pkey, gcry_sexp_t *r,
    ssh_auth_callback cb, void *userdata, const char *desc) {
  const unsigned char *data;
  ssh_string n = NULL;
  ssh_string e = NULL;
  ssh_string d = NULL;
  ssh_string p = NULL;
  ssh_string q = NULL;
  ssh_string unused1 = NULL;
  ssh_string unused2 = NULL;
  ssh_string u = NULL;
  ssh_string v = NULL;
  ssh_buffer buffer = NULL;
  int rc = 1;

  buffer = privatekey_string_to_buffer(pkey, SSH_KEYTYPE_RSA, cb, userdata, desc);
  if (buffer == NULL) {
    return 0;
  }

  if (!asn1_check_sequence(buffer)) {
    ssh_buffer_free(buffer);
    return 0;
  }

  v = asn1_get_int(buffer);
  if (v == NULL) {
    ssh_buffer_free(buffer);
    return 0;
  }

  data = ssh_string_data(v);
  if (ssh_string_len(v) != 1 || data[0] != 0) {
    ssh_buffer_free(buffer);
    return 0;
  }

  n = asn1_get_int(buffer);
  e = asn1_get_int(buffer);
  d = asn1_get_int(buffer);
  q = asn1_get_int(buffer);
  p = asn1_get_int(buffer);
  unused1 = asn1_get_int(buffer);
  unused2 = asn1_get_int(buffer);
  u = asn1_get_int(buffer);

  ssh_buffer_free(buffer);

  if (n == NULL || e == NULL || d == NULL || p == NULL || q == NULL ||
      unused1 == NULL || unused2 == NULL|| u == NULL) {
    rc = 0;
    goto error;
  }

  if (gcry_sexp_build(r, NULL,
      "(private-key(rsa(n %b)(e %b)(d %b)(p %b)(q %b)(u %b)))",
      ssh_string_len(n), ssh_string_data(n),
      ssh_string_len(e), ssh_string_data(e),
      ssh_string_len(d), ssh_string_data(d),
      ssh_string_len(p), ssh_string_data(p),
      ssh_string_len(q), ssh_string_data(q),
      ssh_string_len(u), ssh_string_data(u))) {
    rc = 0;
  }

error:
  ssh_string_free(n);
  ssh_string_free(e);
  ssh_string_free(d);
  ssh_string_free(p);
  ssh_string_free(q);
  ssh_string_free(unused1);
  ssh_string_free(unused2);
  ssh_string_free(u);
  ssh_string_free(v);

  return rc;
}

static int b64decode_dsa_privatekey(const char *pkey, gcry_sexp_t *r, ssh_auth_callback cb,
    void *userdata, const char *desc) {
  const unsigned char *data;
  ssh_buffer buffer = NULL;
  ssh_string p = NULL;
  ssh_string q = NULL;
  ssh_string g = NULL;
  ssh_string y = NULL;
  ssh_string x = NULL;
  ssh_string v = NULL;
  int rc = 1;

  buffer = privatekey_string_to_buffer(pkey, SSH_KEYTYPE_DSS, cb, userdata, desc);
  if (buffer == NULL) {
    return 0;
  }

  if (!asn1_check_sequence(buffer)) {
    ssh_buffer_free(buffer);
    return 0;
  }

  v = asn1_get_int(buffer);
  if (v == NULL) {
    ssh_buffer_free(buffer);
    return 0;
  }

  data = ssh_string_data(v);
  if (ssh_string_len(v) != 1 || data[0] != 0) {
    ssh_buffer_free(buffer);
    return 0;
  }

  p = asn1_get_int(buffer);
  q = asn1_get_int(buffer);
  g = asn1_get_int(buffer);
  y = asn1_get_int(buffer);
  x = asn1_get_int(buffer);
  ssh_buffer_free(buffer);

  if (p == NULL || q == NULL || g == NULL || y == NULL || x == NULL) {
    rc = 0;
    goto error;
  }

  if (gcry_sexp_build(r, NULL,
        "(private-key(dsa(p %b)(q %b)(g %b)(y %b)(x %b)))",
        ssh_string_len(p), ssh_string_data(p),
        ssh_string_len(q), ssh_string_data(q),
        ssh_string_len(g), ssh_string_data(g),
        ssh_string_len(y), ssh_string_data(y),
        ssh_string_len(x), ssh_string_data(x))) {
    rc = 0;
  }

error:
  ssh_string_free(p);
  ssh_string_free(q);
  ssh_string_free(g);
  ssh_string_free(y);
  ssh_string_free(x);
  ssh_string_free(v);

  return rc;
}

#ifdef HAVE_GCRYPT_ECC
int pki_key_ecdsa_nid_from_name(const char *name)
{
    return -1;
}
#endif

ssh_string pki_private_key_to_pem(const ssh_key key,
                                  const char *passphrase,
                                  ssh_auth_callback auth_fn,
                                  void *auth_data)
{
    (void) key;
    (void) passphrase;
    (void) auth_fn;
    (void) auth_data;

    return NULL;
}

ssh_key pki_private_key_from_base64(const char *b64_key,
                                    const char *passphrase,
                                    ssh_auth_callback auth_fn,
                                    void *auth_data)
{
    gcry_sexp_t dsa = NULL;
    gcry_sexp_t rsa = NULL;
    ssh_key key = NULL;
    enum ssh_keytypes_e type;
    int valid;

    /* needed for gcrypt initialization */
    if (ssh_init() < 0) {
        return NULL;
    }

    type = pki_privatekey_type_from_string(b64_key);
    if (type == SSH_KEYTYPE_UNKNOWN) {
        ssh_pki_log("Unknown or invalid private key.");
        return NULL;
    }

    switch (type) {
        case SSH_KEYTYPE_DSS:
            if (passphrase == NULL) {
                if (auth_fn) {
                    valid = b64decode_dsa_privatekey(b64_key, &dsa, auth_fn,
                            auth_data, "Passphrase for private key:");
                } else {
                    valid = b64decode_dsa_privatekey(b64_key, &dsa, NULL, NULL,
                            NULL);
                }
            } else {
                valid = b64decode_dsa_privatekey(b64_key, &dsa, NULL, (void *)
                        passphrase, NULL);
            }

            if (!valid) {
                ssh_pki_log("Parsing private key");
                goto fail;
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            if (passphrase == NULL) {
                if (auth_fn) {
                    valid = b64decode_rsa_privatekey(b64_key, &rsa, auth_fn,
                            auth_data, "Passphrase for private key:");
                } else {
                    valid = b64decode_rsa_privatekey(b64_key, &rsa, NULL, NULL,
                            NULL);
                }
            } else {
                valid = b64decode_rsa_privatekey(b64_key, &rsa, NULL,
                        (void *)passphrase, NULL);
            }

            if (!valid) {
                ssh_pki_log("Parsing private key");
                goto fail;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            ssh_pki_log("Unkown or invalid private key type %d", type);
            return NULL;
    }

    key = ssh_key_new();
    if (key == NULL) {
        goto fail;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PRIVATE | SSH_KEY_FLAG_PUBLIC;
    key->dsa = dsa;
    key->rsa = rsa;

    return key;
fail:
    ssh_key_free(key);
    gcry_sexp_release(dsa);
    gcry_sexp_release(rsa);

    return NULL;
}

int pki_pubkey_build_dss(ssh_key key,
                         ssh_string p,
                         ssh_string q,
                         ssh_string g,
                         ssh_string pubkey) {
    gcry_sexp_build(&key->dsa, NULL,
            "(public-key(dsa(p %b)(q %b)(g %b)(y %b)))",
            ssh_string_len(p), ssh_string_data(p),
            ssh_string_len(q), ssh_string_data(q),
            ssh_string_len(g), ssh_string_data(g),
            ssh_string_len(pubkey), ssh_string_data(pubkey));
    if (key->dsa == NULL) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

int pki_pubkey_build_rsa(ssh_key key,
                         ssh_string e,
                         ssh_string n) {
    gcry_sexp_build(&key->rsa, NULL,
            "(public-key(rsa(n %b)(e %b)))",
            ssh_string_len(n), ssh_string_data(n),
            ssh_string_len(e),ssh_string_data(e));
    if (key->rsa == NULL) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

#ifdef HAVE_GCRYPT_ECC
int pki_pubkey_build_ecdsa(ssh_key key, int nid, ssh_string e)
{
    return -1;
}
#endif

ssh_key pki_key_dup(const ssh_key key, int demote)
{
    ssh_key new;
    gcry_sexp_t sexp;
    gcry_error_t err;
    const char *tmp = NULL;
    size_t size;

    ssh_string p = NULL;
    ssh_string q = NULL;
    ssh_string g = NULL;
    ssh_string y = NULL;
    ssh_string x = NULL;

    ssh_string e = NULL;
    ssh_string n = NULL;
    ssh_string d = NULL;
    ssh_string u = NULL;

    new = ssh_key_new();
    if (new == NULL) {
        return NULL;
    }
    new->type = key->type;
    new->type_c = key->type_c;
    if (demote) {
        new->flags = SSH_KEY_FLAG_PUBLIC;
    } else {
        new->flags = key->flags;
    }

    switch(key->type) {
        case SSH_KEYTYPE_DSS:
            sexp = gcry_sexp_find_token(key->dsa, "p", 0);
            if (sexp == NULL) {
                goto fail;
            }
            tmp = gcry_sexp_nth_data(sexp, 1, &size);
            p = ssh_string_new(size);
            if (p == NULL) {
                goto fail;
            }
            ssh_string_fill(p, (char *)tmp, size);
            gcry_sexp_release(sexp);

            sexp = gcry_sexp_find_token(key->dsa, "q", 0);
            if (sexp == NULL) {
                goto fail;
            }
            tmp = gcry_sexp_nth_data(sexp, 1, &size);
            q = ssh_string_new(size);
            if (q == NULL) {
                goto fail;
            }
            ssh_string_fill(q, (char *)tmp, size);
            gcry_sexp_release(sexp);

            sexp = gcry_sexp_find_token(key->dsa, "g", 0);
            if (sexp == NULL) {
                goto fail;
            }
            tmp = gcry_sexp_nth_data(sexp, 1, &size);
            g = ssh_string_new(size);
            if (g == NULL) {
                goto fail;
            }
            ssh_string_fill(g, (char *)tmp, size);
            gcry_sexp_release(sexp);

            sexp = gcry_sexp_find_token(key->dsa, "y", 0);
            if (sexp == NULL) {
                goto fail;
            }
            tmp = gcry_sexp_nth_data(sexp, 1, &size);
            y = ssh_string_new(size);
            if (y == NULL) {
                goto fail;
            }
            ssh_string_fill(y, (char *)tmp, size);
            gcry_sexp_release(sexp);

            if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE)) {
                sexp = gcry_sexp_find_token(key->dsa, "x", 0);
                if (sexp == NULL) {
                    goto fail;
                }
                tmp = gcry_sexp_nth_data(sexp, 1, &size);
                x = ssh_string_new(size);
                if (x == NULL) {
                    goto fail;
                }
                ssh_string_fill(x, (char *)tmp, size);
                gcry_sexp_release(sexp);

                err = gcry_sexp_build(&new->dsa, NULL,
                        "(private-key(dsa(p %b)(q %b)(g %b)(y %b)(x %b)))",
                        ssh_string_len(p), ssh_string_data(p),
                        ssh_string_len(q), ssh_string_data(q),
                        ssh_string_len(g), ssh_string_data(g),
                        ssh_string_len(y), ssh_string_data(y),
                        ssh_string_len(x), ssh_string_data(x));
            } else {
                err = gcry_sexp_build(&new->dsa, NULL,
                        "(public-key(dsa(p %b)(q %b)(g %b)(y %b)))",
                        ssh_string_len(p), ssh_string_data(p),
                        ssh_string_len(q), ssh_string_data(q),
                        ssh_string_len(g), ssh_string_data(g),
                        ssh_string_len(y), ssh_string_data(y));
            }
            if (err) {
                goto fail;
            }

            ssh_string_burn(p);
            ssh_string_free(p);
            ssh_string_burn(q);
            ssh_string_free(q);
            ssh_string_burn(g);
            ssh_string_free(g);
            ssh_string_burn(y);
            ssh_string_free(y);
            ssh_string_burn(x);
            ssh_string_free(x);
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sexp = gcry_sexp_find_token(key->rsa, "e", 0);
            if (sexp == NULL) {
                goto fail;
            }
            tmp = gcry_sexp_nth_data(sexp, 1, &size);
            e = ssh_string_new(size);
            if (e == NULL) {
                goto fail;
            }
            ssh_string_fill(e, (char *)tmp, size);
            gcry_sexp_release(sexp);

            sexp = gcry_sexp_find_token(key->rsa, "n", 0);
            if (sexp == NULL) {
                goto fail;
            }
            tmp = gcry_sexp_nth_data(sexp, 1, &size);
            n = ssh_string_new(size);
            if (n == NULL) {
                goto fail;
            }
            ssh_string_fill(n, (char *)tmp, size);
            gcry_sexp_release(sexp);

            if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE)) {
                sexp = gcry_sexp_find_token(key->rsa, "d", 0);
                if (sexp == NULL) {
                    goto fail;
                }
                tmp = gcry_sexp_nth_data(sexp, 1, &size);
                d = ssh_string_new(size);
                if (e == NULL) {
                    goto fail;
                }
                ssh_string_fill(d, (char *)tmp, size);
                gcry_sexp_release(sexp);

                sexp = gcry_sexp_find_token(key->rsa, "p", 0);
                if (sexp == NULL) {
                    goto fail;
                }
                tmp = gcry_sexp_nth_data(sexp, 1, &size);
                p = ssh_string_new(size);
                if (p == NULL) {
                    goto fail;
                }
                ssh_string_fill(p, (char *)tmp, size);
                gcry_sexp_release(sexp);

                sexp = gcry_sexp_find_token(key->rsa, "q", 0);
                if (sexp == NULL) {
                    goto fail;
                }
                tmp = gcry_sexp_nth_data(sexp, 1, &size);
                q = ssh_string_new(size);
                if (q == NULL) {
                    goto fail;
                }
                ssh_string_fill(q, (char *)tmp, size);
                gcry_sexp_release(sexp);

                sexp = gcry_sexp_find_token(key->rsa, "u", 0);
                if (sexp == NULL) {
                    goto fail;
                }
                tmp = gcry_sexp_nth_data(sexp, 1, &size);
                u = ssh_string_new(size);
                if (u == NULL) {
                    goto fail;
                }
                ssh_string_fill(u, (char *)tmp, size);
                gcry_sexp_release(sexp);

                err = gcry_sexp_build(&new->rsa, NULL,
                        "(private-key(rsa(n %b)(e %b)(d %b)(p %b)(q %b)(u %b)))",
                        ssh_string_len(n), ssh_string_data(n),
                        ssh_string_len(e), ssh_string_data(e),
                        ssh_string_len(d), ssh_string_data(d),
                        ssh_string_len(p), ssh_string_data(p),
                        ssh_string_len(q), ssh_string_data(q),
                        ssh_string_len(u), ssh_string_data(u));
            } else {
                err = gcry_sexp_build(&new->rsa, NULL,
                        "(public-key(rsa(n %b)(e %b)))",
                        ssh_string_len(n), ssh_string_data(n),
                        ssh_string_len(e), ssh_string_data(e));
            }

            if (err) {
                goto fail;
            }

            ssh_string_burn(e);
            ssh_string_free(e);
            ssh_string_burn(n);
            ssh_string_free(n);
            ssh_string_burn(d);
            ssh_string_free(d);
            ssh_string_burn(p);
            ssh_string_free(p);
            ssh_string_burn(q);
            ssh_string_free(q);
            ssh_string_burn(u);
            ssh_string_free(u);

            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            ssh_key_free(new);
            return NULL;
    }

    return new;
fail:
    gcry_sexp_release(sexp);
    ssh_string_burn(p);
    ssh_string_free(p);
    ssh_string_burn(q);
    ssh_string_free(q);
    ssh_string_burn(g);
    ssh_string_free(g);
    ssh_string_burn(y);
    ssh_string_free(y);
    ssh_string_burn(x);
    ssh_string_free(x);

    ssh_string_burn(e);
    ssh_string_free(e);
    ssh_string_burn(n);
    ssh_string_free(n);
    ssh_string_burn(u);
    ssh_string_free(u);

    ssh_key_free(new);

    return NULL;
}

static int pki_key_generate(ssh_key key, int parameter, const char *type_s, int type){
    gcry_sexp_t parms;
    int rc;
    rc = gcry_sexp_build(&parms,
            NULL,
            "(genkey(%s(nbits %d)(transient-key)))",
            type_s,
            parameter);
    if (rc != 0)
        return SSH_ERROR;
    if(type == SSH_KEYTYPE_RSA)
        rc = gcry_pk_genkey(&key->rsa, parms);
    else
        rc = gcry_pk_genkey(&key->dsa, parms);
    gcry_sexp_release(parms);
    if (rc != 0)
        return SSH_ERROR;
    return SSH_OK;
}

int pki_key_generate_rsa(ssh_key key, int parameter){
    return pki_key_generate(key, parameter, "rsa", SSH_KEYTYPE_RSA);
}
int pki_key_generate_dss(ssh_key key, int parameter){
    return pki_key_generate(key, parameter, "dsa", SSH_KEYTYPE_DSS);
}

#ifdef HAVE_GCRYPT_ECC
int pki_key_generate_ecdsa(ssh_key key, int parameter) {
    return -1;
}
#endif

static int _bignum_cmp(const gcry_sexp_t s1,
                       const gcry_sexp_t s2,
                       const char *what)
{
    gcry_sexp_t sexp;
    bignum b1;
    bignum b2;

    sexp = gcry_sexp_find_token(s1, what, 0);
    if (sexp == NULL) {
        return 1;
    }
    b1 = gcry_sexp_nth_mpi(sexp, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(sexp);
    if (b1 == NULL) {
        return 1;
    }

    sexp = gcry_sexp_find_token(s2, what, 0);
    if (sexp == NULL) {
        return 1;
    }
    b2 = gcry_sexp_nth_mpi(sexp, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(sexp);
    if (b2 == NULL) {
        return 1;
    }

    if (bignum_cmp(b1, b2) != 0) {
        return 1;
    }

    return 0;
}

int pki_key_compare(const ssh_key k1,
                    const ssh_key k2,
                    enum ssh_keycmp_e what)
{
    switch (k1->type) {
        case SSH_KEYTYPE_DSS:
            if (_bignum_cmp(k1->dsa, k2->dsa, "p") != 0) {
                return 1;
            }

            if (_bignum_cmp(k1->dsa, k2->dsa, "q") != 0) {
                return 1;
            }

            if (_bignum_cmp(k1->dsa, k2->dsa, "g") != 0) {
                return 1;
            }

            if (_bignum_cmp(k1->dsa, k2->dsa, "y") != 0) {
                return 1;
            }

            if (what == SSH_KEY_CMP_PRIVATE) {
                if (_bignum_cmp(k1->dsa, k2->dsa, "x") != 0) {
                    return 1;
                }
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            if (_bignum_cmp(k1->rsa, k2->rsa, "e") != 0) {
                return 1;
            }

            if (_bignum_cmp(k1->rsa, k2->rsa, "n") != 0) {
                return 1;
            }

            if (what == SSH_KEY_CMP_PRIVATE) {
                if (_bignum_cmp(k1->rsa, k2->rsa, "d") != 0) {
                    return 1;
                }

                if (_bignum_cmp(k1->rsa, k2->rsa, "p") != 0) {
                    return 1;
                }

                if (_bignum_cmp(k1->rsa, k2->rsa, "q") != 0) {
                    return 1;
                }

                if (_bignum_cmp(k1->rsa, k2->rsa, "u") != 0) {
                    return 1;
                }
            }
            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            return 1;
    }

    return 0;
}

ssh_string pki_publickey_to_blob(const ssh_key key)
{
    ssh_buffer buffer;
    ssh_string type_s;
    ssh_string str = NULL;
    ssh_string e = NULL;
    ssh_string n = NULL;
    ssh_string p = NULL;
    ssh_string g = NULL;
    ssh_string q = NULL;
    const char *tmp = NULL;
    size_t size;
    gcry_sexp_t sexp;
    int rc;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        return NULL;
    }

    type_s = ssh_string_from_char(key->type_c);
    if (type_s == NULL) {
        ssh_buffer_free(buffer);
        return NULL;
    }

    rc = buffer_add_ssh_string(buffer, type_s);
    ssh_string_free(type_s);
    if (rc < 0) {
        ssh_buffer_free(buffer);
        return NULL;
    }

    switch (key->type) {
        case SSH_KEYTYPE_DSS:
            sexp = gcry_sexp_find_token(key->dsa, "p", 0);
            if (sexp == NULL) {
                goto fail;
            }
            tmp = gcry_sexp_nth_data(sexp, 1, &size);
            p = ssh_string_new(size);
            if (p == NULL) {
                goto fail;
            }
            ssh_string_fill(p, (char *) tmp, size);
            gcry_sexp_release(sexp);

            sexp = gcry_sexp_find_token(key->dsa, "q", 0);
            if (sexp == NULL) {
                goto fail;
            }
            tmp = gcry_sexp_nth_data(sexp, 1, &size);
            q = ssh_string_new(size);
            if (q == NULL) {
                goto fail;
            }
            ssh_string_fill(q, (char *) tmp, size);
            gcry_sexp_release(sexp);

            sexp = gcry_sexp_find_token(key->dsa, "g", 0);
            if (sexp == NULL) {
                goto fail;
            }
            tmp = gcry_sexp_nth_data(sexp, 1, &size);
            g = ssh_string_new(size);
            if (g == NULL) {
                goto fail;
            }
            ssh_string_fill(g, (char *) tmp, size);
            gcry_sexp_release(sexp);

            sexp = gcry_sexp_find_token(key->dsa, "y", 0);
            if (sexp == NULL) {
                goto fail;
            }
            tmp = gcry_sexp_nth_data(sexp, 1, &size);
            n = ssh_string_new(size);
            if (n == NULL) {
                goto fail;
            }
            ssh_string_fill(n, (char *) tmp, size);

            if (buffer_add_ssh_string(buffer, p) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, q) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, g) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, n) < 0) {
                goto fail;
            }

            ssh_string_burn(p);
            ssh_string_free(p);
            ssh_string_burn(g);
            ssh_string_free(g);
            ssh_string_burn(q);
            ssh_string_free(q);
            ssh_string_burn(n);
            ssh_string_free(n);

            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sexp = gcry_sexp_find_token(key->rsa, "e", 0);
            if (sexp == NULL) {
                goto fail;
            }
            tmp = gcry_sexp_nth_data(sexp, 1, &size);
            e = ssh_string_new(size);
            if (e == NULL) {
                goto fail;
            }
            ssh_string_fill(e, (char *) tmp, size);
            gcry_sexp_release(sexp);

            sexp = gcry_sexp_find_token(key->rsa, "n", 0);
            if (sexp == NULL) {
                goto fail;
            }
            tmp = gcry_sexp_nth_data(sexp, 1, &size);
            n = ssh_string_new(size);
            if (n == NULL) {
                goto fail;
            }
            ssh_string_fill(n, (char *) tmp, size);
            gcry_sexp_release(sexp);

            if (buffer_add_ssh_string(buffer, e) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, n) < 0) {
                goto fail;
            }

            ssh_string_burn(e);
            ssh_string_free(e);
            ssh_string_burn(n);
            ssh_string_free(n);

            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            goto fail;
    }

    str = ssh_string_new(buffer_get_rest_len(buffer));
    if (str == NULL) {
        goto fail;
    }

    rc = ssh_string_fill(str, buffer_get_rest(buffer), buffer_get_rest_len(buffer));
    if (rc < 0) {
        goto fail;
    }
    ssh_buffer_free(buffer);

    return str;
fail:
    ssh_buffer_free(buffer);
    ssh_string_burn(str);
    ssh_string_free(str);
    ssh_string_burn(e);
    ssh_string_free(e);
    ssh_string_burn(p);
    ssh_string_free(p);
    ssh_string_burn(g);
    ssh_string_free(g);
    ssh_string_burn(q);
    ssh_string_free(q);
    ssh_string_burn(n);
    ssh_string_free(n);

    return NULL;
}

int pki_export_pubkey_rsa1(const ssh_key key,
                           const char *host,
                           char *rsa1,
                           size_t rsa1_len)
{
    gcry_sexp_t sexp;
    int rsa_size;
    bignum b;
    char *e, *n;

    sexp = gcry_sexp_find_token(key->rsa, "e", 0);
    if (sexp == NULL) {
        return SSH_ERROR;
    }
    b = gcry_sexp_nth_mpi(sexp, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(sexp);
    if (b == NULL) {
        return SSH_ERROR;
    }
    e = bignum_bn2dec(b);

    sexp = gcry_sexp_find_token(key->rsa, "n", 0);
    if (sexp == NULL) {
        SAFE_FREE(e);
        return SSH_ERROR;
    }
    b = gcry_sexp_nth_mpi(sexp, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(sexp);
    if (b == NULL) {
        SAFE_FREE(e);
        return SSH_ERROR;
    }
    n = bignum_bn2dec(b);

    rsa_size = (gcry_pk_get_nbits(key->rsa) + 7) / 8;

    snprintf(rsa1, rsa1_len,
             "%s %d %s %s\n",
             host, rsa_size << 3, e, n);
    SAFE_FREE(e);
    SAFE_FREE(n);

    return SSH_OK;
}

ssh_string pki_signature_to_blob(const ssh_signature sig)
{
    char buffer[40] = {0};
    const char *r = NULL;
    const char *s = NULL;
    gcry_sexp_t sexp;
    size_t size = 0;
    ssh_string sig_blob = NULL;

    switch(sig->type) {
        case SSH_KEYTYPE_DSS:
            sexp = gcry_sexp_find_token(sig->dsa_sig, "r", 0);
            if (sexp == NULL) {
                return NULL;
            }
            r = gcry_sexp_nth_data(sexp, 1, &size);
            /* libgcrypt put 0 when first bit is set */
            if (*r == 0) {
                size--;
                r++;
            }
            memcpy(buffer, r + size - 20, 20);
            gcry_sexp_release(sexp);

            sexp = gcry_sexp_find_token(sig->dsa_sig, "s", 0);
            if (sexp == NULL) {
                return NULL;
            }
            s = gcry_sexp_nth_data(sexp,1,&size);
            if (*s == 0) {
                size--;
                s++;
            }
            memcpy(buffer+ 20, s + size - 20, 20);
            gcry_sexp_release(sexp);
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sexp = gcry_sexp_find_token(sig->rsa_sig, "s", 0);
            if (sexp == NULL) {
                return NULL;
            }
            s = gcry_sexp_nth_data(sexp, 1, &size);
            if (*s == 0) {
                size--;
                s++;
            }

            sig_blob = ssh_string_new(size);
            if (sig_blob == NULL) {
                return NULL;
            }
            ssh_string_fill(sig_blob, discard_const_p(char, s), size);

            gcry_sexp_release(sexp);
            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            ssh_pki_log("Unknown signature key type: %d", sig->type);
            return NULL;
            break;
    }

    return sig_blob;
}

ssh_signature pki_signature_from_blob(const ssh_key pubkey,
                                      const ssh_string sig_blob,
                                      enum ssh_keytypes_e type)
{
    ssh_signature sig;
    gcry_error_t err;
    size_t len;
    size_t rsalen;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }

    sig->type = type;

    len = ssh_string_len(sig_blob);

    switch(type) {
        case SSH_KEYTYPE_DSS:
            /* 40 is the dual signature blob len. */
            if (len != 40) {
                ssh_pki_log("Signature has wrong size: %lu",
                            (unsigned long)len);
                ssh_signature_free(sig);
                return NULL;
            }

#ifdef DEBUG_CRYPTO
            ssh_pki_log("DSA signature len: %lu", (unsigned long)len);
            ssh_print_hexa("DSA signature", ssh_string_data(sig_blob), len);
#endif

            err = gcry_sexp_build(&sig->dsa_sig,
                                  NULL,
                                  "(sig-val(dsa(r %b)(s %b)))",
                                  20,
                                  ssh_string_data(sig_blob),
                                  20,
                                  (unsigned char *)ssh_string_data(sig_blob) + 20);
            if (err) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            rsalen = (gcry_pk_get_nbits(pubkey->rsa) + 7) / 8;

            if (len > rsalen) {
                ssh_pki_log("Signature is to big size: %lu",
                            (unsigned long)len);
                ssh_signature_free(sig);
                return NULL;
            }

            if (len < rsalen) {
                ssh_pki_log("RSA signature len %lu < %lu",
                            (unsigned long)len, (unsigned long)rsalen);
            }

#ifdef DEBUG_CRYPTO
            ssh_pki_log("RSA signature len: %lu", (unsigned long)len);
            ssh_print_hexa("RSA signature", ssh_string_data(sig_blob), len);
#endif

            err = gcry_sexp_build(&sig->rsa_sig,
                                  NULL,
                                  "(sig-val(rsa(s %b)))",
                                  ssh_string_len(sig_blob),
                                  ssh_string_data(sig_blob));
            if (err) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            ssh_pki_log("Unknown signature type");
            return NULL;
    }

    return sig;
}

int pki_signature_verify(ssh_session session,
                         const ssh_signature sig,
                         const ssh_key key,
                         const unsigned char *hash,
                         size_t hlen)
{
    unsigned char ghash[hlen + 1];
    gcry_sexp_t sexp;
    gcry_error_t err;

    switch(key->type) {
        case SSH_KEYTYPE_DSS:
            /* That is to mark the number as positive */
            if(hash[0] >= 0x80) {
                memcpy(ghash + 1, hash, hlen);
                ghash[0] = 0;
                hash = ghash;
                hlen += 1;
            }

            err = gcry_sexp_build(&sexp, NULL, "%b", hlen, hash);
            if (err) {
                ssh_set_error(session,
                              SSH_FATAL,
                              "DSA hash error: %s", gcry_strerror(err));
                return SSH_ERROR;
            }
            err = gcry_pk_verify(sig->dsa_sig, sexp, key->dsa);
            gcry_sexp_release(sexp);
            if (err) {
                ssh_set_error(session, SSH_FATAL, "Invalid DSA signature");
                if (gcry_err_code(err) != GPG_ERR_BAD_SIGNATURE) {
                    ssh_set_error(session,
                                  SSH_FATAL,
                                  "DSA verify error: %s",
                                  gcry_strerror(err));
                }
                return SSH_ERROR;
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            err = gcry_sexp_build(&sexp,
                                  NULL,
                                  "(data(flags pkcs1)(hash sha1 %b))",
                                  hlen, hash);
            if (err) {
                ssh_set_error(session,
                              SSH_FATAL,
                              "RSA hash error: %s",
                              gcry_strerror(err));
                return SSH_ERROR;
            }
            err = gcry_pk_verify(sig->rsa_sig, sexp, key->rsa);
            gcry_sexp_release(sexp);
            if (err) {
                ssh_set_error(session, SSH_FATAL, "Invalid RSA signature");
                if (gcry_err_code(err) != GPG_ERR_BAD_SIGNATURE) {
                    ssh_set_error(session,
                            SSH_FATAL,
                            "RSA verify error: %s",
                            gcry_strerror(err));
                }
                return SSH_ERROR;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            ssh_set_error(session, SSH_FATAL, "Unknown public key type");
            return SSH_ERROR;
    }

    return SSH_OK;
}

ssh_signature pki_do_sign(const ssh_key privkey,
                          const unsigned char *hash,
                          size_t hlen) {
    unsigned char ghash[hlen + 1];
    ssh_signature sig;
    gcry_sexp_t sexp;
    gcry_error_t err;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }
    sig->type = privkey->type;
    sig->type_c = privkey->type_c;
    switch (privkey->type) {
        case SSH_KEYTYPE_DSS:
            /* That is to mark the number as positive */
            if(hash[0] >= 0x80) {
                memcpy(ghash + 1, hash, hlen);
                ghash[0] = 0;
                hash = ghash;
                hlen += 1;
            }

            err = gcry_sexp_build(&sexp, NULL, "%b", hlen, hash);
            if (err) {
                ssh_signature_free(sig);
                return NULL;
            }

            err = gcry_pk_sign(&sig->dsa_sig, sexp, privkey->dsa);
            gcry_sexp_release(sexp);
            if (err) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            err = gcry_sexp_build(&sexp,
                                  NULL,
                                  "(data(flags pkcs1)(hash sha1 %b))",
                                  hlen,
                                  hash);
            if (err) {
                ssh_signature_free(sig);
                return NULL;
            }

            err = gcry_pk_sign(&sig->rsa_sig, sexp, privkey->rsa);
            gcry_sexp_release(sexp);
            if (err) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            ssh_signature_free(sig);
            return NULL;
    }

    return sig;
}

#ifdef WITH_SERVER
ssh_signature pki_do_sign_sessionid(const ssh_key key,
                                    const unsigned char *hash,
                                    size_t hlen)
{
    unsigned char ghash[hlen + 1];
    ssh_signature sig;
    gcry_sexp_t sexp;
    gcry_error_t err;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }
    sig->type = key->type;
    sig->type_c = key->type_c;

    switch(key->type) {
        case SSH_KEYTYPE_DSS:
            /* That is to mark the number as positive */
            if(hash[0] >= 0x80) {
                memcpy(ghash + 1, hash, hlen);
                ghash[0] = 0;
                hash = ghash;
                hlen += 1;
            }

            err = gcry_sexp_build(&sexp, NULL, "%b", hlen, hash);
            if (err) {
                ssh_signature_free(sig);
                return NULL;
            }
            err = gcry_pk_sign(&sig->dsa_sig, sexp, key->dsa);
            gcry_sexp_release(sexp);
            if (err) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            err = gcry_sexp_build(&sexp,
                                  NULL,
                                  "(data(flags pkcs1)(hash sha1 %b))",
                                  hlen,
                                  hash);
            if (err) {
                ssh_signature_free(sig);
                return NULL;
            }
            err = gcry_pk_sign(&sig->rsa_sig, sexp, key->rsa);
            gcry_sexp_release(sexp);
            if (err) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            return NULL;
    }

    return sig;
}
#endif /* WITH_SERVER */

#endif /* HAVE_LIBGCRYPT */

/* vim: set ts=4 sw=4 et cindent: */
