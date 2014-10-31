/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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

#ifndef PKI_H_
#define PKI_H_

#include "libssh/priv.h"
#ifdef HAVE_OPENSSL_EC_H
#include <openssl/ec.h>
#endif
#ifdef HAVE_OPENSSL_ECDSA_H
#include <openssl/ecdsa.h>
#endif

#include "libssh/crypto.h"
#include "libssh/ed25519.h"

#define MAX_PUBKEY_SIZE 0x100000 /* 1M */
#define MAX_PRIVKEY_SIZE 0x400000 /* 4M */

#define SSH_KEY_FLAG_EMPTY   0x0
#define SSH_KEY_FLAG_PUBLIC  0x0001
#define SSH_KEY_FLAG_PRIVATE 0x0002

struct ssh_key_struct {
    enum ssh_keytypes_e type;
    int flags;
    const char *type_c; /* Don't free it ! it is static */
    int ecdsa_nid;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa;
    gcry_sexp_t rsa;
    void *ecdsa;
#elif HAVE_LIBCRYPTO
    DSA *dsa;
    RSA *rsa;
#ifdef HAVE_OPENSSL_ECC
    EC_KEY *ecdsa;
#else
    void *ecdsa;
#endif /* HAVE_OPENSSL_EC_H */
#endif
    ed25519_pubkey *ed25519_pubkey;
    ed25519_privkey *ed25519_privkey;
    void *cert;
};

struct ssh_signature_struct {
    enum ssh_keytypes_e type;
    const char *type_c;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t dsa_sig;
    gcry_sexp_t rsa_sig;
    void *ecdsa_sig;
#elif defined HAVE_LIBCRYPTO
    DSA_SIG *dsa_sig;
    ssh_string rsa_sig;
# ifdef HAVE_OPENSSL_ECC
    ECDSA_SIG *ecdsa_sig;
# else
    void *ecdsa_sig;
# endif
#endif
    ed25519_signature *ed25519_sig;
};

typedef struct ssh_signature_struct *ssh_signature;

/* SSH Key Functions */
ssh_key ssh_key_dup(const ssh_key key);
void ssh_key_clean (ssh_key key);

/* SSH Signature Functions */
ssh_signature ssh_signature_new(void);
void ssh_signature_free(ssh_signature sign);

int ssh_pki_export_signature_blob(const ssh_signature sign,
                                  ssh_string *sign_blob);
int ssh_pki_import_signature_blob(const ssh_string sig_blob,
                                  const ssh_key pubkey,
                                  ssh_signature *psig);
int ssh_pki_signature_verify_blob(ssh_session session,
                                  ssh_string sig_blob,
                                  const ssh_key key,
                                  unsigned char *digest,
                                  size_t dlen);

/* SSH Public Key Functions */
int ssh_pki_export_pubkey_blob(const ssh_key key,
                               ssh_string *pblob);
int ssh_pki_import_pubkey_blob(const ssh_string key_blob,
                               ssh_key *pkey);
int ssh_pki_export_pubkey_rsa1(const ssh_key key,
                               const char *host,
                               char *rsa1,
                               size_t rsa1_len);

/* SSH Signing Functions */
ssh_string ssh_pki_do_sign(ssh_session session, ssh_buffer sigbuf,
    const ssh_key privatekey);
ssh_string ssh_pki_do_sign_agent(ssh_session session,
                                 struct ssh_buffer_struct *buf,
                                 const ssh_key pubkey);
ssh_string ssh_srv_pki_do_sign_sessionid(ssh_session session,
                                         const ssh_key privkey);

/* Temporary functions, to be removed after migration to ssh_key */
ssh_public_key ssh_pki_convert_key_to_publickey(const ssh_key key);
ssh_private_key ssh_pki_convert_key_to_privatekey(const ssh_key key);

#endif /* PKI_H_ */
