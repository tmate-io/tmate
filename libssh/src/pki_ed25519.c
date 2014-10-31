/*
 * pki_ed25519 .c - PKI infrastructure using ed25519
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2014 by Aris Adamantiadis
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

#include "libssh/pki.h"
#include "libssh/pki_priv.h"
#include "libssh/ed25519.h"
#include "libssh/buffer.h"

int pki_key_generate_ed25519(ssh_key key)
{
    int rc;

    key->ed25519_privkey = malloc(sizeof (ed25519_privkey));
    if (key->ed25519_privkey == NULL) {
        goto error;
    }

    key->ed25519_pubkey = malloc(sizeof (ed25519_privkey));
    if (key->ed25519_privkey == NULL) {
        goto error;
    }

    rc = crypto_sign_ed25519_keypair(*key->ed25519_pubkey,
                                     *key->ed25519_privkey);
    if (rc != 0) {
        goto error;
    }

    return SSH_OK;
error:
    SAFE_FREE(key->ed25519_privkey);
    SAFE_FREE(key->ed25519_pubkey);

    return SSH_ERROR;
}

int pki_ed25519_sign(const ssh_key privkey,
                     ssh_signature sig,
                     const unsigned char *hash,
                     size_t hlen)
{
    int rc;
    uint8_t *buffer;
    unsigned long long dlen = 0;

    buffer = malloc(hlen + ED25519_SIG_LEN);
    if (buffer == NULL) {
        return SSH_ERROR;
    }

    rc = crypto_sign_ed25519(buffer,
                             &dlen,
                             hash,
                             hlen,
                             *privkey->ed25519_privkey);
    if (rc != 0) {
        goto error;
    }
    sig->ed25519_sig = malloc(ED25519_SIG_LEN);
    if (sig->ed25519_sig == NULL) {
        goto error;
    }

    /* This shouldn't happen */
    if (dlen - hlen != ED25519_SIG_LEN) {
        goto error;
    }
    memcpy(sig->ed25519_sig, buffer, dlen - hlen);
    SAFE_FREE(buffer);

    return SSH_OK;
error:
    SAFE_FREE(buffer);
    return SSH_ERROR;
}

int pki_ed25519_verify(const ssh_key pubkey,
                       ssh_signature sig,
                       const unsigned char *hash,
                       size_t hlen)
{
    unsigned long long mlen = 0;
    uint8_t *buffer;
    uint8_t *buffer2;
    int rc;

    if (pubkey == NULL || sig == NULL ||
        hash == NULL || sig->ed25519_sig == NULL) {
        return SSH_ERROR;
    }

    buffer = malloc(hlen + ED25519_SIG_LEN);
    if (buffer == NULL) {
        return SSH_ERROR;
    }

    buffer2 = malloc(hlen + ED25519_SIG_LEN);
    if (buffer2 == NULL) {
        goto error;
    }

    memcpy(buffer, sig->ed25519_sig, ED25519_SIG_LEN);
    memcpy(buffer + ED25519_SIG_LEN, hash, hlen);

    rc = crypto_sign_ed25519_open(buffer2,
                                  &mlen,
                                  buffer,
                                  hlen + ED25519_SIG_LEN,
                                  *pubkey->ed25519_pubkey);

    BURN_BUFFER(buffer, hlen + ED25519_SIG_LEN);
    BURN_BUFFER(buffer2, hlen);
    SAFE_FREE(buffer);
    SAFE_FREE(buffer2);
    if (rc == 0) {
        return SSH_OK;
    } else {
        return SSH_ERROR;
    }
error:
    SAFE_FREE(buffer);
    SAFE_FREE(buffer2);

    return SSH_ERROR;
}

/**
 * @internal
 *
 * @brief Compare ed25519 keys if they are equal.
 *
 * @param[in] k1        The first key to compare.
 *
 * @param[in] k2        The second key to compare.
 *
 * @param[in] what      What part or type of the key do you want to compare.
 *
 * @return              0 if equal, 1 if not.
 */
int pki_ed25519_key_cmp(const ssh_key k1,
                        const ssh_key k2,
                        enum ssh_keycmp_e what)
{
    int cmp;

    switch(what) {
    case SSH_KEY_CMP_PRIVATE:
        if (k1->ed25519_privkey == NULL || k2->ed25519_privkey == NULL) {
            return 1;
        }
        cmp = memcmp(k1->ed25519_privkey, k2->ed25519_privkey, ED25519_SK_LEN);
        if (cmp != 0) {
            return 1;
        }
        /* FALL THROUGH */
    case SSH_KEY_CMP_PUBLIC:
        if (k1->ed25519_pubkey == NULL || k2->ed25519_pubkey == NULL) {
            return 1;
        }
        cmp = memcmp(k1->ed25519_pubkey, k2->ed25519_pubkey, ED25519_PK_LEN);
        if (cmp != 0) {
            return 1;
        }
    }

    return 0;
}

/**
 * @internal
 *
 * @brief duplicate an ed25519 key
 *
 * @param[out\ new preinitialized output ssh_ke
 *
 * @param[in] key key to copy
 *
 * @return SSH_ERROR on error, SSH_OK on success
 */
int pki_ed25519_key_dup(ssh_key new, const ssh_key key)
{
    if (key->ed25519_privkey == NULL || key->ed25519_pubkey == NULL) {
        return SSH_ERROR;
    }

    new->ed25519_privkey = malloc(ED25519_SK_LEN);
    if (new->ed25519_privkey == NULL) {
        return SSH_ERROR;
    }

    new->ed25519_pubkey = malloc(ED25519_PK_LEN);
    if (new->ed25519_privkey == NULL || new->ed25519_pubkey == NULL){
        SAFE_FREE(new->ed25519_privkey);
        return SSH_ERROR;
    }

    memcpy(new->ed25519_privkey, key->ed25519_privkey, ED25519_SK_LEN);
    memcpy(new->ed25519_pubkey, key->ed25519_pubkey, ED25519_PK_LEN);

    return SSH_OK;
}

/**
 * @internal
 *
 * @brief outputs an ed25519 public key in a blob buffer.
 *
 * @param[out] buffer output buffer
 *
 * @param[in] key key to output
 *
 * @return SSH_ERROR on error, SSH_OK on success
 */
int pki_ed25519_public_key_to_blob(ssh_buffer buffer, ssh_key key)
{
    int rc;

    if (key->ed25519_pubkey == NULL){
        return SSH_ERROR;
    }

    rc = ssh_buffer_pack(buffer,
                         "dP",
                         (uint32_t)ED25519_PK_LEN,
                         (size_t)ED25519_PK_LEN, key->ed25519_pubkey);

    return rc;
}

/**
 * @internal
 *
 * @brief output a signature blob from an ed25519 signature
 *
 * @param[in] sig signature to convert
 *
 * @return Signature blob in SSH string, or NULL on error
 */
ssh_string pki_ed25519_sig_to_blob(ssh_signature sig)
{
    ssh_string sig_blob;

    if (sig->ed25519_sig == NULL) {
        return NULL;
    }

    sig_blob = ssh_string_new(ED25519_SIG_LEN);
    if (sig_blob == NULL) {
        return NULL;
    }
    ssh_string_fill(sig_blob, sig->ed25519_sig, ED25519_SIG_LEN);

    return sig_blob;
}

/**
 * @internal
 *
 * @brief Convert a signature blob in an ed25519 signature.
 *
 * @param[out] sig a preinitialized signature
 *
 * @param[in] sig_blob a signature blob
 *
 * @return SSH_ERROR on error, SSH_OK on success
 */
int pki_ed25519_sig_from_blob(ssh_signature sig, ssh_string sig_blob)
{
    size_t len;

    len = ssh_string_len(sig_blob);
    if (len != ED25519_SIG_LEN){
        ssh_pki_log("Invalid ssh-ed25519 signature len: %zu", len);
        return SSH_ERROR;
    }

    sig->ed25519_sig = malloc(ED25519_SIG_LEN);
    if (sig->ed25519_sig == NULL){
        return SSH_ERROR;
    }

    memcpy(sig->ed25519_sig, ssh_string_data(sig_blob), ED25519_SIG_LEN);

    return SSH_OK;
}
