/*
 * pki_crypto.c - PKI infrastructure using OpenSSL
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 * Copyright (c) 2009-2013 by Andreas Schneider <asn@cryptomilk.org>
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

#ifndef _PKI_CRYPTO_H
#define _PKI_CRYPTO_H

#include "libssh/priv.h"

#include <openssl/pem.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#ifdef HAVE_OPENSSL_EC_H
#include <openssl/ec.h>
#endif
#ifdef HAVE_OPENSSL_ECDSA_H
#include <openssl/ecdsa.h>
#endif

#include "libssh/libssh.h"
#include "libssh/buffer.h"
#include "libssh/session.h"
#include "libssh/pki.h"
#include "libssh/pki_priv.h"
#include "libssh/bignum.h"

struct pem_get_password_struct {
    ssh_auth_callback fn;
    void *data;
};

static int pem_get_password(char *buf, int size, int rwflag, void *userdata) {
    struct pem_get_password_struct *pgp = userdata;

    (void) rwflag; /* unused */

    if (buf == NULL) {
        return 0;
    }

    memset(buf, '\0', size);
    if (pgp) {
        int rc;

        rc = pgp->fn("Passphrase for private key:",
                     buf, size, 0, 0,
                     pgp->data);
        if (rc == 0) {
            return strlen(buf);
        }
    }

    return 0;
}

#ifdef HAVE_OPENSSL_ECC
static int pki_key_ecdsa_to_nid(EC_KEY *k)
{
    const EC_GROUP *g = EC_KEY_get0_group(k);
    int nid;

    nid = EC_GROUP_get_curve_name(g);
    if (nid) {
        return nid;
    }

    return -1;
}

const char *pki_key_ecdsa_nid_to_name(int nid)
{
    switch (nid) {
        case NID_X9_62_prime256v1:
            return "ecdsa-sha2-nistp256";
        case NID_secp384r1:
            return "ecdsa-sha2-nistp384";
        case NID_secp521r1:
            return "ecdsa-sha2-nistp521";
        default:
            break;
    }

    return "unknown";
}

static const char *pki_key_ecdsa_nid_to_char(int nid)
{
    switch (nid) {
        case NID_X9_62_prime256v1:
            return "nistp256";
        case NID_secp384r1:
            return "nistp384";
        case NID_secp521r1:
            return "nistp521";
        default:
            break;
    }

    return "unknown";
}

int pki_key_ecdsa_nid_from_name(const char *name)
{
    if (strcmp(name, "nistp256") == 0) {
        return NID_X9_62_prime256v1;
    } else if (strcmp(name, "nistp384") == 0) {
        return NID_secp384r1;
    } else if (strcmp(name, "nistp521") == 0) {
        return NID_secp521r1;
    }

    return -1;
}

static ssh_string make_ecpoint_string(const EC_GROUP *g,
                                      const EC_POINT *p)
{
    ssh_string s;
    size_t len;

    len = EC_POINT_point2oct(g,
                             p,
                             POINT_CONVERSION_UNCOMPRESSED,
                             NULL,
                             0,
                             NULL);
    if (len == 0) {
        return NULL;
    }

    s = ssh_string_new(len);
    if (s == NULL) {
        return NULL;
    }

    len = EC_POINT_point2oct(g,
                             p,
                             POINT_CONVERSION_UNCOMPRESSED,
                             ssh_string_data(s),
                             ssh_string_len(s),
                             NULL);
    if (len != ssh_string_len(s)) {
        ssh_string_free(s);
        return NULL;
    }

    return s;
}

int pki_pubkey_build_ecdsa(ssh_key key, int nid, ssh_string e)
{
    EC_POINT *p;
    const EC_GROUP *g;
    int ok;

    key->ecdsa_nid = nid;
    key->type_c = pki_key_ecdsa_nid_to_name(nid);

    key->ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid);
    if (key->ecdsa == NULL) {
        return -1;
    }

    g = EC_KEY_get0_group(key->ecdsa);

    p = EC_POINT_new(g);
    if (p == NULL) {
        return -1;
    }

    ok = EC_POINT_oct2point(g,
                            p,
                            ssh_string_data(e),
                            ssh_string_len(e),
                            NULL);
    if (!ok) {
        EC_POINT_free(p);
        return -1;
    }

    /* EC_KEY_set_public_key duplicates p */
    ok = EC_KEY_set_public_key(key->ecdsa, p);
    EC_POINT_free(p);
    if (!ok) {
        return -1;
    }

    return 0;
}
#endif

ssh_key pki_key_dup(const ssh_key key, int demote)
{
    ssh_key new;
    int rc;

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

    switch (key->type) {
    case SSH_KEYTYPE_DSS:
        new->dsa = DSA_new();
        if (new->dsa == NULL) {
            goto fail;
        }

        /*
         * p        = public prime number
         * q        = public 160-bit subprime, q | p-1
         * g        = public generator of subgroup
         * pub_key  = public key y = g^x
         * priv_key = private key x
         */
        new->dsa->p = BN_dup(key->dsa->p);
        if (new->dsa->p == NULL) {
            goto fail;
        }

        new->dsa->q = BN_dup(key->dsa->q);
        if (new->dsa->q == NULL) {
            goto fail;
        }

        new->dsa->g = BN_dup(key->dsa->g);
        if (new->dsa->g == NULL) {
            goto fail;
        }

        new->dsa->pub_key = BN_dup(key->dsa->pub_key);
        if (new->dsa->pub_key == NULL) {
            goto fail;
        }

        if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE)) {
            new->dsa->priv_key = BN_dup(key->dsa->priv_key);
            if (new->dsa->priv_key == NULL) {
                goto fail;
            }
        }

        break;
    case SSH_KEYTYPE_RSA:
    case SSH_KEYTYPE_RSA1:
        new->rsa = RSA_new();
        if (new->rsa == NULL) {
            goto fail;
        }

        /*
         * n    = public modulus
         * e    = public exponent
         * d    = private exponent
         * p    = secret prime factor
         * q    = secret prime factor
         * dmp1 = d mod (p-1)
         * dmq1 = d mod (q-1)
         * iqmp = q^-1 mod p
         */
        new->rsa->n = BN_dup(key->rsa->n);
        if (new->rsa->n == NULL) {
            goto fail;
        }

        new->rsa->e = BN_dup(key->rsa->e);
        if (new->rsa->e == NULL) {
            goto fail;
        }

        if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE)) {
            new->rsa->d = BN_dup(key->rsa->d);
            if (new->rsa->d == NULL) {
                goto fail;
            }

            /* p, q, dmp1, dmq1 and iqmp may be NULL in private keys, but the
             * RSA operations are much faster when these values are available.
             */
            if (key->rsa->p != NULL) {
                new->rsa->p = BN_dup(key->rsa->p);
                if (new->rsa->p == NULL) {
                    goto fail;
                }
            }

            if (key->rsa->q != NULL) {
                new->rsa->q = BN_dup(key->rsa->q);
                if (new->rsa->q == NULL) {
                    goto fail;
                }
            }

            if (key->rsa->dmp1 != NULL) {
                new->rsa->dmp1 = BN_dup(key->rsa->dmp1);
                if (new->rsa->dmp1 == NULL) {
                    goto fail;
                }
            }

            if (key->rsa->dmq1 != NULL) {
                new->rsa->dmq1 = BN_dup(key->rsa->dmq1);
                if (new->rsa->dmq1 == NULL) {
                    goto fail;
                }
            }

            if (key->rsa->iqmp != NULL) {
                new->rsa->iqmp = BN_dup(key->rsa->iqmp);
                if (new->rsa->iqmp == NULL) {
                    goto fail;
                }
            }
        }

        break;
    case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_OPENSSL_ECC
        new->ecdsa_nid = key->ecdsa_nid;

        /* privkey -> pubkey */
        if (demote && ssh_key_is_private(key)) {
            const EC_POINT *p;
            int ok;

            new->ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid);
            if (new->ecdsa == NULL) {
                goto fail;
            }

            p = EC_KEY_get0_public_key(key->ecdsa);
            if (p == NULL) {
                goto fail;
            }

            ok = EC_KEY_set_public_key(new->ecdsa, p);
            if (!ok) {
                goto fail;
            }
        } else {
            new->ecdsa = EC_KEY_dup(key->ecdsa);
        }
        break;
#endif
    case SSH_KEYTYPE_ED25519:
        rc = pki_ed25519_key_dup(new, key);
        if (rc != SSH_OK) {
            goto fail;
        }
        break;
    case SSH_KEYTYPE_UNKNOWN:
    default:
        ssh_key_free(new);
        return NULL;
    }

    return new;
fail:
    ssh_key_free(new);
    return NULL;
}

int pki_key_generate_rsa(ssh_key key, int parameter){
	BIGNUM *e;
	int rc;

	e = BN_new();
	key->rsa = RSA_new();

	BN_set_word(e, 65537);
	rc = RSA_generate_key_ex(key->rsa, parameter, e, NULL);

	BN_free(e);

	if (rc == -1 || key->rsa == NULL)
		return SSH_ERROR;
	return SSH_OK;
}

int pki_key_generate_dss(ssh_key key, int parameter){
    int rc;
    key->dsa = DSA_generate_parameters(parameter, NULL, 0, NULL, NULL,
            NULL, NULL);
    if(key->dsa == NULL){
        return SSH_ERROR;
    }
    rc = DSA_generate_key(key->dsa);
    if (rc != 1){
        DSA_free(key->dsa);
        key->dsa=NULL;
        return SSH_ERROR;
    }
    return SSH_OK;
}

#ifdef HAVE_OPENSSL_ECC
int pki_key_generate_ecdsa(ssh_key key, int parameter) {
    int nid;
    int ok;

    switch (parameter) {
        case 384:
            nid = NID_secp384r1;
            break;
        case 512:
            nid = NID_secp521r1;
            break;
        case 256:
        default:
            nid = NID_X9_62_prime256v1;
    }

    key->ecdsa_nid = nid;
    key->type = SSH_KEYTYPE_ECDSA;
    key->type_c = pki_key_ecdsa_nid_to_name(nid);

    key->ecdsa = EC_KEY_new_by_curve_name(nid);
    if (key->ecdsa == NULL) {
        return SSH_ERROR;
    }

    ok = EC_KEY_generate_key(key->ecdsa);
    if (!ok) {
        EC_KEY_free(key->ecdsa);
        return SSH_ERROR;
    }

    EC_KEY_set_asn1_flag(key->ecdsa, OPENSSL_EC_NAMED_CURVE);

    return SSH_OK;
}
#endif

int pki_key_compare(const ssh_key k1,
                    const ssh_key k2,
                    enum ssh_keycmp_e what)
{
    switch (k1->type) {
        case SSH_KEYTYPE_DSS:
            if (DSA_size(k1->dsa) != DSA_size(k2->dsa)) {
                return 1;
            }
            if (bignum_cmp(k1->dsa->p, k2->dsa->p) != 0) {
                return 1;
            }
            if (bignum_cmp(k1->dsa->q, k2->dsa->q) != 0) {
                return 1;
            }
            if (bignum_cmp(k1->dsa->g, k2->dsa->g) != 0) {
                return 1;
            }
            if (bignum_cmp(k1->dsa->pub_key, k2->dsa->pub_key) != 0) {
                return 1;
            }

            if (what == SSH_KEY_CMP_PRIVATE) {
                if (bignum_cmp(k1->dsa->priv_key, k2->dsa->priv_key) != 0) {
                    return 1;
                }
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            if (RSA_size(k1->rsa) != RSA_size(k2->rsa)) {
                return 1;
            }
            if (bignum_cmp(k1->rsa->e, k2->rsa->e) != 0) {
                return 1;
            }
            if (bignum_cmp(k1->rsa->n, k2->rsa->n) != 0) {
                return 1;
            }

            if (what == SSH_KEY_CMP_PRIVATE) {
                if (bignum_cmp(k1->rsa->p, k2->rsa->p) != 0) {
                    return 1;
                }

                if (bignum_cmp(k1->rsa->q, k2->rsa->q) != 0) {
                    return 1;
                }
            }
            break;
        case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_OPENSSL_ECC
            {
                const EC_POINT *p1 = EC_KEY_get0_public_key(k1->ecdsa);
                const EC_POINT *p2 = EC_KEY_get0_public_key(k2->ecdsa);
                const EC_GROUP *g1 = EC_KEY_get0_group(k1->ecdsa);
                const EC_GROUP *g2 = EC_KEY_get0_group(k2->ecdsa);

                if (p1 == NULL || p2 == NULL) {
                    return 1;
                }

                if (EC_GROUP_cmp(g1, g2, NULL) != 0) {
                    return 1;
                }

                if (EC_POINT_cmp(g1, p1, p2, NULL) != 0) {
                    return 1;
                }

                if (what == SSH_KEY_CMP_PRIVATE) {
                    if (bignum_cmp(EC_KEY_get0_private_key(k1->ecdsa),
                                   EC_KEY_get0_private_key(k2->ecdsa))) {
                        return 1;
                    }
                }

                break;
            }
#endif
        case SSH_KEYTYPE_ED25519:
            /* ed25519 keys handled globaly */
        case SSH_KEYTYPE_UNKNOWN:
        default:
            return 1;
    }

    return 0;
}

ssh_string pki_private_key_to_pem(const ssh_key key,
                                  const char *passphrase,
                                  ssh_auth_callback auth_fn,
                                  void *auth_data)
{
    ssh_string blob;
    BUF_MEM *buf;
    BIO *mem;
    int rc;

    /* needed for openssl initialization */
    if (ssh_init() < 0) {
        return NULL;
    }

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        return NULL;
    }

    switch (key->type) {
        case SSH_KEYTYPE_DSS:
            if (passphrase == NULL) {
                struct pem_get_password_struct pgp = { auth_fn, auth_data };

                rc = PEM_write_bio_DSAPrivateKey(mem,
                                                 key->dsa,
                                                 NULL, /* cipher */
                                                 NULL, /* kstr */
                                                 0, /* klen */
                                                 pem_get_password,
                                                 &pgp);
            } else {
                rc = PEM_write_bio_DSAPrivateKey(mem,
                                                 key->dsa,
                                                 NULL, /* cipher */
                                                 NULL, /* kstr */
                                                 0, /* klen */
                                                 NULL, /* auth_fn */
                                                 (void*) passphrase);
            }
            if (rc != 1) {
                goto err;
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            if (passphrase == NULL) {
                struct pem_get_password_struct pgp = { auth_fn, auth_data };

                rc = PEM_write_bio_RSAPrivateKey(mem,
                                                 key->rsa,
                                                 NULL, /* cipher */
                                                 NULL, /* kstr */
                                                 0, /* klen */
                                                 pem_get_password,
                                                 &pgp);
            } else {
                rc = PEM_write_bio_RSAPrivateKey(mem,
                                                 key->rsa,
                                                 NULL, /* cipher */
                                                 NULL, /* kstr */
                                                 0, /* klen */
                                                 NULL, /* auth_fn */
                                                 (void*) passphrase);
            }
            if (rc != 1) {
                goto err;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_ECC
            if (passphrase == NULL) {
                struct pem_get_password_struct pgp = { auth_fn, auth_data };

                rc = PEM_write_bio_ECPrivateKey(mem,
                                                key->ecdsa,
                                                NULL, /* cipher */
                                                NULL, /* kstr */
                                                0, /* klen */
                                                pem_get_password,
                                                &pgp);
            } else {
                rc = PEM_write_bio_ECPrivateKey(mem,
                                                key->ecdsa,
                                                NULL, /* cipher */
                                                NULL, /* kstr */
                                                0, /* klen */
                                                NULL, /* auth_fn */
                                                (void*) passphrase);
            }
            if (rc != 1) {
                goto err;
            }
            break;
#endif
        case SSH_KEYTYPE_ED25519:
        case SSH_KEYTYPE_UNKNOWN:
            BIO_free(mem);
            ssh_pki_log("Unkown or invalid private key type %d", key->type);
            return NULL;
    }

    BIO_get_mem_ptr(mem, &buf);

    blob = ssh_string_new(buf->length);
    if (blob == NULL) {
        goto err;
    }

    ssh_string_fill(blob, buf->data, buf->length);
    BIO_free(mem);

    return blob;
err:
    BIO_free(mem);
    return NULL;
}

ssh_key pki_private_key_from_base64(const char *b64_key,
                                    const char *passphrase,
                                    ssh_auth_callback auth_fn,
                                    void *auth_data) {
    BIO *mem = NULL;
    DSA *dsa = NULL;
    RSA *rsa = NULL;
    ssh_key key;
    enum ssh_keytypes_e type;
#ifdef HAVE_OPENSSL_ECC
    EC_KEY *ecdsa = NULL;
#else
    void *ecdsa = NULL;
#endif

    /* needed for openssl initialization */
    if (ssh_init() < 0) {
        return NULL;
    }

    type = pki_privatekey_type_from_string(b64_key);
    if (type == SSH_KEYTYPE_UNKNOWN) {
        ssh_pki_log("Unknown or invalid private key.");
        return NULL;
    }

    mem = BIO_new_mem_buf((void*)b64_key, -1);

    switch (type) {
        case SSH_KEYTYPE_DSS:
            if (passphrase == NULL) {
                if (auth_fn) {
                    struct pem_get_password_struct pgp = { auth_fn, auth_data };

                    dsa = PEM_read_bio_DSAPrivateKey(mem, NULL, pem_get_password, &pgp);
                } else {
                    /* openssl uses its own callback to get the passphrase here */
                    dsa = PEM_read_bio_DSAPrivateKey(mem, NULL, NULL, NULL);
                }
            } else {
                dsa = PEM_read_bio_DSAPrivateKey(mem, NULL, NULL, (void *) passphrase);
            }

            BIO_free(mem);

            if (dsa == NULL) {
                ssh_pki_log("Parsing private key: %s",
                            ERR_error_string(ERR_get_error(), NULL));
                return NULL;
            }

            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            if (passphrase == NULL) {
                if (auth_fn) {
                    struct pem_get_password_struct pgp = { auth_fn, auth_data };

                    rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, pem_get_password, &pgp);
                } else {
                    /* openssl uses its own callback to get the passphrase here */
                    rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, NULL);
                }
            } else {
                rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, (void *) passphrase);
            }

            BIO_free(mem);

            if (rsa == NULL) {
                ssh_pki_log("Parsing private key: %s",
                            ERR_error_string(ERR_get_error(),NULL));
                return NULL;
            }

            break;
        case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_OPENSSL_ECC
            if (passphrase == NULL) {
                if (auth_fn) {
                    struct pem_get_password_struct pgp = { auth_fn, auth_data };

                    ecdsa = PEM_read_bio_ECPrivateKey(mem, NULL, pem_get_password, &pgp);
                } else {
                    /* openssl uses its own callback to get the passphrase here */
                    ecdsa = PEM_read_bio_ECPrivateKey(mem, NULL, NULL, NULL);
                }
            } else {
                ecdsa = PEM_read_bio_ECPrivateKey(mem, NULL, NULL, (void *) passphrase);
            }

            BIO_free(mem);

            if (ecdsa == NULL) {
                ssh_pki_log("Parsing private key: %s",
                            ERR_error_string(ERR_get_error(), NULL));
                return NULL;
            }

            break;
#endif
        case SSH_KEYTYPE_ED25519:
        case SSH_KEYTYPE_UNKNOWN:
            BIO_free(mem);
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
    key->ecdsa = ecdsa;
#ifdef HAVE_OPENSSL_ECC
    if (key->type == SSH_KEYTYPE_ECDSA) {
        key->ecdsa_nid = pki_key_ecdsa_to_nid(key->ecdsa);
        key->type_c = pki_key_ecdsa_nid_to_name(key->ecdsa_nid);
    }
#endif

    return key;
fail:
    ssh_key_free(key);
    DSA_free(dsa);
    RSA_free(rsa);
#ifdef HAVE_OPENSSL_ECC
    EC_KEY_free(ecdsa);
#endif

    return NULL;
}

int pki_pubkey_build_dss(ssh_key key,
                         ssh_string p,
                         ssh_string q,
                         ssh_string g,
                         ssh_string pubkey) {
    key->dsa = DSA_new();
    if (key->dsa == NULL) {
        return SSH_ERROR;
    }

    key->dsa->p = make_string_bn(p);
    key->dsa->q = make_string_bn(q);
    key->dsa->g = make_string_bn(g);
    key->dsa->pub_key = make_string_bn(pubkey);
    if (key->dsa->p == NULL ||
        key->dsa->q == NULL ||
        key->dsa->g == NULL ||
        key->dsa->pub_key == NULL) {
        DSA_free(key->dsa);
        return SSH_ERROR;
    }

    return SSH_OK;
}

int pki_pubkey_build_rsa(ssh_key key,
                         ssh_string e,
                         ssh_string n) {
    key->rsa = RSA_new();
    if (key->rsa == NULL) {
        return SSH_ERROR;
    }

    key->rsa->e = make_string_bn(e);
    key->rsa->n = make_string_bn(n);
    if (key->rsa->e == NULL ||
        key->rsa->n == NULL) {
        RSA_free(key->rsa);
        return SSH_ERROR;
    }

    return SSH_OK;
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
            p = make_bignum_string(key->dsa->p);
            if (p == NULL) {
                goto fail;
            }

            q = make_bignum_string(key->dsa->q);
            if (q == NULL) {
                goto fail;
            }

            g = make_bignum_string(key->dsa->g);
            if (g == NULL) {
                goto fail;
            }

            n = make_bignum_string(key->dsa->pub_key);
            if (n == NULL) {
                goto fail;
            }

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
            p = NULL;
            ssh_string_burn(g);
            ssh_string_free(g);
            g = NULL;
            ssh_string_burn(q);
            ssh_string_free(q);
            q = NULL;
            ssh_string_burn(n);
            ssh_string_free(n);
            n = NULL;

            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            e = make_bignum_string(key->rsa->e);
            if (e == NULL) {
                goto fail;
            }

            n = make_bignum_string(key->rsa->n);
            if (n == NULL) {
                goto fail;
            }

            if (buffer_add_ssh_string(buffer, e) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, n) < 0) {
                goto fail;
            }

            ssh_string_burn(e);
            ssh_string_free(e);
            e = NULL;
            ssh_string_burn(n);
            ssh_string_free(n);
            n = NULL;

            break;
        case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_OPENSSL_ECC
            rc = ssh_buffer_reinit(buffer);
            if (rc < 0) {
                ssh_buffer_free(buffer);
                return NULL;
            }

            type_s = ssh_string_from_char(pki_key_ecdsa_nid_to_name(key->ecdsa_nid));
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

            type_s = ssh_string_from_char(pki_key_ecdsa_nid_to_char(key->ecdsa_nid));
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

            e = make_ecpoint_string(EC_KEY_get0_group(key->ecdsa),
                                    EC_KEY_get0_public_key(key->ecdsa));
            if (e == NULL) {
                ssh_buffer_free(buffer);
                return NULL;
            }

            rc = buffer_add_ssh_string(buffer, e);
            if (rc < 0) {
                goto fail;
            }

            ssh_string_burn(e);
            ssh_string_free(e);
            e = NULL;

            break;
#endif
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_public_key_to_blob(buffer, key);
            if (rc == SSH_ERROR){
                goto fail;
            }
            break;
        case SSH_KEYTYPE_UNKNOWN:
        default:
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
    char *e;
    char *n;
    int rsa_size = RSA_size(key->rsa);

    e = bignum_bn2dec(key->rsa->e);
    if (e == NULL) {
        return SSH_ERROR;
    }

    n = bignum_bn2dec(key->rsa->n);
    if (n == NULL) {
        OPENSSL_free(e);
        return SSH_ERROR;
    }

    snprintf(rsa1, rsa1_len,
             "%s %d %s %s\n",
             host, rsa_size << 3, e, n);
    OPENSSL_free(e);
    OPENSSL_free(n);

    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Compute a digital signature.
 *
 * @param[in]  digest    The message digest.
 *
 * @param[in]  dlen      The length of the digest.
 *
 * @param[in]  privkey   The private rsa key to use for signing.
 *
 * @return               A newly allocated rsa sig blob or NULL on error.
 */
static ssh_string _RSA_do_sign(const unsigned char *digest,
                               int dlen,
                               RSA *privkey)
{
    ssh_string sig_blob;
    unsigned char *sig;
    unsigned int slen;
    int ok;

    sig = malloc(RSA_size(privkey));
    if (sig == NULL) {
        return NULL;
    }

    ok = RSA_sign(NID_sha1, digest, dlen, sig, &slen, privkey);
    if (!ok) {
        SAFE_FREE(sig);
        return NULL;
    }

    sig_blob = ssh_string_new(slen);
    if (sig_blob == NULL) {
        SAFE_FREE(sig);
        return NULL;
    }

    ssh_string_fill(sig_blob, sig, slen);
    memset(sig, 'd', slen);
    SAFE_FREE(sig);

    return sig_blob;
}

static ssh_string pki_dsa_signature_to_blob(const ssh_signature sig)
{
    char buffer[40] = { 0 };
    ssh_string sig_blob = NULL;

    ssh_string r;
    int r_len, r_offset_in, r_offset_out;

    ssh_string s;
    int s_len, s_offset_in, s_offset_out;

    r = make_bignum_string(sig->dsa_sig->r);
    if (r == NULL) {
        return NULL;
    }

    s = make_bignum_string(sig->dsa_sig->s);
    if (s == NULL) {
        ssh_string_free(r);
        return NULL;
    }

    r_len = ssh_string_len(r);
    r_offset_in  = (r_len > 20) ? (r_len - 20) : 0;
    r_offset_out = (r_len < 20) ? (20 - r_len) : 0;

    s_len = ssh_string_len(s);
    s_offset_in  = (s_len > 20) ? (s_len - 20) : 0;
    s_offset_out = (s_len < 20) ? (20 - s_len) : 0;

    memcpy(buffer + r_offset_out,
           ((char *)ssh_string_data(r)) + r_offset_in,
           r_len - r_offset_in);
    memcpy(buffer + 20 + s_offset_out,
           ((char *)ssh_string_data(s)) + s_offset_in,
           s_len - s_offset_in);

    ssh_string_free(r);
    ssh_string_free(s);

    sig_blob = ssh_string_new(40);
    if (sig_blob == NULL) {
        return NULL;
    }

    ssh_string_fill(sig_blob, buffer, 40);

    return sig_blob;
}

ssh_string pki_signature_to_blob(const ssh_signature sig)
{
    ssh_string sig_blob = NULL;

    switch(sig->type) {
        case SSH_KEYTYPE_DSS:
            sig_blob = pki_dsa_signature_to_blob(sig);
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sig_blob = ssh_string_copy(sig->rsa_sig);
            break;
        case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_OPENSSL_ECC
        {
            ssh_string r;
            ssh_string s;
            ssh_buffer b;
            int rc;

            b = ssh_buffer_new();
            if (b == NULL) {
                return NULL;
            }

            r = make_bignum_string(sig->ecdsa_sig->r);
            if (r == NULL) {
                ssh_buffer_free(b);
                return NULL;
            }
            rc = buffer_add_ssh_string(b, r);
            ssh_string_free(r);
            if (rc < 0) {
                ssh_buffer_free(b);
                return NULL;
            }

            s = make_bignum_string(sig->ecdsa_sig->s);
            if (s == NULL) {
                ssh_buffer_free(b);
                return NULL;
            }
            rc = buffer_add_ssh_string(b, s);
            ssh_string_free(s);
            if (rc < 0) {
                ssh_buffer_free(b);
                return NULL;
            }

            sig_blob = ssh_string_new(buffer_get_rest_len(b));
            if (sig_blob == NULL) {
                ssh_buffer_free(b);
                return NULL;
            }

            ssh_string_fill(sig_blob, buffer_get_rest(b), buffer_get_rest_len(b));
            ssh_buffer_free(b);
            break;
        }
#endif
        case SSH_KEYTYPE_ED25519:
            sig_blob = pki_ed25519_sig_to_blob(sig);
            break;
        default:
        case SSH_KEYTYPE_UNKNOWN:
            ssh_pki_log("Unknown signature key type: %s", sig->type_c);
            return NULL;
    }

    return sig_blob;
}

static ssh_signature pki_signature_from_rsa_blob(const ssh_key pubkey,
                                                 const ssh_string sig_blob,
                                                 ssh_signature sig)
{
    uint32_t pad_len = 0;
    char *blob_orig;
    char *blob_padded_data;
    ssh_string sig_blob_padded;

    size_t rsalen = 0;
    size_t len = ssh_string_len(sig_blob);

    if (pubkey->rsa == NULL) {
        ssh_pki_log("Pubkey RSA field NULL");
        goto errout;
    }

    rsalen = RSA_size(pubkey->rsa);
    if (len > rsalen) {
        ssh_pki_log("Signature is too big: %lu > %lu",
                    (unsigned long)len, (unsigned long)rsalen);
        goto errout;
    }

#ifdef DEBUG_CRYPTO
    ssh_pki_log("RSA signature len: %lu", (unsigned long)len);
    ssh_print_hexa("RSA signature", ssh_string_data(sig_blob), len);
#endif

    if (len == rsalen) {
        sig->rsa_sig = ssh_string_copy(sig_blob);
    } else {
        /* pad the blob to the expected rsalen size */
        ssh_pki_log("RSA signature len %lu < %lu",
                    (unsigned long)len, (unsigned long)rsalen);

        pad_len = rsalen - len;

        sig_blob_padded = ssh_string_new(rsalen);
        if (sig_blob_padded == NULL) {
            goto errout;
        }

        blob_padded_data = (char *) ssh_string_data(sig_blob_padded);
        blob_orig = (char *) ssh_string_data(sig_blob);

        /* front-pad the buffer with zeroes */
        BURN_BUFFER(blob_padded_data, pad_len);
        /* fill the rest with the actual signature blob */
        memcpy(blob_padded_data + pad_len, blob_orig, len);

        sig->rsa_sig = sig_blob_padded;
    }

    return sig;

errout:
    ssh_signature_free(sig);
    return NULL;
}

ssh_signature pki_signature_from_blob(const ssh_key pubkey,
                                      const ssh_string sig_blob,
                                      enum ssh_keytypes_e type)
{
    ssh_signature sig;
    ssh_string r;
    ssh_string s;
    size_t len;
    int rc;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }

    sig->type = type;
    sig->type_c = ssh_key_type_to_char(type);

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
            ssh_print_hexa("r", ssh_string_data(sig_blob), 20);
            ssh_print_hexa("s", (unsigned char *)ssh_string_data(sig_blob) + 20, 20);
#endif

            sig->dsa_sig = DSA_SIG_new();
            if (sig->dsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

            r = ssh_string_new(20);
            if (r == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            ssh_string_fill(r, ssh_string_data(sig_blob), 20);

            sig->dsa_sig->r = make_string_bn(r);
            ssh_string_free(r);
            if (sig->dsa_sig->r == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

            s = ssh_string_new(20);
            if (s == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            ssh_string_fill(s, (char *)ssh_string_data(sig_blob) + 20, 20);

            sig->dsa_sig->s = make_string_bn(s);
            ssh_string_free(s);
            if (sig->dsa_sig->s == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sig = pki_signature_from_rsa_blob(pubkey, sig_blob, sig);
            break;
        case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_OPENSSL_ECC
            sig->ecdsa_sig = ECDSA_SIG_new();
            if (sig->ecdsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

            { /* build ecdsa siganature */
                ssh_buffer b;
                uint32_t rlen;

                b = ssh_buffer_new();
                if (b == NULL) {
                    ssh_signature_free(sig);
                    return NULL;
                }

                rc = ssh_buffer_add_data(b,
                                         ssh_string_data(sig_blob),
                                         ssh_string_len(sig_blob));
                if (rc < 0) {
                    ssh_buffer_free(b);
                    ssh_signature_free(sig);
                    return NULL;
                }

                r = buffer_get_ssh_string(b);
                if (r == NULL) {
                    ssh_buffer_free(b);
                    ssh_signature_free(sig);
                    return NULL;
                }

#ifdef DEBUG_CRYPTO
                ssh_print_hexa("r", ssh_string_data(r), ssh_string_len(r));
#endif

                sig->ecdsa_sig->r = make_string_bn(r);
                ssh_string_burn(r);
                ssh_string_free(r);
                if (sig->ecdsa_sig->r == NULL) {
                    ssh_buffer_free(b);
                    ssh_signature_free(sig);
                    return NULL;
                }

                s = buffer_get_ssh_string(b);
                rlen = buffer_get_rest_len(b);
                ssh_buffer_free(b);
                if (s == NULL) {
                    ssh_signature_free(sig);
                    return NULL;
                }

#ifdef DEBUG_CRYPTO
                ssh_print_hexa("s", ssh_string_data(s), ssh_string_len(s));
#endif

                sig->ecdsa_sig->s = make_string_bn(s);
                ssh_string_burn(s);
                ssh_string_free(s);
                if (sig->ecdsa_sig->s == NULL) {
                    ssh_signature_free(sig);
                    return NULL;
                }

                if (rlen != 0) {
                    ssh_pki_log("Signature has remaining bytes in inner "
                                "sigblob: %lu",
                                (unsigned long)rlen);
                    ssh_signature_free(sig);
                    return NULL;
                }
            }

            break;
#endif
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_sig_from_blob(sig, sig_blob);
            if (rc == SSH_ERROR){
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        default:
        case SSH_KEYTYPE_UNKNOWN:
            ssh_pki_log("Unknown signature type");
            ssh_signature_free(sig);
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
    int rc;

    switch(key->type) {
        case SSH_KEYTYPE_DSS:
            rc = DSA_do_verify(hash,
                               hlen,
                               sig->dsa_sig,
                               key->dsa);
            if (rc <= 0) {
                ssh_set_error(session,
                              SSH_FATAL,
                              "DSA error: %s",
                              ERR_error_string(ERR_get_error(), NULL));
                return SSH_ERROR;
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            rc = RSA_verify(NID_sha1,
                            hash,
                            hlen,
                            ssh_string_data(sig->rsa_sig),
                            ssh_string_len(sig->rsa_sig),
                            key->rsa);
            if (rc <= 0) {
                ssh_set_error(session,
                              SSH_FATAL,
                              "RSA error: %s",
                              ERR_error_string(ERR_get_error(), NULL));
                return SSH_ERROR;
            }
            break;
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_verify(key, sig, hash, hlen);
            if (rc != SSH_OK){
                ssh_set_error(session,
                              SSH_FATAL,
                              "ed25519 signature verification error");
                return SSH_ERROR;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_OPENSSL_ECC
            rc = ECDSA_do_verify(hash,
                                 hlen,
                                 sig->ecdsa_sig,
                                 key->ecdsa);
            if (rc <= 0) {
                ssh_set_error(session,
                              SSH_FATAL,
                              "ECDSA error: %s",
                              ERR_error_string(ERR_get_error(), NULL));
                return SSH_ERROR;
            }
            break;
#endif
        case SSH_KEYTYPE_UNKNOWN:
        default:
            ssh_set_error(session, SSH_FATAL, "Unknown public key type");
            return SSH_ERROR;
    }

    return SSH_OK;
}

ssh_signature pki_do_sign(const ssh_key privkey,
                          const unsigned char *hash,
                          size_t hlen) {
    ssh_signature sig;
    int rc;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }

    sig->type = privkey->type;
    sig->type_c = privkey->type_c;

    switch(privkey->type) {
        case SSH_KEYTYPE_DSS:
            sig->dsa_sig = DSA_do_sign(hash, hlen, privkey->dsa);
            if (sig->dsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

#ifdef DEBUG_CRYPTO
            ssh_print_bignum("r", sig->dsa_sig->r);
            ssh_print_bignum("s", sig->dsa_sig->s);
#endif

            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sig->rsa_sig = _RSA_do_sign(hash, hlen, privkey->rsa);
            if (sig->rsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            sig->dsa_sig = NULL;
            break;
        case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_OPENSSL_ECC
            sig->ecdsa_sig = ECDSA_do_sign(hash, hlen, privkey->ecdsa);
            if (sig->ecdsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }

# ifdef DEBUG_CRYPTO
            ssh_print_bignum("r", sig->ecdsa_sig->r);
            ssh_print_bignum("s", sig->ecdsa_sig->s);
# endif /* DEBUG_CRYPTO */

            break;
#endif /* HAVE_OPENSSL_ECC */
        case SSH_KEYTYPE_ED25519:
            rc = pki_ed25519_sign(privkey, sig, hash, hlen);
            if (rc != SSH_OK){
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_UNKNOWN:
        default:
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
    ssh_signature sig;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }
    sig->type = key->type;
    sig->type_c = key->type_c;

    switch(key->type) {
        case SSH_KEYTYPE_DSS:
            sig->dsa_sig = DSA_do_sign(hash, hlen, key->dsa);
            if (sig->dsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            sig->rsa_sig = _RSA_do_sign(hash, hlen, key->rsa);
            if (sig->rsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
        case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_OPENSSL_ECC
            sig->ecdsa_sig = ECDSA_do_sign(hash, hlen, key->ecdsa);
            if (sig->ecdsa_sig == NULL) {
                ssh_signature_free(sig);
                return NULL;
            }
            break;
#endif
        case SSH_KEYTYPE_ED25519:
            /* ED25519 handled in caller */
        case SSH_KEYTYPE_UNKNOWN:
        default:
            ssh_signature_free(sig);
            return NULL;
    }

    return sig;
}
#endif /* WITH_SERVER */

#endif /* _PKI_CRYPTO_H */
