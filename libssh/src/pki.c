/*
 * known_hosts.c
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
 * Copyright (c) 2011-2013 Andreas Schneider <asn@cryptomilk.org>
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

/**
 * @defgroup libssh_pki The SSH Public Key Infrastructure
 * @ingroup libssh
 *
 * Functions for the creation, importation and manipulation of public and
 * private keys in the context of the SSH protocol
 *
 * @{
 */

#include "config.h"

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
# if _MSC_VER >= 1400
#  include <io.h>
#  undef open
#  define open _open
#  undef close
#  define close _close
#  undef read
#  define read _read
#  undef unlink
#  define unlink _unlink
# endif /* _MSC_VER */
#endif

#include "libssh/libssh.h"
#include "libssh/session.h"
#include "libssh/priv.h"
#include "libssh/pki.h"
#include "libssh/pki_priv.h"
#include "libssh/keys.h"
#include "libssh/buffer.h"
#include "libssh/misc.h"
#include "libssh/agent.h"

void _ssh_pki_log(const char *function, const char *format, ...)
{
#ifdef DEBUG_CRYPTO
    char buffer[1024];
    va_list va;

    va_start(va, format);
    vsnprintf(buffer, sizeof(buffer), format, va);
    va_end(va);

    ssh_log_function(SSH_LOG_DEBUG, function, buffer);
#else
    (void) function;
    (void) format;
#endif
    return;
}

enum ssh_keytypes_e pki_privatekey_type_from_string(const char *privkey) {
    if (strncmp(privkey, DSA_HEADER_BEGIN, strlen(DSA_HEADER_BEGIN)) == 0) {
        return SSH_KEYTYPE_DSS;
    }

    if (strncmp(privkey, RSA_HEADER_BEGIN, strlen(RSA_HEADER_BEGIN)) == 0) {
        return SSH_KEYTYPE_RSA;
    }

    if (strncmp(privkey, ECDSA_HEADER_BEGIN, strlen(ECDSA_HEADER_BEGIN)) == 0) {
        return SSH_KEYTYPE_ECDSA;
    }

    return SSH_KEYTYPE_UNKNOWN;
}

/**
 * @brief returns the ECDSA key name ("ecdsa-sha2-nistp256" for example)
 *
 * @param[in] key the ssh_key whose ECDSA name to get
 *
 * @returns the ECDSA key name ("ecdsa-sha2-nistp256" for example)
 *
 * @returns "unknown" if the ECDSA key name is not known
 */
const char *ssh_pki_key_ecdsa_name(const ssh_key key)
{
#ifdef HAVE_OPENSSL_ECC /* FIXME Better ECC check needed */
    return pki_key_ecdsa_nid_to_name(key->ecdsa_nid);
#else
    (void) key; /* unused */
    return NULL;
#endif
}

/**
 * @brief creates a new empty SSH key
 * @returns an empty ssh_key handle, or NULL on error.
 */
ssh_key ssh_key_new (void) {
  ssh_key ptr = malloc (sizeof (struct ssh_key_struct));
  if (ptr == NULL) {
      return NULL;
  }
  ZERO_STRUCTP(ptr);
  return ptr;
}

ssh_key ssh_key_dup(const ssh_key key)
{
    if (key == NULL) {
        return NULL;
    }

    return pki_key_dup(key, 0);
}

/**
 * @brief clean up the key and deallocate all existing keys
 * @param[in] key ssh_key to clean
 */
void ssh_key_clean (ssh_key key){
    if(key == NULL)
        return;
#ifdef HAVE_LIBGCRYPT
    if(key->dsa) gcry_sexp_release(key->dsa);
    if(key->rsa) gcry_sexp_release(key->rsa);
    if(key->ecdsa) gcry_sexp_release(key->ecdsa);
#elif defined HAVE_LIBCRYPTO
    if(key->dsa) DSA_free(key->dsa);
    if(key->rsa) RSA_free(key->rsa);
#ifdef HAVE_OPENSSL_ECC
    if(key->ecdsa) EC_KEY_free(key->ecdsa);
#endif /* HAVE_OPENSSL_ECC */
#endif
    if (key->ed25519_privkey != NULL){
        BURN_BUFFER(key->ed25519_privkey, sizeof(ed25519_privkey));
        SAFE_FREE(key->ed25519_privkey);
    }
    SAFE_FREE(key->ed25519_pubkey);
    key->flags=SSH_KEY_FLAG_EMPTY;
    key->type=SSH_KEYTYPE_UNKNOWN;
    key->ecdsa_nid = 0;
    key->type_c=NULL;
    key->dsa = NULL;
    key->rsa = NULL;
    key->ecdsa = NULL;
}

/**
 * @brief deallocate a SSH key
 * @param[in] key ssh_key handle to free
 */
void ssh_key_free (ssh_key key){
    if(key){
        ssh_key_clean(key);
        SAFE_FREE(key);
    }
}

/**
 * @brief returns the type of a ssh key
 * @param[in] key the ssh_key handle
 * @returns one of SSH_KEYTYPE_RSA,SSH_KEYTYPE_DSS,SSH_KEYTYPE_RSA1
 * @returns SSH_KEYTYPE_UNKNOWN if the type is unknown
 */
enum ssh_keytypes_e ssh_key_type(const ssh_key key){
    if (key == NULL) {
        return SSH_KEYTYPE_UNKNOWN;
    }
    return key->type;
}

/**
 * @brief Convert a key type to a string.
 *
 * @param[in]  type     The type to convert.
 *
 * @return              A string for the keytype or NULL if unknown.
 */
const char *ssh_key_type_to_char(enum ssh_keytypes_e type) {
  switch (type) {
    case SSH_KEYTYPE_DSS:
      return "ssh-dss";
    case SSH_KEYTYPE_RSA:
      return "ssh-rsa";
    case SSH_KEYTYPE_RSA1:
      return "ssh-rsa1";
    case SSH_KEYTYPE_ECDSA:
      return "ssh-ecdsa";
    case SSH_KEYTYPE_ED25519:
      return "ssh-ed25519";
    case SSH_KEYTYPE_UNKNOWN:
      return NULL;
  }

  /* We should never reach this */
  return NULL;
}

/**
 * @brief Convert a ssh key name to a ssh key type.
 *
 * @param[in] name      The name to convert.
 *
 * @return              The enum ssh key type.
 */
enum ssh_keytypes_e ssh_key_type_from_name(const char *name) {
    if (name == NULL) {
        return SSH_KEYTYPE_UNKNOWN;
    }

    if (strcmp(name, "rsa1") == 0) {
        return SSH_KEYTYPE_RSA1;
    } else if (strcmp(name, "rsa") == 0) {
        return SSH_KEYTYPE_RSA;
    } else if (strcmp(name, "dsa") == 0) {
        return SSH_KEYTYPE_DSS;
    } else if (strcmp(name, "ssh-rsa1") == 0) {
        return SSH_KEYTYPE_RSA1;
    } else if (strcmp(name, "ssh-rsa") == 0) {
        return SSH_KEYTYPE_RSA;
    } else if (strcmp(name, "ssh-dss") == 0) {
        return SSH_KEYTYPE_DSS;
    } else if (strcmp(name, "ssh-ecdsa") == 0
            || strcmp(name, "ecdsa") == 0
            || strcmp(name, "ecdsa-sha2-nistp256") == 0
            || strcmp(name, "ecdsa-sha2-nistp384") == 0
            || strcmp(name, "ecdsa-sha2-nistp521") == 0) {
        return SSH_KEYTYPE_ECDSA;
    } else if (strcmp(name, "ssh-ed25519") == 0){
        return SSH_KEYTYPE_ED25519;
    }

    return SSH_KEYTYPE_UNKNOWN;
}

/**
 * @brief Check if the key has/is a public key.
 *
 * @param[in] k         The key to check.
 *
 * @return              1 if it is a public key, 0 if not.
 */
int ssh_key_is_public(const ssh_key k) {
    if (k == NULL) {
        return 0;
    }

    return (k->flags & SSH_KEY_FLAG_PUBLIC);
}

/**
 * @brief Check if the key is a private key.
 *
 * @param[in] k         The key to check.
 *
 * @return              1 if it is a private key, 0 if not.
 */
int ssh_key_is_private(const ssh_key k) {
    if (k == NULL) {
        return 0;
    }

    return (k->flags & SSH_KEY_FLAG_PRIVATE);
}

/**
 * @brief Compare keys if they are equal.
 *
 * @param[in] k1        The first key to compare.
 *
 * @param[in] k2        The second key to compare.
 *
 * @param[in] what      What part or type of the key do you want to compare.
 *
 * @return              0 if equal, 1 if not.
 */
int ssh_key_cmp(const ssh_key k1,
                const ssh_key k2,
                enum ssh_keycmp_e what)
{
    if (k1 == NULL || k2 == NULL) {
        return 1;
    }

    if (k1->type != k2->type) {
        ssh_pki_log("key types don't match!");
        return 1;
    }

    if (what == SSH_KEY_CMP_PRIVATE) {
        if (!ssh_key_is_private(k1) ||
            !ssh_key_is_private(k2)) {
            return 1;
        }
    }

    if (k1->type == SSH_KEYTYPE_ED25519) {
        return pki_ed25519_key_cmp(k1, k2, what);
    }

    return pki_key_compare(k1, k2, what);
}

ssh_signature ssh_signature_new(void)
{
    struct ssh_signature_struct *sig;

    sig = malloc(sizeof(struct ssh_signature_struct));
    if (sig == NULL) {
        return NULL;
    }
    ZERO_STRUCTP(sig);

    return sig;
}

void ssh_signature_free(ssh_signature sig)
{
    if (sig == NULL) {
        return;
    }

    switch(sig->type) {
        case SSH_KEYTYPE_DSS:
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_release(sig->dsa_sig);
#elif defined HAVE_LIBCRYPTO
            DSA_SIG_free(sig->dsa_sig);
#endif
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
#ifdef HAVE_LIBGCRYPT
            gcry_sexp_release(sig->rsa_sig);
#elif defined HAVE_LIBCRYPTO
            SAFE_FREE(sig->rsa_sig);
#endif
            break;
        case SSH_KEYTYPE_ECDSA:
#if defined(HAVE_LIBCRYPTO) && defined(HAVE_OPENSSL_ECC)
            ECDSA_SIG_free(sig->ecdsa_sig);
#endif
            break;
        case SSH_KEYTYPE_ED25519:
            SAFE_FREE(sig->ed25519_sig);
            break;
        case SSH_KEYTYPE_UNKNOWN:
            break;
    }

    SAFE_FREE(sig);
}

/**
 * @brief import a base64 formated key from a memory c-string
 *
 * @param[in]  b64_key  The c-string holding the base64 encoded key
 *
 * @param[in]  passphrase The passphrase to decrypt the key, or NULL
 *
 * @param[in]  auth_fn  An auth function you may want to use or NULL.
 *
 * @param[in]  auth_data Private data passed to the auth function.
 *
 * @param[out] pkey     A pointer where the allocated key can be stored. You
 *                      need to free the memory.
 *
 * @return  SSH_ERROR in case of error, SSH_OK otherwise.
 *
 * @see ssh_key_free()
 */
int ssh_pki_import_privkey_base64(const char *b64_key,
                                  const char *passphrase,
                                  ssh_auth_callback auth_fn,
                                  void *auth_data,
                                  ssh_key *pkey)
{
    ssh_key key;

    if (b64_key == NULL || pkey == NULL) {
        return SSH_ERROR;
    }

    if (b64_key == NULL || !*b64_key) {
        return SSH_ERROR;
    }

    ssh_pki_log("Trying to decode privkey passphrase=%s",
                passphrase ? "true" : "false");

    key = pki_private_key_from_base64(b64_key, passphrase, auth_fn, auth_data);
    if (key == NULL) {
        return SSH_ERROR;
    }

    *pkey = key;

    return SSH_OK;
}

/**
 * @brief Import a key from a file.
 *
 * @param[in]  filename The filename of the the private key.
 *
 * @param[in]  passphrase The passphrase to decrypt the private key. Set to NULL
 *                        if none is needed or it is unknown.
 *
 * @param[in]  auth_fn  An auth function you may want to use or NULL.
 *
 * @param[in]  auth_data Private data passed to the auth function.
 *
 * @param[out] pkey     A pointer to store the allocated ssh_key. You need to
 *                      free the key.
 *
 * @returns SSH_OK on success, SSH_EOF if the file doesn't exist or permission
 *          denied, SSH_ERROR otherwise.
 *
 * @see ssh_key_free()
 **/
int ssh_pki_import_privkey_file(const char *filename,
                                const char *passphrase,
                                ssh_auth_callback auth_fn,
                                void *auth_data,
                                ssh_key *pkey) {
    struct stat sb;
    char *key_buf;
    ssh_key key;
    FILE *file;
    off_t size;
    int rc;

    if (pkey == NULL || filename == NULL || *filename == '\0') {
        return SSH_ERROR;
    }

    file = fopen(filename, "rb");
    if (file == NULL) {
        ssh_pki_log("Error opening %s: %s",
                    filename, strerror(errno));
        return SSH_EOF;
    }

    rc = fstat(fileno(file), &sb);
    if (rc < 0) {
        fclose(file);
        ssh_pki_log("Error getting stat of %s: %s",
                    filename, strerror(errno));
        switch (errno) {
            case ENOENT:
            case EACCES:
                return SSH_EOF;
        }

        return SSH_ERROR;
    }

    if (sb.st_size > MAX_PRIVKEY_SIZE) {
        ssh_pki_log("Private key is bigger than 4M.");
        fclose(file);
        return SSH_ERROR;
    }

    key_buf = malloc(sb.st_size + 1);
    if (key_buf == NULL) {
        fclose(file);
        ssh_pki_log("Out of memory!");
        return SSH_ERROR;
    }

    size = fread(key_buf, 1, sb.st_size, file);
    fclose(file);

    if (size != sb.st_size) {
        SAFE_FREE(key_buf);
        ssh_pki_log("Error reading %s: %s",
                    filename, strerror(errno));
        return SSH_ERROR;
    }
    key_buf[size] = 0;

    key = pki_private_key_from_base64(key_buf, passphrase, auth_fn, auth_data);
    SAFE_FREE(key_buf);
    if (key == NULL) {
        return SSH_ERROR;
    }

    *pkey = key;
    return SSH_OK;
}

/**
 * @brief Export a private key to a pam file on disk.
 *
 * @param[in]  privkey  The private key to export.
 *
 * @param[in]  passphrase The passphrase to use to encrypt the key with or
 *             NULL. An empty string means no passphrase.
 *
 * @param[in]  auth_fn  An auth function you may want to use or NULL.
 *
 * @param[in]  auth_data Private data passed to the auth function.
 *
 * @param[in]  filename  The path where to store the pem file.
 *
 * @return     SSH_OK on success, SSH_ERROR on error.
 */
int ssh_pki_export_privkey_file(const ssh_key privkey,
                                const char *passphrase,
                                ssh_auth_callback auth_fn,
                                void *auth_data,
                                const char *filename)
{
    ssh_string blob;
    FILE *fp;
    int rc;

    if (privkey == NULL || !ssh_key_is_private(privkey)) {
        return SSH_ERROR;
    }

    fp = fopen(filename, "wb");
    if (fp == NULL) {
        SSH_LOG(SSH_LOG_FUNCTIONS, "Error opening %s: %s",
                filename, strerror(errno));
        return SSH_EOF;
    }


    blob = pki_private_key_to_pem(privkey,
                                  passphrase,
                                  auth_fn,
                                  auth_data);
    if (blob == NULL) {
        fclose(fp);
        return -1;
    }

    rc = fwrite(ssh_string_data(blob), ssh_string_len(blob), 1, fp);
    ssh_string_free(blob);
    if (rc != 1 || ferror(fp)) {
        fclose(fp);
        unlink(filename);
        return SSH_ERROR;
    }
    fclose(fp);

    return SSH_OK;
}

/* temporary function to migrate seemlessly to ssh_key */
ssh_public_key ssh_pki_convert_key_to_publickey(const ssh_key key) {
    ssh_public_key pub;
    ssh_key tmp;

    if(key == NULL) {
        return NULL;
    }

    tmp = ssh_key_dup(key);
    if (tmp == NULL) {
        return NULL;
    }

    pub = malloc(sizeof(struct ssh_public_key_struct));
    if (pub == NULL) {
        ssh_key_free(tmp);
        return NULL;
    }
    ZERO_STRUCTP(pub);

    pub->type = tmp->type;
    pub->type_c = tmp->type_c;

    pub->dsa_pub = tmp->dsa;
    tmp->dsa = NULL;
    pub->rsa_pub = tmp->rsa;
    tmp->rsa = NULL;

    ssh_key_free(tmp);

    return pub;
}

ssh_private_key ssh_pki_convert_key_to_privatekey(const ssh_key key) {
    ssh_private_key privkey;

    privkey = malloc(sizeof(struct ssh_private_key_struct));
    if (privkey == NULL) {
        ssh_key_free(key);
        return NULL;
    }

    privkey->type = key->type;
    privkey->dsa_priv = key->dsa;
    privkey->rsa_priv = key->rsa;

    return privkey;
}

static int pki_import_pubkey_buffer(ssh_buffer buffer,
                                    enum ssh_keytypes_e type,
                                    ssh_key *pkey) {
    ssh_key key;
    int rc;

    key = ssh_key_new();
    if (key == NULL) {
        return SSH_ERROR;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PUBLIC;

    switch (type) {
        case SSH_KEYTYPE_DSS:
            {
                ssh_string p;
                ssh_string q;
                ssh_string g;
                ssh_string pubkey;

                p = buffer_get_ssh_string(buffer);
                if (p == NULL) {
                    goto fail;
                }
                q = buffer_get_ssh_string(buffer);
                if (q == NULL) {
                    ssh_string_burn(p);
                    ssh_string_free(p);

                    goto fail;
                }
                g = buffer_get_ssh_string(buffer);
                if (g == NULL) {
                    ssh_string_burn(p);
                    ssh_string_free(p);
                    ssh_string_burn(q);
                    ssh_string_free(q);

                    goto fail;
                }
                pubkey = buffer_get_ssh_string(buffer);
                if (pubkey == NULL) {
                    ssh_string_burn(p);
                    ssh_string_free(p);
                    ssh_string_burn(q);
                    ssh_string_free(q);
                    ssh_string_burn(g);
                    ssh_string_free(g);

                    goto fail;
                }

                rc = pki_pubkey_build_dss(key, p, q, g, pubkey);
#ifdef DEBUG_CRYPTO
                ssh_print_hexa("p", ssh_string_data(p), ssh_string_len(p));
                ssh_print_hexa("q", ssh_string_data(q), ssh_string_len(q));
                ssh_print_hexa("g", ssh_string_data(g), ssh_string_len(g));
#endif
                ssh_string_burn(p);
                ssh_string_free(p);
                ssh_string_burn(q);
                ssh_string_free(q);
                ssh_string_burn(g);
                ssh_string_free(g);
                ssh_string_burn(pubkey);
                ssh_string_free(pubkey);
                if (rc == SSH_ERROR) {
                    goto fail;
                }
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            {
                ssh_string e;
                ssh_string n;

                e = buffer_get_ssh_string(buffer);
                if (e == NULL) {
                    goto fail;
                }
                n = buffer_get_ssh_string(buffer);
                if (n == NULL) {
                    ssh_string_burn(e);
                    ssh_string_free(e);

                    goto fail;
                }

                rc = pki_pubkey_build_rsa(key, e, n);
#ifdef DEBUG_CRYPTO
                ssh_print_hexa("e", ssh_string_data(e), ssh_string_len(e));
                ssh_print_hexa("n", ssh_string_data(n), ssh_string_len(n));
#endif
                ssh_string_burn(e);
                ssh_string_free(e);
                ssh_string_burn(n);
                ssh_string_free(n);
                if (rc == SSH_ERROR) {
                    goto fail;
                }
            }
            break;
        case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_ECC
            {
                ssh_string e;
                ssh_string i;
                int nid;

                i = buffer_get_ssh_string(buffer);
                if (i == NULL) {
                    goto fail;
                }
                nid = pki_key_ecdsa_nid_from_name(ssh_string_get_char(i));
                ssh_string_free(i);
                if (nid == -1) {
                    goto fail;
                }


                e = buffer_get_ssh_string(buffer);
                if (e == NULL) {
                    goto fail;
                }

                rc = pki_pubkey_build_ecdsa(key, nid, e);
                ssh_string_burn(e);
                ssh_string_free(e);
                if (rc < 0) {
                    goto fail;
                }

                /* Update key type */
                key->type_c = ssh_pki_key_ecdsa_name(key);
            }
            break;
#endif
        case SSH_KEYTYPE_ED25519:
        {
            ssh_string pubkey = buffer_get_ssh_string(buffer);
            if (ssh_string_len(pubkey) != ED25519_PK_LEN) {
                ssh_pki_log("Invalid public key length");
                ssh_string_burn(pubkey);
                ssh_string_free(pubkey);
                goto fail;
            }

            key->ed25519_pubkey = malloc(ED25519_PK_LEN);
            if (key->ed25519_pubkey == NULL) {
                ssh_string_burn(pubkey);
                ssh_string_free(pubkey);
                goto fail;
            }

            memcpy(key->ed25519_pubkey, ssh_string_data(pubkey), ED25519_PK_LEN);
            ssh_string_burn(pubkey);
            ssh_string_free(pubkey);
        }
        break;
        case SSH_KEYTYPE_UNKNOWN:
        default:
            ssh_pki_log("Unknown public key protocol %d", type);
            goto fail;
    }

    *pkey = key;
    return SSH_OK;
fail:
    ssh_key_free(key);

    return SSH_ERROR;
}

/**
 * @brief Import a base64 formated public key from a memory c-string.
 *
 * @param[in]  b64_key  The base64 key to format.
 *
 * @param[in]  type     The type of the key to format.
 *
 * @param[out] pkey     A pointer where the allocated key can be stored. You
 *                      need to free the memory.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 *
 * @see ssh_key_free()
 */
int ssh_pki_import_pubkey_base64(const char *b64_key,
                                 enum ssh_keytypes_e type,
                                 ssh_key *pkey) {
    ssh_buffer buffer;
    ssh_string type_s;
    int rc;

    if (b64_key == NULL || pkey == NULL) {
        return SSH_ERROR;
    }

    buffer = base64_to_bin(b64_key);
    if (buffer == NULL) {
        return SSH_ERROR;
    }

    type_s = buffer_get_ssh_string(buffer);
    if (type_s == NULL) {
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }
    ssh_string_free(type_s);

    rc = pki_import_pubkey_buffer(buffer, type, pkey);
    ssh_buffer_free(buffer);

    return rc;
}

/**
 * @internal
 *
 * @brief Import a public key from a ssh string.
 *
 * @param[in]  key_blob The key blob to import as specified in RFC 4253 section
 *                      6.6 "Public Key Algorithms".
 *
 * @param[out] pkey     A pointer where the allocated key can be stored. You
 *                      need to free the memory.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 *
 * @see ssh_key_free()
 */
int ssh_pki_import_pubkey_blob(const ssh_string key_blob,
                               ssh_key *pkey) {
    ssh_buffer buffer;
    ssh_string type_s = NULL;
    enum ssh_keytypes_e type;
    int rc;

    if (key_blob == NULL || pkey == NULL) {
        return SSH_ERROR;
    }

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        ssh_pki_log("Out of memory!");
        return SSH_ERROR;
    }

    rc = ssh_buffer_add_data(buffer, ssh_string_data(key_blob),
            ssh_string_len(key_blob));
    if (rc < 0) {
        ssh_pki_log("Out of memory!");
        goto fail;
    }

    type_s = buffer_get_ssh_string(buffer);
    if (type_s == NULL) {
        ssh_pki_log("Out of memory!");
        goto fail;
    }

    type = ssh_key_type_from_name(ssh_string_get_char(type_s));
    if (type == SSH_KEYTYPE_UNKNOWN) {
        ssh_pki_log("Unknown key type found!");
        goto fail;
    }
    ssh_string_free(type_s);

    rc = pki_import_pubkey_buffer(buffer, type, pkey);

    ssh_buffer_free(buffer);

    return rc;
fail:
    ssh_buffer_free(buffer);
    ssh_string_free(type_s);

    return SSH_ERROR;
}

/**
 * @brief Import a public key from the given filename.
 *
 * @param[in]  filename The path to the public key.
 *
 * @param[out] pkey     A pointer to store the allocated public key. You need to
 *                      free the memory.
 *
 * @returns SSH_OK on success, SSH_EOF if the file doesn't exist or permission
 *          denied, SSH_ERROR otherwise.
 *
 * @see ssh_key_free()
 */
int ssh_pki_import_pubkey_file(const char *filename, ssh_key *pkey)
{
    enum ssh_keytypes_e type;
    struct stat sb;
    char *key_buf, *p;
    const char *q;
    FILE *file;
    off_t size;
    int rc;

    if (pkey == NULL || filename == NULL || *filename == '\0') {
        return SSH_ERROR;
    }

    file = fopen(filename, "r");
    if (file == NULL) {
        ssh_pki_log("Error opening %s: %s",
                    filename, strerror(errno));
        return SSH_EOF;
    }

    rc = fstat(fileno(file), &sb);
    if (rc < 0) {
        fclose(file);
        ssh_pki_log("Error gettint stat of %s: %s",
                    filename, strerror(errno));
        switch (errno) {
            case ENOENT:
            case EACCES:
                return SSH_EOF;
        }
        return SSH_ERROR;
    }

    if (sb.st_size > MAX_PUBKEY_SIZE) {
        fclose(file);
        return SSH_ERROR;
    }

    key_buf = malloc(sb.st_size + 1);
    if (key_buf == NULL) {
        fclose(file);
        ssh_pki_log("Out of memory!");
        return SSH_ERROR;
    }

    size = fread(key_buf, 1, sb.st_size, file);
    fclose(file);

    if (size != sb.st_size) {
        SAFE_FREE(key_buf);
        ssh_pki_log("Error reading %s: %s",
                    filename, strerror(errno));
        return SSH_ERROR;
    }
    key_buf[size] = '\0';

    q = p = key_buf;
    while (!isspace((int)*p)) p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    if (type == SSH_KEYTYPE_UNKNOWN) {
        SAFE_FREE(key_buf);
        return SSH_ERROR;
    }
    q = ++p;
    while (!isspace((int)*p)) p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, pkey);
    SAFE_FREE(key_buf);

    return rc;
}

/**
 * @brief Generates a keypair.
 *
 * @param[in] type      Type of key to create
 *
 * @param[in] parameter Parameter to the creation of key:
 *                      rsa : length of the key in bits (e.g. 1024, 2048, 4096)
 *                      dsa : length of the key in bits (e.g. 1024, 2048, 3072)
 *                      ecdsa : bits of the key (e.g. 256, 384, 512)
 * @param[out] pkey     A pointer to store the allocated private key. You need
 *                      to free the memory.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 *
 * @warning             Generating a key pair may take some time.
 */
int ssh_pki_generate(enum ssh_keytypes_e type, int parameter,
        ssh_key *pkey){
    int rc;
    ssh_key key = ssh_key_new();

    if (key == NULL) {
        return SSH_ERROR;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PRIVATE | SSH_KEY_FLAG_PUBLIC;

    switch(type){
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            rc = pki_key_generate_rsa(key, parameter);
            if(rc == SSH_ERROR)
                goto error;
            break;
        case SSH_KEYTYPE_DSS:
            rc = pki_key_generate_dss(key, parameter);
            if(rc == SSH_ERROR)
                goto error;
            break;
        case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_ECC
            rc = pki_key_generate_ecdsa(key, parameter);
            if (rc == SSH_ERROR) {
                goto error;
            }

            /* Update key type */
            key->type_c = ssh_pki_key_ecdsa_name(key);
            break;
#endif
        case SSH_KEYTYPE_ED25519:
            rc = pki_key_generate_ed25519(key);
            if (rc == SSH_ERROR) {
                goto error;
            }
            break;
        case SSH_KEYTYPE_UNKNOWN:
            goto error;
    }

    *pkey = key;
    return SSH_OK;
error:
    ssh_key_free(key);
    return SSH_ERROR;
}

/**
 * @brief Create a public key from a private key.
 *
 * @param[in]  privkey  The private key to get the public key from.
 *
 * @param[out] pkey     A pointer to store the newly allocated public key. You
 *                      NEED to free the key.
 *
 * @return              A public key, NULL on error.
 *
 * @see ssh_key_free()
 */
int ssh_pki_export_privkey_to_pubkey(const ssh_key privkey,
                                     ssh_key *pkey)
{
    ssh_key pubkey;

    if (privkey == NULL || !ssh_key_is_private(privkey)) {
        return SSH_ERROR;
    }

    pubkey = pki_key_dup(privkey, 1);
    if (pubkey == NULL) {
        return SSH_ERROR;
    }

    *pkey = pubkey;
    return SSH_OK;
}

/**
 * @internal
 *
 * @brief Create a key_blob from a public key.
 *
 * The "key_blob" is encoded as per RFC 4253 section 6.6 "Public Key
 * Algorithms" for any of the supported protocol 2 key types.
 *
 * @param[in]  key      A public or private key to create the public ssh_string
 *                      from.
 *
 * @param[out] pblob    A pointer to store the newly allocated key blob. You
 *                      NEED to free it.
 *
 * @return              SSH_OK on success, SSH_ERROR otherwise.
 *
 * @see ssh_string_free()
 */
int ssh_pki_export_pubkey_blob(const ssh_key key,
                               ssh_string *pblob)
{
    ssh_string blob;

    if (key == NULL) {
        return SSH_OK;
    }

    blob = pki_publickey_to_blob(key);
    if (blob == NULL) {
        return SSH_ERROR;
    }

    *pblob = blob;
    return SSH_OK;
}

/**
 * @brief Convert a public key to a base64 encoded key.
 *
 * @param[in] key       The key to hash
 *
 * @param[out] b64_key  A pointer to store the allocated base64 encoded key. You
 *                      need to free the buffer.
 *
 * @return              SSH_OK on success, SSH_ERROR on error.
 *
 * @see ssh_string_free_char()
 */
int ssh_pki_export_pubkey_base64(const ssh_key key,
                                 char **b64_key)
{
    ssh_string key_blob;
    unsigned char *b64;

    if (key == NULL || b64_key == NULL) {
        return SSH_ERROR;
    }

    key_blob = pki_publickey_to_blob(key);
    if (key_blob == NULL) {
        return SSH_ERROR;
    }

    b64 = bin_to_base64(ssh_string_data(key_blob), ssh_string_len(key_blob));
    ssh_string_free(key_blob);
    if (b64 == NULL) {
        return SSH_ERROR;
    }

    *b64_key = (char *)b64;

    return SSH_OK;
}

int ssh_pki_export_pubkey_file(const ssh_key key,
                               const char *filename)
{
    char key_buf[4096];
    char host[256];
    char *b64_key;
    char *user;
    FILE *fp;
    int rc;

    if (key == NULL || filename == NULL || *filename == '\0') {
        return SSH_ERROR;
    }

    user = ssh_get_local_username();
    if (user == NULL) {
        return SSH_ERROR;
    }

    rc = gethostname(host, sizeof(host));
    if (rc < 0) {
        free(user);
        return SSH_ERROR;
    }

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    if (rc < 0) {
        free(user);
        return SSH_ERROR;
    }

    rc = snprintf(key_buf, sizeof(key_buf),
                  "%s %s %s@%s\n",
                  key->type_c,
                  b64_key,
                  user,
                  host);
    free(user);
    free(b64_key);
    if (rc < 0) {
        return SSH_ERROR;
    }

    fp = fopen(filename, "w+");
    if (fp == NULL) {
        return SSH_ERROR;
    }
    rc = fwrite(key_buf, strlen(key_buf), 1, fp);
    if (rc != 1 || ferror(fp)) {
        fclose(fp);
        unlink(filename);
        return SSH_ERROR;
    }
    fclose(fp);

    return SSH_OK;
}

int ssh_pki_export_pubkey_rsa1(const ssh_key key,
                               const char *host,
                               char *rsa1,
                               size_t rsa1_len)
{
    return pki_export_pubkey_rsa1(key, host, rsa1, rsa1_len);
}

int ssh_pki_export_signature_blob(const ssh_signature sig,
                                  ssh_string *sig_blob)
{
    ssh_buffer buf = NULL;
    ssh_string str;
    int rc;

    if (sig == NULL || sig_blob == NULL) {
        return SSH_ERROR;
    }

    buf = ssh_buffer_new();
    if (buf == NULL) {
        return SSH_ERROR;
    }

    str = ssh_string_from_char(sig->type_c);
    if (str == NULL) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    rc = buffer_add_ssh_string(buf, str);
    ssh_string_free(str);
    if (rc < 0) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    str = pki_signature_to_blob(sig);
    if (str == NULL) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    rc = buffer_add_ssh_string(buf, str);
    ssh_string_free(str);
    if (rc < 0) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    str = ssh_string_new(buffer_get_rest_len(buf));
    if (str == NULL) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    ssh_string_fill(str, buffer_get_rest(buf), buffer_get_rest_len(buf));
    ssh_buffer_free(buf);

    *sig_blob = str;

    return SSH_OK;
}

int ssh_pki_import_signature_blob(const ssh_string sig_blob,
                                  const ssh_key pubkey,
                                  ssh_signature *psig)
{
    ssh_signature sig;
    enum ssh_keytypes_e type;
    ssh_string str;
    ssh_buffer buf;
    int rc;

    if (sig_blob == NULL || psig == NULL) {
        return SSH_ERROR;
    }

    buf = ssh_buffer_new();
    if (buf == NULL) {
        return SSH_ERROR;
    }

    rc = ssh_buffer_add_data(buf,
                             ssh_string_data(sig_blob),
                             ssh_string_len(sig_blob));
    if (rc < 0) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    str = buffer_get_ssh_string(buf);
    if (str == NULL) {
        ssh_buffer_free(buf);
        return SSH_ERROR;
    }

    type = ssh_key_type_from_name(ssh_string_get_char(str));
    ssh_string_free(str);

    str = buffer_get_ssh_string(buf);
    ssh_buffer_free(buf);
    if (str == NULL) {
        return SSH_ERROR;
    }

    sig = pki_signature_from_blob(pubkey, str, type);
    ssh_string_free(str);
    if (sig == NULL) {
        return SSH_ERROR;
    }

    *psig = sig;
    return SSH_OK;
}

int ssh_pki_signature_verify_blob(ssh_session session,
                                  ssh_string sig_blob,
                                  const ssh_key key,
                                  unsigned char *digest,
                                  size_t dlen)
{
    ssh_signature sig;
    int rc;

    rc = ssh_pki_import_signature_blob(sig_blob, key, &sig);
    if (rc < 0) {
        return SSH_ERROR;
    }

    SSH_LOG(SSH_LOG_FUNCTIONS,
            "Going to verify a %s type signature",
            key->type_c);


    if (key->type == SSH_KEYTYPE_ECDSA) {
#if HAVE_ECC
        unsigned char ehash[EVP_DIGEST_LEN] = {0};
        uint32_t elen;

        evp(key->ecdsa_nid, digest, dlen, ehash, &elen);

#ifdef DEBUG_CRYPTO
        ssh_print_hexa("Hash to be verified with ecdsa",
                       ehash, elen);
#endif

        rc = pki_signature_verify(session,
                                  sig,
                                  key,
                                  ehash,
                                  elen);
#endif
    } else if (key->type == SSH_KEYTYPE_ED25519) {
        rc = pki_signature_verify(session, sig, key, digest, dlen);
    } else {
        unsigned char hash[SHA_DIGEST_LEN] = {0};

        sha1(digest, dlen, hash);
#ifdef DEBUG_CRYPTO
        ssh_print_hexa("Hash to be verified with dsa", hash, SHA_DIGEST_LEN);
#endif

        rc = pki_signature_verify(session,
                                  sig,
                                  key,
                                  hash,
                                  SHA_DIGEST_LEN);
    }

    ssh_signature_free(sig);

    return rc;
}

/*
 * This function signs the session id as a string then
 * the content of sigbuf */
ssh_string ssh_pki_do_sign(ssh_session session,
                           ssh_buffer sigbuf,
                           const ssh_key privkey) {
    struct ssh_crypto_struct *crypto =
        session->current_crypto ? session->current_crypto :
                                  session->next_crypto;
    ssh_signature sig;
    ssh_string sig_blob;
    ssh_string session_id;
    int rc;

    if (privkey == NULL || !ssh_key_is_private(privkey)) {
        return NULL;
    }

    session_id = ssh_string_new(crypto->digest_len);
    if (session_id == NULL) {
        return NULL;
    }
    ssh_string_fill(session_id, crypto->session_id, crypto->digest_len);

    if (privkey->type == SSH_KEYTYPE_ECDSA) {
#ifdef HAVE_ECC
        unsigned char ehash[EVP_DIGEST_LEN] = {0};
        uint32_t elen;
        EVPCTX ctx;

        ctx = evp_init(privkey->ecdsa_nid);
        if (ctx == NULL) {
            ssh_string_free(session_id);
            return NULL;
        }

        evp_update(ctx, session_id, ssh_string_len(session_id) + 4);
        evp_update(ctx, buffer_get_rest(sigbuf), buffer_get_rest_len(sigbuf));
        evp_final(ctx, ehash, &elen);

#ifdef DEBUG_CRYPTO
        ssh_print_hexa("Hash being signed", ehash, elen);
#endif

        sig = pki_do_sign(privkey, ehash, elen);
#endif
    } else if (privkey->type == SSH_KEYTYPE_ED25519){
        ssh_buffer buf;

        buf = ssh_buffer_new();
        if (buf == NULL) {
            ssh_string_free(session_id);
            return NULL;
        }

        ssh_buffer_set_secure(buf);
        rc = ssh_buffer_pack(buf,
                             "SP",
                             session_id,
                             buffer_get_rest_len(sigbuf), buffer_get_rest(sigbuf));
        if (rc != SSH_OK) {
            ssh_string_free(session_id);
            ssh_buffer_free(buf);
            return NULL;
        }

        sig = pki_do_sign(privkey,
                          ssh_buffer_get_begin(buf),
                          ssh_buffer_get_len(buf));
        ssh_buffer_free(buf);
    } else {
        unsigned char hash[SHA_DIGEST_LEN] = {0};
        SHACTX ctx;

        ctx = sha1_init();
        if (ctx == NULL) {
            ssh_string_free(session_id);
            return NULL;
        }

        sha1_update(ctx, session_id, ssh_string_len(session_id) + 4);
        sha1_update(ctx, buffer_get_rest(sigbuf), buffer_get_rest_len(sigbuf));
        sha1_final(hash, ctx);

#ifdef DEBUG_CRYPTO
        ssh_print_hexa("Hash being signed", hash, SHA_DIGEST_LEN);
#endif

        sig = pki_do_sign(privkey, hash, SHA_DIGEST_LEN);
    }
    ssh_string_free(session_id);
    if (sig == NULL) {
        return NULL;
    }

    rc = ssh_pki_export_signature_blob(sig, &sig_blob);
    ssh_signature_free(sig);
    if (rc < 0) {
        return NULL;
    }

    return sig_blob;
}

#ifndef _WIN32
ssh_string ssh_pki_do_sign_agent(ssh_session session,
                                 struct ssh_buffer_struct *buf,
                                 const ssh_key pubkey) {
    struct ssh_crypto_struct *crypto;
    ssh_string session_id;
    ssh_string sig_blob;
    ssh_buffer sig_buf;
    int rc;

    if (session->current_crypto) {
        crypto = session->current_crypto;
    } else {
        crypto = session->next_crypto;
    }

    /* prepend session identifier */
    session_id = ssh_string_new(crypto->digest_len);
    if (session_id == NULL) {
        return NULL;
    }
    ssh_string_fill(session_id, crypto->session_id, crypto->digest_len);

    sig_buf = ssh_buffer_new();
    if (sig_buf == NULL) {
        ssh_string_free(session_id);
        return NULL;
    }

    rc = buffer_add_ssh_string(sig_buf, session_id);
    if (rc < 0) {
        ssh_string_free(session_id);
        ssh_buffer_free(sig_buf);
        return NULL;
    }
    ssh_string_free(session_id);

    /* append out buffer */
    if (buffer_add_buffer(sig_buf, buf) < 0) {
        ssh_buffer_free(sig_buf);
        return NULL;
    }

    /* create signature */
    sig_blob = ssh_agent_sign_data(session, pubkey, sig_buf);

    ssh_buffer_free(sig_buf);

    return sig_blob;
}
#endif /* _WIN32 */

#ifdef WITH_SERVER
ssh_string ssh_srv_pki_do_sign_sessionid(ssh_session session,
                                         const ssh_key privkey)
{
    struct ssh_crypto_struct *crypto;
    ssh_signature sig;
    ssh_string sig_blob;
    int rc;

    if (session == NULL || privkey == NULL || !ssh_key_is_private(privkey)) {
        return NULL;
    }
    crypto = session->next_crypto ? session->next_crypto :
                                       session->current_crypto;

    if (crypto->secret_hash == NULL){
        ssh_set_error(session,SSH_FATAL,"Missing secret_hash");
        return NULL;
    }

    if (privkey->type == SSH_KEYTYPE_ECDSA) {
#ifdef HAVE_ECC
        unsigned char ehash[EVP_DIGEST_LEN] = {0};
        uint32_t elen;

        evp(privkey->ecdsa_nid, crypto->secret_hash, crypto->digest_len,
            ehash, &elen);

#ifdef DEBUG_CRYPTO
        ssh_print_hexa("Hash being signed", ehash, elen);
#endif

        sig = pki_do_sign_sessionid(privkey, ehash, elen);
        if (sig == NULL) {
            return NULL;
        }
#endif
    } else if (privkey->type == SSH_KEYTYPE_ED25519) {
        sig = ssh_signature_new();
        if (sig == NULL){
            return NULL;
        }

        sig->type = privkey->type;
        sig->type_c = privkey->type_c;

        rc = pki_ed25519_sign(privkey,
                              sig,
                              crypto->secret_hash,
                              crypto->digest_len);
        if (rc != SSH_OK){
            ssh_signature_free(sig);
            sig = NULL;
        }
    } else {
        unsigned char hash[SHA_DIGEST_LEN] = {0};
        SHACTX ctx;

        ctx = sha1_init();
        if (ctx == NULL) {
            return NULL;
        }
        sha1_update(ctx, crypto->secret_hash, crypto->digest_len);
        sha1_final(hash, ctx);

#ifdef DEBUG_CRYPTO
        ssh_print_hexa("Hash being signed", hash, SHA_DIGEST_LEN);
#endif

        sig = pki_do_sign_sessionid(privkey, hash, SHA_DIGEST_LEN);
        if (sig == NULL) {
            return NULL;
        }
    }

    rc = ssh_pki_export_signature_blob(sig, &sig_blob);
    ssh_signature_free(sig);
    if (rc < 0) {
        return NULL;
    }

    return sig_blob;
}
#endif /* WITH_SERVER */

/**
 * @}
 */
