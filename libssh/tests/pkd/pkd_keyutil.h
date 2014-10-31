/*
 * pkd_keyutil.h --
 *
 * (c) 2014 Jon Simons
 */

#ifndef __PKD_KEYUTIL_H__
#define __PKD_KEYUTIL_H__

/* Server keys. */
#define LIBSSH_DSA_TESTKEY        "libssh_testkey.id_dsa"
#define LIBSSH_RSA_TESTKEY        "libssh_testkey.id_rsa"
#define LIBSSH_ECDSA_256_TESTKEY  "libssh_testkey.id_ecdsa256"
#define LIBSSH_ECDSA_384_TESTKEY  "libssh_testkey.id_ecdsa384"
#define LIBSSH_ECDSA_521_TESTKEY  "libssh_testkey.id_ecdsa521"

void setup_dsa_key(void);
void setup_rsa_key(void);
void setup_ecdsa_keys(void);
void cleanup_dsa_key(void);
void cleanup_rsa_key(void);
void cleanup_ecdsa_keys(void);

/* Client keys. */
#define OPENSSH_DSA_TESTKEY       "openssh_testkey.id_dsa"
#define OPENSSH_RSA_TESTKEY       "openssh_testkey.id_rsa"
#define OPENSSH_ECDSA256_TESTKEY  "openssh_testkey.id_ecdsa256"
#define OPENSSH_ECDSA384_TESTKEY  "openssh_testkey.id_ecdsa384"
#define OPENSSH_ECDSA521_TESTKEY  "openssh_testkey.id_ecdsa521"
#define OPENSSH_ED25519_TESTKEY   "openssh_testkey.id_ed25519"

#define DROPBEAR_RSA_TESTKEY      "dropbear_testkey.id_rsa"

void setup_openssh_client_keys(void);
void cleanup_openssh_client_keys(void);

void setup_dropbear_client_rsa_key(void);
void cleanup_dropbear_client_rsa_key(void);

#endif /* __PKD_KEYUTIL_H__ */
