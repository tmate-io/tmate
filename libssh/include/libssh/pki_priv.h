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

#ifndef PKI_PRIV_H_
#define PKI_PRIV_H_

#define RSA_HEADER_BEGIN "-----BEGIN RSA PRIVATE KEY-----"
#define RSA_HEADER_END "-----END RSA PRIVATE KEY-----"
#define DSA_HEADER_BEGIN "-----BEGIN DSA PRIVATE KEY-----"
#define DSA_HEADER_END "-----END DSA PRIVATE KEY-----"
#define ECDSA_HEADER_BEGIN "-----BEGIN EC PRIVATE KEY-----"
#define ECDSA_HEADER_END "-----END EC PRIVATE KEY-----"

#define ssh_pki_log(...) \
    _ssh_pki_log(__FUNCTION__, __VA_ARGS__)
void _ssh_pki_log(const char *function,
                  const char *format, ...) PRINTF_ATTRIBUTE(2, 3);

int pki_key_ecdsa_nid_from_name(const char *name);
const char *pki_key_ecdsa_nid_to_name(int nid);

/* SSH Key Functions */
ssh_key pki_key_dup(const ssh_key key, int demote);
int pki_key_generate_rsa(ssh_key key, int parameter);
int pki_key_generate_dss(ssh_key key, int parameter);
int pki_key_generate_ecdsa(ssh_key key, int parameter);
int pki_key_generate_ed25519(ssh_key key);

int pki_key_compare(const ssh_key k1,
                    const ssh_key k2,
                    enum ssh_keycmp_e what);

/* SSH Private Key Functions */
enum ssh_keytypes_e pki_privatekey_type_from_string(const char *privkey);
ssh_key pki_private_key_from_base64(const char *b64_key,
                                    const char *passphrase,
                                    ssh_auth_callback auth_fn,
                                    void *auth_data);

ssh_string pki_private_key_to_pem(const ssh_key key,
                                  const char *passphrase,
                                  ssh_auth_callback auth_fn,
                                  void *auth_data);

/* SSH Public Key Functions */
int pki_pubkey_build_dss(ssh_key key,
                         ssh_string p,
                         ssh_string q,
                         ssh_string g,
                         ssh_string pubkey);
int pki_pubkey_build_rsa(ssh_key key,
                         ssh_string e,
                         ssh_string n);
int pki_pubkey_build_ecdsa(ssh_key key, int nid, ssh_string e);
ssh_string pki_publickey_to_blob(const ssh_key key);
int pki_export_pubkey_rsa1(const ssh_key key,
                           const char *host,
                           char *rsa1,
                           size_t rsa1_len);

/* SSH Signature Functions */
ssh_string pki_signature_to_blob(const ssh_signature sign);
ssh_signature pki_signature_from_blob(const ssh_key pubkey,
                                      const ssh_string sig_blob,
                                      enum ssh_keytypes_e type);
int pki_signature_verify(ssh_session session,
                         const ssh_signature sig,
                         const ssh_key key,
                         const unsigned char *hash,
                         size_t hlen);

/* SSH Signing Functions */
ssh_signature pki_do_sign(const ssh_key privkey,
                          const unsigned char *hash,
                          size_t hlen);
ssh_signature pki_do_sign_sessionid(const ssh_key key,
                                    const unsigned char *hash,
                                    size_t hlen);
int pki_ed25519_sign(const ssh_key privkey, ssh_signature sig,
		const unsigned char *hash, size_t hlen);
int pki_ed25519_verify(const ssh_key pubkey, ssh_signature sig,
		const unsigned char *hash, size_t hlen);
int pki_ed25519_key_cmp(const ssh_key k1,
                const ssh_key k2,
                enum ssh_keycmp_e what);
int pki_ed25519_key_dup(ssh_key new, const ssh_key key);
int pki_ed25519_public_key_to_blob(ssh_buffer buffer, ssh_key key);
ssh_string pki_ed25519_sig_to_blob(ssh_signature sig);
int pki_ed25519_sig_from_blob(ssh_signature sig, ssh_string sig_blob);

#endif /* PKI_PRIV_H_ */
