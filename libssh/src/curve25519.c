/*
 * curve25519.c - Curve25519 ECDH functions for key exchange
 * curve25519-sha256@libssh.org
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2013      by Aris Adamantiadis <aris@badcode.be>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, version 2.1 of the License.
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

#include "libssh/curve25519.h"
#ifdef HAVE_CURVE25519

#ifdef WITH_NACL
#include "nacl/crypto_scalarmult_curve25519.h"
#endif

#include "libssh/ssh2.h"
#include "libssh/buffer.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/crypto.h"
#include "libssh/dh.h"
#include "libssh/pki.h"
#include "libssh/bignum.h"

/** @internal
 * @brief Starts curve25519-sha256@libssh.org key exchange
 */
int ssh_client_curve25519_init(ssh_session session){
  int rc;

  rc = ssh_get_random(session->next_crypto->curve25519_privkey, CURVE25519_PRIVKEY_SIZE, 1);
  if (rc == 0){
	  ssh_set_error(session, SSH_FATAL, "PRNG error");
	  return SSH_ERROR;
  }

  crypto_scalarmult_base(session->next_crypto->curve25519_client_pubkey,
		  session->next_crypto->curve25519_privkey);

  rc = ssh_buffer_pack(session->out_buffer,
                       "bdP",
                       SSH2_MSG_KEX_ECDH_INIT,
                       CURVE25519_PUBKEY_SIZE,
                       (size_t)CURVE25519_PUBKEY_SIZE, session->next_crypto->curve25519_client_pubkey);
  if (rc != SSH_OK) {
      ssh_set_error_oom(session);
      return SSH_ERROR;
  }

  rc = packet_send(session);

  return rc;
}

static int ssh_curve25519_build_k(ssh_session session) {
  ssh_curve25519_pubkey k;
  session->next_crypto->k = bignum_new();

  if (session->next_crypto->k == NULL) {
    return SSH_ERROR;
  }

  if (session->server)
	  crypto_scalarmult(k, session->next_crypto->curve25519_privkey,
			  session->next_crypto->curve25519_client_pubkey);
  else
	  crypto_scalarmult(k, session->next_crypto->curve25519_privkey,
			  session->next_crypto->curve25519_server_pubkey);

  bignum_bin2bn(k, CURVE25519_PUBKEY_SIZE, session->next_crypto->k);

#ifdef DEBUG_CRYPTO
    ssh_print_hexa("Session server cookie",
                   session->next_crypto->server_kex.cookie, 16);
    ssh_print_hexa("Session client cookie",
                   session->next_crypto->client_kex.cookie, 16);
    ssh_print_bignum("Shared secret key", session->next_crypto->k);
#endif

  return 0;
}

/** @internal
 * @brief parses a SSH_MSG_KEX_ECDH_REPLY packet and sends back
 * a SSH_MSG_NEWKEYS
 */
int ssh_client_curve25519_reply(ssh_session session, ssh_buffer packet){
  ssh_string q_s_string = NULL;
  ssh_string pubkey = NULL;
  ssh_string signature = NULL;
  int rc;
  pubkey = buffer_get_ssh_string(packet);
  if (pubkey == NULL){
    ssh_set_error(session,SSH_FATAL, "No public key in packet");
    goto error;
  }
  /* this is the server host key */
  session->next_crypto->server_pubkey = pubkey;
  pubkey = NULL;

  q_s_string = buffer_get_ssh_string(packet);
  if (q_s_string == NULL) {
	  ssh_set_error(session,SSH_FATAL, "No Q_S ECC point in packet");
	  goto error;
  }
  if (ssh_string_len(q_s_string) != CURVE25519_PUBKEY_SIZE){
	  ssh_set_error(session, SSH_FATAL, "Incorrect size for server Curve25519 public key: %d",
			  (int)ssh_string_len(q_s_string));
	  ssh_string_free(q_s_string);
	  goto error;
  }
  memcpy(session->next_crypto->curve25519_server_pubkey, ssh_string_data(q_s_string), CURVE25519_PUBKEY_SIZE);
  ssh_string_free(q_s_string);

  signature = buffer_get_ssh_string(packet);
  if (signature == NULL) {
    ssh_set_error(session, SSH_FATAL, "No signature in packet");
    goto error;
  }
  session->next_crypto->dh_server_signature = signature;
  signature=NULL; /* ownership changed */
  /* TODO: verify signature now instead of waiting for NEWKEYS */
  if (ssh_curve25519_build_k(session) < 0) {
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

#ifdef WITH_SERVER

/** @brief Parse a SSH_MSG_KEXDH_INIT packet (server) and send a
 * SSH_MSG_KEXDH_REPLY
 */
int ssh_server_curve25519_init(ssh_session session, ssh_buffer packet){
    /* ECDH keys */
    ssh_string q_c_string;
    ssh_string q_s_string;

    /* SSH host keys (rsa,dsa,ecdsa) */
    ssh_key privkey;
    ssh_string sig_blob = NULL;
    int rc;

    /* Extract the client pubkey from the init packet */
    q_c_string = buffer_get_ssh_string(packet);
    if (q_c_string == NULL) {
        ssh_set_error(session,SSH_FATAL, "No Q_C ECC point in packet");
        return SSH_ERROR;
    }
    if (ssh_string_len(q_c_string) != CURVE25519_PUBKEY_SIZE){
    	ssh_set_error(session, SSH_FATAL, "Incorrect size for server Curve25519 public key: %d",
    			(int)ssh_string_len(q_c_string));
    	ssh_string_free(q_c_string);
    	return SSH_ERROR;
    }

    memcpy(session->next_crypto->curve25519_client_pubkey,
    		ssh_string_data(q_c_string), CURVE25519_PUBKEY_SIZE);
    ssh_string_free(q_c_string);
    /* Build server's keypair */

    rc = ssh_get_random(session->next_crypto->curve25519_privkey, CURVE25519_PRIVKEY_SIZE, 1);
    if (rc == 0){
        ssh_set_error(session, SSH_FATAL, "PRNG error");
        return SSH_ERROR;
    }

    crypto_scalarmult_base(session->next_crypto->curve25519_server_pubkey,
  		  session->next_crypto->curve25519_privkey);

    rc = buffer_add_u8(session->out_buffer, SSH2_MSG_KEX_ECDH_REPLY);
    if (rc < 0) {
        ssh_set_error_oom(session);
        goto error;
    }

    /* build k and session_id */
    rc = ssh_curve25519_build_k(session);
    if (rc < 0) {
        ssh_set_error(session, SSH_FATAL, "Cannot build k number");
        goto error;
    }

    /* privkey is not allocated */
    rc = ssh_get_key_params(session, &privkey);
    if (rc == SSH_ERROR) {
        goto error;
    }

    rc = make_sessionid(session);
    if (rc != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not create a session id");
        goto error;
    }

    /* add host's public key */
    rc = buffer_add_ssh_string(session->out_buffer,
                               session->next_crypto->server_pubkey);
    if (rc < 0) {
        ssh_set_error_oom(session);
        goto error;
    }

    /* add ecdh public key */
    q_s_string = ssh_string_new(CURVE25519_PUBKEY_SIZE);
    if (q_s_string == NULL) {
        goto error;
    }

    ssh_string_fill(q_s_string,
                    session->next_crypto->curve25519_server_pubkey,
                    CURVE25519_PUBKEY_SIZE);

    rc = buffer_add_ssh_string(session->out_buffer, q_s_string);
    ssh_string_free(q_s_string);
    if (rc < 0) {
        ssh_set_error_oom(session);
        goto error;
    }
    /* add signature blob */
    sig_blob = ssh_srv_pki_do_sign_sessionid(session, privkey);
    if (sig_blob == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not sign the session id");
        goto error;
    }

    rc = buffer_add_ssh_string(session->out_buffer, sig_blob);
    ssh_string_free(sig_blob);
    if (rc < 0) {
        ssh_set_error_oom(session);
        goto error;
    }

    SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_KEX_ECDH_REPLY sent");
    rc = packet_send(session);
    if (rc == SSH_ERROR) {
        return SSH_ERROR;
    }

    /* Send the MSG_NEWKEYS */
    rc = buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS);
    if (rc < 0) {
        goto error;
    }

    session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;
    rc = packet_send(session);
    SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_NEWKEYS sent");

    return rc;
error:
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}

#endif /* WITH_SERVER */

#endif /* HAVE_CURVE25519 */
