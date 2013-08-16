/*
 * kex.c - key exchange
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
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

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/crypto.h"
#include "libssh/kex.h"
#include "libssh/keys.h"
#include "libssh/session.h"
#include "libssh/ssh1.h"
#include "libssh/wrapper.h"

/* SSHv1 functions */

/* makes a STRING contating 3 strings : ssh-rsa1,e and n */
/* this is a public key in openssh's format */
static ssh_string make_rsa1_string(ssh_string e, ssh_string n){
  ssh_buffer buffer = NULL;
  ssh_string rsa = NULL;
  ssh_string ret = NULL;

  buffer = ssh_buffer_new();
  rsa = ssh_string_from_char("ssh-rsa1");
  if (rsa == NULL) {
      goto error;
  }

  if (buffer_add_ssh_string(buffer, rsa) < 0) {
    goto error;
  }
  if (buffer_add_ssh_string(buffer, e) < 0) {
    goto error;
  }
  if (buffer_add_ssh_string(buffer, n) < 0) {
    goto error;
  }

  ret = ssh_string_new(ssh_buffer_get_len(buffer));
  if (ret == NULL) {
    goto error;
  }

  ssh_string_fill(ret, ssh_buffer_get_begin(buffer), ssh_buffer_get_len(buffer));
error:
  ssh_buffer_free(buffer);
  ssh_string_free(rsa);

  return ret;
}

static int build_session_id1(ssh_session session, ssh_string servern,
    ssh_string hostn) {
  MD5CTX md5 = NULL;

  md5 = md5_init();
  if (md5 == NULL) {
    return -1;
  }

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("host modulus",ssh_string_data(hostn),ssh_string_len(hostn));
  ssh_print_hexa("server modulus",ssh_string_data(servern),ssh_string_len(servern));
#endif
  md5_update(md5,ssh_string_data(hostn),ssh_string_len(hostn));
  md5_update(md5,ssh_string_data(servern),ssh_string_len(servern));
  md5_update(md5,session->next_crypto->server_kex.cookie,8);
  if(session->next_crypto->session_id != NULL)
      SAFE_FREE(session->next_crypto->session_id);
  session->next_crypto->session_id = malloc(MD5_DIGEST_LEN);
  if(session->next_crypto->session_id == NULL){
      ssh_set_error_oom(session);
      return SSH_ERROR;
  }
  md5_final(session->next_crypto->session_id,md5);
#ifdef DEBUG_CRYPTO
  ssh_print_hexa("session_id",session->next_crypto->session_id,MD5_DIGEST_LEN);
#endif

  return 0;
}

/* returns 1 if the modulus of k1 is < than the one of k2 */
static int modulus_smaller(ssh_public_key k1, ssh_public_key k2){
    bignum n1;
    bignum n2;
    int res;
#ifdef HAVE_LIBGCRYPT
    gcry_sexp_t sexp;
    sexp=gcry_sexp_find_token(k1->rsa_pub,"n",0);
    n1=gcry_sexp_nth_mpi(sexp,1,GCRYMPI_FMT_USG);
    gcry_sexp_release(sexp);
    sexp=gcry_sexp_find_token(k2->rsa_pub,"n",0);
    n2=gcry_sexp_nth_mpi(sexp,1,GCRYMPI_FMT_USG);
    gcry_sexp_release(sexp);
#elif defined HAVE_LIBCRYPTO
    n1=k1->rsa_pub->n;
    n2=k2->rsa_pub->n;
#endif
    if(bignum_cmp(n1,n2)<0)
        res=1;
    else
        res=0;
#ifdef HAVE_LIBGCRYPT
    bignum_free(n1);
    bignum_free(n2);
#endif
    return res;
    
}

static ssh_string ssh_encrypt_rsa1(ssh_session session,
                                   ssh_string data,
                                   ssh_public_key key) {
  ssh_string str = NULL;
  size_t len = ssh_string_len(data);
  size_t size = 0;
#ifdef HAVE_LIBGCRYPT
  const char *tmp = NULL;
  gcry_sexp_t ret_sexp;
  gcry_sexp_t data_sexp;

  if (gcry_sexp_build(&data_sexp, NULL, "(data(flags pkcs1)(value %b))",
      len, ssh_string_data(data))) {
    ssh_set_error(session, SSH_FATAL, "RSA1 encrypt: libgcrypt error");
    return NULL;
  }
  if (gcry_pk_encrypt(&ret_sexp, data_sexp, key->rsa_pub)) {
    gcry_sexp_release(data_sexp);
    ssh_set_error(session, SSH_FATAL, "RSA1 encrypt: libgcrypt error");
    return NULL;
  }

  gcry_sexp_release(data_sexp);

  data_sexp = gcry_sexp_find_token(ret_sexp, "a", 0);
  if (data_sexp == NULL) {
    ssh_set_error(session, SSH_FATAL, "RSA1 encrypt: libgcrypt error");
    gcry_sexp_release(ret_sexp);
    return NULL;
  }
  tmp = gcry_sexp_nth_data(data_sexp, 1, &size);
  if (*tmp == 0) {
    size--;
    tmp++;
  }

  str = ssh_string_new(size);
  if (str == NULL) {
    ssh_set_error(session, SSH_FATAL, "Not enough space");
    gcry_sexp_release(data_sexp);
    gcry_sexp_release(ret_sexp);
    return NULL;
  }
  ssh_string_fill(str, tmp, size);

  gcry_sexp_release(data_sexp);
  gcry_sexp_release(ret_sexp);
#elif defined HAVE_LIBCRYPTO
  size = RSA_size(key->rsa_pub);

  str = ssh_string_new(size);
  if (str == NULL) {
    ssh_set_error(session, SSH_FATAL, "Not enough space");
    return NULL;
  }

  if (RSA_public_encrypt(len, ssh_string_data(data), ssh_string_data(str), key->rsa_pub,
      RSA_PKCS1_PADDING) < 0) {
    ssh_string_free(str);
    return NULL;
  }
#endif

  return str;
}

#define ABS(A) ( (A)<0 ? -(A):(A) )
static ssh_string encrypt_session_key(ssh_session session, ssh_public_key srvkey,
    ssh_public_key hostkey, int slen, int hlen) {
  unsigned char buffer[32] = {0};
  int i;
  ssh_string data1 = NULL;
  ssh_string data2 = NULL;
  if(session->next_crypto->encryptkey != NULL)
      SAFE_FREE(session->next_crypto->encryptkey);
  if(session->next_crypto->decryptkey != NULL)
        SAFE_FREE(session->next_crypto->decryptkey);
  if(session->next_crypto->encryptIV != NULL)
          SAFE_FREE(session->next_crypto->encryptIV);
  if(session->next_crypto->decryptIV != NULL)
          SAFE_FREE(session->next_crypto->decryptIV);
  session->next_crypto->encryptkey = malloc(32);
  session->next_crypto->decryptkey = malloc(32);
  session->next_crypto->encryptIV = malloc(32);
  session->next_crypto->decryptIV = malloc(32);
  if(session->next_crypto->encryptkey == NULL ||
          session->next_crypto->decryptkey == NULL ||
          session->next_crypto->encryptIV == NULL ||
          session->next_crypto->decryptIV == NULL){
      ssh_set_error_oom(session);
      return NULL;
  }
  /* first, generate a session key */
  ssh_get_random(session->next_crypto->encryptkey, 32, 1);
  memcpy(buffer, session->next_crypto->encryptkey, 32);
  memcpy(session->next_crypto->decryptkey, session->next_crypto->encryptkey, 32);
  memset(session->next_crypto->encryptIV, 0, 32);
  memset(session->next_crypto->decryptIV, 0, 32);

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("session key",buffer,32);
#endif

  /* xor session key with session_id */
  for (i = 0; i < 16; i++) {
    buffer[i] ^= session->next_crypto->session_id[i];
  }
  data1 = ssh_string_new(32);
  if (data1 == NULL) {
    return NULL;
  }
  ssh_string_fill(data1, buffer, 32);
  if (ABS(hlen - slen) < 128){
    SSH_LOG(SSH_LOG_FUNCTIONS,
        "Difference between server modulus and host modulus is only %d. "
        "It's illegal and may not work",
        ABS(hlen - slen));
  }

  if (modulus_smaller(srvkey, hostkey)) {
    data2 = ssh_encrypt_rsa1(session, data1, srvkey);
    ssh_string_free(data1);
    data1 = NULL;
    if (data2 == NULL) {
      return NULL;
    }
    data1 = ssh_encrypt_rsa1(session, data2, hostkey);
    ssh_string_free(data2);
    if (data1 == NULL) {
      return NULL;
    }
  } else {
    data2 = ssh_encrypt_rsa1(session, data1, hostkey);
    ssh_string_free(data1);
    data1 = NULL;
    if (data2 == NULL) {
      return NULL;
    }
    data1 = ssh_encrypt_rsa1(session, data2, srvkey);
    ssh_string_free(data2);
    if (data1 == NULL) {
      return NULL;
    }
  }

  return data1;
}

/*    2 SSH_SMSG_PUBLIC_KEY
 *
 *    8 bytes      anti_spoofing_cookie
 *    32-bit int   server_key_bits
 *    mp-int       server_key_public_exponent
 *    mp-int       server_key_public_modulus
 *    32-bit int   host_key_bits
 *    mp-int       host_key_public_exponent
 *    mp-int       host_key_public_modulus
 *    32-bit int   protocol_flags
 *    32-bit int   supported_ciphers_mask
 *    32-bit int   supported_authentications_mask
 */
/**
 * @brief Wait for a SSH_SMSG_PUBLIC_KEY and does the key exchange
 */
SSH_PACKET_CALLBACK(ssh_packet_publickey1){
  ssh_string server_exp = NULL;
  ssh_string server_mod = NULL;
  ssh_string host_exp = NULL;
  ssh_string host_mod = NULL;
  ssh_string serverkey = NULL;
  ssh_string hostkey = NULL;
  ssh_public_key srv = NULL;
  ssh_public_key host = NULL;
  uint32_t server_bits;
  uint32_t host_bits;
  uint32_t protocol_flags;
  uint32_t supported_ciphers_mask;
  uint32_t supported_authentications_mask;
  ssh_string enc_session = NULL;
  uint16_t bits;
  int ko;
  uint32_t support_3DES = 0;
  uint32_t support_DES = 0;

  (void)type;
  (void)user;
  SSH_LOG(SSH_LOG_PROTOCOL, "Got a SSH_SMSG_PUBLIC_KEY");
  if(session->session_state != SSH_SESSION_STATE_INITIAL_KEX){
    ssh_set_error(session,SSH_FATAL,"SSH_KEXINIT received in wrong state");
    goto error;
  }
  if (buffer_get_data(packet, session->next_crypto->server_kex.cookie, 8) != 8) {
    ssh_set_error(session, SSH_FATAL, "Can't get cookie in buffer");
    goto error;
  }

  buffer_get_u32(packet, &server_bits);
  server_exp = buffer_get_mpint(packet);
  if (server_exp == NULL) {
    goto error;
  }
  server_mod = buffer_get_mpint(packet);
  if (server_mod == NULL) {
    goto error;
  }
  buffer_get_u32(packet, &host_bits);
  host_exp = buffer_get_mpint(packet);
  if (host_exp == NULL) {
    goto error;
  }
  host_mod = buffer_get_mpint(packet);
  if (host_mod == NULL) {
    goto error;
  }
  buffer_get_u32(packet, &protocol_flags);
  buffer_get_u32(packet, &supported_ciphers_mask);
  ko = buffer_get_u32(packet, &supported_authentications_mask);

  if ((ko != sizeof(uint32_t)) || !host_mod || !host_exp
      || !server_mod || !server_exp) {
    SSH_LOG(SSH_LOG_RARE, "Invalid SSH_SMSG_PUBLIC_KEY packet");
    ssh_set_error(session, SSH_FATAL, "Invalid SSH_SMSG_PUBLIC_KEY packet");
    goto error;
  }

  server_bits = ntohl(server_bits);
  host_bits = ntohl(host_bits);
  protocol_flags = ntohl(protocol_flags);
  supported_ciphers_mask = ntohl(supported_ciphers_mask);
  supported_authentications_mask = ntohl(supported_authentications_mask);
  SSH_LOG(SSH_LOG_PROTOCOL,
      "Server bits: %d; Host bits: %d; Protocol flags: %.8lx; "
      "Cipher mask: %.8lx; Auth mask: %.8lx",
      server_bits,
      host_bits,
      (unsigned long int) protocol_flags,
      (unsigned long int) supported_ciphers_mask,
      (unsigned long int) supported_authentications_mask);

  serverkey = make_rsa1_string(server_exp, server_mod);
  if (serverkey == NULL) {
    goto error;
  }
  hostkey = make_rsa1_string(host_exp,host_mod);
  if (hostkey == NULL) {
    goto error;
  }
  if (build_session_id1(session, server_mod, host_mod) < 0) {
    goto error;
  }

  srv = publickey_from_string(session, serverkey);
  if (srv == NULL) {
    goto error;
  }
  host = publickey_from_string(session, hostkey);
  if (host == NULL) {
    goto error;
  }

  session->next_crypto->server_pubkey = ssh_string_copy(hostkey);
  if (session->next_crypto->server_pubkey == NULL) {
    goto error;
  }
  session->next_crypto->server_pubkey_type = "ssh-rsa1";

  /* now, we must choose an encryption algo */
  /* hardcode 3des */
  //
  support_3DES = (supported_ciphers_mask & (1<<SSH_CIPHER_3DES));
  support_DES  = (supported_ciphers_mask & (1<<SSH_CIPHER_DES));
  if(!support_3DES && !support_DES){
    ssh_set_error(session, SSH_FATAL, "Remote server doesn't accept 3DES");
    goto error;
  }
  SSH_LOG(SSH_LOG_PROTOCOL, "Sending SSH_CMSG_SESSION_KEY");

   if (buffer_add_u8(session->out_buffer, SSH_CMSG_SESSION_KEY) < 0) {
     goto error;
   }
   if (buffer_add_u8(session->out_buffer, support_3DES ? SSH_CIPHER_3DES : SSH_CIPHER_DES) < 0) {
     goto error;
   }
   if (buffer_add_data(session->out_buffer, session->next_crypto->server_kex.cookie, 8) < 0) {
     goto error;
   }

   enc_session = encrypt_session_key(session, srv, host, server_bits, host_bits);
   if (enc_session == NULL) {
     goto error;
   }

   bits = ssh_string_len(enc_session) * 8 - 7;
   SSH_LOG(SSH_LOG_PROTOCOL, "%d bits, %" PRIdS " bytes encrypted session",
       bits, ssh_string_len(enc_session));
   bits = htons(bits);
   /* the encrypted mpint */
   if (buffer_add_data(session->out_buffer, &bits, sizeof(uint16_t)) < 0) {
     goto error;
   }
   if (buffer_add_data(session->out_buffer, ssh_string_data(enc_session),
         ssh_string_len(enc_session)) < 0) {
     goto error;
   }
   /* the protocol flags */
   if (buffer_add_u32(session->out_buffer, 0) < 0) {
     goto error;
   }
   session->session_state=SSH_SESSION_STATE_KEXINIT_RECEIVED;
   if (packet_send(session) == SSH_ERROR) {
     goto error;
   }

   /* we can set encryption */
   if(crypt_set_algorithms(session, support_3DES ? SSH_3DES : SSH_DES)){
      goto error;
   }

   session->current_crypto = session->next_crypto;
   session->next_crypto = NULL;
   goto end;
error:
  session->session_state=SSH_SESSION_STATE_ERROR;
end:

   ssh_string_free(host_mod);
   ssh_string_free(host_exp);
   ssh_string_free(server_mod);
   ssh_string_free(server_exp);
   ssh_string_free(serverkey);
   ssh_string_free(hostkey);
   ssh_string_free(enc_session);

   publickey_free(srv);
   publickey_free(host);

   return SSH_PACKET_USED;
}

int ssh_get_kex1(ssh_session session) {
  SSH_LOG(SSH_LOG_PROTOCOL, "Waiting for a SSH_SMSG_PUBLIC_KEY");

  /* Here the callback is called */
  while(session->session_state==SSH_SESSION_STATE_INITIAL_KEX){
    ssh_handle_packets(session, SSH_TIMEOUT_USER);
  }
  if (session->session_state==SSH_SESSION_STATE_ERROR) {
      return SSH_ERROR;
  }
  SSH_LOG(SSH_LOG_PROTOCOL, "Waiting for a SSH_SMSG_SUCCESS");
  /* Waiting for SSH_SMSG_SUCCESS */
  while(session->session_state==SSH_SESSION_STATE_KEXINIT_RECEIVED){
    ssh_handle_packets(session, SSH_TIMEOUT_USER);
  }
  if(session->session_state==SSH_SESSION_STATE_ERROR) {
      return SSH_ERROR;
  }
  SSH_LOG(SSH_LOG_PROTOCOL, "received SSH_SMSG_SUCCESS\n");

  return SSH_OK;
}
