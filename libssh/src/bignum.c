/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2014 by Aris Adamantiadis <aris@badcode.be>
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

#include <stdio.h>

#include "libssh/priv.h"
#include "libssh/bignum.h"
#include "libssh/string.h"

ssh_string make_bignum_string(bignum num) {
  ssh_string ptr = NULL;
  int pad = 0;
  unsigned int len = bignum_num_bytes(num);
  unsigned int bits = bignum_num_bits(num);

  if (len == 0) {
      return NULL;
  }

  /* If the first bit is set we have a negative number */
  if (!(bits % 8) && bignum_is_bit_set(num, bits - 1)) {
    pad++;
  }

#ifdef DEBUG_CRYPTO
  fprintf(stderr, "%d bits, %d bytes, %d padding\n", bits, len, pad);
#endif /* DEBUG_CRYPTO */

  ptr = ssh_string_new(len + pad);
  if (ptr == NULL) {
    return NULL;
  }

  /* We have a negative number so we need a leading zero */
  if (pad) {
    ptr->data[0] = 0;
  }

#ifdef HAVE_LIBGCRYPT
  bignum_bn2bin(num, len, ptr->data + pad);
#elif HAVE_LIBCRYPTO
  bignum_bn2bin(num, ptr->data + pad);
#endif

  return ptr;
}

bignum make_string_bn(ssh_string string){
  bignum bn = NULL;
  unsigned int len = ssh_string_len(string);

#ifdef DEBUG_CRYPTO
  fprintf(stderr, "Importing a %d bits, %d bytes object ...\n",
      len * 8, len);
#endif /* DEBUG_CRYPTO */

#ifdef HAVE_LIBGCRYPT
  bignum_bin2bn(string->data, len, &bn);
#elif defined HAVE_LIBCRYPTO
  bn = bignum_bin2bn(string->data, len, NULL);
#endif

  return bn;
}

/* prints the bignum on stderr */
void ssh_print_bignum(const char *which, bignum num) {
#ifdef HAVE_LIBGCRYPT
  unsigned char *hex = NULL;
  bignum_bn2hex(num, &hex);
#elif defined HAVE_LIBCRYPTO
  char *hex = NULL;
  hex = bignum_bn2hex(num);
#endif
  fprintf(stderr, "%s value: ", which);
  fprintf(stderr, "%s\n", (hex == NULL) ? "(null)" : (char *) hex);
  SAFE_FREE(hex);
}
