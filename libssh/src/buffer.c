/*
 * buffer.c - buffer functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
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

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/misc.h"
#include "libssh/bignum.h"

/**
 * @defgroup libssh_buffer The SSH buffer functions.
 * @ingroup libssh
 *
 * Functions to handle SSH buffers.
 *
 * @{
 */


#ifdef DEBUG_BUFFER
/**
 * @internal
 *
 * @brief Check that preconditions and postconditions are valid.
 *
 * @param[in]  buf      The buffer to check.
 */
static void buffer_verify(ssh_buffer buf){
  int doabort=0;
  if(buf->data == NULL)
    return;
  if(buf->used > buf->allocated){
    fprintf(stderr,"Buffer error : allocated %u, used %u\n",buf->allocated, buf->used);
    doabort=1;
  }
  if(buf->pos > buf->used){
    fprintf(stderr,"Buffer error : position %u, used %u\n",buf->pos, buf->used);
    doabort=1;
  }
  if(buf->pos > buf->allocated){
      fprintf(stderr,"Buffer error : position %u, allocated %u\n",buf->pos, buf->allocated);
      doabort=1;
  }
  if(doabort)
    abort();
}

#else
#define buffer_verify(x)
#endif

/**
 * @brief Create a new SSH buffer.
 *
 * @return A newly initialized SSH buffer, NULL on error.
 */
struct ssh_buffer_struct *ssh_buffer_new(void) {
  struct ssh_buffer_struct *buf = malloc(sizeof(struct ssh_buffer_struct));

  if (buf == NULL) {
    return NULL;
  }
  memset(buf, 0, sizeof(struct ssh_buffer_struct));
  buffer_verify(buf);
  return buf;
}

/**
 * @brief Deallocate a SSH buffer.
 *
 * \param[in]  buffer   The buffer to free.
 */
void ssh_buffer_free(struct ssh_buffer_struct *buffer) {
  if (buffer == NULL) {
    return;
  }
  buffer_verify(buffer);

  if (buffer->data) {
    /* burn the data */
    BURN_BUFFER(buffer->data, buffer->allocated);
    SAFE_FREE(buffer->data);
  }
  BURN_BUFFER(buffer, sizeof(struct ssh_buffer_struct));
  SAFE_FREE(buffer);
}

/**
 * @brief Sets the buffer as secure.
 *
 * A secure buffer will never leave cleartext data in the heap
 * after being reallocated or freed.
 *
 * @param[in] buffer buffer to set secure.
 */
void ssh_buffer_set_secure(ssh_buffer buffer){
	buffer->secure = 1;
}

static int realloc_buffer(struct ssh_buffer_struct *buffer, size_t needed) {
  size_t smallest = 1;
  char *new;

  buffer_verify(buffer);

  /* Find the smallest power of two which is greater or equal to needed */
  while(smallest <= needed) {
      if (smallest == 0) {
          return -1;
      }
      smallest <<= 1;
  }
  needed = smallest;
  if (buffer->secure){
	  new = malloc(needed);
	  if (new == NULL) {
		  return -1;
      }
	  memcpy(new, buffer->data,buffer->used);
	  BURN_BUFFER(buffer->data, buffer->used);
	  SAFE_FREE(buffer->data);
  } else {
	  new = realloc(buffer->data, needed);
	  if (new == NULL) {
		  buffer->data = NULL;
		  return -1;
	  }
  }
  buffer->data = new;
  buffer->allocated = needed;
  buffer_verify(buffer);
  return 0;
}

/** @internal
 * @brief shifts a buffer to remove unused data in the beginning
 * @param buffer SSH buffer
 */
static void buffer_shift(ssh_buffer buffer){
  uint32_t burn_pos = buffer->pos;

  buffer_verify(buffer);
  if(buffer->pos==0)
    return;
  memmove(buffer->data, buffer->data + buffer->pos, buffer->used - buffer->pos);
  buffer->used -= buffer->pos;
  buffer->pos=0;

  if (buffer->secure){
	  void *ptr = buffer->data + buffer->used;
	  BURN_BUFFER(ptr, burn_pos);
  }

  buffer_verify(buffer);
}

/**
 * @internal
 *
 * @brief Reinitialize a SSH buffer.
 *
 * @param[in]  buffer   The buffer to reinitialize.
 *
 * @return              0 on success, < 0 on error.
 */
int ssh_buffer_reinit(struct ssh_buffer_struct *buffer)
{
  buffer_verify(buffer);
  BURN_BUFFER(buffer->data, buffer->used);
  buffer->used = 0;
  buffer->pos = 0;
  if(buffer->allocated > 127) {
    if (realloc_buffer(buffer, 127) < 0) {
      return -1;
    }
  }
  buffer_verify(buffer);
  return 0;
}

/**
 * @internal
 *
 * @brief Add data at the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the data.
 *
 * @param[in]  data     A pointer to the data to add.
 *
 * @param[in]  len      The length of the data to add.
 *
 * @return              0 on success, < 0 on error.
 */
int ssh_buffer_add_data(struct ssh_buffer_struct *buffer, const void *data, uint32_t len)
{
  buffer_verify(buffer);

  if (buffer->used + len < len) {
    return -1;
  }

  if (buffer->allocated < (buffer->used + len)) {
    if(buffer->pos > 0)
      buffer_shift(buffer);
    if (realloc_buffer(buffer, buffer->used + len) < 0) {
      return -1;
    }
  }

  memcpy(buffer->data+buffer->used, data, len);
  buffer->used+=len;
  buffer_verify(buffer);
  return 0;
}

/**
 * @internal
 *
 * @brief Add a SSH string to the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the string.
 *
 * @param[in]  string   The SSH String to add.
 *
 * @return              0 on success, < 0 on error.
 */
int buffer_add_ssh_string(struct ssh_buffer_struct *buffer,
    struct ssh_string_struct *string) {
  uint32_t len = 0;

  len = ssh_string_len(string);
  if (ssh_buffer_add_data(buffer, string, len + sizeof(uint32_t)) < 0) {
    return -1;
  }

  return 0;
}

/**
 * @internal
 *
 * @brief Add a 32 bits unsigned integer to the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the integer.
 *
 * @param[in]  data     The 32 bits integer to add.
 *
 * @return              0 on success, -1 on error.
 */
int buffer_add_u32(struct ssh_buffer_struct *buffer,uint32_t data)
{
    int rc;

    rc = ssh_buffer_add_data(buffer, &data, sizeof(data));
    if (rc < 0) {
        return -1;
    }

    return 0;
}

/**
 * @internal
 *
 * @brief Add a 16 bits unsigned integer to the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the integer.
 *
 * @param[in]  data     The 16 bits integer to add.
 *
 * @return              0 on success, -1 on error.
 */
int buffer_add_u16(struct ssh_buffer_struct *buffer,uint16_t data)
{
    int rc;

    rc = ssh_buffer_add_data(buffer, &data, sizeof(data));
    if (rc < 0) {
        return -1;
    }

    return 0;
}

/**
 * @internal
 *
 * @brief Add a 64 bits unsigned integer to the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the integer.
 *
 * @param[in]  data     The 64 bits integer to add.
 *
 * @return              0 on success, -1 on error.
 */
int buffer_add_u64(struct ssh_buffer_struct *buffer, uint64_t data)
{
    int rc;

    rc = ssh_buffer_add_data(buffer, &data, sizeof(data));
    if (rc < 0) {
        return -1;
    }

    return 0;
}

/**
 * @internal
 *
 * @brief Add a 8 bits unsigned integer to the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the integer.
 *
 * @param[in]  data     The 8 bits integer to add.
 *
 * @return              0 on success, -1 on error.
 */
int buffer_add_u8(struct ssh_buffer_struct *buffer,uint8_t data)
{
    int rc;

    rc = ssh_buffer_add_data(buffer, &data, sizeof(uint8_t));
    if (rc < 0) {
        return -1;
    }

    return 0;
}

/**
 * @internal
 *
 * @brief Add data at the head of a buffer.
 *
 * @param[in]  buffer   The buffer to add the data.
 *
 * @param[in]  data     The data to prepend.
 *
 * @param[in]  len      The length of data to prepend.
 *
 * @return              0 on success, -1 on error.
 */
int buffer_prepend_data(struct ssh_buffer_struct *buffer, const void *data,
    uint32_t len) {
  buffer_verify(buffer);

  if(len <= buffer->pos){
    /* It's possible to insert data between begin and pos */
    memcpy(buffer->data + (buffer->pos - len), data, len);
    buffer->pos -= len;
    buffer_verify(buffer);
    return 0;
  }
  /* pos isn't high enough */
  if (buffer->used - buffer->pos + len < len) {
    return -1;
  }

  if (buffer->allocated < (buffer->used - buffer->pos + len)) {
    if (realloc_buffer(buffer, buffer->used - buffer->pos + len) < 0) {
      return -1;
    }
  }
  memmove(buffer->data + len, buffer->data + buffer->pos, buffer->used - buffer->pos);
  memcpy(buffer->data, data, len);
  buffer->used += len - buffer->pos;
  buffer->pos = 0;
  buffer_verify(buffer);
  return 0;
}

/**
 * @internal
 *
 * @brief Append data from a buffer to the tail of another buffer.
 *
 * @param[in]  buffer   The destination buffer.
 *
 * @param[in]  source   The source buffer to append. It doesn't take the
 *                      position of the buffer into account.
 *
 * @return              0 on success, -1 on error.
 */
int buffer_add_buffer(struct ssh_buffer_struct *buffer,
    struct ssh_buffer_struct *source)
{
    int rc;

    rc = ssh_buffer_add_data(buffer,
                             buffer_get_rest(source),
                             buffer_get_rest_len(source));
    if (rc < 0) {
        return -1;
    }

    return 0;
}

/**
 * @brief Get a pointer on the head of a buffer.
 *
 * @param[in]  buffer   The buffer to get the head pointer.
 *
 * @return              A data pointer on the head. It doesn't take the position
 *                      into account.
 *
 * @warning Don't expect data to be nul-terminated.
 *
 * @see buffer_get_rest()
 * @see buffer_get_len()
 */
void *ssh_buffer_get_begin(struct ssh_buffer_struct *buffer){
  return buffer->data;
}

/**
 * @internal
 *
 * @brief Get a pointer to the head of a buffer at the current position.
 *
 * @param[in]  buffer   The buffer to get the head pointer.
 *
 * @return              A pointer to the data from current position.
 *
 * @see buffer_get_rest_len()
 * @see buffer_get()
 */
void *buffer_get_rest(struct ssh_buffer_struct *buffer){
    return buffer->data + buffer->pos;
}

/**
 * @brief Get the length of the buffer, not counting position.
 *
 * @param[in]  buffer   The buffer to get the length from.
 *
 * @return              The length of the buffer.
 *
 * @see buffer_get()
 */
uint32_t ssh_buffer_get_len(struct ssh_buffer_struct *buffer){
    return buffer->used;
}

/**
 * @internal
 *
 * @brief Get the length of the buffer from the current position.
 *
 * @param[in]  buffer   The buffer to get the length from.
 *
 * @return              The length of the buffer.
 *
 * @see buffer_get_rest()
 */
uint32_t buffer_get_rest_len(struct ssh_buffer_struct *buffer){
  buffer_verify(buffer);
  return buffer->used - buffer->pos;
}

/**
 * @internal
 *
 * @brief Advance the position in the buffer.
 *
 * This has effect to "eat" bytes at head of the buffer.
 *
 * @param[in]  buffer   The buffer to advance the position.
 *
 * @param[in]  len      The number of bytes to eat.
 *
 * @return              The new size of the buffer.
 */
uint32_t buffer_pass_bytes(struct ssh_buffer_struct *buffer, uint32_t len){
    buffer_verify(buffer);

    if (buffer->pos + len < len || buffer->used < buffer->pos + len) {
        return 0;
    }

    buffer->pos+=len;
    /* if the buffer is empty after having passed the whole bytes into it, we can clean it */
    if(buffer->pos==buffer->used){
        buffer->pos=0;
        buffer->used=0;
    }
    buffer_verify(buffer);
    return len;
}

/**
 * @internal
 *
 * @brief Cut the end of the buffer.
 *
 * @param[in]  buffer   The buffer to cut.
 *
 * @param[in]  len      The number of bytes to remove from the tail.
 *
 * @return              The new size of the buffer.
 */
uint32_t buffer_pass_bytes_end(struct ssh_buffer_struct *buffer, uint32_t len){
  buffer_verify(buffer);

  if (buffer->used < len) {
      return 0;
  }

  buffer->used-=len;
  buffer_verify(buffer);
  return len;
}

/**
 * @internal
 *
 * @brief Get the remaining data out of the buffer and adjust the read pointer.
 *
 * @param[in]  buffer   The buffer to read.
 *
 * @param[in]  data     The data buffer where to store the data.
 *
 * @param[in]  len      The length to read from the buffer.
 *
 * @returns             0 if there is not enough data in buffer, len otherwise.
 */
uint32_t buffer_get_data(struct ssh_buffer_struct *buffer, void *data, uint32_t len){
    /*
     * Check for a integer overflow first, then check if not enough data is in
     * the buffer.
     */
    if (buffer->pos + len < len || buffer->pos + len > buffer->used) {
      return 0;
    }
    memcpy(data,buffer->data+buffer->pos,len);
    buffer->pos+=len;
    return len;   /* no yet support for partial reads (is it really needed ?? ) */
}

/**
 * @internal
 *
 * @brief Get a 8 bits unsigned int out of the buffer and adjusts the read
 * pointer.
 *
 * @param[in]  buffer   The buffer to read.
 *
 * @param[in]   data    A pointer to a uint8_t where to store the data.
 *
 * @returns             0 if there is not enough data in buffer, 1 otherwise.
 */
int buffer_get_u8(struct ssh_buffer_struct *buffer, uint8_t *data){
    return buffer_get_data(buffer,data,sizeof(uint8_t));
}

/** \internal
 * \brief gets a 32 bits unsigned int out of the buffer. Adjusts the read pointer.
 * \param buffer Buffer to read
 * \param data pointer to a uint32_t where to store the data
 * \returns 0 if there is not enough data in buffer
 * \returns 4 otherwise.
 */
int buffer_get_u32(struct ssh_buffer_struct *buffer, uint32_t *data){
    return buffer_get_data(buffer,data,sizeof(uint32_t));
}
/**
 * @internal
 *
 * @brief Get a 64 bits unsigned int out of the buffer and adjusts the read
 * pointer.
 *
 * @param[in]  buffer   The buffer to read.
 *
 * @param[in]  data     A pointer to a uint64_t where to store the data.
 *
 * @returns             0 if there is not enough data in buffer, 8 otherwise.
 */
int buffer_get_u64(struct ssh_buffer_struct *buffer, uint64_t *data){
    return buffer_get_data(buffer,data,sizeof(uint64_t));
}

/**
 * @internal
 *
 * @brief Get a SSH String out of the buffer and adjusts the read pointer.
 *
 * @param[in]  buffer   The buffer to read.
 *
 * @returns             The SSH String, NULL on error.
 */
struct ssh_string_struct *buffer_get_ssh_string(struct ssh_buffer_struct *buffer) {
  uint32_t stringlen;
  uint32_t hostlen;
  struct ssh_string_struct *str = NULL;

  if (buffer_get_u32(buffer, &stringlen) == 0) {
    return NULL;
  }
  hostlen = ntohl(stringlen);
  /* verify if there is enough space in buffer to get it */
  if (buffer->pos + hostlen < hostlen || buffer->pos + hostlen > buffer->used) {
    return NULL; /* it is indeed */
  }
  str = ssh_string_new(hostlen);
  if (str == NULL) {
    return NULL;
  }
  if (buffer_get_data(buffer, ssh_string_data(str), hostlen) != hostlen) {
    /* should never happen */
    SAFE_FREE(str);
    return NULL;
  }

  return str;
}

/**
 * @internal
 *
 * @brief Get a mpint out of the buffer and adjusts the read pointer.
 *
 * @note This function is SSH-1 only.
 *
 * @param[in]  buffer   The buffer to read.
 *
 * @returns             The SSH String containing the mpint, NULL on error.
 */
struct ssh_string_struct *buffer_get_mpint(struct ssh_buffer_struct *buffer) {
  uint16_t bits;
  uint32_t len;
  struct ssh_string_struct *str = NULL;

  if (buffer_get_data(buffer, &bits, sizeof(uint16_t)) != sizeof(uint16_t)) {
    return NULL;
  }
  bits = ntohs(bits);
  len = (bits + 7) / 8;
  if (buffer->pos + len < len || buffer->pos + len > buffer->used) {
    return NULL;
  }
  str = ssh_string_new(len);
  if (str == NULL) {
    return NULL;
  }
  if (buffer_get_data(buffer, ssh_string_data(str), len) != len) {
    SAFE_FREE(str);
    return NULL;
  }
  return str;
}

/** @internal
 * @brief Add multiple values in a buffer on a single function call
 * @param[in] buffer    The buffer to add to
 * @param[in] format    A format string of arguments.
 * @param[in] ap        A va_list of arguments.
 * @returns             SSH_OK on success
 *                      SSH_ERROR on error
 * @see ssh_buffer_add_format() for format list values.
 */
int ssh_buffer_pack_va(struct ssh_buffer_struct *buffer, const char *format, va_list ap){
    int rc = SSH_ERROR;
    const char *p;
    union {
        uint8_t byte;
        uint16_t word;
        uint32_t dword;
        uint64_t qword;
        ssh_string string;
        void *data;
    } o;
    char *cstring;
    bignum b;
    size_t len;

    for (p = format; *p != '\0'; p++) {
        switch(*p) {
        case 'b':
            o.byte = (uint8_t)va_arg(ap, unsigned int);
            rc = buffer_add_u8(buffer, o.byte);
            break;
        case 'w':
            o.word = (uint16_t)va_arg(ap, unsigned int);
            o.word = htons(o.word);
            rc = buffer_add_u16(buffer, o.word);
            break;
        case 'd':
            o.dword = va_arg(ap, uint32_t);
            o.dword = htonl(o.dword);
            rc = buffer_add_u32(buffer, o.dword);
            break;
        case 'q':
            o.qword = va_arg(ap, uint64_t);
            o.qword = htonll(o.qword);
            rc = buffer_add_u64(buffer, o.qword);
            break;
        case 'S':
            o.string = va_arg(ap, ssh_string);
            rc = buffer_add_ssh_string(buffer, o.string);
            o.string = NULL;
            break;
        case 's':
            cstring = va_arg(ap, char *);
            len = strlen(cstring);
            rc = buffer_add_u32(buffer, htonl(len));
            if (rc == SSH_OK){
                rc = ssh_buffer_add_data(buffer, cstring, len);
            }
            cstring = NULL;
            break;
        case 'P':
            len = va_arg(ap, size_t);
            o.data = va_arg(ap, void *);
            rc = ssh_buffer_add_data(buffer, o.data, len);
            o.data = NULL;
            break;
        case 'B':
            b = va_arg(ap, bignum);
            o.string = make_bignum_string(b);
            if(o.string == NULL){
                rc = SSH_ERROR;
                break;
            }
            rc = buffer_add_ssh_string(buffer, o.string);
            SAFE_FREE(o.string);
            break;
        case 't':
            cstring = va_arg(ap, char *);
            len = strlen(cstring);
            rc = ssh_buffer_add_data(buffer, cstring, len);
            cstring = NULL;
            break;
        default:
            SSH_LOG(SSH_LOG_WARN, "Invalid buffer format %c", *p);
            rc = SSH_ERROR;
        }
        if (rc != SSH_OK){
            break;
        }
    }

    if (rc != SSH_ERROR){
        /* verify that the last hidden argument is correct */
        o.dword = va_arg(ap, uint32_t);
        if (o.dword != SSH_BUFFER_PACK_END){
            rc = SSH_ERROR;
        }
    }
    return rc;
}

/** @internal
 * @brief Add multiple values in a buffer on a single function call
 * @param[in] buffer    The buffer to add to
 * @param[in] format    A format string of arguments. This string contains single
 *                      letters describing the order and type of arguments:
 *                         'b': uint8_t  (pushed in network byte order)
 *                         'w': uint16_t (pushed in network byte order)
 *                         'd': uint32_t (pushed in network byte order)
 *                         'q': uint64_t (pushed in network byte order)
 *                         'S': ssh_string
 *                         's': char * (C string, pushed as SSH string)
 *                         't': char * (C string, pushed as free text)
 *                         'P': size_t, void * (len of data, pointer to data)
 *                              only pushes data.
 *                         'B': bignum (pushed as SSH string)
 * @returns             SSH_OK on success
 *                      SSH_ERROR on error
 * @warning             when using 'P' with a constant size (e.g. 8), do not
 *                      forget to cast to (size_t).
 */
int _ssh_buffer_pack(struct ssh_buffer_struct *buffer, const char *format, ...){
    va_list ap;
    int rc;

    va_start(ap, format);
    rc = ssh_buffer_pack_va(buffer, format, ap);
    va_end(ap);
    return rc;
}

/** @internal
 * @brief Get multiple values from a buffer on a single function call
 * @param[in] buffer    The buffer to get from
 * @param[in] format    A format string of arguments.
 * @param[in] ap        A va_list of arguments.
 * @returns             SSH_OK on success
 *                      SSH_ERROR on error
 * @see ssh_buffer_get_format() for format list values.
 */
int ssh_buffer_unpack_va(struct ssh_buffer_struct *buffer, const char *format, va_list ap){
    int rc = SSH_ERROR;
    const char *p, *last;
    union {
        uint8_t *byte;
        uint16_t *word;
        uint32_t *dword;
        uint64_t *qword;
        ssh_string *string;
        char **cstring;
        void **data;
    } o;
    size_t len, rlen;
    uint32_t u32len;
    va_list ap_copy;

    /* copy the argument list in case a rollback is needed */
    va_copy(ap_copy, ap);

    for (p = format; *p != '\0'; p++) {
        switch (*p) {
        case 'b':
            o.byte = va_arg(ap, uint8_t *);
            rlen = buffer_get_u8(buffer, o.byte);
            rc = rlen==1 ? SSH_OK : SSH_ERROR;
            break;
        case 'w':
            o.word = va_arg(ap,  uint16_t *);
            rlen = buffer_get_data(buffer, o.word, sizeof(uint16_t));
            *o.word = ntohs(*o.word);
            rc = rlen==2 ? SSH_OK : SSH_ERROR;
            break;
        case 'd':
            o.dword = va_arg(ap, uint32_t *);
            rlen = buffer_get_u32(buffer, o.dword);
            *o.dword = ntohl(*o.dword);
            rc = rlen==4 ? SSH_OK : SSH_ERROR;
            break;
        case 'q':
            o.qword = va_arg(ap, uint64_t*);
            rlen = buffer_get_u64(buffer, o.qword);
            *o.qword = ntohll(*o.qword);
            rc = rlen==8 ? SSH_OK : SSH_ERROR;
            break;
        case 'S':
            o.string = va_arg(ap, ssh_string *);
            *o.string = buffer_get_ssh_string(buffer);
            rc = *o.string != NULL ? SSH_OK : SSH_ERROR;
            o.string = NULL;
            break;
        case 's':
            o.cstring = va_arg(ap, char **);
            *o.cstring = NULL;
            rc = buffer_get_u32(buffer, &u32len);
            if (rc != 4){
                rc = SSH_ERROR;
                break;
            }
            len = ntohl(u32len);
            if (len > UINT_MAX - 1){
                rc = SSH_ERROR;
                break;
            }
            *o.cstring = malloc(len + 1);
            if (*o.cstring == NULL){
                rc = SSH_ERROR;
                break;
            }
            rlen = buffer_get_data(buffer, *o.cstring, len);
            if (rlen != len){
                SAFE_FREE(*o.cstring);
                rc = SSH_ERROR;
                break;
            }
            (*o.cstring)[len] = '\0';
            o.cstring = NULL;
            rc = SSH_OK;
            break;
        case 'P':
            len = va_arg(ap, size_t);
            o.data = va_arg(ap, void **);
            *o.data = malloc(len);
            if(*o.data == NULL){
                rc = SSH_ERROR;
                break;
            }
            rlen = buffer_get_data(buffer, *o.data, len);
            if (rlen != len){
                SAFE_FREE(*o.data);
                rc = SSH_ERROR;
                break;
            }
            o.data = NULL;
            rc = SSH_OK;
            break;
        default:
            SSH_LOG(SSH_LOG_WARN, "Invalid buffer format %c", *p);
            rc = SSH_ERROR;
        }
        if (rc != SSH_OK) {
            break;
        }
    }
    if (rc != SSH_ERROR){
        /* verify that the last hidden argument is correct */
        uint32_t canary = va_arg(ap, uint32_t);
        if (canary != SSH_BUFFER_PACK_END){
            rc = SSH_ERROR;
        }
    }
    if (rc != SSH_OK){
        /* Reset the format string and erase everything that was allocated */
        last = p;
        for(p=format;p<last;++p){
            switch(*p){
            case 'b':
            case 'w':
            case 'd':
            case 'q':
                (void)va_arg(ap_copy, void *);
                break;
            case 'S':
                o.string=va_arg(ap_copy, ssh_string *);
                SAFE_FREE(*o.string);
                break;
            case 's':
                o.cstring=va_arg(ap_copy, char **);
                SAFE_FREE(*o.cstring);
                break;
            case 'P':
                (void)va_arg(ap_copy, size_t);
                o.data = va_arg(ap_copy, void **);
                SAFE_FREE(*o.data);
                break;
            default:
                (void)va_arg(ap_copy, void *);
                break;
            }
        }
    }
    va_end(ap_copy);

    return rc;
}

/** @internal
 * @brief Get multiple values from a buffer on a single function call
 * @param[in] buffer    The buffer to get from
 * @param[in] format    A format string of arguments. This string contains single
 *                      letters describing the order and type of arguments:
 *                         'b': uint8_t *  (pulled in network byte order)
 *                         'w': uint16_t * (pulled in network byte order)
 *                         'd': uint32_t * (pulled in network byte order)
 *                         'q': uint64_t * (pulled in network byte order)
 *                         'S': ssh_string *
 *                         's': char ** (C string, pulled as SSH string)
 *                         'P': size_t, void ** (len of data, pointer to data)
 *                              only pulls data.
 * @returns             SSH_OK on success
 *                      SSH_ERROR on error
 * @warning             when using 'P' with a constant size (e.g. 8), do not
 *                      forget to cast to (size_t).
 */
int _ssh_buffer_unpack(struct ssh_buffer_struct *buffer, const char *format, ...){
    va_list ap;
    int rc;

    va_start(ap, format);
    rc = ssh_buffer_unpack_va(buffer, format, ap);
    va_end(ap);
    return rc;
}

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
