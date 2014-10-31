/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
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

/*
 * priv.h file
 * This include file contains everything you shouldn't deal with in
 * user programs. Consider that anything in this file might change
 * without notice; libssh.h file will keep backward compatibility
 * on binary & source
 */

#ifndef _LIBSSH_PRIV_H
#define _LIBSSH_PRIV_H

#include "config.h"

#if !defined(HAVE_STRTOULL)
# if defined(HAVE___STRTOULL)
#  define strtoull __strtoull
# elif defined(HAVE__STRTOUI64)
#  define strtoull _strtoui64
# elif defined(__hpux) && defined(__LP64__)
#  define strtoull strtoul
# else
#  error "no strtoull function found"
# endif
#endif /* !defined(HAVE_STRTOULL) */

#ifdef _WIN32

/* Imitate define of inttypes.h */
# ifndef PRIdS
#  define PRIdS "Id"
# endif

# ifndef PRIu64
#  if __WORDSIZE == 64
#   define PRIu64 "lu"
#  else
#   define PRIu64 "llu"
#  endif /* __WORDSIZE */
# endif /* PRIu64 */

# ifdef _MSC_VER
#  include <stdio.h>

/* On Microsoft compilers define inline to __inline on all others use inline */
#  undef inline
#  define inline __inline

#  define strcasecmp _stricmp
#  define strncasecmp _strnicmp
#  if ! defined(HAVE_ISBLANK)
#   define isblank(ch) ((ch) == ' ' || (ch) == '\t' || (ch) == '\n' || (ch) == '\r')
#  endif

#  define usleep(X) Sleep(((X)+1000)/1000)

#  undef strtok_r
#  define strtok_r strtok_s

#  if defined(HAVE__SNPRINTF_S)
#   undef snprintf
#   define snprintf(d, n, ...) _snprintf_s((d), (n), _TRUNCATE, __VA_ARGS__)
#  else /* HAVE__SNPRINTF_S */
#   if defined(HAVE__SNPRINTF)
#     undef snprintf
#     define snprintf _snprintf
#   else /* HAVE__SNPRINTF */
#    if !defined(HAVE_SNPRINTF)
#     error "no snprintf compatible function found"
#    endif /* HAVE_SNPRINTF */
#   endif /* HAVE__SNPRINTF */
#  endif /* HAVE__SNPRINTF_S */

#  if defined(HAVE__VSNPRINTF_S)
#   undef vsnprintf
#   define vsnprintf(s, n, f, v) _vsnprintf_s((s), (n), _TRUNCATE, (f), (v))
#  else /* HAVE__VSNPRINTF_S */
#   if defined(HAVE__VSNPRINTF)
#    undef vsnprintf
#    define vsnprintf _vsnprintf
#   else
#    if !defined(HAVE_VSNPRINTF)
#     error "No vsnprintf compatible function found"
#    endif /* HAVE_VSNPRINTF */
#   endif /* HAVE__VSNPRINTF */
#  endif /* HAVE__VSNPRINTF_S */

# endif /* _MSC_VER */

struct timeval;
int gettimeofday(struct timeval *__p, void *__t);

#else /* _WIN32 */

#include <unistd.h>
#define PRIdS "zd"

#endif /* _WIN32 */

#include "libssh/libssh.h"
#include "libssh/callbacks.h"

/* some constants */
#ifndef MAX_PACKAT_LEN
#define MAX_PACKET_LEN 262144
#endif
#ifndef ERROR_BUFFERLEN
#define ERROR_BUFFERLEN 1024
#endif
#ifndef CLIENTBANNER1
#define CLIENTBANNER1 "SSH-1.5-libssh-" SSH_STRINGIFY(LIBSSH_VERSION)
#endif
#ifndef CLIENTBANNER2
#define CLIENTBANNER2 "SSH-2.0-libssh-" SSH_STRINGIFY(LIBSSH_VERSION)
#endif
#ifndef KBDINT_MAX_PROMPT
#define KBDINT_MAX_PROMPT 256 /* more than openssh's :) */
#endif
#ifndef MAX_BUF_SIZE
#define MAX_BUF_SIZE 4096
#endif

#ifndef __FUNCTION__
#if defined(__SUNPRO_C)
#define __FUNCTION__ __func__
#endif
#endif

#if defined(HAVE_GCC_THREAD_LOCAL_STORAGE)
# define LIBSSH_THREAD __thread
#elif defined(HAVE_MSC_THREAD_LOCAL_STORAGE)
# define LIBSSH_THREAD __declspec(thread)
#else
# define LIBSSH_THREAD
#endif

/*
 * This makes sure that the compiler doesn't optimize out the code
 *
 * Use it in a macro where the provided variable is 'x'.
 */
#if defined(HAVE_GCC_VOLATILE_MEMORY_PROTECTION)
# define LIBSSH_MEM_PROTECTION __asm__ volatile("" : : "r"(&(x)) : "memory")
#else
# define LIBSSH_MEM_PROTECTION
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* forward declarations */
struct ssh_common_struct;
struct ssh_kex_struct;

int ssh_get_key_params(ssh_session session, ssh_key *privkey);

/* LOGGING */
void ssh_log_function(int verbosity,
                      const char *function,
                      const char *buffer);
#define SSH_LOG(priority, ...) \
    _ssh_log(priority, __FUNCTION__, __VA_ARGS__)

/* LEGACY */
void ssh_log_common(struct ssh_common_struct *common,
                    int verbosity,
                    const char *function,
                    const char *format, ...) PRINTF_ATTRIBUTE(4, 5);


/* ERROR HANDLING */

/* error handling structure */
struct error_struct {
    int error_code;
    char error_buffer[ERROR_BUFFERLEN];
};

#define ssh_set_error(error, code, ...) \
    _ssh_set_error(error, code, __FUNCTION__, __VA_ARGS__)
void _ssh_set_error(void *error,
                    int code,
                    const char *function,
                    const char *descr, ...) PRINTF_ATTRIBUTE(4, 5);

#define ssh_set_error_oom(error) \
    _ssh_set_error_oom(error, __FUNCTION__)
void _ssh_set_error_oom(void *error, const char *function);

#define ssh_set_error_invalid(error) \
    _ssh_set_error_invalid(error, __FUNCTION__)
void _ssh_set_error_invalid(void *error, const char *function);


/* server.c */
#ifdef WITH_SERVER
int ssh_auth_reply_default(ssh_session session,int partial);
int ssh_auth_reply_success(ssh_session session, int partial);
#endif
/* client.c */

int ssh_send_banner(ssh_session session, int is_server);

/* connect.c */
socket_t ssh_connect_host(ssh_session session, const char *host,const char
        *bind_addr, int port, long timeout, long usec);
socket_t ssh_connect_host_nonblocking(ssh_session session, const char *host,
		const char *bind_addr, int port);

/* in base64.c */
ssh_buffer base64_to_bin(const char *source);
unsigned char *bin_to_base64(const unsigned char *source, int len);

/* gzip.c */
int compress_buffer(ssh_session session,ssh_buffer buf);
int decompress_buffer(ssh_session session,ssh_buffer buf, size_t maxlen);

/* match.c */
int match_hostname(const char *host, const char *pattern, unsigned int len);

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

/** Free memory space */
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)

/** Zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

/** Zero a structure given a pointer to the structure */
#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); } while(0)

/** Get the size of an array */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

/*
 * See http://llvm.org/bugs/show_bug.cgi?id=15495
 */
#if defined(HAVE_GCC_VOLATILE_MEMORY_PROTECTION)
/** Overwrite a string with '\0' */
# define BURN_STRING(x) do { \
    if ((x) != NULL) \
        memset((x), '\0', strlen((x))); __asm__ volatile("" : : "r"(&(x)) : "memory"); \
  } while(0)

/** Overwrite the buffer with '\0' */
# define BURN_BUFFER(x, size) do { \
    if ((x) != NULL) \
        memset((x), '\0', (size)); __asm__ volatile("" : : "r"(&(x)) : "memory"); \
  } while(0)
#else /* HAVE_GCC_VOLATILE_MEMORY_PROTECTION */
/** Overwrite a string with '\0' */
# define BURN_STRING(x) do { \
    if ((x) != NULL) memset((x), '\0', strlen((x))); \
  } while(0)

/** Overwrite the buffer with '\0' */
# define BURN_BUFFER(x, size) do { \
    if ((x) != NULL) \
        memset((x), '\0', (size)); \
  } while(0)
#endif /* HAVE_GCC_VOLATILE_MEMORY_PROTECTION */

/**
 * This is a hack to fix warnings. The idea is to use this everywhere that we
 * get the "discarding const" warning by the compiler. That doesn't actually
 * fix the real issue, but marks the place and you can search the code for
 * discard_const.
 *
 * Please use this macro only when there is no other way to fix the warning.
 * We should use this function in only in a very few places.
 *
 * Also, please call this via the discard_const_p() macro interface, as that
 * makes the return type safe.
 */
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))

/**
 * Type-safe version of discard_const
 */
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))

#endif /* _LIBSSH_PRIV_H */
/* vim: set ts=4 sw=4 et cindent: */
