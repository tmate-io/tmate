/* Name of package */
#cmakedefine PACKAGE "${APPLICATION_NAME}"

/* Version number of package */
#cmakedefine VERSION "${APPLICATION_VERSION}"

#cmakedefine LOCALEDIR "${LOCALE_INSTALL_DIR}"
#cmakedefine DATADIR "${DATADIR}"
#cmakedefine LIBDIR "${LIBDIR}"
#cmakedefine PLUGINDIR "${PLUGINDIR}"
#cmakedefine SYSCONFDIR "${SYSCONFDIR}"
#cmakedefine BINARYDIR "${BINARYDIR}"
#cmakedefine SOURCEDIR "${SOURCEDIR}"

/************************** HEADER FILES *************************/

/* Define to 1 if you have the <argp.h> header file. */
#cmakedefine HAVE_ARGP_H 1

/* Define to 1 if you have the <pty.h> header file. */
#cmakedefine HAVE_PTY_H 1

/* Define to 1 if you have the <util.h> header file. */
#cmakedefine HAVE_UTIL_H 1

/* Define to 1 if you have the <termios.h> header file. */
#cmakedefine HAVE_TERMIOS_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#cmakedefine HAVE_UNISTD_H 1

/* Define to 1 if you have the <openssl/aes.h> header file. */
#cmakedefine HAVE_OPENSSL_AES_H 1

/* Define to 1 if you have the <wspiapi.h> header file. */
#cmakedefine HAVE_WSPIAPI_H 1

/* Define to 1 if you have the <openssl/blowfish.h> header file. */
#cmakedefine HAVE_OPENSSL_BLOWFISH_H 1

/* Define to 1 if you have the <openssl/des.h> header file. */
#cmakedefine HAVE_OPENSSL_DES_H 1

/* Define to 1 if you have the <openssl/ecdh.h> header file. */
#cmakedefine HAVE_OPENSSL_ECDH_H 1

/* Define to 1 if you have the <openssl/ec.h> header file. */
#cmakedefine HAVE_OPENSSL_EC_H 1

/* Define to 1 if you have the <openssl/ecdsa.h> header file. */
#cmakedefine HAVE_OPENSSL_ECDSA_H 1

/* Define to 1 if you have the <pthread.h> header file. */
#cmakedefine HAVE_PTHREAD_H 1

/* Define to 1 if you have eliptic curve cryptography in openssl */
#cmakedefine HAVE_OPENSSL_ECC 1

/* Define to 1 if you have eliptic curve cryptography in gcrypt */
#cmakedefine HAVE_GCRYPT_ECC 1

/* Define to 1 if you have eliptic curve cryptography */
#cmakedefine HAVE_ECC 1

/*************************** FUNCTIONS ***************************/

/* Define to 1 if you have the `snprintf' function. */
#cmakedefine HAVE_SNPRINTF 1

/* Define to 1 if you have the `_snprintf' function. */
#cmakedefine HAVE__SNPRINTF 1

/* Define to 1 if you have the `_snprintf_s' function. */
#cmakedefine HAVE__SNPRINTF_S 1

/* Define to 1 if you have the `vsnprintf' function. */
#cmakedefine HAVE_VSNPRINTF 1

/* Define to 1 if you have the `_vsnprintf' function. */
#cmakedefine HAVE__VSNPRINTF 1

/* Define to 1 if you have the `_vsnprintf_s' function. */
#cmakedefine HAVE__VSNPRINTF_S 1

/* Define to 1 if you have the `isblank' function. */
#cmakedefine HAVE_ISBLANK 1

/* Define to 1 if you have the `strncpy' function. */
#cmakedefine HAVE_STRNCPY 1

/* Define to 1 if you have the `cfmakeraw' function. */
#cmakedefine HAVE_CFMAKERAW 1

/* Define to 1 if you have the `getaddrinfo' function. */
#cmakedefine HAVE_GETADDRINFO 1

/* Define to 1 if you have the `poll' function. */
#cmakedefine HAVE_POLL 1

/* Define to 1 if you have the `select' function. */
#cmakedefine HAVE_SELECT 1

/* Define to 1 if you have the `clock_gettime' function. */
#cmakedefine HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have the `ntohll' function. */
#cmakedefine HAVE_NTOHLL 1

/* Define to 1 if you have the `htonll' function. */
#cmakedefine HAVE_HTONLL 1

/* Define to 1 if you have the `strtoull' function. */
#cmakedefine HAVE_STRTOULL 1

/* Define to 1 if you have the `__strtoull' function. */
#cmakedefine HAVE___STRTOULL 1

/* Define to 1 if you have the `_strtoui64' function. */
#cmakedefine HAVE__STRTOUI64 1

/*************************** LIBRARIES ***************************/

/* Define to 1 if you have the `crypto' library (-lcrypto). */
#cmakedefine HAVE_LIBCRYPTO 1

/* Define to 1 if you have the `gcrypt' library (-lgcrypt). */
#cmakedefine HAVE_LIBGCRYPT 1

/* Define to 1 if you have the `pthread' library (-lpthread). */
#cmakedefine HAVE_PTHREAD 1

/**************************** OPTIONS ****************************/

#cmakedefine HAVE_GCC_THREAD_LOCAL_STORAGE 1
#cmakedefine HAVE_MSC_THREAD_LOCAL_STORAGE 1

#cmakedefine HAVE_GCC_VOLATILE_MEMORY_PROTECTION 1

/* Define to 1 if you want to enable GSSAPI */
#cmakedefine WITH_GSSAPI 1

/* Define to 1 if you want to enable ZLIB */
#cmakedefine WITH_ZLIB 1

/* Define to 1 if you want to enable SFTP */
#cmakedefine WITH_SFTP 1

/* Define to 1 if you want to enable SSH1 */
#cmakedefine WITH_SSH1 1

/* Define to 1 if you want to enable server support */
#cmakedefine WITH_SERVER 1

/* Define to 1 if you want to enable debug output for crypto functions */
#cmakedefine DEBUG_CRYPTO 1

/* Define to 1 if you want to enable pcap output support (experimental) */
#cmakedefine WITH_PCAP 1

/* Define to 1 if you want to enable calltrace debug output */
#cmakedefine DEBUG_CALLTRACE 1

/* Define to 1 if you want to enable NaCl support */
#cmakedefine WITH_NACL 1

/*************************** ENDIAN *****************************/

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#cmakedefine WORDS_BIGENDIAN 1
