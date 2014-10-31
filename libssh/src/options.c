/*
 * options.c - handle pre-connection options
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <pwd.h>
#else
#include <winsock2.h>
#endif
#include <sys/types.h>
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/misc.h"
#include "libssh/options.h"
#ifdef WITH_SERVER
#include "libssh/server.h"
#include "libssh/bind.h"
#endif

/**
 * @addtogroup libssh_session
 * @{
 */

/**
 * @brief Duplicate the options of a session structure.
 *
 * If you make several sessions with the same options this is useful. You
 * cannot use twice the same option structure in ssh_session_connect.
 *
 * @param src           The session to use to copy the options.
 *
 * @param dest          A pointer to store the allocated session with duplicated
 *                      options. You have to free the memory.
 *
 * @returns             0 on sucess, -1 on error with errno set.
 *
 * @see ssh_session_connect()
 */
int ssh_options_copy(ssh_session src, ssh_session *dest) {
    ssh_session new;
    int i;

    if (src == NULL || dest == NULL) {
        return -1;
    }

    new = ssh_new();
    if (new == NULL) {
        return -1;
    }

    if (src->opts.username) {
        new->opts.username = strdup(src->opts.username);
        if (new->opts.username == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.host) {
        new->opts.host = strdup(src->opts.host);
        if (new->opts.host == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.identity) {
        struct ssh_iterator *it;

        new->opts.identity = ssh_list_new();
        if (new->opts.identity == NULL) {
            ssh_free(new);
            return -1;
        }

        it = ssh_list_get_iterator(src->opts.identity);
        while (it) {
            char *id;
            int rc;

            id = strdup((char *) it->data);
            if (id == NULL) {
                ssh_free(new);
                return -1;
            }

            rc = ssh_list_append(new->opts.identity, id);
            if (rc < 0) {
                free(id);
                ssh_free(new);
                return -1;
            }
            it = it->next;
        }
    }

    if (src->opts.sshdir) {
        new->opts.sshdir = strdup(src->opts.sshdir);
        if (new->opts.sshdir == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    if (src->opts.knownhosts) {
        new->opts.knownhosts = strdup(src->opts.knownhosts);
        if (new->opts.knownhosts == NULL) {
            ssh_free(new);
            return -1;
        }
    }

    for (i = 0; i < 10; i++) {
        if (src->opts.wanted_methods[i]) {
            new->opts.wanted_methods[i] = strdup(src->opts.wanted_methods[i]);
            if (new->opts.wanted_methods[i] == NULL) {
                ssh_free(new);
                return -1;
            }
        }
    }

    if (src->opts.ProxyCommand) {
        new->opts.ProxyCommand = strdup(src->opts.ProxyCommand);
        if (new->opts.ProxyCommand == NULL) {
            ssh_free(new);
            return -1;
        }
    }
    new->opts.fd                   = src->opts.fd;
    new->opts.port                 = src->opts.port;
    new->opts.timeout              = src->opts.timeout;
    new->opts.timeout_usec         = src->opts.timeout_usec;
    new->opts.ssh2                 = src->opts.ssh2;
    new->opts.ssh1                 = src->opts.ssh1;
    new->opts.compressionlevel     = src->opts.compressionlevel;
    new->common.log_verbosity      = src->common.log_verbosity;
    new->common.callbacks          = src->common.callbacks;

    *dest = new;

    return 0;
}

int ssh_options_set_algo(ssh_session session, int algo,
    const char *list) {
  if (!verify_existing_algo(algo, list)) {
    ssh_set_error(session, SSH_REQUEST_DENIED,
        "Setting method: no algorithm for method \"%s\" (%s)\n",
        ssh_kex_get_description(algo), list);
    return -1;
  }

  SAFE_FREE(session->opts.wanted_methods[algo]);
  session->opts.wanted_methods[algo] = strdup(list);
  if (session->opts.wanted_methods[algo] == NULL) {
    ssh_set_error_oom(session);
    return -1;
  }

  return 0;
}

/**
 * @brief This function can set all possible ssh options.
 *
 * @param  session An allocated SSH session structure.
 *
 * @param  type The option type to set. This could be one of the
 *              following:
 *
 *              - SSH_OPTIONS_HOST:
 *                The hostname or ip address to connect to (const char *).
 *
 *              - SSH_OPTIONS_PORT:
 *                The port to connect to (unsigned int).
 *
 *              - SSH_OPTIONS_PORT_STR:
 *                The port to connect to (const char *).
 *
 *              - SSH_OPTIONS_FD:
 *                The file descriptor to use (socket_t).\n
 *                \n
 *                If you wish to open the socket yourself for a reason
 *                or another, set the file descriptor. Don't forget to
 *                set the hostname as the hostname is used as a key in
 *                the known_host mechanism.
 *
 *              - SSH_OPTIONS_BINDADDR:
 *                The address to bind the client to (const char *).
 *
 *              - SSH_OPTIONS_USER:
 *                The username for authentication (const char *).\n
 *                \n
 *                If the value is NULL, the username is set to the
 *                default username.
 *
 *              - SSH_OPTIONS_SSH_DIR:
 *                Set the ssh directory (const char *,format string).\n
 *                \n
 *                If the value is NULL, the directory is set to the
 *                default ssh directory.\n
 *                \n
 *                The ssh directory is used for files like known_hosts
 *                and identity (private and public key). It may include
 *                "%s" which will be replaced by the user home
 *                directory.
 *
 *              - SSH_OPTIONS_KNOWNHOSTS:
 *                Set the known hosts file name (const char *,format string).\n
 *                \n
 *                If the value is NULL, the directory is set to the
 *                default known hosts file, normally
 *                ~/.ssh/known_hosts.\n
 *                \n
 *                The known hosts file is used to certify remote hosts
 *                are genuine. It may include "%s" which will be
 *                replaced by the user home directory.
 *
 *              - SSH_OPTIONS_IDENTITY:
 *                Set the identity file name (const char *,format string).\n
 *                \n
 *                By default identity, id_dsa and id_rsa are checked.\n
 *                \n
 *                The identity file used authenticate with public key.
 *                It may include "%s" which will be replaced by the
 *                user home directory.
 *
 *              - SSH_OPTIONS_TIMEOUT:
 *                Set a timeout for the connection in seconds (long).
 *
 *              - SSH_OPTIONS_TIMEOUT_USEC:
 *                Set a timeout for the connection in micro seconds
 *                        (long).
 *
 *              - SSH_OPTIONS_SSH1:
 *                Allow or deny the connection to SSH1 servers
 *                (int, 0 is false).
 *
 *              - SSH_OPTIONS_SSH2:
 *                Allow or deny the connection to SSH2 servers
 *                (int, 0 is false).
 *
 *              - SSH_OPTIONS_LOG_VERBOSITY:
 *                Set the session logging verbosity (int).\n
 *                \n
 *                The verbosity of the messages. Every log smaller or
 *                equal to verbosity will be shown.
 *                - SSH_LOG_NOLOG: No logging
 *                - SSH_LOG_RARE: Rare conditions or warnings
 *                - SSH_LOG_ENTRY: API-accessible entrypoints
 *                - SSH_LOG_PACKET: Packet id and size
 *                - SSH_LOG_FUNCTIONS: Function entering and leaving
 *
 *              - SSH_OPTIONS_LOG_VERBOSITY_STR:
 *                Set the session logging verbosity (const char *).\n
 *                \n
 *                The verbosity of the messages. Every log smaller or
 *                equal to verbosity will be shown.
 *                - SSH_LOG_NOLOG: No logging
 *                - SSH_LOG_RARE: Rare conditions or warnings
 *                - SSH_LOG_ENTRY: API-accessible entrypoints
 *                - SSH_LOG_PACKET: Packet id and size
 *                - SSH_LOG_FUNCTIONS: Function entering and leaving
 *                \n
 *                See the corresponding numbers in libssh.h.
 *
 *              - SSH_OPTIONS_AUTH_CALLBACK:
 *                Set a callback to use your own authentication function
 *                (function pointer).
 *
 *              - SSH_OPTIONS_AUTH_USERDATA:
 *                Set the user data passed to the authentication
 *                function (generic pointer).
 *
 *              - SSH_OPTIONS_LOG_CALLBACK:
 *                Set a callback to use your own logging function
 *                (function pointer).
 *
 *              - SSH_OPTIONS_LOG_USERDATA:
 *                Set the user data passed to the logging function
 *                (generic pointer).
 *
 *              - SSH_OPTIONS_STATUS_CALLBACK:
 *                Set a callback to show connection status in realtime
 *                (function pointer).\n
 *                \n
 *                @code
 *                fn(void *arg, float status)
 *                @endcode
 *                \n
 *                During ssh_connect(), libssh will call the callback
 *                with status from 0.0 to 1.0.
 *
 *              - SSH_OPTIONS_STATUS_ARG:
 *                Set the status argument which should be passed to the
 *                status callback (generic pointer).
 *
 *              - SSH_OPTIONS_CIPHERS_C_S:
 *                Set the symmetric cipher client to server (const char *,
 *                comma-separated list).
 *
 *              - SSH_OPTIONS_CIPHERS_S_C:
 *                Set the symmetric cipher server to client (const char *,
 *                comma-separated list).
 *
 *              - SSH_OPTIONS_KEY_EXCHANGE:
 *                Set the key exchange method to be used (const char *,
 *                comma-separated list). ex:
 *                "ecdh-sha2-nistp256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
 *
 *              - SSH_OPTIONS_HOSTKEYS:
 *                Set the preferred server host key types (const char *,
 *                comma-separated list). ex:
 *                "ssh-rsa,ssh-dsa,ecdh-sha2-nistp256"
 *
 *              - SSH_OPTIONS_COMPRESSION_C_S:
 *                Set the compression to use for client to server
 *                communication (const char *, "yes", "no" or a specific
 *                algorithm name if needed ("zlib","zlib@openssh.com","none").
 *
 *              - SSH_OPTIONS_COMPRESSION_S_C:
 *                Set the compression to use for server to client
 *                communication (const char *, "yes", "no" or a specific
 *                algorithm name if needed ("zlib","zlib@openssh.com","none").
 *
 *              - SSH_OPTIONS_COMPRESSION:
 *                Set the compression to use for both directions
 *                communication (const char *, "yes", "no" or a specific
 *                algorithm name if needed ("zlib","zlib@openssh.com","none").
 *
 *              - SSH_OPTIONS_COMPRESSION_LEVEL:
 *                Set the compression level to use for zlib functions. (int,
 *                value from 1 to 9, 9 being the most efficient but slower).
 *
 *              - SSH_OPTIONS_STRICTHOSTKEYCHECK:
 *                Set the parameter StrictHostKeyChecking to avoid
 *                asking about a fingerprint (int, 0 = false).
 *
 *              - SSH_OPTIONS_PROXYCOMMAND:
 *                Set the command to be executed in order to connect to
 *                server (const char *).
 *
 *              - SSH_OPTIONS_GSSAPI_SERVER_IDENTITY
 *                Set it to specify the GSSAPI server identity that libssh
 *                should expect when connecting to the server (const char *).
 *
 *              - SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY
 *                Set it to specify the GSSAPI client identity that libssh
 *                should expect when connecting to the server (const char *).
 *
 *              - SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS
 *                Set it to specify that GSSAPI should delegate credentials
 *                to the server (int, 0 = false).
 *
 * @param  value The value to set. This is a generic pointer and the
 *               datatype which is used should be set according to the
 *               type set.
 *
 * @return       0 on success, < 0 on error.
 */
int ssh_options_set(ssh_session session, enum ssh_options_e type,
    const void *value) {
    const char *v;
    char *p, *q;
    long int i;
    int rc;

    if (session == NULL) {
        return -1;
    }

    switch (type) {
        case SSH_OPTIONS_HOST:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                q = strdup(value);
                if (q == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                p = strchr(q, '@');

                SAFE_FREE(session->opts.host);

                if (p) {
                    *p = '\0';
                    session->opts.host = strdup(p + 1);
                    if (session->opts.host == NULL) {
                        SAFE_FREE(q);
                        ssh_set_error_oom(session);
                        return -1;
                    }

                    SAFE_FREE(session->opts.username);
                    session->opts.username = strdup(q);
                    SAFE_FREE(q);
                    if (session->opts.username == NULL) {
                        ssh_set_error_oom(session);
                        return -1;
                    }
                } else {
                    session->opts.host = q;
                }
            }
            break;
        case SSH_OPTIONS_PORT:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;
                if (*x <= 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.port = *x & 0xffff;
            }
            break;
        case SSH_OPTIONS_PORT_STR:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                q = strdup(v);
                if (q == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                i = strtol(q, &p, 10);
                if (q == p) {
                    SAFE_FREE(q);
                }
                SAFE_FREE(q);
                if (i <= 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.port = i & 0xffff;
            }
            break;
        case SSH_OPTIONS_FD:
            if (value == NULL) {
                session->opts.fd = SSH_INVALID_SOCKET;
                ssh_set_error_invalid(session);
                return -1;
            } else {
                socket_t *x = (socket_t *) value;
                if (*x < 0) {
                    session->opts.fd = SSH_INVALID_SOCKET;
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.fd = *x & 0xffff;
            }
            break;
        case SSH_OPTIONS_BINDADDR:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }

            q = strdup(v);
            if (q == NULL) {
                return -1;
            }
            SAFE_FREE(session->opts.bindaddr);
            session->opts.bindaddr = q;
            break;
        case SSH_OPTIONS_USER:
            v = value;
            SAFE_FREE(session->opts.username);
            if (v == NULL) {
                q = ssh_get_local_username();
                if (q == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                session->opts.username = q;
            } else if (v[0] == '\0') {
                ssh_set_error_oom(session);
                return -1;
            } else { /* username provided */
                session->opts.username = strdup(value);
                if (session->opts.username == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_SSH_DIR:
            v = value;
            SAFE_FREE(session->opts.sshdir);
            if (v == NULL) {
                session->opts.sshdir = ssh_path_expand_tilde("~/.ssh");
                if (session->opts.sshdir == NULL) {
                    return -1;
                }
            } else if (v[0] == '\0') {
                ssh_set_error_oom(session);
                return -1;
            } else {
                session->opts.sshdir = ssh_path_expand_tilde(v);
                if (session->opts.sshdir == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_IDENTITY:
        case SSH_OPTIONS_ADD_IDENTITY:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }
            q = strdup(v);
            if (q == NULL) {
                return -1;
            }
            rc = ssh_list_prepend(session->opts.identity, q);
            if (rc < 0) {
                free(q);
                return -1;
            }
            break;
        case SSH_OPTIONS_KNOWNHOSTS:
            v = value;
            SAFE_FREE(session->opts.knownhosts);
            if (v == NULL) {
                session->opts.knownhosts = ssh_path_expand_escape(session,
                                                             "%d/known_hosts");
                if (session->opts.knownhosts == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            } else if (v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                session->opts.knownhosts = strdup(v);
                if (session->opts.knownhosts == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_TIMEOUT:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                long *x = (long *) value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.timeout = *x & 0xffffffff;
            }
            break;
        case SSH_OPTIONS_TIMEOUT_USEC:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                long *x = (long *) value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.timeout_usec = *x & 0xffffffff;
            }
            break;
        case SSH_OPTIONS_SSH1:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.ssh1 = *x;
            }
            break;
        case SSH_OPTIONS_SSH2:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->opts.ssh2 = *x & 0xffff;
            }
            break;
        case SSH_OPTIONS_LOG_VERBOSITY:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;
                if (*x < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->common.log_verbosity = *x & 0xffff;
                ssh_set_log_level(*x & 0xffff);
            }
            break;
        case SSH_OPTIONS_LOG_VERBOSITY_STR:
            v = value;
            if (v == NULL || v[0] == '\0') {
                session->common.log_verbosity = 0;
                ssh_set_error_invalid(session);
                return -1;
            } else {
                q = strdup(v);
                if (q == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
                i = strtol(q, &p, 10);
                if (q == p) {
                    SAFE_FREE(q);
                }
                SAFE_FREE(q);
                if (i < 0) {
                    ssh_set_error_invalid(session);
                    return -1;
                }

                session->common.log_verbosity = i & 0xffff;
                ssh_set_log_level(i & 0xffff);
            }
            break;
        case SSH_OPTIONS_CIPHERS_C_S:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_options_set_algo(session, SSH_CRYPT_C_S, v) < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_CIPHERS_S_C:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_options_set_algo(session, SSH_CRYPT_S_C, v) < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_KEY_EXCHANGE:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_options_set_algo(session, SSH_KEX, v) < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_HOSTKEYS:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_options_set_algo(session, SSH_HOSTKEYS, v) < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_HMAC_C_S:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_options_set_algo(session, SSH_MAC_C_S, v) < 0)
                    return -1;
            }
            break;
         case SSH_OPTIONS_HMAC_S_C:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (ssh_options_set_algo(session, SSH_MAC_S_C, v) < 0)
                    return -1;
            }
            break;
        case SSH_OPTIONS_COMPRESSION_C_S:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (strcasecmp(value,"yes")==0){
                    if(ssh_options_set_algo(session,SSH_COMP_C_S,"zlib@openssh.com,zlib") < 0)
                        return -1;
                } else if (strcasecmp(value,"no")==0){
                    if(ssh_options_set_algo(session,SSH_COMP_C_S,"none") < 0)
                        return -1;
                } else {
                    if (ssh_options_set_algo(session, SSH_COMP_C_S, v) < 0)
                        return -1;
                }
            }
            break;
        case SSH_OPTIONS_COMPRESSION_S_C:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                if (strcasecmp(value,"yes")==0){
                    if(ssh_options_set_algo(session,SSH_COMP_S_C,"zlib@openssh.com,zlib") < 0)
                        return -1;
                } else if (strcasecmp(value,"no")==0){
                    if(ssh_options_set_algo(session,SSH_COMP_S_C,"none") < 0)
                        return -1;
                } else {
                    if (ssh_options_set_algo(session, SSH_COMP_S_C, v) < 0)
                        return -1;
                }
            }
            break;
        case SSH_OPTIONS_COMPRESSION:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            }
            if(ssh_options_set(session,SSH_OPTIONS_COMPRESSION_C_S, v) < 0)
                return -1;
            if(ssh_options_set(session,SSH_OPTIONS_COMPRESSION_S_C, v) < 0)
                return -1;
            break;
        case SSH_OPTIONS_COMPRESSION_LEVEL:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *)value;
                if (*x < 1 || *x > 9) {
                    ssh_set_error_invalid(session);
                    return -1;
                }
                session->opts.compressionlevel = *x & 0xff;
            }
            break;
        case SSH_OPTIONS_STRICTHOSTKEYCHECK:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int *x = (int *) value;

                session->opts.StrictHostKeyChecking = (*x & 0xff) > 0 ? 1 : 0;
            }
            session->opts.StrictHostKeyChecking = *(int*)value;
            break;
        case SSH_OPTIONS_PROXYCOMMAND:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                SAFE_FREE(session->opts.ProxyCommand);
                /* Setting the command to 'none' disables this option. */
                rc = strcasecmp(v, "none");
                if (rc != 0) {
                    q = strdup(v);
                    if (q == NULL) {
                        return -1;
                    }
                    session->opts.ProxyCommand = q;
                }
            }
            break;
        case SSH_OPTIONS_GSSAPI_SERVER_IDENTITY:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                SAFE_FREE(session->opts.gss_server_identity);
                session->opts.gss_server_identity = strdup(v);
                if (session->opts.gss_server_identity == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY:
            v = value;
            if (v == NULL || v[0] == '\0') {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                SAFE_FREE(session->opts.gss_client_identity);
                session->opts.gss_client_identity = strdup(v);
                if (session->opts.gss_client_identity == NULL) {
                    ssh_set_error_oom(session);
                    return -1;
                }
            }
            break;
        case SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS:
            if (value == NULL) {
                ssh_set_error_invalid(session);
                return -1;
            } else {
                int x = *(int *)value;

                session->opts.gss_delegate_creds = (x & 0xff);
            }
            break;

        default:
            ssh_set_error(session, SSH_REQUEST_DENIED, "Unknown ssh option %d", type);
            return -1;
            break;
    }

    return 0;
}

/**
 * @brief This function can get ssh the ssh port. It must only be used on
 *        a valid ssh session. This function is useful when the session
 *        options have been automatically inferred from the environment
 *        or configuration files and one
 *
 * @param  session An allocated SSH session structure.
 *
 * @param  port_target An unsigned integer into which the
 *         port will be set from the ssh session.
 *
 * @return       0 on success, < 0 on error.
 *
 */
int ssh_options_get_port(ssh_session session, unsigned int* port_target) {
    if (session == NULL) {
        return -1;
    }
    if (!session->opts.port) {
        ssh_set_error_invalid(session);
        return -1;
    }
    *port_target = session->opts.port;
    return 0;
}

/**
 * @brief This function can get ssh options, it does not support all options provided for
 *        ssh options set, but mostly those which a user-space program may care about having
 *        trusted the ssh driver to infer these values from underlaying configuration files.
 *        It operates only on those SSH_OPTIONS_* which return char*. If you wish to receive
 *        the port then please use ssh_options_get_port() which returns an unsigned int.
 *
 * @param  session An allocated SSH session structure.
 *
 * @param  type The option type to get. This could be one of the
 *              following:
 *
 *              - SSH_OPTIONS_HOST:
 *                The hostname or ip address to connect to (const char *).
 *
 *              - SSH_OPTIONS_USER:
 *                The username for authentication (const char *).\n
 *                \n when not explicitly set this will be inferred from the
 *                ~/.ssh/config file.
 *
 *              - SSH_OPTIONS_IDENTITY:
 *                Set the identity file name (const char *,format string).\n
 *                \n
 *                By default identity, id_dsa and id_rsa are checked.\n
 *                \n
 *                The identity file used authenticate with public key.
 *                It may include "%s" which will be replaced by the
 *                user home directory.
 *
 *              - SSH_OPTIONS_PROXYCOMMAND:
 *                Get the proxycommand necessary to log into the
 *                remote host. When not explicitly set, it will be read
 *                from the ~/.ssh/config file.
 *
 * @param  value The value to get into. As a char**, space will be
 *               allocated by the function for the value, it is
 *               your responsibility to free the memory using
 *               ssh_string_free_char().
 *
 * @return       SSH_OK on success, SSH_ERROR on error.
 */
int ssh_options_get(ssh_session session, enum ssh_options_e type, char** value)
{
    char* src = NULL;

    if (session == NULL) {
        return SSH_ERROR;
    }

    if (value == NULL) {
        ssh_set_error_invalid(session);
        return SSH_ERROR;
    }

    switch(type)
    {
        case SSH_OPTIONS_HOST: {
            src = session->opts.host;
            break;
        }
        case SSH_OPTIONS_USER: {
            src = session->opts.username;
            break;
        }
        case SSH_OPTIONS_IDENTITY: {
            struct ssh_iterator *it = ssh_list_get_iterator(session->opts.identity);
            if (it == NULL) {
                return SSH_ERROR;
            }
            src = ssh_iterator_value(char *, it);
            break;
        }
        case SSH_OPTIONS_PROXYCOMMAND: {
            src = session->opts.ProxyCommand;
            break;
        }
        default:
            ssh_set_error(session, SSH_REQUEST_DENIED, "Unknown ssh option %d", type);
            return SSH_ERROR;
        break;
    }
    if (src == NULL) {
        return SSH_ERROR;
    }
    *value = strdup(src);
    if (*value == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    return SSH_OK;
}

/**
 * @brief Parse command line arguments.
 *
 * This is a helper for your application to generate the appropriate
 * options from the command line arguments.\n
 * The argv array and argc value are changed so that the parsed
 * arguments wont appear anymore in them.\n
 * The single arguments (without switches) are not parsed. thus,
 * myssh -l user localhost\n
 * The command wont set the hostname value of options to localhost.
 *
 * @param session       The session to configure.
 *
 * @param argcptr       The pointer to the argument count.
 *
 * @param argv          The arguments list pointer.
 *
 * @returns 0 on success, < 0 on error.
 *
 * @see ssh_session_new()
 */
int ssh_options_getopt(ssh_session session, int *argcptr, char **argv) {
  char *user = NULL;
  char *cipher = NULL;
  char *identity = NULL;
  char *port = NULL;
  char **save = NULL;
  char **tmp = NULL;
  int i = 0;
  int argc = *argcptr;
  int debuglevel = 0;
  int usersa = 0;
  int usedss = 0;
  int compress = 0;
  int cont = 1;
  int current = 0;
#ifdef WITH_SSH1
  int ssh1 = 1;
#else
  int ssh1 = 0;
#endif
  int ssh2 = 1;
#ifdef _MSC_VER
    /* Not supported with a Microsoft compiler */
    return -1;
#else
  int saveoptind = optind; /* need to save 'em */
  int saveopterr = opterr;

  opterr = 0; /* shut up getopt */
  while(cont && ((i = getopt(argc, argv, "c:i:Cl:p:vb:rd12")) != -1)) {
    switch(i) {
      case 'l':
        user = optarg;
        break;
      case 'p':
        port = optarg;
        break;
      case 'v':
        debuglevel++;
        break;
      case 'r':
        usersa++;
        break;
      case 'd':
        usedss++;
        break;
      case 'c':
        cipher = optarg;
        break;
      case 'i':
        identity = optarg;
        break;
      case 'C':
        compress++;
        break;
      case '2':
        ssh2 = 1;
        ssh1 = 0;
        break;
      case '1':
        ssh2 = 0;
        ssh1 = 1;
        break;
      default:
        {
          char opt[3]="- ";
          opt[1] = optopt;
          tmp = realloc(save, (current + 1) * sizeof(char*));
          if (tmp == NULL) {
            SAFE_FREE(save);
            ssh_set_error_oom(session);
            return -1;
          }
          save = tmp;
          save[current] = strdup(opt);
          if (save[current] == NULL) {
            SAFE_FREE(save);
            ssh_set_error_oom(session);
            return -1;
          }
          current++;
          if (optarg) {
            save[current++] = argv[optind + 1];
          }
        }
    } /* switch */
  } /* while */
  opterr = saveopterr;
  tmp = realloc(save, (current + (argc - optind)) * sizeof(char*));
  if (tmp == NULL) {
    SAFE_FREE(save);
    ssh_set_error_oom(session);
    return -1;
  }
  save = tmp;
  while (optind < argc) {
      tmp = realloc(save, (current + 1) * sizeof(char*));
      if (tmp == NULL) {
          SAFE_FREE(save);
          ssh_set_error_oom(session);
          return -1;
      }
      save = tmp;
      save[current] = argv[optind];
      current++;
      optind++;
  }

  if (usersa && usedss) {
    ssh_set_error(session, SSH_FATAL, "Either RSA or DSS must be chosen");
    cont = 0;
  }

  ssh_set_log_level(debuglevel);

  optind = saveoptind;

  if(!cont) {
    SAFE_FREE(save);
    return -1;
  }

  /* first recopy the save vector into the original's */
  for (i = 0; i < current; i++) {
    /* don't erase argv[0] */
    argv[ i + 1] = save[i];
  }
  argv[current + 1] = NULL;
  *argcptr = current + 1;
  SAFE_FREE(save);

  /* set a new option struct */
  if (compress) {
    if (ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "yes") < 0) {
      cont = 0;
    }
  }

  if (cont && cipher) {
    if (ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, cipher) < 0) {
      cont = 0;
    }
    if (cont && ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, cipher) < 0) {
      cont = 0;
    }
  }

  if (cont && user) {
    if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
      cont = 0;
    }
  }

  if (cont && identity) {
    if (ssh_options_set(session, SSH_OPTIONS_IDENTITY, identity) < 0) {
      cont = 0;
    }
  }

  ssh_options_set(session, SSH_OPTIONS_PORT_STR, port);

  ssh_options_set(session, SSH_OPTIONS_SSH1, &ssh1);
  ssh_options_set(session, SSH_OPTIONS_SSH2, &ssh2);

  if (!cont) {
    return SSH_ERROR;
  }

  return SSH_OK;
#endif
}

/**
 * @brief Parse the ssh config file.
 *
 * This should be the last call of all options, it may overwrite options which
 * are already set. It requires that the host name is already set with
 * ssh_options_set_host().
 *
 * @param  session      SSH session handle
 *
 * @param  filename     The options file to use, if NULL the default
 *                      ~/.ssh/config will be used.
 *
 * @return 0 on success, < 0 on error.
 *
 * @see ssh_options_set_host()
 */
int ssh_options_parse_config(ssh_session session, const char *filename) {
  char *expanded_filename;
  int r;

  if (session == NULL) {
    return -1;
  }
  if (session->opts.host == NULL) {
    ssh_set_error_invalid(session);
    return -1;
  }

  if (session->opts.sshdir == NULL) {
      r = ssh_options_set(session, SSH_OPTIONS_SSH_DIR, NULL);
      if (r < 0) {
          ssh_set_error_oom(session);
          return -1;
      }
  }

  /* set default filename */
  if (filename == NULL) {
    expanded_filename = ssh_path_expand_escape(session, "%d/config");
  } else {
    expanded_filename = ssh_path_expand_escape(session, filename);
  }
  if (expanded_filename == NULL) {
    return -1;
  }

  r = ssh_config_parse_file(session, expanded_filename);
  if (r < 0) {
      goto out;
  }
  if (filename == NULL) {
      r = ssh_config_parse_file(session, "/etc/ssh/ssh_config");
  }

out:
  free(expanded_filename);
  return r;
}

int ssh_options_apply(ssh_session session) {
    struct ssh_iterator *it;
    char *tmp;
    int rc;

    if (session->opts.sshdir == NULL) {
        rc = ssh_options_set(session, SSH_OPTIONS_SSH_DIR, NULL);
        if (rc < 0) {
            return -1;
        }
    }

    if (session->opts.username == NULL) {
        rc = ssh_options_set(session, SSH_OPTIONS_USER, NULL);
        if (rc < 0) {
            return -1;
        }
    }

    if (session->opts.knownhosts == NULL) {
        tmp = ssh_path_expand_escape(session, "%d/known_hosts");
    } else {
        tmp = ssh_path_expand_escape(session, session->opts.knownhosts);
    }
    if (tmp == NULL) {
        return -1;
    }
    free(session->opts.knownhosts);
    session->opts.knownhosts = tmp;

    if (session->opts.ProxyCommand != NULL) {
        tmp = ssh_path_expand_escape(session, session->opts.ProxyCommand);
        if (tmp == NULL) {
            return -1;
        }
        free(session->opts.ProxyCommand);
        session->opts.ProxyCommand = tmp;
    }

    for (it = ssh_list_get_iterator(session->opts.identity);
         it != NULL;
         it = it->next) {
        char *id = (char *) it->data;
        tmp = ssh_path_expand_escape(session, id);
        if (tmp == NULL) {
            return -1;
        }
        free(id);
        it->data = tmp;
    }

    return 0;
}

/** @} */

#ifdef WITH_SERVER
/**
 * @addtogroup libssh_server
 * @{
 */
static int ssh_bind_set_key(ssh_bind sshbind, char **key_loc,
                            const void *value) {
    if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
    } else {
        SAFE_FREE(*key_loc);
        *key_loc = strdup(value);
        if (*key_loc == NULL) {
            ssh_set_error_oom(sshbind);
            return -1;
        }
    }
    return 0;
}

/**
 * @brief Set options for an SSH server bind.
 *
 * @param  sshbind      The ssh server bind to configure.
 *
 * @param  type         The option type to set. This should be one of the
 *                      following:
 *
 *                      - SSH_BIND_OPTIONS_HOSTKEY:
 *                        Set the path to an ssh host key, regardless
 *                        of type.  Only one key from per key type
 *                        (RSA, DSA, ECDSA) is allowed in an ssh_bind
 *                        at a time, and later calls to this function
 *                        with this option for the same key type will
 *                        override prior calls (const char *).
 *
 *                      - SSH_BIND_OPTIONS_BINDADDR:
 *                        Set the IP address to bind (const char *).
 *
 *                      - SSH_BIND_OPTIONS_BINDPORT:
 *                        Set the port to bind (unsigned int *).
 *
 *                      - SSH_BIND_OPTIONS_BINDPORT_STR:
 *                        Set the port to bind (const char *).
 *
 *                      - SSH_BIND_OPTIONS_LOG_VERBOSITY:
 *                        Set the session logging verbosity (int *).
 *                        The logging verbosity should have one of the
 *                        following values, which are listed in order
 *                        of increasing verbosity.  Every log message
 *                        with verbosity less than or equal to the
 *                        logging verbosity will be shown.
 *                        - SSH_LOG_NOLOG: No logging
 *                        - SSH_LOG_RARE: Rare conditions or warnings
 *                        - SSH_LOG_ENTRY: API-accessible entrypoints
 *                        - SSH_LOG_PACKET: Packet id and size
 *                        - SSH_LOG_FUNCTIONS: Function entering and leaving
 *
 *                      - SSH_BIND_OPTIONS_LOG_VERBOSITY_STR:
 *                        Set the session logging verbosity via a
 *                        string that will be converted to a numerical
 *                        value (e.g. "3") and interpreted according
 *                        to the values of
 *                        SSH_BIND_OPTIONS_LOG_VERBOSITY above (const
 *                        char *).
 *
 *                      - SSH_BIND_OPTIONS_DSAKEY:
 *                        Set the path to the ssh host dsa key, SSHv2
 *                        only (const char *).
 *
 *                      - SSH_BIND_OPTIONS_RSAKEY:
 *                        Set the path to the ssh host rsa key, SSHv2
 *                        only (const char *).
 *
 *                      - SSH_BIND_OPTIONS_ECDSAKEY:
 *                        Set the path to the ssh host ecdsa key,
 *                        SSHv2 only (const char *).
 *
 *                      - SSH_BIND_OPTIONS_BANNER:
 *                        Set the server banner sent to clients (const char *).
 *
 * @param  value        The value to set. This is a generic pointer and the
 *                      datatype which should be used is described at the
 *                      corresponding value of type above.
 *
 * @return              0 on success, < 0 on error, invalid option, or parameter.
 */
int ssh_bind_options_set(ssh_bind sshbind, enum ssh_bind_options_e type,
    const void *value) {
  char *p, *q;
  int i, rc;

  if (sshbind == NULL) {
    return -1;
  }

  switch (type) {
    case SSH_BIND_OPTIONS_HOSTKEY:
      if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
      } else {
          int key_type;
          ssh_key key;
          ssh_key *bind_key_loc = NULL;
          char **bind_key_path_loc;

          rc = ssh_pki_import_privkey_file(value, NULL, NULL, NULL, &key);
          if (rc != SSH_OK) {
              return -1;
          }
          key_type = ssh_key_type(key);
          switch (key_type) {
          case SSH_KEYTYPE_DSS:
              bind_key_loc = &sshbind->dsa;
              bind_key_path_loc = &sshbind->dsakey;
              break;
          case SSH_KEYTYPE_ECDSA:
#ifdef HAVE_ECC
              bind_key_loc = &sshbind->ecdsa;
              bind_key_path_loc = &sshbind->ecdsakey;
#else
              ssh_set_error(sshbind,
                            SSH_FATAL,
                            "ECDSA key used and libssh compiled "
                            "without ECDSA support");
#endif
              break;
          case SSH_KEYTYPE_RSA:
          case SSH_KEYTYPE_RSA1:
              bind_key_loc = &sshbind->rsa;
              bind_key_path_loc = &sshbind->rsakey;
              break;
          default:
              ssh_set_error(sshbind,
                            SSH_FATAL,
                            "Unsupported key type %d", key_type);
          }

          if (bind_key_loc == NULL) {
              ssh_key_free(key);
              return -1;
          }

          /* Set the location of the key on disk even though we don't
             need it in case some other function wants it */
          rc = ssh_bind_set_key(sshbind, bind_key_path_loc, value);
          if (rc < 0) {
              ssh_key_free(key);
              return -1;
          }
          ssh_key_free(*bind_key_loc);
          *bind_key_loc = key;
      }
      break;
    case SSH_BIND_OPTIONS_BINDADDR:
      if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        SAFE_FREE(sshbind->bindaddr);
        sshbind->bindaddr = strdup(value);
        if (sshbind->bindaddr == NULL) {
          ssh_set_error_oom(sshbind);
          return -1;
        }
      }
      break;
    case SSH_BIND_OPTIONS_BINDPORT:
      if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        int *x = (int *) value;
        sshbind->bindport = *x & 0xffff;
      }
      break;
    case SSH_BIND_OPTIONS_BINDPORT_STR:
      if (value == NULL) {
        sshbind->bindport = 22 & 0xffff;
      } else {
        q = strdup(value);
        if (q == NULL) {
          ssh_set_error_oom(sshbind);
          return -1;
        }
        i = strtol(q, &p, 10);
        if (q == p) {
          SAFE_FREE(q);
        }
        SAFE_FREE(q);

        sshbind->bindport = i & 0xffff;
      }
      break;
    case SSH_BIND_OPTIONS_LOG_VERBOSITY:
      if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        int *x = (int *) value;
        ssh_set_log_level(*x & 0xffff);
      }
      break;
    case SSH_BIND_OPTIONS_LOG_VERBOSITY_STR:
      if (value == NULL) {
      	ssh_set_log_level(0);
      } else {
        q = strdup(value);
        if (q == NULL) {
          ssh_set_error_oom(sshbind);
          return -1;
        }
        i = strtol(q, &p, 10);
        if (q == p) {
          SAFE_FREE(q);
        }
        SAFE_FREE(q);

        ssh_set_log_level(i & 0xffff);
      }
      break;
    case SSH_BIND_OPTIONS_DSAKEY:
        rc = ssh_bind_set_key(sshbind, &sshbind->dsakey, value);
        if (rc < 0) {
            return -1;
        }
        break;
    case SSH_BIND_OPTIONS_RSAKEY:
        rc = ssh_bind_set_key(sshbind, &sshbind->rsakey, value);
        if (rc < 0) {
            return -1;
        }
        break;
    case SSH_BIND_OPTIONS_ECDSAKEY:
        rc = ssh_bind_set_key(sshbind, &sshbind->ecdsakey, value);
        if (rc < 0) {
            return -1;
        }
        break;
    case SSH_BIND_OPTIONS_BANNER:
      if (value == NULL) {
        ssh_set_error_invalid(sshbind);
        return -1;
      } else {
        SAFE_FREE(sshbind->banner);
        sshbind->banner = strdup(value);
        if (sshbind->banner == NULL) {
          ssh_set_error_oom(sshbind);
          return -1;
        }
      }
      break;
    default:
      ssh_set_error(sshbind, SSH_REQUEST_DENIED, "Unknown ssh option %d", type);
      return -1;
    break;
  }

  return 0;
}
#endif

/** @} */

/* vim: set ts=4 sw=4 et cindent: */
