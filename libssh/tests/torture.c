/*
 * torture.c - torture library for testing libssh
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2008-2009 by Andreas Schneider <mail@cynapses.org>
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
#ifndef _WIN32
# include <sys/types.h>
# include <sys/stat.h>
# include <dirent.h>
# include <errno.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "torture.h"

static int verbosity = 0;

#ifndef _WIN32
static int _torture_auth_kbdint(ssh_session session,
                               const char *password) {
    const char *prompt;
    char echo;
    int err;

    if (session == NULL || password == NULL) {
        return SSH_AUTH_ERROR;
    }

    err = ssh_userauth_kbdint(session, NULL, NULL);
    if (err == SSH_AUTH_ERROR) {
        return err;
    }

    if (ssh_userauth_kbdint_getnprompts(session) != 1) {
        return SSH_AUTH_ERROR;
    }

    prompt = ssh_userauth_kbdint_getprompt(session, 0, &echo);
    if (prompt == NULL) {
        return SSH_AUTH_ERROR;
    }

    if (ssh_userauth_kbdint_setanswer(session, 0, password) < 0) {
        return SSH_AUTH_ERROR;
    }
    err = ssh_userauth_kbdint(session, NULL, NULL);
    if (err == SSH_AUTH_INFO) {
        if (ssh_userauth_kbdint_getnprompts(session) != 0) {
            return SSH_AUTH_ERROR;
        }
        err = ssh_userauth_kbdint(session, NULL, NULL);
    }

    return err;
}

int torture_rmdirs(const char *path) {
    DIR *d;
    struct dirent *dp;
    struct stat sb;
    char *fname;

    if ((d = opendir(path)) != NULL) {
        while(stat(path, &sb) == 0) {
            /* if we can remove the directory we're done */
            if (rmdir(path) == 0) {
                break;
            }
            switch (errno) {
                case ENOTEMPTY:
                case EEXIST:
                case EBADF:
                    break; /* continue */
                default:
                    closedir(d);
                    return 0;
            }

            while ((dp = readdir(d)) != NULL) {
                size_t len;
                /* skip '.' and '..' */
                if (dp->d_name[0] == '.' &&
                        (dp->d_name[1] == '\0' ||
                         (dp->d_name[1] == '.' && dp->d_name[2] == '\0'))) {
                    continue;
                }

                len = strlen(path) + strlen(dp->d_name) + 2;
                fname = malloc(len);
                if (fname == NULL) {
                    closedir(d);
                    return -1;
                }
                snprintf(fname, len, "%s/%s", path, dp->d_name);

                /* stat the file */
                if (lstat(fname, &sb) != -1) {
                    if (S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode)) {
                        if (rmdir(fname) < 0) { /* can't be deleted */
                            if (errno == EACCES) {
                                closedir(d);
                                SAFE_FREE(fname);
                                return -1;
                            }
                            torture_rmdirs(fname);
                        }
                    } else {
                        unlink(fname);
                    }
                } /* lstat */
                SAFE_FREE(fname);
            } /* readdir */

            rewinddir(d);
        }
    } else {
        return -1;
    }

    closedir(d);
    return 0;
}

int torture_isdir(const char *path) {
    struct stat sb;

    if (lstat (path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
        return 1;
    }

    return 0;
}

ssh_session torture_ssh_session(const char *host,
                                const char *user,
                                const char *password) {
    ssh_session session;
    int method;
    int rc;

    if (host == NULL) {
        return NULL;
    }

    session = ssh_new();
    if (session == NULL) {
        return NULL;
    }

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0) {
        goto failed;
    }

    if (user != NULL) {
        if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
            goto failed;
        }
    }

    if (ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity) < 0) {
        goto failed;
    }

    if (ssh_connect(session)) {
        goto failed;
    }

    /* We are in testing mode, so consinder the hostkey as verified ;) */

    /* This request should return a SSH_REQUEST_DENIED error */
    rc = ssh_userauth_none(session, NULL);
    if (rc == SSH_ERROR) {
        goto failed;
    }
    method = ssh_userauth_list(session, NULL);
    if (method == 0) {
        goto failed;
    }

    if (password != NULL) {
        if (method & SSH_AUTH_METHOD_INTERACTIVE) {
            rc = _torture_auth_kbdint(session, password);
        } else if (method & SSH_AUTH_METHOD_PASSWORD) {
            rc = ssh_userauth_password(session, NULL, password);
        }
    } else {
        rc = ssh_userauth_publickey_auto(session, NULL, NULL);
        if (rc == SSH_AUTH_ERROR) {
            goto failed;
        }
    }
    if (rc != SSH_AUTH_SUCCESS) {
        goto failed;
    }

    return session;
failed:
    if (ssh_is_connected(session)) {
        ssh_disconnect(session);
    }
    ssh_free(session);

    return NULL;
}

#ifdef WITH_SFTP

struct torture_sftp *torture_sftp_session(ssh_session session) {
    struct torture_sftp *t;
    char template[] = "/tmp/ssh_torture_XXXXXX";
    char *p;
    int rc;

    if (session == NULL) {
        return NULL;
    }

    t = malloc(sizeof(struct torture_sftp));
    if (t == NULL) {
        return NULL;
    }

    t->ssh = session;
    t->sftp = sftp_new(session);
    if (t->sftp == NULL) {
        goto failed;
    }

    rc = sftp_init(t->sftp);
    if (rc < 0) {
        goto failed;
    }

    p = mkdtemp(template);
    if (p == NULL) {
        goto failed;
    }
    /* useful if TESTUSER is not the local user */
    chmod(template,0777);
    t->testdir = strdup(p);
    if (t->testdir == NULL) {
        goto failed;
    }

    return t;
failed:
    if (t->sftp != NULL) {
        sftp_free(t->sftp);
    }
    ssh_disconnect(t->ssh);
    ssh_free(t->ssh);
	free(t);

    return NULL;
}

void torture_sftp_close(struct torture_sftp *t) {
    if (t == NULL) {
        return;
    }

    if (t->sftp != NULL) {
        sftp_free(t->sftp);
    }

    if (t->ssh != NULL) {
        if (ssh_is_connected(t->ssh)) {
            ssh_disconnect(t->ssh);
        }
        ssh_free(t->ssh);
    }

    free(t->testdir);
    free(t);
}
#endif /* WITH_SFTP */

#endif /* _WIN32 */


int torture_libssh_verbosity(void){
  return verbosity;
}

int main(int argc, char **argv) {
  struct argument_s arguments;

  arguments.verbose=0;
  torture_cmdline_parse(argc, argv, &arguments);
  verbosity=arguments.verbose;

  return torture_run_tests();
}

/* vim: set ts=4 sw=4 et cindent syntax=c.doxygen: */
