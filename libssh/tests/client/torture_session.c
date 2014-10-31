/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2012 by Aris Adamantiadis
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

#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/session.h"

#define BUFLEN 4096
static char buffer[BUFLEN];

static void setup(void **state) {
    int verbosity = torture_libssh_verbosity();
    ssh_session session = ssh_new();

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    *state = session;
}

static void teardown(void **state) {
    ssh_disconnect(*state);
    ssh_free(*state);
}

static void torture_channel_read_error(void **state) {
    ssh_session session = *state;
    char *user = getenv("TORTURE_USER");
    ssh_channel channel;
    int rc;
    int i;

    if (user == NULL) {
        print_message("*** Please set the environment variable TORTURE_USER"
                      " to enable this test!!\n");
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_USER, user);
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);

    rc = ssh_userauth_none(session,NULL);
    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_ERROR) {
        assert_true(ssh_get_error_code(session) == SSH_REQUEST_DENIED);
    }
    rc = ssh_userauth_list(session, NULL);
    assert_true(rc & SSH_AUTH_METHOD_PUBLICKEY);

    rc = ssh_userauth_publickey_auto(session, NULL, NULL);
    assert_true(rc == SSH_AUTH_SUCCESS);

    channel = ssh_channel_new(session);
    assert_true(channel != NULL);

    rc = ssh_channel_open_session(channel);
    assert_true(rc == SSH_OK);

    rc = ssh_channel_request_exec(channel, "hexdump -C /dev/urandom");
    assert_true(rc == SSH_OK);

    /* send crap and for server to send us a disconnect */
    rc = write(ssh_get_fd(session),"AAAA", 4);
    assert_int_equal(rc, 4);

    for (i=0;i<20;++i){
        rc = ssh_channel_read(channel,buffer,sizeof(buffer),0);
        if (rc == SSH_ERROR)
            break;
    }
    assert_true(rc == SSH_ERROR);

    ssh_channel_free(channel);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test_setup_teardown(torture_channel_read_error, setup, teardown),
    };

    ssh_init();

    rc = run_tests(tests);
    ssh_finalize();

    return rc;
}
