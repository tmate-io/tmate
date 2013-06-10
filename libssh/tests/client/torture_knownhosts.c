/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2010 by Aris Adamantiadis
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
#include "session.c"

#define KNOWNHOSTFILES "libssh_torture_knownhosts"

static void setup(void **state) {
    int verbosity=torture_libssh_verbosity();
    ssh_session session = ssh_new();

    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    *state = session;
}

static void teardown(void **state) {
    ssh_session session = *state;

    ssh_disconnect(session);
    ssh_free(session);

    unlink(KNOWNHOSTFILES);
}

static void torture_knownhosts_port(void **state) {
    ssh_session session = *state;
    char buffer[200];
    char *p;
    FILE *file;
    int rc;

    /* Connect to localhost:22, force the port to 1234 and then write
     * the known hosts file. Then check that the entry written is
     * [localhost]:1234
     */
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    session->opts.port = 1234;
    rc = ssh_write_knownhost(session);
    assert_true(rc == SSH_OK);

    file = fopen(KNOWNHOSTFILES, "r");
    assert_true(file != NULL);
    p = fgets(buffer, sizeof(buffer), file);
    assert_false(p == NULL);
    fclose(file);
    buffer[sizeof(buffer) - 1] = '\0';
    assert_true(strstr(buffer,"[localhost]:1234 ") != NULL);

    ssh_disconnect(session);
    ssh_free(session);

    /* Now, connect back to the ssh server and verify the known host line */
    *state = session = ssh_new();

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);

    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);

    session->opts.port = 1234;
    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_KNOWN_OK);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test_setup_teardown(torture_knownhosts_port, setup, teardown),
    };

    ssh_init();

    rc = run_tests(tests);

    ssh_finalize();
    return rc;
}
