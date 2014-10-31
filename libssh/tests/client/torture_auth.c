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
#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "agent.c"

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

static void torture_auth_autopubkey(void **state) {
    ssh_session session = *state;
    char *user = getenv("TORTURE_USER");
    int rc;

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
}

static void torture_auth_autopubkey_nonblocking(void **state) {
    ssh_session session = *state;
    char *user = getenv("TORTURE_USER");
    int rc;

    if (user == NULL) {
        print_message("*** Please set the environment variable TORTURE_USER"
                      " to enable this test!!\n");
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_USER, user);
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);

    ssh_set_blocking(session,0);
    do {
      rc = ssh_userauth_none(session, NULL);
    } while (rc == SSH_AUTH_AGAIN);

    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_ERROR) {
        assert_true(ssh_get_error_code(session) == SSH_REQUEST_DENIED);
    }

    rc = ssh_userauth_list(session, NULL);
    assert_true(rc & SSH_AUTH_METHOD_PUBLICKEY);

    do {
        rc = ssh_userauth_publickey_auto(session, NULL, NULL);
    } while (rc == SSH_AUTH_AGAIN);
    assert_true(rc == SSH_AUTH_SUCCESS);
}

static void torture_auth_kbdint(void **state) {
    ssh_session session = *state;
    char *user = getenv("TORTURE_USER");
    char *password = getenv("TORTURE_PASSWORD");
    int rc;

    if (user == NULL) {
        print_message("*** Please set the environment variable TORTURE_USER"
                      " to enable this test!!\n");
        return;
    }

    if (password == NULL) {
        print_message("*** Please set the environment variable "
                      "TORTURE_PASSWORD to enable this test!!\n");
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
    assert_true(rc & SSH_AUTH_METHOD_INTERACTIVE);

    rc = ssh_userauth_kbdint(session, NULL, NULL);
    assert_true(rc == SSH_AUTH_INFO);
    assert_int_equal(ssh_userauth_kbdint_getnprompts(session), 1);

    rc = ssh_userauth_kbdint_setanswer(session, 0, password);
    assert_false(rc < 0);

    rc = ssh_userauth_kbdint(session, NULL, NULL);
    /* Sometimes, SSH server send an empty query at the end of exchange */
    if(rc == SSH_AUTH_INFO) {
        assert_int_equal(ssh_userauth_kbdint_getnprompts(session), 0);
        rc = ssh_userauth_kbdint(session, NULL, NULL);
    }
    assert_true(rc == SSH_AUTH_SUCCESS);
}

static void torture_auth_kbdint_nonblocking(void **state) {
    ssh_session session = *state;
    char *user = getenv("TORTURE_USER");
    char *password = getenv("TORTURE_PASSWORD");
    int rc;

    if (user == NULL) {
        print_message("*** Please set the environment variable TORTURE_USER"
                      " to enable this test!!\n");
        return;
    }

    if (password == NULL) {
        print_message("*** Please set the environment variable "
                      "TORTURE_PASSWORD to enable this test!!\n");
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_USER, user);
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);

    ssh_set_blocking(session,0);
    do {
      rc = ssh_userauth_none(session, NULL);
    } while (rc == SSH_AUTH_AGAIN);

    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_ERROR) {
        assert_true(ssh_get_error_code(session) == SSH_REQUEST_DENIED);
    }
    rc = ssh_userauth_list(session, NULL);
    assert_true(rc & SSH_AUTH_METHOD_INTERACTIVE);

    do {
        rc = ssh_userauth_kbdint(session, NULL, NULL);
    } while (rc == SSH_AUTH_AGAIN);
    assert_true(rc == SSH_AUTH_INFO);
    assert_int_equal(ssh_userauth_kbdint_getnprompts(session), 1);
    do {
        rc = ssh_userauth_kbdint_setanswer(session, 0, password);
    } while (rc == SSH_AUTH_AGAIN);
    assert_false(rc < 0);

    do {
        rc = ssh_userauth_kbdint(session, NULL, NULL);
    } while (rc == SSH_AUTH_AGAIN);
    /* Sometimes, SSH server send an empty query at the end of exchange */
    if(rc == SSH_AUTH_INFO) {
        assert_int_equal(ssh_userauth_kbdint_getnprompts(session), 0);
        do {
            rc = ssh_userauth_kbdint(session, NULL, NULL);
        } while (rc == SSH_AUTH_AGAIN);
    }
    assert_true(rc == SSH_AUTH_SUCCESS);
}

static void torture_auth_password(void **state) {
    ssh_session session = *state;
    char *user = getenv("TORTURE_USER");
    char *password = getenv("TORTURE_PASSWORD");
    int rc;

    if (user == NULL) {
        print_message("*** Please set the environment variable TORTURE_USER"
                      " to enable this test!!\n");
        return;
    }

    if (password == NULL) {
        print_message("*** Please set the environment variable "
                      "TORTURE_PASSWORD to enable this test!!\n");
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_USER, user);
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);

    rc = ssh_userauth_none(session, NULL);
    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_AUTH_ERROR) {
        assert_true(ssh_get_error_code(session) == SSH_REQUEST_DENIED);
    }
    rc = ssh_userauth_list(session, NULL);
    assert_true(rc & SSH_AUTH_METHOD_PASSWORD);

    rc = ssh_userauth_password(session, NULL, password);
    assert_true(rc == SSH_AUTH_SUCCESS);
}

static void torture_auth_password_nonblocking(void **state) {
    ssh_session session = *state;
    char *user = getenv("TORTURE_USER");
    char *password = getenv("TORTURE_PASSWORD");
    int rc;

    if (user == NULL) {
        print_message("*** Please set the environment variable TORTURE_USER"
                      " to enable this test!!\n");
        return;
    }

    if (password == NULL) {
        print_message("*** Please set the environment variable "
                      "TORTURE_PASSWORD to enable this test!!\n");
        return;
    }

    rc = ssh_options_set(session, SSH_OPTIONS_USER, user);
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);

    ssh_set_blocking(session,0);
    do {
      rc = ssh_userauth_none(session, NULL);
    } while (rc == SSH_AUTH_AGAIN);

    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_AUTH_ERROR) {
        assert_true(ssh_get_error_code(session) == SSH_REQUEST_DENIED);
    }

    rc = ssh_userauth_list(session, NULL);
    assert_true(rc & SSH_AUTH_METHOD_PASSWORD);

    do {
      rc = ssh_userauth_password(session, NULL, password);
    } while(rc==SSH_AUTH_AGAIN);

    assert_true(rc == SSH_AUTH_SUCCESS);
}

static void torture_auth_agent(void **state) {
    ssh_session session = *state;
    char *user = getenv("TORTURE_USER");
    int rc;

    if (user == NULL) {
        print_message("*** Please set the environment variable TORTURE_USER"
                      " to enable this test!!\n");
        return;
    }
    if (!agent_is_running(session)){
        print_message("*** Agent not running. Test ignored\n");
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

    rc = ssh_userauth_agent(session, NULL);
    assert_true(rc == SSH_AUTH_SUCCESS);
}

static void torture_auth_agent_nonblocking(void **state) {
    ssh_session session = *state;
    char *user = getenv("TORTURE_USER");
    int rc;

    if (user == NULL) {
        print_message("*** Please set the environment variable TORTURE_USER"
                      " to enable this test!!\n");
        return;
    }
    if (!agent_is_running(session)){
        print_message("*** Agent not running. Test ignored\n");
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

    ssh_set_blocking(session,0);

    do {
      rc = ssh_userauth_agent(session, NULL);
    } while (rc == SSH_AUTH_AGAIN);
    assert_true(rc == SSH_AUTH_SUCCESS);
}


static void torture_auth_none(void **state) {
    ssh_session session = *state;
    char *user = getenv("TORTURE_USER");
    int rc;

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

    assert_true(rc == SSH_AUTH_DENIED);
    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_ERROR) {
        assert_true(ssh_get_error_code(session) == SSH_REQUEST_DENIED);
    }
}

static void torture_auth_none_nonblocking(void **state) {
    ssh_session session = *state;
    char *user = getenv("TORTURE_USER");
    int rc;

    if (user == NULL) {
        print_message("*** Please set the environment variable TORTURE_USER"
                      " to enable this test!!\n");
        return;
    }
    rc = ssh_options_set(session, SSH_OPTIONS_USER, user);
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);

    /* This request should return a SSH_REQUEST_DENIED error */
    if (rc == SSH_ERROR) {
        assert_true(ssh_get_error_code(session) == SSH_REQUEST_DENIED);
    }

    ssh_set_blocking(session,0);

    do {
        rc = ssh_userauth_none(session,NULL);
    } while (rc == SSH_AUTH_AGAIN);
    assert_true(rc == SSH_AUTH_DENIED);
    assert_true(ssh_get_error_code(session) == SSH_REQUEST_DENIED);

}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test_setup_teardown(torture_auth_kbdint, setup, teardown),
        unit_test_setup_teardown(torture_auth_kbdint_nonblocking, setup, teardown),
        unit_test_setup_teardown(torture_auth_password, setup, teardown),
        unit_test_setup_teardown(torture_auth_password_nonblocking, setup, teardown),
        unit_test_setup_teardown(torture_auth_autopubkey, setup, teardown),
        unit_test_setup_teardown(torture_auth_autopubkey_nonblocking, setup, teardown),
        unit_test_setup_teardown(torture_auth_agent, setup, teardown),
        unit_test_setup_teardown(torture_auth_agent_nonblocking, setup, teardown),
        unit_test_setup_teardown(torture_auth_none, setup, teardown),
        unit_test_setup_teardown(torture_auth_none_nonblocking, setup, teardown),
    };

    ssh_init();

    rc = run_tests(tests);
    ssh_finalize();

    return rc;
}
