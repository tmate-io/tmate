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
#include "known_hosts.c"

#define KNOWNHOSTFILES "libssh_torture_knownhosts"
#define BADRSA "AAAAB3NzaC1yc2EAAAADAQABAAABAQChm5" \
               "a6Av65O8cKtx5YXOnui3wJnYE6A6J/I4kZSAibbn14Jcl+34VJQwv96f25AxNmo" \
               "NwoiZV93IzdypQmiuieh6s6wB9WhYjU9K/6CkIpNhpCxswA90b3ePjS7LnR9B9J" \
               "slPSbG1H0KC1c5lb7G3utXteXtM+4YvCvpN5VdC4CpghT+p0cwN2Na8Md5vRItz" \
               "YgIytryNn7LLiwYfoSxvWigFrTTZsrVtCOYyNgklmffpGdzuC43wdANvTewfI9G" \
               "o71r8EXmEc228CrYPmb8Scv3mpXFK/BosohSGkPlEHu9lf3YjnknBicDaVtJOYp" \
               "wnXJPjZo2EhG79HxDRpjJHH"
#define BADDSA "AAAAB3NzaC1kc3MAAACBAITDKqGQ5aC5wHySG6ZdL1+BVBY2nLP5vzw3i3pvZfP" \
               "yNUS0UCwrt5pajsMvDRGXXebTJhWVonDnv8tpSgiuIBXMZrma8CU1KCFGRzwb/n8" \
               "cc5tJmIphlOUTrObjBmsRz7u1eZmoaddXC9ask6BNnt0DmhzYi2esL3mbardy8IN" \
               "zAAAAFQDlPFCm410pgQQPb3X5FWjyVEIl+QAAAIAp0vqfir8K8p+zP4dzFG7ppnt" \
               "DjaXf3ge6URF7f5xPDo6CClGo2JQ2REF8NxM7K9cLgR9Ifx2ahO48UMgrXEl/BOp" \
               "IQHpeBqUz26a49O5J0WEW16YSUHxWwMxWVe/SRmyKdTUZJ6fcepH88JNqm3XudNn" \
               "s78grM+yx9mcXnK2AsAAAAIBxpF8ZQIlGrSgwCmCfwjP156bC3Ya6LYf9ZpLJ0dX" \
               "EcxqLVllrNEvd2EGD9p16BYO2yaalYon8im59PtOcul2ay5XQ6rVDQ2T0pgNUpsI" \
               "h0dSi8VJXI1wes5HTyLsv9VBmU1uCXUUvufoQKfF/OcSH0ufcCpnd62g1/adZcy2" \
               "WJg=="

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

static void torture_knownhosts_fail(void **state) {
    ssh_session session = *state;
    FILE *file;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-rsa");
    assert_true(rc == SSH_OK);

    file = fopen(KNOWNHOSTFILES, "w");
    assert_true(file != NULL);
    fprintf(file, "localhost ssh-rsa %s\n", BADRSA);
    fclose(file);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_KNOWN_CHANGED);
}

static void torture_knownhosts_other(void **state) {
    ssh_session session = *state;
    FILE *file;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-dss");
    assert_true(rc == SSH_OK);

    file = fopen(KNOWNHOSTFILES, "w");
    assert_true(file != NULL);
    fprintf(file, "localhost ssh-rsa %s\n", BADRSA);
    fclose(file);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_FOUND_OTHER);
}

static void torture_knownhosts_other_auto(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-dss");
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_NOT_KNOWN);

    rc = ssh_write_knownhost(session);
    assert_true(rc == SSH_OK);

    ssh_disconnect(session);
    ssh_free(session);

    /* connect again and check host key */
    *state = session = ssh_new();

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    /* ssh-rsa is the default but libssh should try ssh-dss instead */
    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_KNOWN_OK);
}

static void torture_knownhosts_conflict(void **state) {
    ssh_session session = *state;
    FILE *file;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-rsa");
    assert_true(rc == SSH_OK);

    file = fopen(KNOWNHOSTFILES, "w");
    assert_true(file != NULL);
    fprintf(file, "localhost ssh-rsa %s\n", BADRSA);
    fprintf(file, "localhost ssh-dss %s\n", BADDSA);
    fclose(file);

    rc = ssh_connect(session);
    assert_true(rc==SSH_OK);

    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_KNOWN_CHANGED);

    rc = ssh_write_knownhost(session);
    assert_true(rc==SSH_OK);

    ssh_disconnect(session);
    ssh_free(session);

    /* connect again and check host key */
    *state = session = ssh_new();

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    rc = ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-rsa");
    assert_true(rc == SSH_OK);

    rc = ssh_connect(session);
    assert_true(rc == SSH_OK);

    rc = ssh_is_server_known(session);
    assert_true(rc == SSH_SERVER_KNOWN_OK);
}

static void torture_knownhosts_precheck(void **state) {
    ssh_session session = *state;
    FILE *file;
    int rc;
    char **kex;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, KNOWNHOSTFILES);
    assert_true(rc == SSH_OK);

    file = fopen(KNOWNHOSTFILES, "w");
    assert_true(file != NULL);
    fprintf(file, "localhost ssh-rsa %s\n", BADRSA);
    fprintf(file, "localhost ssh-dss %s\n", BADDSA);
    fclose(file);

    kex = ssh_knownhosts_algorithms(session);
    assert_true(kex != NULL);
    assert_string_equal(kex[0],"ssh-rsa");
    assert_string_equal(kex[1],"ssh-dss");
    assert_true(kex[2]==NULL);
    free(kex[1]);
    free(kex[0]);
    free(kex);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test_setup_teardown(torture_knownhosts_port, setup, teardown),
        unit_test_setup_teardown(torture_knownhosts_fail, setup, teardown),
        unit_test_setup_teardown(torture_knownhosts_other, setup, teardown),
        unit_test_setup_teardown(torture_knownhosts_other_auto, setup, teardown),
        unit_test_setup_teardown(torture_knownhosts_conflict, setup, teardown),
        unit_test_setup_teardown(torture_knownhosts_precheck, setup, teardown)
    };

    ssh_init();

    rc = run_tests(tests);

    ssh_finalize();
    return rc;
}
