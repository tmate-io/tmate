#define LIBSSH_STATIC

#ifndef _WIN32
#define _POSIX_PTHREAD_SEMANTICS
# include <pwd.h>
#endif

#include "torture.h"
#include <libssh/session.h>
#include <libssh/misc.h>

static void setup(void **state) {
    ssh_session session = ssh_new();
    *state = session;
}

static void teardown(void **state) {
    ssh_free(*state);
}

static void torture_options_set_host(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == 0);
    assert_string_equal(session->opts.host, "localhost");

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "guru@meditation");
    assert_true(rc == 0);
    assert_string_equal(session->opts.host, "meditation");
    assert_string_equal(session->opts.username, "guru");
}

static void torture_options_get_host(void **state) {
    ssh_session session = *state;
    int rc;
    char* host = NULL;

    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_true(rc == 0);
    assert_string_equal(session->opts.host, "localhost");

    assert_false(ssh_options_get(session, SSH_OPTIONS_HOST, &host));

    assert_string_equal(host, "localhost");
    free(host);
}

static void torture_options_set_port(void **state) {
    ssh_session session = *state;
    int rc;
    unsigned int port = 42;

    rc = ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    assert_true(rc == 0);
    assert_true(session->opts.port == port);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT_STR, "23");
    assert_true(rc == 0);
    assert_true(session->opts.port == 23);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT_STR, "five");
    assert_true(rc == -1);

    rc = ssh_options_set(session, SSH_OPTIONS_PORT, NULL);
    assert_true(rc == -1);
}

static void torture_options_get_port(void **state) {
  ssh_session session = *state;
  unsigned int given_port = 1234;
  unsigned int port_container;
  int rc;
  rc = ssh_options_set(session, SSH_OPTIONS_PORT, &given_port);
  assert_true(rc == 0);
  rc = ssh_options_get_port(session, &port_container);
  assert_true(rc == 0);
  assert_int_equal(port_container, 1234);
}

static void torture_options_get_user(void **state) {
  ssh_session session = *state;
  char* user = NULL;
  int rc;
  rc = ssh_options_set(session, SSH_OPTIONS_USER, "magicaltrevor");
  assert_true(rc == SSH_OK);
  rc = ssh_options_get(session, SSH_OPTIONS_USER, &user);
  assert_string_equal(user, "magicaltrevor");
  free(user);
}

static void torture_options_set_fd(void **state) {
    ssh_session session = *state;
    socket_t fd = 42;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_FD, &fd);
    assert_true(rc == 0);
    assert_true(session->opts.fd == fd);

    rc = ssh_options_set(session, SSH_OPTIONS_FD, NULL);
    assert_true(rc == SSH_ERROR);
    assert_true(session->opts.fd == SSH_INVALID_SOCKET);
}

static void torture_options_set_user(void **state) {
    ssh_session session = *state;
    int rc;
#ifndef _WIN32
# ifndef NSS_BUFLEN_PASSWD
#  define NSS_BUFLEN_PASSWD 4096
# endif /* NSS_BUFLEN_PASSWD */
    struct passwd pwd;
    struct passwd *pwdbuf;
    char buf[NSS_BUFLEN_PASSWD];

    /* get local username */
    rc = getpwuid_r(getuid(), &pwd, buf, NSS_BUFLEN_PASSWD, &pwdbuf);
    assert_true(rc == 0);
#endif /* _WIN32 */

    rc = ssh_options_set(session, SSH_OPTIONS_USER, "guru");
    assert_true(rc == 0);
    assert_string_equal(session->opts.username, "guru");


    rc = ssh_options_set(session, SSH_OPTIONS_USER, NULL);
    assert_true(rc == 0);

#ifndef _WIN32
    assert_string_equal(session->opts.username, pwd.pw_name);
#endif
}

/* TODO */
#if 0
static voidtorture_options_set_sshdir)
{
}
END_TEST
#endif

static void torture_options_set_identity(void **state) {
    ssh_session session = *state;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_ADD_IDENTITY, "identity1");
    assert_true(rc == 0);
    assert_string_equal(session->opts.identity->root->data, "identity1");

    rc = ssh_options_set(session, SSH_OPTIONS_IDENTITY, "identity2");
    assert_true(rc == 0);
    assert_string_equal(session->opts.identity->root->data, "identity2");
    assert_string_equal(session->opts.identity->root->next->data, "identity1");
}

static void torture_options_get_identity(void **state) {
    ssh_session session = *state;
    char *identity = NULL;
    int rc;

    rc = ssh_options_set(session, SSH_OPTIONS_ADD_IDENTITY, "identity1");
    assert_true(rc == 0);
    rc = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &identity);
    assert_true(rc == SSH_OK);
    assert_string_equal(identity, "identity1");
    SAFE_FREE(identity);

    rc = ssh_options_set(session, SSH_OPTIONS_IDENTITY, "identity2");
    assert_true(rc == 0);
    assert_string_equal(session->opts.identity->root->data, "identity2");
    rc = ssh_options_get(session, SSH_OPTIONS_IDENTITY, &identity);
    assert_true(rc == SSH_OK);
    assert_string_equal(identity, "identity2");
    free(identity);
}

static void torture_options_proxycommand(void **state) {
    ssh_session session = *state;
    int rc;

    /* Enable ProxyCommand */
    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "ssh -q -A -X -W %h:%p JUMPHOST");
    assert_int_equal(rc, 0);

    assert_string_equal(session->opts.ProxyCommand, "ssh -q -A -X -W %h:%p JUMPHOST");

    /* Disable ProxyCommand */
    rc = ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, "none");
    assert_int_equal(rc, 0);

    assert_null(session->opts.ProxyCommand);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test_setup_teardown(torture_options_set_host, setup, teardown),
        unit_test_setup_teardown(torture_options_get_host, setup, teardown),
        unit_test_setup_teardown(torture_options_set_port, setup, teardown),
        unit_test_setup_teardown(torture_options_get_port, setup, teardown),
        unit_test_setup_teardown(torture_options_set_fd, setup, teardown),
        unit_test_setup_teardown(torture_options_set_user, setup, teardown),
        unit_test_setup_teardown(torture_options_get_user, setup, teardown),
        unit_test_setup_teardown(torture_options_set_identity, setup, teardown),
        unit_test_setup_teardown(torture_options_get_identity, setup, teardown),
        unit_test_setup_teardown(torture_options_proxycommand, setup, teardown),
    };

    ssh_init();
    rc=run_tests(tests);
    ssh_finalize();
    return rc;
}
