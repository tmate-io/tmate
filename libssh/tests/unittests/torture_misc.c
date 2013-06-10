
#include <sys/types.h>
#ifndef _WIN32

#define _POSIX_PTHREAD_SEMANTICS
#include <pwd.h>
#endif

#define LIBSSH_STATIC
#include <libssh/priv.h>

#include "torture.h"
#include "misc.c"
#include "error.c"

#define TORTURE_TEST_DIR "/usr/local/bin/truc/much/.."


static void setup(void **state) {
    ssh_session session = ssh_new();
    *state = session;
}

static void teardown(void **state) {
    ssh_free(*state);
}

static void torture_get_user_home_dir(void **state) {
#ifndef _WIN32
    struct passwd *pwd = getpwuid(getuid());
#endif /* _WIN32 */
    char *user;

    (void) state;

    user = ssh_get_user_home_dir();
    assert_false(user == NULL);
#ifndef _WIN32
    assert_string_equal(user, pwd->pw_dir);
#endif /* _WIN32 */

    SAFE_FREE(user);
}

static void torture_basename(void **state) {
    char *path;

    (void) state;

    path=ssh_basename(TORTURE_TEST_DIR "/test");
    assert_true(path != NULL);
    assert_string_equal(path, "test");
    SAFE_FREE(path);
    path=ssh_basename(TORTURE_TEST_DIR "/test/");
    assert_true(path != NULL);
    assert_string_equal(path, "test");
    SAFE_FREE(path);
}

static void torture_dirname(void **state) {
    char *path;

    (void) state;

    path=ssh_dirname(TORTURE_TEST_DIR "/test");
    assert_true(path != NULL);
    assert_string_equal(path, TORTURE_TEST_DIR );
    SAFE_FREE(path);
    path=ssh_dirname(TORTURE_TEST_DIR "/test/");
    assert_true(path != NULL);
    assert_string_equal(path, TORTURE_TEST_DIR);
    SAFE_FREE(path);
}

static void torture_ntohll(void **state) {
    uint64_t value = 0x0123456789abcdef;
    uint32_t sample = 1;
    unsigned char *ptr = (unsigned char *) &sample;
    uint64_t check;

    (void) state;

    if (ptr[0] == 1){
      /* we're in little endian */
      check = 0xefcdab8967452301;
    } else {
      /* big endian */
      check = value;
    }
    value = ntohll(value);
    assert_true(value == check);
}

#ifdef _WIN32

static void torture_path_expand_tilde_win(void **state) {
    char *d;

    (void) state;

    d = ssh_path_expand_tilde("~\\.ssh");
    assert_false(d == NULL);
    print_message("Expanded path: %s\n", d);
    free(d);

    d = ssh_path_expand_tilde("/guru/meditation");
    assert_string_equal(d, "/guru/meditation");
    free(d);
}

#else /* _WIN32 */

static void torture_path_expand_tilde_unix(void **state) {
    char h[256];
    char *d;

    (void) state;

    snprintf(h, 256 - 1, "%s/.ssh", getenv("HOME"));

    d = ssh_path_expand_tilde("~/.ssh");
    assert_string_equal(d, h);
    free(d);

    d = ssh_path_expand_tilde("/guru/meditation");
    assert_string_equal(d, "/guru/meditation");
    free(d);

    snprintf(h, 256 - 1, "~%s/.ssh", getenv("USER"));
    d = ssh_path_expand_tilde(h);

    snprintf(h, 256 - 1, "%s/.ssh", getenv("HOME"));
    assert_string_equal(d, h);
    free(d);
}

#endif /* _WIN32 */

static void torture_path_expand_escape(void **state) {
    ssh_session session = *state;
    const char *s = "%d/%h/by/%r";
    char *e;

    session->opts.sshdir = strdup("guru");
    session->opts.host = strdup("meditation");
    session->opts.username = strdup("root");

    e = ssh_path_expand_escape(session, s);
    assert_string_equal(e, "guru/meditation/by/root");
    free(e);
}

static void torture_path_expand_known_hosts(void **state) {
    ssh_session session = *state;
    char *tmp;

    session->opts.sshdir = strdup("/home/guru/.ssh");

    tmp = ssh_path_expand_escape(session, "%d/known_hosts");
    assert_string_equal(tmp, "/home/guru/.ssh/known_hosts");
    free(tmp);
}

static void torture_timeout_elapsed(void **state){
    struct ssh_timestamp ts;
    (void) state;
    ssh_timestamp_init(&ts);
    usleep(50000);
    assert_true(ssh_timeout_elapsed(&ts,25));
    assert_false(ssh_timeout_elapsed(&ts,30000));
    assert_false(ssh_timeout_elapsed(&ts,75));
    assert_true(ssh_timeout_elapsed(&ts,0));
    assert_false(ssh_timeout_elapsed(&ts,-1));
}

static void torture_timeout_update(void **state){
    struct ssh_timestamp ts;
    (void) state;
    ssh_timestamp_init(&ts);
    usleep(50000);
    assert_int_equal(ssh_timeout_update(&ts,25), 0);
    assert_in_range(ssh_timeout_update(&ts,30000),29000,29960);
    assert_in_range(ssh_timeout_update(&ts,75),1,40);
    assert_int_equal(ssh_timeout_update(&ts,0),0);
    assert_int_equal(ssh_timeout_update(&ts,-1),-1);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test(torture_get_user_home_dir),
        unit_test(torture_basename),
        unit_test(torture_dirname),
        unit_test(torture_ntohll),
#ifdef _WIN32
        unit_test(torture_path_expand_tilde_win),
#else
        unit_test(torture_path_expand_tilde_unix),
#endif
        unit_test_setup_teardown(torture_path_expand_escape, setup, teardown),
        unit_test_setup_teardown(torture_path_expand_known_hosts, setup, teardown),
        unit_test(torture_timeout_elapsed),
        unit_test(torture_timeout_update),
    };

    ssh_init();
    rc=run_tests(tests);
    ssh_finalize();
    return rc;
}
