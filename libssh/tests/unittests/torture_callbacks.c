#define LIBSSH_STATIC

#include "torture.h"
#include <libssh/priv.h>
#include <libssh/callbacks.h>

static int myauthcallback (const char *prompt, char *buf, size_t len,
    int echo, int verify, void *userdata) {
    (void) prompt;
    (void) buf;
    (void) len;
    (void) echo;
    (void) verify;
    (void) userdata;
    return 0;
}

static void setup(void **state) {
    struct ssh_callbacks_struct *cb;

    cb = malloc(sizeof(struct ssh_callbacks_struct));
    assert_false(cb == NULL);
    ZERO_STRUCTP(cb);

    cb->userdata = (void *) 0x0badc0de;
    cb->auth_function = myauthcallback;

    ssh_callbacks_init(cb);
    *state = cb;
}

static void teardown(void **state) {
    free(*state);
}

static void torture_callbacks_size(void **state) {
    struct ssh_callbacks_struct *cb = *state;;

    assert_int_not_equal(cb->size, 0);
}

static void torture_callbacks_exists(void **state) {
    struct ssh_callbacks_struct *cb = *state;

    assert_int_not_equal(ssh_callbacks_exists(cb, auth_function), 0);
    assert_int_equal(ssh_callbacks_exists(cb, log_function), 0);

    /*
     * We redefine size so auth_function is outside the range of
     * callbacks->size.
     */
    cb->size = (unsigned char *) &cb->auth_function - (unsigned char *) cb;
    assert_int_equal(ssh_callbacks_exists(cb, auth_function), 0);

    /* Now make it one pointer bigger so we spill over the auth_function slot */
    cb->size += sizeof(void *);
    assert_int_not_equal(ssh_callbacks_exists(cb, auth_function), 0);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test_setup_teardown(torture_callbacks_size, setup, teardown),
        unit_test_setup_teardown(torture_callbacks_exists, setup, teardown),
    };

    ssh_init();
    rc=run_tests(tests);
    ssh_finalize();
    return rc;
}
