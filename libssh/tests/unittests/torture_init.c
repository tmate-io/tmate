#define LIBSSH_STATIC

#include "torture.h"
#include "libssh/libssh.h"

static void torture_ssh_init(void **state) {
    int rc;

    (void) state;

    rc = ssh_init();
    assert_int_equal(rc, SSH_OK);
    rc = ssh_finalize();
    assert_int_equal(rc, SSH_OK);
}

int torture_run_tests(void) {
    const UnitTest tests[] = {
        unit_test(torture_ssh_init),
    };

    return run_tests(tests);
}
