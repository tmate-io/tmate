#define LIBSSH_STATIC

#include "torture.h"
#include "sftp.c"

static void torture_sftp_ext_new(void **state) {
    sftp_ext x;

    (void) state;

    x = sftp_ext_new();
    assert_false(x == NULL);
    assert_int_equal(x->count, 0);
    assert_true(x->name == NULL);
    assert_true(x->data == NULL);

    sftp_ext_free(x);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test(torture_sftp_ext_new),
    };

    ssh_init();

    rc = run_tests(tests);
    ssh_finalize();

    return rc;
}
