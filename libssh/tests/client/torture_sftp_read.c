#define LIBSSH_STATIC

#include "torture.h"
#include "sftp.c"

#define MAX_XFER_BUF_SIZE 16384

static void setup(void **state) {
    ssh_session session;
    struct torture_sftp *t;
    const char *host;
    const char *user;
    const char *password;

    host = getenv("TORTURE_HOST");
    if (host == NULL) {
        host = "localhost";
    }

    user = getenv("TORTURE_USER");
    password = getenv("TORTURE_PASSWORD");

    session = torture_ssh_session(host, user, password);
    assert_false(session == NULL);
    t = torture_sftp_session(session);
    assert_false(t == NULL);

    *state = t;
}

static void teardown(void **state) {
    struct torture_sftp *t = (struct torture_sftp*) *state;

    assert_false(t == NULL);

    torture_rmdirs(t->testdir);
    torture_sftp_close(t);
}

static void torture_sftp_read_blocking(void **state) {
    struct torture_sftp *t = (struct torture_sftp*) *state;
    char libssh_tmp_file[] = "/tmp/libssh_sftp_test_XXXXXX";
    char buf[MAX_XFER_BUF_SIZE];
    ssize_t bytesread;
    ssize_t byteswritten;
    int fd;
    sftp_file file;


    file = sftp_open(t->sftp, "/usr/bin/ssh", O_RDONLY, 0);
    assert_non_null(file);

    fd = mkstemp(libssh_tmp_file);
    unlink(libssh_tmp_file);

    for (;;) {
        bytesread = sftp_read(file, buf, MAX_XFER_BUF_SIZE);
        if (bytesread == 0) {
                break; /* EOF */
        }
        assert_false(bytesread < 0);

        byteswritten = write(fd, buf, bytesread);
        assert_int_equal(byteswritten, bytesread);
    }

    close(fd);
    sftp_close(file);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test_setup_teardown(torture_sftp_read_blocking, setup, teardown)
    };

    ssh_init();

    rc = run_tests(tests);
    ssh_finalize();

    return rc;
}
