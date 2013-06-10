#define LIBSSH_STATIC
#include <libssh/priv.h>
#include <libssh/callbacks.h>
#include <pthread.h>
#include <errno.h>
#include "torture.h"

#ifdef HAVE_LIBGCRYPT
#define NUM_LOOPS 1000
#else
/* openssl is much faster */
#define NUM_LOOPS 20000
#endif
#define NUM_THREADS 100

static void setup(void **state) {
    (void) state;

    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    ssh_init();
}

static void teardown(void **state) {
    (void) state;

    ssh_finalize();
}

static void *torture_rand_thread(void *threadid) {
    char buffer[12];
    int i;
    int r;

    (void) threadid;

    buffer[0] = buffer[1] = buffer[10] = buffer[11] = 'X';
    for(i = 0; i < NUM_LOOPS; ++i) {
        r = ssh_get_random(&buffer[2], i % 8 + 1, 0);
        assert_true(r == 1);
    }

    pthread_exit(NULL);
}

static void torture_rand_threading(void **state) {
    pthread_t threads[NUM_THREADS];
    int i;
    int err;

    (void) state;

    for(i = 0; i < NUM_THREADS; ++i) {
        err = pthread_create(&threads[i], NULL, torture_rand_thread, NULL);
        assert_int_equal(err, 0);
    }
    for(i = 0; i < NUM_THREADS; ++i) {
        err=pthread_join(threads[i], NULL);
        assert_int_equal(err, 0);
    }
}

int torture_run_tests(void) {
    const UnitTest tests[] = {
        unit_test_setup_teardown(torture_rand_threading, setup, teardown),
    };

    return run_tests(tests);
}
