#define LIBSSH_STATIC

#include "torture.h"
#include "legacy.c"

#define LIBSSH_RSA_TESTKEY "libssh_testkey.id_rsa"
#define LIBSSH_DSA_TESTKEY "libssh_testkey.id_dsa"
#define LIBSSH_PASSPHRASE "libssh-rocks"

static void setup_rsa_key(void **state) {
    ssh_session session;
    int rc;

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    rc = system("ssh-keygen -t rsa -q -N \"\" -f " LIBSSH_RSA_TESTKEY);
    assert_true(rc == 0);

    session = ssh_new();
    *state = session;
}

static void setup_dsa_key(void **state) {
    ssh_session session;
    int rc;

    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    rc = system("ssh-keygen -t dsa -q -N \"\" -f " LIBSSH_DSA_TESTKEY);
    assert_true(rc == 0);

    session = ssh_new();
    *state = session;
}

static void setup_both_keys(void **state) {
    setup_rsa_key(state);
    ssh_free(*state);
    setup_dsa_key(state);
}

static void setup_both_keys_passphrase(void **state) {
    ssh_session session;
    int rc;

    rc = system("ssh-keygen -t rsa -N " LIBSSH_PASSPHRASE " -f " LIBSSH_RSA_TESTKEY);
    assert_true(rc == 0);

    rc = system("ssh-keygen -t dsa -N " LIBSSH_PASSPHRASE " -f " LIBSSH_DSA_TESTKEY);
    assert_true(rc == 0);

    session = ssh_new();
    *state = session;
}
static void teardown(void **state) {
    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    ssh_free(*state);
}

static void torture_pubkey_from_file(void **state) {
    ssh_session session = *state;
    ssh_string pubkey;
    int type, rc;

    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey, &type);

    assert_true(rc == 0);

    ssh_string_free(pubkey);

    /* test if it returns 1 if pubkey doesn't exist */
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey, &type);
    assert_true(rc == 1);

    /* test if it returns -1 if privkey doesn't exist */
    unlink(LIBSSH_RSA_TESTKEY);

    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey, &type);
    assert_true(rc == -1);
}

static int torture_read_one_line(const char *filename, char *buffer, size_t len) {
  FILE *fp;
  size_t rc;

  fp = fopen(filename, "r");
  if (fp == NULL) {
    return -1;
  }

  rc = fread(buffer, len, 1, fp);
  if (rc != 0 || ferror(fp)) {
    fclose(fp);
    return -1;
  }

  fclose(fp);

  return 0;
}

static void torture_pubkey_generate_from_privkey(void **state) {
    ssh_session session = *state;
    ssh_private_key privkey = NULL;
    ssh_public_key pubkey = NULL;
    ssh_string pubkey_orig = NULL;
    ssh_string pubkey_new = NULL;
    char pubkey_line_orig[512] = {0};
    char pubkey_line_new[512] = {0};
    int type_orig = 0;
    int type_new = 0;
    int rc;

    /* read the publickey */
    rc = ssh_try_publickey_from_file(session, LIBSSH_RSA_TESTKEY, &pubkey_orig,
        &type_orig);
    assert_true(rc == 0);
    assert_true(pubkey_orig != NULL);

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub", pubkey_line_orig,
        sizeof(pubkey_line_orig));
    assert_true(rc == 0);

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    privkey = privatekey_from_file(session, LIBSSH_RSA_TESTKEY, 0, NULL);
    assert_true(privkey != NULL);

    pubkey = publickey_from_privatekey(privkey);
    assert_true(pubkey != NULL);
    type_new = privkey->type;
    privatekey_free(privkey);

    pubkey_new = publickey_to_string(pubkey);
    publickey_free(pubkey);

    assert_true(pubkey_new != NULL);

    assert_true(ssh_string_len(pubkey_orig) == ssh_string_len(pubkey_new));
    assert_memory_equal(ssh_string_data(pubkey_orig),
                        ssh_string_data(pubkey_new),
                        ssh_string_len(pubkey_orig));

    rc = ssh_publickey_to_file(session, LIBSSH_RSA_TESTKEY ".pub", pubkey_new, type_new);
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub", pubkey_line_new,
        sizeof(pubkey_line_new));
    assert_true(rc == 0);

    assert_string_equal(pubkey_line_orig, pubkey_line_new);

    ssh_string_free(pubkey_orig);
    ssh_string_free(pubkey_new);
}

/**
 * @brief tests the privatekey_from_file function without passphrase
 */
static void torture_privatekey_from_file(void **state) {
    ssh_session session = *state;
    ssh_private_key key = NULL;

    key = privatekey_from_file(session, LIBSSH_RSA_TESTKEY, SSH_KEYTYPE_RSA, NULL);
    assert_true(key != NULL);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }

    key = privatekey_from_file(session, LIBSSH_DSA_TESTKEY, SSH_KEYTYPE_DSS, NULL);
    assert_true(key != NULL);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }

    /* Test the automatic type discovery */
    key = privatekey_from_file(session, LIBSSH_RSA_TESTKEY, 0, NULL);
    assert_true(key != NULL);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }

    key = privatekey_from_file(session, LIBSSH_DSA_TESTKEY, 0, NULL);
    assert_true(key != NULL);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }
}

/**
 * @brief tests the privatekey_from_file function with passphrase
 */
static void torture_privatekey_from_file_passphrase(void **state) {
    ssh_session session = *state;
    ssh_private_key key = NULL;

    key = privatekey_from_file(session, LIBSSH_RSA_TESTKEY, SSH_KEYTYPE_RSA, LIBSSH_PASSPHRASE);
    assert_true(key != NULL);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }

    key = privatekey_from_file(session, LIBSSH_DSA_TESTKEY, SSH_KEYTYPE_DSS, LIBSSH_PASSPHRASE);
    assert_true(key != NULL);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }

    /* Test the automatic type discovery */
    key = privatekey_from_file(session, LIBSSH_RSA_TESTKEY, 0, LIBSSH_PASSPHRASE);
    assert_true(key != NULL);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }

    key = privatekey_from_file(session, LIBSSH_DSA_TESTKEY, 0, LIBSSH_PASSPHRASE);
    assert_true(key != NULL);
    if (key != NULL) {
        privatekey_free(key);
        key = NULL;
    }
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test_setup_teardown(torture_pubkey_from_file,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pubkey_generate_from_privkey,
                                 setup_rsa_key, teardown),
        unit_test_setup_teardown(torture_privatekey_from_file,
                                 setup_both_keys,
                                 teardown),
        unit_test_setup_teardown(torture_privatekey_from_file_passphrase,
                                 setup_both_keys_passphrase, teardown),
    };


    ssh_init();
    rc=run_tests(tests);
    ssh_finalize();
    return rc;
}
