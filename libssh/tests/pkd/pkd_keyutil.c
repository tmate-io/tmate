/*
 * pkd_keyutil.c -- pkd test key utilities
 *
 * (c) 2014 Jon Simons
 */

#include <setjmp.h> // for cmocka
#include <stdarg.h> // for cmocka
#include <unistd.h> // for cmocka
#include <cmocka.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pkd_client.h"
#include "pkd_keyutil.h"
#include "pkd_util.h"

void setup_rsa_key() {
    int rc = 0;
    if (access(LIBSSH_RSA_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t rsa -q -N \"\" -f "
                            LIBSSH_RSA_TESTKEY);
    }
    assert_int_equal(rc, 0);
}

void setup_dsa_key() {
    int rc = 0;
    if (access(LIBSSH_DSA_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t dsa -q -N \"\" -f "
                            LIBSSH_DSA_TESTKEY);
    }
    assert_int_equal(rc, 0);
}

void setup_ecdsa_keys() {
    int rc = 0;

    if (access(LIBSSH_ECDSA_256_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ecdsa -b 256 -q -N \"\" -f "
                            LIBSSH_ECDSA_256_TESTKEY);
        assert_int_equal(rc, 0);
    }
    if (access(LIBSSH_ECDSA_384_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ecdsa -b 384 -q -N \"\" -f "
                            LIBSSH_ECDSA_384_TESTKEY);
        assert_int_equal(rc, 0);
    }
    if (access(LIBSSH_ECDSA_521_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ecdsa -b 521 -q -N \"\" -f "
                            LIBSSH_ECDSA_521_TESTKEY);
        assert_int_equal(rc, 0);
    }
}

static void cleanup_key(const char *privkey, const char *pubkey) {
    unlink(privkey);
    unlink(pubkey);
}

void cleanup_rsa_key() {
    cleanup_key(LIBSSH_RSA_TESTKEY, LIBSSH_RSA_TESTKEY ".pub");
}

void cleanup_dsa_key() {
    cleanup_key(LIBSSH_DSA_TESTKEY, LIBSSH_DSA_TESTKEY ".pub");
}

void cleanup_ecdsa_keys() {
    cleanup_key(LIBSSH_ECDSA_256_TESTKEY, LIBSSH_ECDSA_256_TESTKEY ".pub");
    cleanup_key(LIBSSH_ECDSA_384_TESTKEY, LIBSSH_ECDSA_384_TESTKEY ".pub");
    cleanup_key(LIBSSH_ECDSA_521_TESTKEY, LIBSSH_ECDSA_521_TESTKEY ".pub");
}

void setup_openssh_client_keys() {
    int rc = 0;

    if (access(OPENSSH_DSA_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t dsa -q -N \"\" -f "
                            OPENSSH_DSA_TESTKEY);
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_RSA_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t rsa -q -N \"\" -f "
                            OPENSSH_RSA_TESTKEY);
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_ECDSA256_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ecdsa -b 256 -q -N \"\" -f "
                            OPENSSH_ECDSA256_TESTKEY);
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_ECDSA384_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ecdsa -b 384 -q -N \"\" -f "
                            OPENSSH_ECDSA384_TESTKEY);
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_ECDSA521_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ecdsa -b 521 -q -N \"\" -f "
                            OPENSSH_ECDSA521_TESTKEY);
    }
    assert_int_equal(rc, 0);

    if (access(OPENSSH_ED25519_TESTKEY, F_OK) != 0) {
        rc = system_checked(OPENSSH_KEYGEN " -t ed25519 -q -N \"\" -f "
                            OPENSSH_ED25519_TESTKEY);
    }
    assert_int_equal(rc, 0);
}

void cleanup_openssh_client_keys() {
    cleanup_key(OPENSSH_DSA_TESTKEY, OPENSSH_DSA_TESTKEY ".pub");
    cleanup_key(OPENSSH_RSA_TESTKEY, OPENSSH_RSA_TESTKEY ".pub");
    cleanup_key(OPENSSH_ECDSA256_TESTKEY, OPENSSH_ECDSA256_TESTKEY ".pub");
    cleanup_key(OPENSSH_ECDSA384_TESTKEY, OPENSSH_ECDSA384_TESTKEY ".pub");
    cleanup_key(OPENSSH_ECDSA521_TESTKEY, OPENSSH_ECDSA521_TESTKEY ".pub");
    cleanup_key(OPENSSH_ED25519_TESTKEY,  OPENSSH_ED25519_TESTKEY  ".pub");
}

void setup_dropbear_client_rsa_key() {
    int rc = 0;
    if (access(DROPBEAR_RSA_TESTKEY, F_OK) != 0) {
        rc = system_checked(DROPBEAR_KEYGEN " -t rsa -f "
                            DROPBEAR_RSA_TESTKEY " 1>/dev/null 2>/dev/null");
    }
    assert_int_equal(rc, 0);
}

void cleanup_dropbear_client_rsa_key() {
    unlink(DROPBEAR_RSA_TESTKEY);
}
