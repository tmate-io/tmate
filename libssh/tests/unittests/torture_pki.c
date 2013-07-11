#define LIBSSH_STATIC

#include "torture.h"
#include "pki.c"
#include <sys/stat.h>
#include <fcntl.h>

#define LIBSSH_RSA_TESTKEY "libssh_testkey.id_rsa"
#define LIBSSH_DSA_TESTKEY "libssh_testkey.id_dsa"
#define LIBSSH_ECDSA_TESTKEY "libssh_testkey.id_ecdsa"
#define LIBSSH_PASSPHRASE "libssh-rocks"
const unsigned char HASH[] = "12345678901234567890";

static void setup_rsa_key(void **state) {
    int rc;

    (void) state; /* unused */

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    rc = system("ssh-keygen -t rsa -q -N \"\" -f " LIBSSH_RSA_TESTKEY);
    assert_true(rc == 0);
}

static void setup_dsa_key(void **state) {
    int rc;

    (void) state; /* unused */

    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    rc = system("ssh-keygen -t dsa -q -N \"\" -f " LIBSSH_DSA_TESTKEY);
    assert_true(rc == 0);
}

#ifdef HAVE_OPENSSL_ECC
static void setup_ecdsa_key(void **state) {
    int rc;

    (void) state; /* unused */

    unlink(LIBSSH_ECDSA_TESTKEY);
    unlink(LIBSSH_ECDSA_TESTKEY ".pub");

    rc = system("ssh-keygen -t ecdsa -q -N \"\" -f " LIBSSH_ECDSA_TESTKEY);
    assert_true(rc == 0);
}
#endif

static void setup_both_keys(void **state) {
    (void) state; /* unused */

    setup_rsa_key(state);
    setup_dsa_key(state);
}

static void setup_both_keys_passphrase(void **state) {
    int rc;

    (void) state; /* unused */

    rc = system("ssh-keygen -t rsa -q -N " LIBSSH_PASSPHRASE " -f " LIBSSH_RSA_TESTKEY);
    assert_true(rc == 0);

    rc = system("ssh-keygen -t dsa -q -N " LIBSSH_PASSPHRASE " -f " LIBSSH_DSA_TESTKEY);
    assert_true(rc == 0);
}

static void teardown(void **state) {
    (void) state; /* unused */

    unlink(LIBSSH_DSA_TESTKEY);
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    unlink(LIBSSH_RSA_TESTKEY);
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    unlink(LIBSSH_ECDSA_TESTKEY);
    unlink(LIBSSH_ECDSA_TESTKEY ".pub");
}

static char *read_file(const char *filename) {
    char *key;
    int fd;
    int size;
    int rc;
    struct stat buf;

    assert_true(filename != NULL);
    assert_true(*filename != '\0');

    rc = stat(filename, &buf);
    assert_int_equal(rc, 0);

    key = malloc(buf.st_size + 1);
    assert_true(key != NULL);

    fd = open(filename, O_RDONLY);
    assert_true(fd >= 0);

    size = read(fd, key, buf.st_size);
    assert_true(size == buf.st_size);

    close(fd);

    key[size] = '\0';
    return key;
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

static void torture_pki_keytype(void **state) {
    enum ssh_keytypes_e type;
    const char *type_c;

    (void) state; /* unused */

    type = ssh_key_type(NULL);
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type = ssh_key_type_from_name(NULL);
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type = ssh_key_type_from_name("42");
    assert_true(type == SSH_KEYTYPE_UNKNOWN);

    type_c = ssh_key_type_to_char(SSH_KEYTYPE_UNKNOWN);
    assert_true(type_c == NULL);

    type_c = ssh_key_type_to_char(42);
    assert_true(type_c == NULL);
}

static void torture_pki_signature(void **state)
{
    ssh_signature sig;

    (void) state; /* unused */

    sig = ssh_signature_new();
    assert_true(sig != NULL);

    ssh_signature_free(sig);
}

static void torture_pki_import_privkey_base64_RSA(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;
    enum ssh_keytypes_e type;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    type = ssh_key_type(key);
    assert_true(type == SSH_KEYTYPE_RSA);

    rc = ssh_key_is_public(key);
    assert_true(rc == 1);

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_import_privkey_base64_NULL_key(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    key = ssh_key_new();
    assert_true(key != NULL);

    /* test if it returns -1 if key is NULL */
    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, NULL);
    assert_true(rc == -1);

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_import_privkey_base64_NULL_str(void **state) {
    int rc;
    char *key_str;
    ssh_key key = NULL;
    const char *passphrase = LIBSSH_PASSPHRASE;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    /* test if it returns -1 if key_str is NULL */
    rc = ssh_pki_import_privkey_base64(NULL, passphrase, NULL, NULL, &key);
    assert_true(rc == -1);

    free(key_str);
    ssh_key_free(key);
}

static void torture_pki_import_privkey_base64_DSA(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_DSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    free(key_str);
    ssh_key_free(key);
}

#ifdef HAVE_ECC
static void torture_pki_import_privkey_base64_ECDSA(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    const char *passphrase = LIBSSH_PASSPHRASE;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_ECDSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    free(key_str);
    ssh_key_free(key);
}
#endif

static void torture_pki_import_privkey_base64_passphrase(void **state) {
    int rc;
    char *key_str;
    ssh_key key = NULL;
    const char *passphrase = LIBSSH_PASSPHRASE;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);
    ssh_key_free(key);

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(key_str, "wrong passphrase !!", NULL,
            NULL, &key);
    assert_true(rc == -1);

#ifndef HAVE_LIBCRYPTO
    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(key_str, NULL, NULL, NULL, &key);
    assert_true(rc == -1);
#endif

    free(key_str);

    /* same for DSA */
    key_str = read_file(LIBSSH_DSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);
    ssh_key_free(key);

    /* test if it returns -1 if passphrase is wrong */
    rc = ssh_pki_import_privkey_base64(key_str, "wrong passphrase !!", NULL, NULL, &key);
    assert_true(rc == -1);

#ifndef HAVE_LIBCRYPTO
    /* test if it returns -1 if passphrase is NULL */
    /* libcrypto asks for a passphrase, so skip this test */
    rc = ssh_pki_import_privkey_base64(key_str, NULL, NULL, NULL, &key);
    assert_true(rc == -1);
#endif

    free(key_str);
}

static void torture_pki_pki_publickey_from_privatekey_RSA(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_RSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    free(key_str);
    ssh_key_free(key);
    ssh_key_free(pubkey);
}

static void torture_pki_pki_publickey_from_privatekey_DSA(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_DSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    free(key_str);
    ssh_key_free(key);
    ssh_key_free(pubkey);
}

#ifdef HAVE_ECC
static void torture_pki_publickey_from_privatekey_ECDSA(void **state) {
    int rc;
    char *key_str;
    ssh_key key;
    ssh_key pubkey;
    const char *passphrase = NULL;

    (void) state; /* unused */

    key_str = read_file(LIBSSH_ECDSA_TESTKEY);
    assert_true(key_str != NULL);

    rc = ssh_pki_import_privkey_base64(key_str, passphrase, NULL, NULL, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(key, &pubkey);
    assert_true(rc == SSH_OK);

    free(key_str);
    ssh_key_free(key);
    ssh_key_free(pubkey);
}
#endif

static void torture_pki_publickey_dsa_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key, *key_buf, *p;
    const char *q;
    ssh_key key;
    int rc;

    (void) state; /* unused */

    key_buf = read_file(LIBSSH_DSA_TESTKEY ".pub");
    assert_true(key_buf != NULL);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(type == SSH_KEYTYPE_DSS);

    q = ++p;
    while (*p != ' ') p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);

    assert_string_equal(q, b64_key);

    free(b64_key);
    free(key_buf);
    ssh_key_free(key);
}

#ifdef HAVE_ECC
static void torture_pki_publickey_ecdsa_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key, *key_buf, *p;
    const char *q;
    ssh_key key;
    int rc;

    (void) state; /* unused */

    key_buf = read_file(LIBSSH_ECDSA_TESTKEY ".pub");
    assert_true(key_buf != NULL);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(type == SSH_KEYTYPE_ECDSA);

    q = ++p;
    while (*p != ' ') p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);

    assert_string_equal(q, b64_key);

    free(b64_key);
    free(key_buf);
    ssh_key_free(key);
}
#endif

static void torture_pki_publickey_rsa_base64(void **state)
{
    enum ssh_keytypes_e type;
    char *b64_key, *key_buf, *p;
    const char *q;
    ssh_key key;
    int rc;

    (void) state; /* unused */

    key_buf = read_file(LIBSSH_RSA_TESTKEY ".pub");
    assert_true(key_buf != NULL);

    q = p = key_buf;
    while (*p != ' ') p++;
    *p = '\0';

    type = ssh_key_type_from_name(q);
    assert_true(((type == SSH_KEYTYPE_RSA) ||
                 (type == SSH_KEYTYPE_RSA1)));

    q = ++p;
    while (*p != ' ') p++;
    *p = '\0';

    rc = ssh_pki_import_pubkey_base64(q, type, &key);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(key, &b64_key);
    assert_true(rc == 0);

    assert_string_equal(q, b64_key);

    free(b64_key);
    free(key_buf);
    ssh_key_free(key);
}

static void torture_generate_pubkey_from_privkey_rsa(void **state) {
    char pubkey_original[4096] = {0};
    char pubkey_generated[4096] = {0};
    ssh_key privkey;
    ssh_key pubkey;
    int rc;

    (void) state; /* unused */

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub",
                               pubkey_original,
                               sizeof(pubkey_original));
    assert_true(rc == 0);

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_RSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_RSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_RSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);

    assert_string_equal(pubkey_original, pubkey_generated);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}

static void torture_generate_pubkey_from_privkey_dsa(void **state) {
    char pubkey_original[4096] = {0};
    char pubkey_generated[4096] = {0};
    ssh_key privkey;
    ssh_key pubkey;
    int rc;

    (void) state; /* unused */

    rc = torture_read_one_line(LIBSSH_DSA_TESTKEY ".pub",
                               pubkey_original,
                               sizeof(pubkey_original));
    assert_true(rc == 0);

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_DSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_DSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_DSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);

    assert_string_equal(pubkey_original, pubkey_generated);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}

#ifdef HAVE_ECC
static void torture_generate_pubkey_from_privkey_ecdsa(void **state) {
    char pubkey_original[4096] = {0};
    char pubkey_generated[4096] = {0};
    ssh_key privkey;
    ssh_key pubkey;
    int rc;

    (void) state; /* unused */

    rc = torture_read_one_line(LIBSSH_ECDSA_TESTKEY ".pub",
                               pubkey_original,
                               sizeof(pubkey_original));
    assert_true(rc == 0);

    /* remove the public key, generate it from the private key and write it. */
    unlink(LIBSSH_ECDSA_TESTKEY ".pub");

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_file(pubkey, LIBSSH_ECDSA_TESTKEY ".pub");
    assert_true(rc == 0);

    rc = torture_read_one_line(LIBSSH_ECDSA_TESTKEY ".pub",
                               pubkey_generated,
                               sizeof(pubkey_generated));
    assert_true(rc == 0);

    assert_string_equal(pubkey_original, pubkey_generated);

    ssh_key_free(privkey);
    ssh_key_free(pubkey);
}
#endif

static void torture_pki_duplicate_key_rsa(void **state)
{
    int rc;
    char *b64_key;
    char *b64_key_gen;
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_RSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    ssh_key_free(pubkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_RSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key_gen);
    assert_true(rc == 0);

    assert_string_equal(b64_key, b64_key_gen);

    rc = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
    ssh_string_free_char(b64_key);
    ssh_string_free_char(b64_key_gen);
}

static void torture_pki_duplicate_key_dsa(void **state)
{
    int rc;
    char *b64_key;
    char *b64_key_gen;
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_DSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    ssh_key_free(pubkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_DSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key_gen);
    assert_true(rc == 0);

    assert_string_equal(b64_key, b64_key_gen);

    rc = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
    ssh_string_free_char(b64_key);
    ssh_string_free_char(b64_key_gen);
}

#ifdef HAVE_ECC
static void torture_pki_duplicate_key_ecdsa(void **state)
{
    int rc;
    char *b64_key;
    char *b64_key_gen;
    ssh_key pubkey;
    ssh_key privkey;
    ssh_key privkey_dup;

    (void) state;

    rc = ssh_pki_import_pubkey_file(LIBSSH_ECDSA_TESTKEY ".pub", &pubkey);
    assert_true(rc == 0);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key);
    assert_true(rc == 0);
    ssh_key_free(pubkey);

    rc = ssh_pki_import_privkey_file(LIBSSH_ECDSA_TESTKEY,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &privkey);
    assert_true(rc == 0);

    privkey_dup = ssh_key_dup(privkey);
    assert_true(privkey_dup != NULL);

    rc = ssh_pki_export_privkey_to_pubkey(privkey, &pubkey);
    assert_true(rc == SSH_OK);

    rc = ssh_pki_export_pubkey_base64(pubkey, &b64_key_gen);
    assert_true(rc == 0);

    assert_string_equal(b64_key, b64_key_gen);

    rc = ssh_key_cmp(privkey, privkey_dup, SSH_KEY_CMP_PRIVATE);
    assert_true(rc == 0);

    ssh_key_free(pubkey);
    ssh_key_free(privkey);
    ssh_key_free(privkey_dup);
    ssh_string_free_char(b64_key);
    ssh_string_free_char(b64_key_gen);
}
#endif

static void torture_pki_generate_key_rsa(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 1024, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 4096, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

static void torture_pki_generate_key_rsa1(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA1, 1024, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA1, 2048, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_RSA1, 4096, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

static void torture_pki_generate_key_dsa(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 1024, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 2048, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_DSS, 3072, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}

#ifdef HAVE_ECC
static void torture_pki_generate_key_ecdsa(void **state)
{
    int rc;
    ssh_key key;
    ssh_signature sign;
    ssh_session session=ssh_new();
    (void) state;

    rc = ssh_pki_generate(SSH_KEYTYPE_ECDSA, 256, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_ECDSA, 384, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    rc = ssh_pki_generate(SSH_KEYTYPE_ECDSA, 512, &key);
    assert_true(rc == SSH_OK);
    assert_true(key != NULL);
    sign = pki_do_sign(key, HASH, 20);
    assert_true(sign != NULL);
    rc = pki_signature_verify(session,sign,key,HASH,20);
    assert_true(rc == SSH_OK);
    ssh_signature_free(sign);
    ssh_key_free(key);
    key=NULL;

    ssh_free(session);
}
#endif

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test(torture_pki_keytype),

        unit_test(torture_pki_signature),

        /* ssh_pki_import_privkey_base64 */
        unit_test_setup_teardown(torture_pki_import_privkey_base64_NULL_key,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_NULL_str,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_RSA,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_import_privkey_base64_DSA,
                                 setup_dsa_key,
                                 teardown),
#ifdef HAVE_ECC
        unit_test_setup_teardown(torture_pki_import_privkey_base64_ECDSA,
                                 setup_ecdsa_key,
                                 teardown),
#endif
        unit_test_setup_teardown(torture_pki_import_privkey_base64_passphrase,
                                 setup_both_keys_passphrase,
                                 teardown),
        /* ssh_pki_export_privkey_to_pubkey */
        unit_test_setup_teardown(torture_pki_pki_publickey_from_privatekey_RSA,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_pki_publickey_from_privatekey_DSA,
                                 setup_dsa_key,
                                 teardown),
#ifdef HAVE_ECC
        unit_test_setup_teardown(torture_pki_publickey_from_privatekey_ECDSA,
                                 setup_ecdsa_key,
                                 teardown),
#endif
        /* public key */
        unit_test_setup_teardown(torture_pki_publickey_dsa_base64,
                                 setup_dsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_publickey_rsa_base64,
                                 setup_rsa_key,
                                 teardown),
#ifdef HAVE_ECC
        unit_test_setup_teardown(torture_pki_publickey_ecdsa_base64,
                                 setup_ecdsa_key,
                                 teardown),
#endif

        unit_test_setup_teardown(torture_generate_pubkey_from_privkey_dsa,
                                 setup_dsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_generate_pubkey_from_privkey_rsa,
                                 setup_rsa_key,
                                 teardown),
#ifdef HAVE_ECC
        unit_test_setup_teardown(torture_generate_pubkey_from_privkey_ecdsa,
                                 setup_ecdsa_key,
                                 teardown),
#endif

        unit_test_setup_teardown(torture_pki_duplicate_key_rsa,
                                 setup_rsa_key,
                                 teardown),
        unit_test_setup_teardown(torture_pki_duplicate_key_dsa,
                                 setup_dsa_key,
                                 teardown),
#ifdef HAVE_ECC
        unit_test_setup_teardown(torture_pki_duplicate_key_ecdsa,
                                 setup_ecdsa_key,
                                 teardown),
#endif
        unit_test(torture_pki_generate_key_rsa),
        unit_test(torture_pki_generate_key_rsa1),
        unit_test(torture_pki_generate_key_dsa),
#ifdef HAVE_ECC
        unit_test(torture_pki_generate_key_ecdsa),
#endif
    };

    (void)setup_both_keys;

    ssh_init();
    rc=run_tests(tests);
    ssh_finalize();
    return rc;
}
