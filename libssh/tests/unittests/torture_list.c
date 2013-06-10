#define LIBSSH_STATIC

#include "torture.h"
#include "error.c"
#include "misc.c"

static void torture_ssh_list_new(void **state) {
    struct ssh_list *xlist;

    (void) state;

    xlist = ssh_list_new();

    assert_true(xlist != NULL);
    assert_true(xlist->root == NULL);
    assert_true(xlist->end == NULL);

    ssh_list_free(xlist);
}

static void torture_ssh_list_append(void **state) {
    struct ssh_list *xlist;
    int rc;

    (void) state;

    xlist = ssh_list_new();
    assert_true(xlist != NULL);

    rc = ssh_list_append(xlist, "item1");
    assert_true(rc == 0);
    assert_string_equal((const char *) xlist->root->data, "item1");
    assert_string_equal((const char *) xlist->end->data, "item1");

    rc = ssh_list_append(xlist, "item2");
    assert_true(rc == 0);
    assert_string_equal((const char *) xlist->root->data, "item1");
    assert_string_equal((const char *) xlist->end->data, "item2");

    rc = ssh_list_append(xlist, "item3");
    assert_true(rc == 0);
    assert_string_equal((const char *) xlist->root->data, "item1");
    assert_string_equal((const char *) xlist->root->next->data, "item2");
    assert_string_equal((const char *) xlist->root->next->next->data, "item3");
    assert_string_equal((const char *) xlist->end->data, "item3");

    ssh_list_free(xlist);
}

static void torture_ssh_list_prepend(void **state) {
    struct ssh_list *xlist;
    int rc;

    (void) state;

    xlist = ssh_list_new();
    assert_true(xlist != NULL);

    rc = ssh_list_prepend(xlist, "item1");
    assert_true(rc == 0);
    assert_string_equal((const char *) xlist->root->data, "item1");
    assert_string_equal((const char *) xlist->end->data, "item1");

    rc = ssh_list_append(xlist, "item2");
    assert_true(rc == 0);
    assert_string_equal((const char *) xlist->root->data, "item1");
    assert_string_equal((const char *) xlist->end->data, "item2");

    rc = ssh_list_prepend(xlist, "item3");
    assert_true(rc == 0);
    assert_string_equal((const char *) xlist->root->data, "item3");
    assert_string_equal((const char *) xlist->root->next->data, "item1");
    assert_string_equal((const char *) xlist->root->next->next->data, "item2");
    assert_string_equal((const char *) xlist->end->data, "item2");

    ssh_list_free(xlist);
}

int torture_run_tests(void) {
    int rc;
    const UnitTest tests[] = {
        unit_test(torture_ssh_list_new),
        unit_test(torture_ssh_list_append),
        unit_test(torture_ssh_list_prepend),
    };

    ssh_init();
    rc=run_tests(tests);
    ssh_finalize();
    return rc;
}
