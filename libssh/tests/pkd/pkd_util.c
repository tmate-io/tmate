/*
 * pkd_util.c -- pkd utilities
 *
 * (c) 2014 Jon Simons
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "pkd_client.h"
#include "pkd_util.h"

/**
 * @brief runs system(3); exits if that is interrupted with SIGINT/QUIT
 * @returns 0 upon success, non-zero otherwise
 */
int system_checked(const char *cmd) {
    int rc = system(cmd);

    if (WIFSIGNALED(rc) &&
        ((WTERMSIG(rc) == SIGINT) || (WTERMSIG(rc) == SIGQUIT))) {
        exit(1);
    }

    if (rc == -1) {
        return -1;
    }

    return WEXITSTATUS(rc);
}

static int bin_exists(const char *binary) {
    char bin[1024] = { 0 };
    snprintf(&bin[0], sizeof(bin), "type %s 1>/dev/null 2>/dev/null", binary);
    return (system_checked(bin) == 0);
}

int is_openssh_client_enabled(void) {
    return (bin_exists(OPENSSH_BINARY) && bin_exists(OPENSSH_KEYGEN));
}

int is_dropbear_client_enabled(void) {
    return (bin_exists(DROPBEAR_BINARY) && bin_exists(DROPBEAR_KEYGEN));
}
