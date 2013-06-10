/*
 * config.c - parse the ssh config file
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009      by Andreas Schneider <mail@cynapses.org>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/misc.h"
#include "libssh/options.h"

enum ssh_config_opcode_e {
  SOC_UNSUPPORTED = -1,
  SOC_HOST,
  SOC_HOSTNAME,
  SOC_PORT,
  SOC_USERNAME,
  SOC_IDENTITY,
  SOC_CIPHERS,
  SOC_COMPRESSION,
  SOC_TIMEOUT,
  SOC_PROTOCOL,
  SOC_STRICTHOSTKEYCHECK,
  SOC_KNOWNHOSTS,
  SOC_PROXYCOMMAND
};

struct ssh_config_keyword_table_s {
  const char *name;
  enum ssh_config_opcode_e opcode;
};

static struct ssh_config_keyword_table_s ssh_config_keyword_table[] = {
  { "host", SOC_HOST },
  { "hostname", SOC_HOSTNAME },
  { "port", SOC_PORT },
  { "user", SOC_USERNAME },
  { "identityfile", SOC_IDENTITY },
  { "ciphers", SOC_CIPHERS },
  { "compression", SOC_COMPRESSION },
  { "connecttimeout", SOC_TIMEOUT },
  { "protocol", SOC_PROTOCOL },
  { "stricthostkeychecking", SOC_STRICTHOSTKEYCHECK },
  { "userknownhostsfile", SOC_KNOWNHOSTS },
  { "proxycommand", SOC_PROXYCOMMAND },
  { NULL, SOC_UNSUPPORTED }
};

static enum ssh_config_opcode_e ssh_config_get_opcode(char *keyword) {
  int i;

  for (i = 0; ssh_config_keyword_table[i].name != NULL; i++) {
    if (strcasecmp(keyword, ssh_config_keyword_table[i].name) == 0) {
      return ssh_config_keyword_table[i].opcode;
    }
  }

  return SOC_UNSUPPORTED;
}

static char *ssh_config_get_cmd(char **str) {
  register char *c;
  char *r;

  /* Ignore leading spaces */
  for (c = *str; *c; c++) {
    if (! isblank(*c)) {
      break;
    }
  }

  if (*c == '\"') {
    for (r = ++c; *c; c++) {
      if (*c == '\"') {
        *c = '\0';
        goto out;
      }
    }
  }

  for (r = c; *c; c++) {
    if (*c == '\n') {
      *c = '\0';
      goto out;
    }
  }

out:
  *str = c + 1;

  return r;
}

static char *ssh_config_get_token(char **str) {
  register char *c;
  char *r;

  c = ssh_config_get_cmd(str);

  for (r = c; *c; c++) {
    if (isblank(*c)) {
      *c = '\0';
      goto out;
    }
  }

out:
  *str = c + 1;

  return r;
}

static int ssh_config_get_int(char **str, int notfound) {
  char *p, *endp;
  int i;

  p = ssh_config_get_token(str);
  if (p && *p) {
    i = strtol(p, &endp, 10);
    if (p == endp) {
      return notfound;
    }
    return i;
  }

  return notfound;
}

static const char *ssh_config_get_str_tok(char **str, const char *def) {
  char *p;

  p = ssh_config_get_token(str);
  if (p && *p) {
    return p;
  }

  return def;
}

static int ssh_config_get_yesno(char **str, int notfound) {
  const char *p;

  p = ssh_config_get_str_tok(str, NULL);
  if (p == NULL) {
    return notfound;
  }

  if (strncasecmp(p, "yes", 3) == 0) {
    return 1;
  } else if (strncasecmp(p, "no", 2) == 0) {
    return 0;
  }

  return notfound;
}

static int ssh_config_parse_line(ssh_session session, const char *line,
    unsigned int count, int *parsing) {
  enum ssh_config_opcode_e opcode;
  const char *p;
  char *s, *x;
  char *keyword;
  char *lowerhost;
  size_t len;
  int i;

  x = s = strdup(line);
  if (s == NULL) {
    ssh_set_error_oom(session);
    return -1;
  }

  /* Remove trailing spaces */
  for (len = strlen(s) - 1; len > 0; len--) {
    if (! isspace(s[len])) {
      break;
    }
    s[len] = '\0';
  }

  keyword = ssh_config_get_token(&s);
  if (keyword == NULL || *keyword == '#' ||
      *keyword == '\0' || *keyword == '\n') {
    SAFE_FREE(x);
    return 0;
  }

  opcode = ssh_config_get_opcode(keyword);

  switch (opcode) {
    case SOC_HOST:
      *parsing = 0;
      lowerhost = (session->opts.host) ? ssh_lowercase(session->opts.host) : NULL;
      for (p = ssh_config_get_str_tok(&s, NULL); p && *p;
          p = ssh_config_get_str_tok(&s, NULL)) {
        if (match_hostname(lowerhost, p, strlen(p))) {
          *parsing = 1;
        }
      }
      SAFE_FREE(lowerhost);
      break;
    case SOC_HOSTNAME:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_HOST, p);
      }
      break;
    case SOC_PORT:
      if (session->opts.port == 22) {
          p = ssh_config_get_str_tok(&s, NULL);
          if (p && *parsing) {
              ssh_options_set(session, SSH_OPTIONS_PORT_STR, p);
          }
      }
      break;
    case SOC_USERNAME:
      if (session->opts.username == NULL) {
          p = ssh_config_get_str_tok(&s, NULL);
          if (p && *parsing) {
            ssh_options_set(session, SSH_OPTIONS_USER, p);
         }
      }
      break;
    case SOC_IDENTITY:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_ADD_IDENTITY, p);
      }
      break;
    case SOC_CIPHERS:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, p);
        ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, p);
      }
      break;
    case SOC_COMPRESSION:
      i = ssh_config_get_yesno(&s, -1);
      if (i >= 0 && *parsing) {
        if (i) {
          ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "yes");
        } else {
          ssh_options_set(session, SSH_OPTIONS_COMPRESSION, "no");
        }
      }
      break;
    case SOC_PROTOCOL:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        char *a, *b;
        b = strdup(p);
        if (b == NULL) {
          SAFE_FREE(x);
          ssh_set_error_oom(session);
          return -1;
        }
        i = 0;
        ssh_options_set(session, SSH_OPTIONS_SSH1, &i);
        ssh_options_set(session, SSH_OPTIONS_SSH2, &i);

        for (a = strtok(b, ","); a; a = strtok(NULL, ",")) {
          switch (atoi(a)) {
            case 1:
              i = 1;
              ssh_options_set(session, SSH_OPTIONS_SSH1, &i);
              break;
            case 2:
              i = 1;
              ssh_options_set(session, SSH_OPTIONS_SSH2, &i);
              break;
            default:
              break;
          }
        }
        SAFE_FREE(b);
      }
      break;
    case SOC_TIMEOUT:
      i = ssh_config_get_int(&s, -1);
      if (i >= 0 && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &i);
      }
      break;
    case SOC_STRICTHOSTKEYCHECK:
      i = ssh_config_get_yesno(&s, -1);
      if (i >= 0 && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &i);
      }
      break;
    case SOC_KNOWNHOSTS:
      p = ssh_config_get_str_tok(&s, NULL);
      if (p && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, p);
      }
      break;
    case SOC_PROXYCOMMAND:
      p = ssh_config_get_cmd(&s);
      if (p && *parsing) {
        ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, p);
      }
      break;
    case SOC_UNSUPPORTED:
      ssh_log(session, SSH_LOG_RARE, "Unsupported option: %s, line: %d\n",
              keyword, count);
      break;
    default:
      ssh_set_error(session, SSH_FATAL, "ERROR - unimplemented opcode: %d\n",
              opcode);
      SAFE_FREE(x);
      return -1;
      break;
  }

  SAFE_FREE(x);
  return 0;
}

/* ssh_config_parse_file */
int ssh_config_parse_file(ssh_session session, const char *filename) {
  char line[1024] = {0};
  unsigned int count = 0;
  FILE *f;
  int parsing;

  if ((f = fopen(filename, "r")) == NULL) {
    return 0;
  }

  ssh_log(session, SSH_LOG_RARE, "Reading configuration data from %s", filename);

  parsing = 1;
  while (fgets(line, sizeof(line), f)) {
    count++;
    if (ssh_config_parse_line(session, line, count, &parsing) < 0) {
      fclose(f);
      return -1;
    }
  }

  fclose(f);
  return 0;
}
