#include "tmate.h"

struct tmate_env {
	TAILQ_ENTRY(tmate_env) entry;
	char *name;
	char *value;
};

TAILQ_HEAD(, tmate_env) tmate_env_list;

void tmate_set_env(const char *name, const char *value)
{
	struct tmate_env *tmate_env;

	TAILQ_FOREACH(tmate_env, &tmate_env_list, entry) {
		if (!strcmp(tmate_env->name, name)) {
			free(tmate_env->value);
			tmate_env->value = xstrdup(value);
			return;
		}
	}

	tmate_env = xmalloc(sizeof(*tmate_env));
	tmate_env->name = xstrdup(name);
	tmate_env->value = xstrdup(value);
	TAILQ_INSERT_HEAD(&tmate_env_list, tmate_env, entry);
}

void tmate_format(struct format_tree *ft)
{
	struct tmate_env *tmate_env;

	TAILQ_FOREACH(tmate_env, &tmate_env_list, entry) {
		format_add(ft, tmate_env->name, "%s", tmate_env->value);
	}
}
