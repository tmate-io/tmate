#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <signal.h>
#include "tmate.h"

#ifndef HAVE_BACKTRACE

void tmate_print_stack_trace(void) {}
void tmate_catch_sigsegv(void) {}
void tmate_preload_trace_lib(void) {}

#else

#if DEBUG

static int print_resolved_stack_frame(const char *frame)
{
	char file[100];
	char cmd[200];
	char output[300];
	char address[20];
	char *line;
	FILE *ps;

	static regex_t _regex;
	static regex_t *regex;
	regmatch_t matches[3];

	if (!regex) {
		if (regcomp(&_regex, "(.+)\\(\\) \\[([^]]+)\\]", REG_EXTENDED))
			return -1;
		regex = &_regex;
	}

	if (regexec(regex, frame, 3, matches, 0))
		return -1;

	memcpy(file, &frame[matches[1].rm_so], matches[1].rm_eo - matches[1].rm_so);
	file[matches[1].rm_eo - matches[1].rm_so] = 0;

	memcpy(address, &frame[matches[2].rm_so], matches[2].rm_eo - matches[2].rm_so);
	address[matches[2].rm_eo - matches[2].rm_so] = 0;

	sprintf(cmd, "addr2line -e %s %s -f -p -s", file, address);

	ps = popen(cmd, "r");
	if (!ps)
		return -1;

	line = fgets(output, sizeof(output), ps);
	pclose(ps);

	if (!line)
		return -1;

	line[strlen(line)-1] = 0; /* remove \n */
	tmate_debug("%s(%s) [%s]", file, line, address);
	return 0;
}
#endif

void tmate_print_stack_trace(void)
{
	void *array[20];
	size_t size;
	char **strings;
	size_t i;

	size = backtrace (array, 20);
	strings = backtrace_symbols (array, size);

	tmate_info ("============ %zd stack frames ============", size);

	for (i = 1; i < size; i++) {
#if DEBUG
		if (print_resolved_stack_frame(strings[i]) < 0)
#endif
			tmate_info("%s", strings[i]);
	}

	free (strings);
}

static void handle_crash(int sig)
{
	/* TODO send stack trace to server */
	const char *what = sig == SIGSEGV ? "SIGSEGV" : "SIGABRT";
	tmate_info("%s printing stack trace", what);
	tmate_print_stack_trace();

	/* Reraise */
	signal(sig, NULL);
	kill(getpid(), sig);
}

void tmate_catch_sigsegv(void)
{
	signal(SIGSEGV, handle_crash);
	signal(SIGABRT, handle_crash);
}

void tmate_preload_trace_lib(void)
{
       void *array[1];
       backtrace(array, 1);
}

#endif
