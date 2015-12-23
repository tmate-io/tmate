#ifndef WINDOW_COPY_H
#define WINDOW_COPY_H

#include "tmux.h"

enum window_copy_input_type {
	WINDOW_COPY_OFF,
	WINDOW_COPY_NAMEDBUFFER,
	WINDOW_COPY_NUMERICPREFIX,
	WINDOW_COPY_SEARCHUP,
	WINDOW_COPY_SEARCHDOWN,
	WINDOW_COPY_JUMPFORWARD,
	WINDOW_COPY_JUMPBACK,
	WINDOW_COPY_JUMPTOFORWARD,
	WINDOW_COPY_JUMPTOBACK,
	WINDOW_COPY_GOTOLINE,
#ifdef TMATE
	WINDOW_COPY_PASSWORD,
#endif
};

/*
 * Copy-mode's visible screen (the "screen" field) is filled from one of
 * two sources: the original contents of the pane (used when we
 * actually enter via the "copy-mode" command, to copy the contents of
 * the current pane), or else a series of lines containing the output
 * from an output-writing tmux command (such as any of the "show-*" or
 * "list-*" commands).
 *
 * In either case, the full content of the copy-mode grid is pointed at
 * by the "backing" field, and is copied into "screen" as needed (that
 * is, when scrolling occurs). When copy-mode is backed by a pane,
 * backing points directly at that pane's screen structure (&wp->base);
 * when backed by a list of output-lines from a command, it points at
 * a newly-allocated screen structure (which is deallocated when the
 * mode ends).
 */

#ifdef TMATE
typedef void (*copy_password_callback)(const char *password, void *private);
#endif

struct window_copy_mode_data {
	struct screen		 screen;

	struct screen		*backing;
	int			 backing_written; /* backing display started */

	struct mode_key_data	 mdata;

	u_int			 oy;

	u_int			 selx;
	u_int			 sely;

	int			 rectflag;	/* in rectangle copy mode? */
	int			 scroll_exit;	/* exit on scroll to end? */

	u_int			 cx;
	u_int			 cy;

	u_int			 lastcx; /* position in last line w/ content */
	u_int			 lastsx; /* size of last line w/ content */

	enum window_copy_input_type inputtype;
	const char		*inputprompt;
	char			*inputstr;
	int			 inputexit;

	int			 numprefix;

	enum window_copy_input_type searchtype;
	char			*searchstr;

	enum window_copy_input_type jumptype;
	char			 jumpchar;

#ifdef TMATE
	copy_password_callback	password_cb;
	void        	    	*password_cb_private;
#endif
};

extern int window_copy_update_selection(struct window_pane *, int);
extern void window_copy_redraw_screen(struct window_pane *);

#endif
