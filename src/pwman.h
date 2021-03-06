/*
 *  PWMan - password management application
 *
 *  Copyright (C) 2002  Ivan Kelly <ivan@ivankelly.net>
 *  Copyright (c) 2014	Felicity Tarnell.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef PWMAN_H
#define PWMAN_H

#include	<sys/types.h>

#include	<curses.h>
#include	<stdio.h>
#include	<string.h>
#include	<config.h>
#include	<time.h>
#include	<stdarg.h>

#include	"config.h"

#ifdef	HAVE_INTTYPES_H
#include	<inttypes.h>
#endif

#ifdef	HAVE_STDINT_H
#include	<stdint.h>
#endif

#include	"queue.h"

#define CONF_FILE 	".pwmanrc"
#define	DB_FILE		".pwman.db"

/* string lengths */
#define STRING_SHORT	64
#define STRING_MEDIUM	128
#define STRING_LONG	256

#define MAIN_HELPLINE 	"q:quit  ?:help  a:add  e:edit  d:delete"
#define READONLY_MSG	"RO"
#define SAFE_MSG	"SAFE"

#define MAX_SEARCH_DEPTH 25

#define DEFAULT_UMASK 066

#define FF_VERSION 3

#define	xstrdup(s)	strdup(s)
#define	xmalloc(s)	malloc(s)
#define	xcalloc(n,s)	calloc(n,s)
#define	xfree(s)	do { if (s) free(s); } while (0)

#include	"password.h"
#include	"folder.h"

typedef struct search_result {
	/* Always has a sublist, whether the list or child matches */
	folder_t       *sublist;

	/* If the entry itself matches, will be present */
	password_t     *entry;

	struct search_result *next;
} search_result_t;

typedef struct filter {
	int		field;
	char           *filter;
} filter_t;

typedef struct search {
	char           *search_term;
} search_t;

typedef struct {
	char		*gpg_id;
	char		*gpg_path;
	char		*password_file;
	int		 passphrase_timeout;
	filter_t	*filter;
	search_t	*search;
	int		 readonly;
	int		 safemode;
	char		*copy_command;
} Options;

extern Options *options;
extern int	write_options;
extern folder_t *folder;
extern folder_t *current_pw_sublist;
extern search_result_t *search_results;
extern time_t	time_base;

char           *trim_ws(char *);
void		debug     (char const *,...);
void		pw_abort  (char const *,...);
int		ui_init    (void);
int		ui_run     (void);
int		ui_end     (void);

filter_t       *filter_new(void);
search_t       *search_new(void);
Options        *options_new(void);
int		options_read(void);
int		options_write(void);
void		options_get(void);

void		search_get(void);
void		search_remove(void);

char           *pwgen_ask(void);
void		pwgen_indep(void);

int		launch     (password_t *pw);

#ifndef HAVE_ARC4RANDOM
uint32_t	arc4random(void);

#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t	arc4random_uniform(uint32_t);

#endif

#ifndef	HAVE_STRLCPY
size_t		strlcpy (char *dst, const char *src, size_t size);

#endif

#ifndef	HAVE_STRLCAT
size_t		strlcat (char *dst, const char *src, size_t size);

#endif

struct pw_option {
	const char	*name;
	int		 has_arg;
	int		*flag;
	int		 val;
};

#define pw_no_argument        0
#define pw_required_argument  1
#define pw_optional_argument  2

int pw_getopt(int nargc, char * const *, const char *,
	const struct pw_option *, int *);

int copy_string(char const *);

#endif
