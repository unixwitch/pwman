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

#ifndef PW_MINDER_H
#define PW_MINDER_H

#include	<curses.h>
#include	<stdio.h>
#include	<string.h>
#include	<config.h>
#include	<time.h>
#include	<stdarg.h>

#include	"config.h"

#ifdef	HAVE_INTTYPES_H
# include	<inttypes.h>
#endif

#ifdef	HAVE_STDINT_H
# include	<stdint.h>
#endif

#define CONF_FILE 	".pwmanrc" 
#define	DB_FILE		".pwman.db"

/* string lengths */
#define STRING_SHORT	64
#define STRING_MEDIUM	128
#define STRING_LONG	256

#define MAIN_HELPLINE 	"q:quit  ?:help  a:add  e:edit  d:delete"
#define READONLY_MSG	"RO"

#define MAX_SEARCH_DEPTH 25

#define DEFAULT_UMASK 066

#define FF_VERSION 3 

#define	xstrdup(s)	strdup(s)
#define	xmalloc(s)	malloc(s)
#define	xcalloc(n,s)	calloc(n,s)
#define	xfree(s)	do { if (s) free(s); } while (0)

struct _PW {
	int id;
	char *name;
	char *host;
	char *user;
	char *passwd;
	char *launch;
	struct _PW *next;
};
typedef struct _PW Pw;

struct _PWList {
	char *name;
	Pw *list;
	struct _PWList *parent;
	struct _PWList *sublists;
	struct _PWList *next;

	/* ui stuff, shouldn't be here but this is a quick hack */
	int current_item;
};
typedef struct _PWList PWList;

struct _PWSearchResult {
	/* Always has a sublist, whether the list or child matches */
	PWList *sublist;
	/* If the entry itself matches, will be present */
	Pw *entry;

	/* The next one along, as with other structs */
	struct _PWSearchResult* next;
};
typedef struct _PWSearchResult PWSearchResult;


typedef struct {
	int field;
	char *filter;
} PwFilter;

typedef struct {
	char *search_term;
} PwSearch;

typedef struct {
	char *gpg_id;
	char *gpg_path;
	char *password_file;
	int passphrase_timeout;
	PwFilter *filter;
	PwSearch *search;
	int readonly;
} Options;

extern Options *options;
extern int write_options;
extern PWList *pwlist;
extern PWList *current_pw_sublist;
extern PWSearchResult *search_results;
extern time_t time_base;

char *trim_ws(char*);
void debug(char const *, ...);
void pw_abort(char const *, ...);
int ui_init(void);
int ui_run(void);
int ui_end(void);

PwFilter * filter_new(void);
PwSearch * search_new(void);
Options * options_new(void);
int options_read(void);
int options_write(void);
void options_get(void);

void search_get(void);
void search_remove(void);

int pwlist_add_ptr(PWList*, Pw*);
Pw* pwlist_new_pw(void);
PWList *pwlist_new(char const*);
int pwlist_change_item_order(Pw* pw, PWList *parent, int moveUp);
int pwlist_init(void);

int pwlist_export_passwd(Pw *pw);
int pwlist_free_all(void);
int pwlist_read_file(void);
int pwlist_change_list_order(PWList *pw, int moveUp);
void pwlist_detach_sublist(PWList *parent, PWList *old);
void pwlist_detach_pw(PWList *list, Pw *pw);
void pwlist_delete_sublist(PWList *parent, PWList *old);
void pwlist_delete_pw(PWList *list, Pw *pw);
void pwlist_free_pw(Pw *old);
void pwlist_rename_item(Pw* pwitem, char const *new_name);
void pwlist_rename_sublist(PWList *pwlist, char const *new_name);
int pwlist_add_sublist(PWList *parent, PWList *new);
int pwlist_export_list(PWList *pwlist);
int pwlist_write_file(void);
int pwlist_import_passwd(void);

char *pwgen_ask(char *pw);
void pwgen_indep(void);

int launch(Pw *pw);

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(void);
#endif

#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t);
#endif

#ifndef	HAVE_STRLCPY
size_t strlcpy(char * restrict dst, const char * restrict src, size_t size);
#endif

#ifndef	HAVE_STRLCAT
size_t strlcat(char * restrict dst, const char * restrict src, size_t size);
#endif

#endif
