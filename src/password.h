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

#ifndef	PWMAN_PASSWORD_H
#define	PWMAN_PASSWORD_H

#include	"queue.h"

struct folder;

typedef struct password {
	int		 id;
	char		*name;
	char		*host;
	char		*user;
	char		*passwd;
	char		*launch;
	struct folder	*parent;

	/* ui */
	int		 marked;

	TAILQ_ENTRY(password)	pw_entries;
} password_t;

typedef TAILQ_HEAD(pw_list, password) pw_list_t;

#define	PWLIST_INIT(list)			TAILQ_INIT((list))
#define	PWLIST_EMPTY(list)			TAILQ_EMPTY((list))
#define	PWLIST_FIRST(list)			TAILQ_FIRST((list))
#define	PWLIST_PREV(elm,list)			TAILQ_PREV((elm), pw_list, pw_entries)
#define	PWLIST_NEXT(elm)			TAILQ_NEXT((elm), pw_entries)
#define	PWLIST_FOREACH(elm,list)		TAILQ_FOREACH((elm), (list), pw_entries)
#define	PWLIST_FOREACH_SAFE(elm,list,t)		TAILQ_FOREACH_SAFE((elm), (list), pw_entries, (t))
#define	PWLIST_REMOVE(list, elm)		TAILQ_REMOVE((list), (elm), pw_entries)
#define	PWLIST_INSERT_BEFORE(list,lelm,elm)	TAILQ_INSERT_BEFORE((lelm), (elm), pw_entries)
#define	PWLIST_INSERT_AFTER(list,lelm,elm)	TAILQ_INSERT_AFTER((list), (lelm), (elm), pw_entries)
#define	PWLIST_INSERT_TAIL(list,elm)		TAILQ_INSERT_TAIL((list), (elm), pw_entries)

#endif	/* !PWMAN_PASSWORD_H */
