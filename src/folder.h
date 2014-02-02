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

#ifndef	PWMAN_FOLDER_H
#define	PWMAN_FOLDER_H

typedef struct folder {
	char           *name;
	pw_list_t	list;

	int		marked;

	struct folder  *parent;
	struct folder  *sublists;
	struct folder  *next;

	/* ui stuff, shouldn't be here but this is a quick hack */
	int		current_item;
} folder_t;

void		folder_add_pw(folder_t *, password_t *);
folder_t       *folder_new(char const *);
int		folder_change_item_order(password_t *pw, folder_t *parent, int moveUp);
int		folder_init(void);

int		folder_export_passwd(password_t *pw);
int		folder_free_all(void);
int		folder_read_file(void);
int		folder_change_list_order(folder_t *pw, int moveUp);
void		folder_detach_sublist(folder_t *parent, folder_t *old);
void		folder_detach_pw(folder_t *list, password_t *pw);
void		folder_delete_sublist(folder_t *parent, folder_t *old);
void		folder_rename_sublist(folder_t *folder, char const *new_name);
void		folder_add_sublist(folder_t *parent, folder_t *new);
int		folder_export_list(folder_t *folder);
int		folder_write_file(void);
int		folder_import_passwd(void);

void		pw_rename(password_t *, char const *);
void		pw_free(password_t *);
void		pw_delete(password_t *);

#endif	/* !PWMAN_FOLDER_H */
