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

#include	<stdlib.h>
#include	<assert.h>

#include	"pwman.h"
#include	"password.h"

void
pw_rename(item, new_name)
	password_t	*item;
	char const	*new_name;
{
	free(item->name);
	item->name = xstrdup(new_name);
}

void
pw_delete(pw)
	password_t	*pw;
{
	assert(pw);

	if (pw->parent)
		PWLIST_REMOVE(&pw->parent->list, pw);
	pw_free(pw);
}

void
pw_free(pw)
	password_t	*pw;
{
	if (!pw)
		return;

	free(pw->name);
	free(pw->user);
	free(pw->host);
	free(pw->passwd);
	free(pw->launch);
	free(pw);
}

