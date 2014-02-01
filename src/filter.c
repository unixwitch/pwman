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
#include	<string.h>

#include	"pwman.h"
#include	"ui.h"

#define	FIL_NONE	(-1)
#define	FIL_NAME	0
#define	FIL_HOST	1
#define	FIL_USER	2
#define	FIL_LAUNCH	3

filter_t *
filter_new()
{
filter_t       *new;

	new = xcalloc(1, sizeof(*new));
	new->field = FIL_NONE;
	return new;
}

/*
 * String checking only case insensitive using gnu glibc
 */
static char*
filter_strcasestr(haystack, needle)
	char const	*haystack, *needle;
{
	/* Never matches if null/empty string given */
	if (haystack == NULL) {
		return 0;
	}
	if (strlen(haystack) == 0) {
		return 0;
	}

#ifdef HAVE_STRCASESTR
	return (char *)strcasestr(haystack, needle);
#else
	return (char *)strstr(haystack, needle);
#endif
}

int
filter_apply(pw, fil)
	password_t	*pw;
	filter_t	*fil;
{
char const	*field;

	if ((fil == NULL) || (fil->filter == NULL))
		/* no filter object */
		return 1;

	if (strlen(fil->filter) == 0)
		/* no filter */
		return 1;

	switch (fil->field) {
	case FIL_NAME:
		field = pw->name;
		break;

	case FIL_HOST:
		field = pw->host;
		break;

	case FIL_USER:
		field = pw->user;
		break;

	case FIL_LAUNCH:
		field = pw->launch;
		break;

	default:
		return 0;
	}

	if (filter_strcasestr(field, fil->filter))
		return 1;

	return 0;
}

void
filter_get()
{
char		c;

	c = ui_ask_char("Filter which field? (n)ame (h)ost (u)ser (l)aunch n(o)ne", "nhulo\n");
	switch (c) {
	case 'n':
		options->filter->field = FIL_NAME;
		break;

	case 'h':
		options->filter->field = FIL_HOST;
		break;

	case 'u':
		options->filter->field = FIL_USER;
		break;

	case 'l':
		options->filter->field = FIL_LAUNCH;
		break;

	case 'o':
	default:
		options->filter->field = FIL_NONE;
		free(options->filter->filter);
		options->filter->filter = NULL;

		uilist_refresh();
		return;
	}

	options->filter->filter = ui_ask_str("String to search for: ", NULL);

	current_pw_sublist->current_item = -1;
	uilist_refresh();
}


void
filter_alert(fil)
	filter_t	*fil;
{
char		alert[80];

	if ((fil == NULL) || (fil->filter == NULL))
		/* no filter object */
		return;

	if (strlen(fil->filter) == 0)
		/* no filter */
		return;

	switch (fil->field) {
	case FIL_NAME:
		snprintf(alert, sizeof(alert), " (Filtering on name with '%s')", fil->filter);
		break;

	case FIL_HOST:
		snprintf(alert, sizeof(alert), " (Filtering on host with '%s')", fil->filter);
		break;

	case FIL_USER:
		snprintf(alert, sizeof(alert), " (Filtering on user with '%s')", fil->filter);
		break;

	case FIL_LAUNCH:
		snprintf(alert, sizeof(alert), " (Filtering on launch with '%s')", fil->filter);
		break;

	default:
		break;
	}

	ui_statusline_clear();
	ui_statusline_msg(alert);
}
