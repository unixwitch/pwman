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

#include	"ui.h"
#include	"pwman.h"

static void	uilist_highlight_line(int line);
static int	_uilist_render_sublist(pwlist_t *sublist, int i, int num_shown);
static int	_uilist_render_entry(password_t *entry, int i, int num_shown);

static WINDOW  *list;
static int	lines = 0;
static int	first_list_item = 0;

void
uilist_init()
{
	list = newwin(LIST_LINES, COLS, LIST_TOP, 0);
	scrollok(list, TRUE);
}

/*
void
resize_list()
{
	wresize(list, LIST_LINES, COLS);
}
*/

void
uilist_free()
{
	delwin(list);
	list = NULL;
}

static void
uilist_highlight_line(int line)
{
int		i;

	wstandout(list);
/*	mvwchgat(list, i, 0, -1, A_STANDOUT, 0, NULL);*/

	scrollok(list, FALSE);
	wmove(list, line, 0);
	for (i = 0; i < COLS; i++)
		waddch(list, ' ');
	scrollok(list, TRUE);
}

search_result_t *
uilist_get_highlighted_searchresult()
{
search_result_t *srchiter;
int		i = -1;

	for (srchiter = search_results; (srchiter != NULL); srchiter = srchiter->next) {
		i++;
		if (i == current_pw_sublist->current_item)
			break;
	}
	return srchiter;
}

pwlist_t       *
uilist_get_highlighted_sublist()
{
pwlist_t       *iter;
int		i = -1;

	if (!current_pw_sublist)
		return NULL;

	if (current_pw_sublist->parent)
		i++;

	for (iter = current_pw_sublist->sublists; iter != NULL; iter = iter->next) {
		i++;
		if (i == current_pw_sublist->current_item)
			break;

	}

	return iter;
}

password_t     *
uilist_get_highlighted_item()
{
password_t     *iter;
pwlist_t       *listiter;
int		i = -1;

	if (current_pw_sublist->parent)
		i++;

	for (listiter = current_pw_sublist->sublists; listiter != NULL; listiter = listiter->next)
		i++;


	for (iter = current_pw_sublist->list; iter != NULL; iter = iter->next) {
		if (filter_apply(iter, options->filter))
			i++;

		if (i == current_pw_sublist->current_item) {
			debug("get_highlighted_item: found %d, break now", i);
			return iter;
		}
	}
	debug("get_highlighted_item: nothing found, return NULL");
	return NULL;
}

LIST_ITEM_TYPE
uilist_get_highlighted_type()
{
password_t     *iter;
pwlist_t       *listiter;
int		i = -1;

	if (current_pw_sublist->parent) {
		if (current_pw_sublist->current_item == 0)
			return PW_UPLEVEL;

		i++;
	}

	for (listiter = current_pw_sublist->sublists; listiter != NULL; listiter = listiter->next) {
		i++;
		if (i == current_pw_sublist->current_item)
			return PW_SUBLIST;
	}

	for (iter = current_pw_sublist->list; iter != NULL; iter = iter->next) {
		if (filter_apply(iter, options->filter))
			i++;

		if (i == current_pw_sublist->current_item)
			return PW_ITEM;
	}
	return PW_NULL;
}

/* Draw a sublist on the screen */
static int
_uilist_render_sublist(pwlist_t *sublist, int i, int num_shown)
{
	if ((i >= first_list_item) && (i <= LAST_LIST_ITEM)) {
		if (lines == current_pw_sublist->current_item)
			uilist_highlight_line(num_shown);
		else
			wattrset(list, A_BOLD);

		mvwprintw(list, num_shown, NAMEPOS, "%s ->", sublist->name);
		wattrset(list, A_NORMAL);
		wstandend(list);
		num_shown++;
	}

	return num_shown;
}

/* Draw an entry summary on the screen */
static int
_uilist_render_entry(password_t *entry, int i, int num_shown)
{
	if ((i >= first_list_item) && (i <= LAST_LIST_ITEM)) {
		if (lines == current_pw_sublist->current_item)
			uilist_highlight_line(num_shown);

		mvwaddnstr(list, num_shown, NAMEPOS, entry->name, NAMELEN);
		mvwaddnstr(list, num_shown, HOSTPOS, entry->host, HOSTLEN);
		mvwaddnstr(list, num_shown, USERPOS, entry->user, USERLEN);
		wstandend(list);
		num_shown++;
	}
	return num_shown;
}

void
uilist_refresh()
{
password_t     *iter;
pwlist_t       *listiter;
search_result_t *srchiter;
int		i = 0;
int		num_shown = 0;

	debug("refresh_list: refreshing list");
	if (list == NULL)
		uilist_init();

	if (current_pw_sublist == NULL)
		return;

	uilist_clear();
	first_list_item = 0;
	lines = 0;

	uilist_headerline();

	/* Ensure we don't end up off the screen */
	if (current_pw_sublist->current_item < 0)
		current_pw_sublist->current_item = 0;

	if (current_pw_sublist->current_item < first_list_item)
		first_list_item = current_pw_sublist->current_item;
	else if ((current_pw_sublist->current_item > LAST_LIST_ITEM))
		first_list_item = current_pw_sublist->current_item - (LIST_LINES - 1);

	if (search_results == NULL) {
		/* If we aren't at the top level, off the "Up One Level" item */
		if (current_pw_sublist->parent && search_results == NULL) {
			if ((i >= first_list_item) && (i <= LAST_LIST_ITEM)) {
				if (lines == current_pw_sublist->current_item)
					uilist_highlight_line(num_shown);
				else
					wattrset(list, A_BOLD);

				mvwprintw(list, num_shown, NAMEPOS, "<Up One Level - \"%s\">", current_pw_sublist->parent->name);
				wattrset(list, A_NORMAL);
				wstandend(list);
				num_shown++;
			}
			i++;
			lines++;
		}
		/* Draw our sublists */
		for (listiter = current_pw_sublist->sublists; listiter != NULL; listiter = listiter->next) {
			num_shown = _uilist_render_sublist(listiter, i, num_shown);
			lines++;
			i++;
		}
		/* Draw our entries, if the filter says it's ok */
		for (iter = current_pw_sublist->list; (iter != NULL); iter = iter->next) {

			/*
			 * if line satifies filter criteria increment i and
			 * lines
			 */
			if (filter_apply(iter, options->filter)) {
				num_shown = _uilist_render_entry(iter, i, num_shown);
				lines++;
				i++;
			}
		}
	} else {
		for (srchiter = search_results; (srchiter != NULL); srchiter = srchiter->next) {
			if (srchiter->entry != NULL)
				num_shown = _uilist_render_entry(srchiter->entry, i, num_shown);
			else
				num_shown = _uilist_render_sublist(srchiter->sublist, i, num_shown);

			lines++;
			i++;
		}
	}

	wrefresh(list);
	hide_cursor();

	/*
	 * Is the cursor off the screen, after moving up or down the tree?
	 * (Don't trigger this if we have no entries yet)
	 */
	if (current_pw_sublist->current_item) {
		if ((lines - 1) < current_pw_sublist->current_item) {
			/* Just adjust, then redraw */
			current_pw_sublist->current_item = lines - 1;
			uilist_refresh();
		}
	}

	/* If we have filtering turned on, then warn the user of that */
	if (options->filter)
		filter_alert(options->filter);

	/* If we have searching active, then warn the user of that */
	if (options->search)
		search_alert(options->search);

	debug("refresh_list: done refreshing list");
}

void
uilist_clear()
{
int		i;

	werase(list);
	for (i = 0; i < COLS; i++)
		mvaddch(LIST_TOP - 1, i, ' ');
}

void
uilist_headerline()
{
	show_cursor();
	attrset(A_BOLD);

	mvaddnstr(LIST_TOP - 1, NAMEPOS, "Name", NAMELEN);
	mvaddnstr(LIST_TOP - 1, HOSTPOS, "Host", HOSTLEN);
	mvaddnstr(LIST_TOP - 1, USERPOS, "Username", USERLEN);

	attrset(A_NORMAL);
	hide_cursor();
}

void
uilist_page_up()
{
	current_pw_sublist->current_item -= (LIST_LINES - 1);

	if (current_pw_sublist->current_item < 1)
		current_pw_sublist->current_item = 0;

	uilist_refresh();
}

void
uilist_page_down()
{
	current_pw_sublist->current_item += (LIST_LINES - 1);

	if (current_pw_sublist->current_item >= (lines - 1))
		current_pw_sublist->current_item = lines - 1;

	uilist_refresh();
}

void
uilist_up()
{
	if (current_pw_sublist->current_item < 1)
		return;

	current_pw_sublist->current_item--;

	uilist_refresh();
}

void
uilist_down()
{
	if (current_pw_sublist->current_item >= (lines - 1))
		return;

	current_pw_sublist->current_item++;

	uilist_refresh();
}
