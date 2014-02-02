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

#include	<errno.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<assert.h>
#include	<limits.h>

#include	<libxml/tree.h>
#include	<libxml/parser.h>

#include	"pwman.h"
#include	"gnupg.h"
#include	"ui.h"

static int	folder_read(xmlNodePtr parent, folder_t *parent_list);
static void	folder_free(folder_t *old);
static void	folder_write(xmlNodePtr parent, folder_t *list);
static void	folder_read_node(xmlNodePtr parent, folder_t *list);
static void	folder_write_node(xmlNodePtr root, password_t *pw);
static int	folder_do_export(folder_t *folder, password_t *pw);

#if 0
static int 
folder_add(folder_t *parent, char const *name, char const *host,
	   char const *user, char const *passwd, char const *launch);

#endif

static int	pwindex = 0;

folder_t *
folder_new(char const *name)
{
folder_t       *ret;

	ret = xcalloc(1, sizeof(*ret));
	ret->name = xstrdup(name);
	PWLIST_INIT(&ret->list);
	debug("new_folder: %s", name);

	return ret;
}

int
folder_init()
{
	pwindex = 0;
	folder = NULL;
	current_pw_sublist = NULL;
	return 0;
}

static void
folder_free(folder_t *old)
{
password_t     *current, *next;
folder_t       *curlist, *nlist;

	if (!old)
		return;

	PWLIST_FOREACH_SAFE(current, &old->list, next)
		pw_free(current);

	for (curlist = old->sublists; curlist != NULL; curlist = nlist) {
		nlist = curlist->next;
		folder_free(curlist);
	}

	free(old->name);
	free(old);
	old = NULL;
}

int
folder_free_all()
{
	folder_free(folder);
	return 0;
}

int
folder_change_item_order(pw, parent, moveUp)
	password_t	*pw;
	folder_t	*parent;
{
password_t	*swap;
	
	assert(pw);
	assert(parent);

	if (moveUp) {
		swap = PWLIST_PREV(pw, &parent->list);

		if (!swap)
			return 0;

		PWLIST_REMOVE(&parent->list, pw);
		PWLIST_INSERT_BEFORE(&parent->list, swap, pw);
		return 1;
	}

	swap = PWLIST_NEXT(pw);
	if (!swap)
		return 0;

	PWLIST_REMOVE(&parent->list, pw);
	PWLIST_INSERT_AFTER(&parent->list, swap, pw);
	return 1;
}

int
folder_change_list_order(pw, moveUp)
	folder_t	*pw;
{
	/* Grab the parent, assuming there is one */
folder_t       *parent = pw->parent;
folder_t       *iter = NULL;
folder_t       *pprev = NULL;
folder_t       *prev = NULL;
folder_t       *next = NULL;
folder_t       *nnext = NULL;

	if (parent == NULL)
		return 0;

	/* Find us, in our parents list of children */
	for (iter = parent->sublists; iter != NULL; iter = iter->next) {
		if (iter == pw) {
			/* Grab the next one, and the one after */
			next = pw->next;

			if (next != NULL)
				nnext = next->next;
			else
				nnext = NULL;


			/* Which way do we need to shuffle? */
			if (moveUp) {
				/* Up the list, if we can */
				if (prev == NULL)
					break;

				/* Are we going to the top? */
				if (prev == parent->sublists) {
					parent->sublists = pw;
					pw->next = prev;
					prev->next = next;
				} else {
					pprev->next = pw;
					pw->next = prev;
					prev->next = next;
				}

				return 1;
			} else {
				/* Down the list, if we can */
				if (next == NULL)
					break;

				/* Were we at the top? */
				if (pw == parent->sublists) {
					parent->sublists = next;
					next->next = pw;
					pw->next = nnext;
				} else {
					prev->next = next;
					next->next = pw;
					pw->next = nnext;
				}

				return 1;
			}
		} else {
			/* Update the running list of prev and pprev */
			pprev = prev;
			prev = iter;
		}
	}

	return 0;
}

void
folder_rename_sublist(list, new_name)
	folder_t	*list;
	char const	*new_name;
{
	free(list->name);
	list->name = xstrdup(new_name);
}

void
folder_add_sublist(parent, new)
	folder_t	*parent;
	folder_t	*new;
{
folder_t       *current;

	current = parent->sublists;
	new->parent = parent;
	new->current_item = 1;

	if (current == NULL) {
		debug("add_pw_sublist: current = NULL");
		parent->sublists = new;
		new->next = NULL;
		return;
	}

	while (current->next != NULL)
		current = current->next;

	current->next = new;
	new->next = NULL;
}

void
folder_add_pw(list, new)
	folder_t	*list;
	password_t	*new;
{
	assert(list);
	assert(new);

	PWLIST_INSERT_TAIL(&list->list, new);
	new->parent = list;
}

void
folder_detach_pw(list, pw)
	folder_t	*list;
	password_t	*pw;
{
	assert(list);
	assert(pw);

	PWLIST_REMOVE(&list->list, pw);
	pw->parent = NULL;
}

void
folder_detach_sublist(parent, old)
	folder_t	*parent, *old;
{
folder_t       *iter, *prev;

	prev = NULL;
	for (iter = parent->sublists; iter != NULL; iter = iter->next) {
		if (iter == old) {
			if (prev == NULL)
				parent->sublists = iter->next;
			else
				prev->next = iter->next;

			break;
		}
		prev = iter;
	}
}

void
folder_delete_sublist(parent, old)
	folder_t	*parent, *old;
{
folder_t       *iter, *prev;

	prev = NULL;
	for (iter = parent->sublists; iter != NULL; iter = iter->next) {
		if (iter == old) {
			if (prev == NULL)
				parent->sublists = iter->next;
			else
				prev->next = iter->next;

			folder_free(iter);
			break;
		}
		prev = iter;
	}
}

static void
folder_write_node(root, pw)
	xmlNodePtr	root;
	password_t	*pw;
{
xmlNodePtr	node;

	/* We need to escape the strings before storing them */
	/* Otherwise, special characters (especially &) will */
	/* end up broken! */
xmlChar        *escapedName = xmlEncodeSpecialChars(root->doc, (xmlChar *) pw->name);
xmlChar        *escapedHost = xmlEncodeSpecialChars(root->doc, (xmlChar *) pw->host);
xmlChar        *escapedUser = xmlEncodeSpecialChars(root->doc, (xmlChar *) pw->user);
xmlChar        *escapedPasswd = xmlEncodeSpecialChars(root->doc, (xmlChar *) pw->passwd);
xmlChar        *escapedLaunch = xmlEncodeSpecialChars(root->doc, (xmlChar *) pw->launch);

	/* Build the entry and add in our (escaped) contents */
	node = xmlNewChild(root, NULL, (xmlChar const *)"PwItem", NULL);

	xmlNewChild(node, NULL, (xmlChar const *)"name", escapedName);
	xmlNewChild(node, NULL, (xmlChar const *)"host", escapedHost);
	xmlNewChild(node, NULL, (xmlChar const *)"user", escapedUser);
	xmlNewChild(node, NULL, (xmlChar const *)"passwd", escapedPasswd);
	xmlNewChild(node, NULL, (xmlChar const *)"launch", escapedLaunch);

	/* Finally, we need to free all our escaped versions now we're done */
	xmlFree(escapedName);
	xmlFree(escapedHost);
	xmlFree(escapedUser);
	xmlFree(escapedPasswd);
	xmlFree(escapedLaunch);
}

static void
folder_write(parent, list)
	xmlNodePtr	parent;
	folder_t	*list;
{
xmlNodePtr	node;
password_t     *iter;
folder_t       *pwliter;

	node = xmlNewChild(parent, NULL, (xmlChar const *)"PwList", NULL);
	xmlSetProp(node, (xmlChar const *)"name", (xmlChar *) list->name);

	PWLIST_FOREACH(iter, &list->list)
		folder_write_node(node, iter);

	for (pwliter = list->sublists; pwliter != NULL; pwliter = pwliter->next)
		folder_write(node, pwliter);
}

int
folder_write_file()
{
char		vers[5];
xmlDocPtr	doc;
xmlNodePtr	root;
char		tfile[PATH_MAX];

	if (options->readonly)
		return 0;

	if (!folder) {
		debug("write_file: bad password file");
		ui_statusline_msg("Bad password list");
		return -1;
	}

	snprintf(vers, 5, "%d", FF_VERSION);
	doc = xmlNewDoc((xmlChar const *)"1.0");

	root = xmlNewDocNode(doc, NULL, (xmlChar const *)"PWMan_PasswordList", NULL);

	xmlSetProp(root, (xmlChar const *)"version", (xmlChar *) vers);
	folder_write(root, folder);

	xmlDocSetRootElement(doc, root);

	snprintf(tfile, sizeof(tfile), "%s.tmp", options->password_file);
	if (gnupg_write(doc, options->gpg_id, tfile) == 0)
		rename(tfile, options->password_file);

	xmlFreeDoc(doc);
	return 0;
}

static void
folder_read_node(parent, list)
	xmlNodePtr	parent;
	folder_t	*list;
{
password_t     *new;
xmlNodePtr	node;

	new = xcalloc(1, sizeof(*new));

	for (node = parent->children; node != NULL; node = node->next) {
	char const     *text;

		if (!node || !node->name) {
			debug("Messed up xml node");
			continue;
		}

		text = (char const *)xmlNodeGetContent(node);
		if (!text)
			continue;

		if (strcmp((char const *)node->name, "name") == 0)
			new->name = xstrdup(text);

		else if (strcmp((char const *)node->name, "user") == 0)
			new->user = xstrdup(text);

		else if (strcmp((char const *)node->name, "passwd") == 0)
			new->passwd = xstrdup(text);

		else if (strcmp((char const *)node->name, "host") == 0)
			new->host = xstrdup(text);

		else if (strcmp((char const *)node->name, "launch") == 0)
			new->launch = xstrdup(text);
	}

	folder_add_pw(list, new);
}

static int
folder_read(parent, parent_list)
	xmlNodePtr	parent;
	folder_t	*parent_list;
{
xmlNodePtr	node;
folder_t       *new;
char const     *name;

	if (!parent || !parent->name) {
		ui_statusline_msg("Messed up xml node");
		return -1;
	}

	if (strcmp((char const *)parent->name, "PwList") != 0)
		return 0;

	name = (char const *)xmlGetProp(parent, (xmlChar const *)"name");
	new = folder_new(name);

	for (node = parent->children; node != NULL; node = node->next) {
		if (!node || !node->name) {
			debug("read_folder: messed up child node");
			continue;
		}

		if (strcmp((char const *)node->name, "PwList") == 0)
			folder_read(node, new);

		else if (strcmp((char const *)node->name, "PwItem") == 0)
			folder_read_node(node, new);
	}

	if (parent_list)
		folder_add_sublist(parent_list, new);
	else
		folder = current_pw_sublist = new;

	return 0;
}

int
folder_read_file()
{
char		fn[STRING_LONG];
char const     *buf;
int		i = 0;
int		gnupg_worked = 0;
xmlNodePtr	node, root;
xmlDocPtr	doc;

	/* Have the defined a file yet? */
	if (!options->password_file)
		return -1;

	/* Do we need to create a new file? */
	snprintf(fn, sizeof(fn), "%s", options->password_file);
	if (access(fn, F_OK) != 0) {
		ui_statusline_msg("Database not found, created. Press any key to begin  ");
		getch();
		return -1;
	}

	/* Try to load the file */
	gnupg_worked = gnupg_read(options->password_file, &doc);

	/* Did it work? */
	if (gnupg_worked != 0)
		return gnupg_worked;

	if (!doc) {
		ui_statusline_msg("Bad XML data");
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	if (!root || !root->name || (strcmp((char const *)root->name, "PWMan_PasswordList") != 0)) {
		ui_statusline_msg("Badly formed password data");
		return -1;
	}

	if ((buf = (char const *)xmlGetProp(root, (xmlChar const *)"version")) != NULL)
		i = atoi(buf);

	if (i < FF_VERSION) {
		ui_statusline_msg("Password file in older format, use convert_pwdb");
		return -1;
	}

	for (node = root->children; node != NULL; node = node->next) {
		if (strcmp((char const *)node->name, "PwList") == 0) {
			folder_read(node, NULL);
			break;
		}
	}

	xmlFreeDoc(doc);
	return 0;
}

static int
folder_do_export(list, pw)
	folder_t	*list;
	password_t	*pw;
{
#define	MAX_ID_NUM	5
char		vers[5], *ids[MAX_ID_NUM], *file;
int		i = 0,	valid_ids = 0;
xmlDocPtr	doc;
xmlNodePtr	root;

	bzero(ids, sizeof(ids));

	if (!list && !pw) {
		debug("export_passwd: bad password");
		ui_statusline_msg("Bad password");
		return -1;
	}

	/* Fetch the IDs */
	gnupg_get_ids(ids, MAX_ID_NUM);

	/* Check we really got one */
	for (i = 0; i < MAX_ID_NUM; i++)
		if (ids[i])
			valid_ids++;

	if (valid_ids == 0) {
		debug("export_passwd: cancel because id is blank");
		return -1;
	} else {
		debug("exporting to %d ids", valid_ids);
	}

	file = gnupg_get_filename('w');

	debug("export_passwd: construct xml doc");
	snprintf(vers, 5, "%d", FF_VERSION);
	doc = xmlNewDoc((xmlChar const *)"1.0");

	root = xmlNewDocNode(doc, NULL, (xmlChar const *)"PWMan_Export", NULL);

	xmlSetProp(root, (xmlChar const *)"version", (xmlChar const *)vers);

	if (list)
		folder_write(root, list);
	else
		folder_write_node(root, pw);

	xmlDocSetRootElement(doc, root);

	gnupg_write_many(doc, ids, MAX_ID_NUM, file);
	free(file);

	xmlFreeDoc(doc);

	for (i = 0; i < MAX_ID_NUM; i++)
		free(ids[i]);

	return 0;
}

int
folder_export_passwd(pw)
	password_t	*pw;
{
	return folder_do_export(NULL, pw);
}

int
folder_export_list(list)
	folder_t	*list;
{
	return folder_do_export(list, NULL);
}

int
folder_import_passwd()
{
char           *file;
char const     *buf;
int		i = 0;

xmlNodePtr	node, root;
xmlDocPtr	doc;

	file = gnupg_get_filename('r');
	gnupg_read(file, &doc);
	free(file);

	if (!doc) {
		debug("import_passwd: bad data");
		return -1;
	}
	root = xmlDocGetRootElement(doc);
	if (!root || !root->name || (strcmp((char const *)root->name, "PWMan_Export") != 0)) {
		ui_statusline_msg("Badly formed password data");
		return -1;
	}
	if ((buf = (char const *)xmlGetProp(root, (xmlChar const *)"version")) != NULL)
		i = atoi(buf);

	if (i < FF_VERSION) {
		ui_statusline_msg("Password export file in older format, use convert_pwdb");
		return -1;
	}
	for (node = root->children; node != NULL; node = node->next) {
		if (strcmp((char const *)node->name, "PwList") == 0) {
			folder_read(node, current_pw_sublist);
			break;
		} else if (strcmp((char const *)node->name, "PwItem") == 0) {
			folder_read_node(node, current_pw_sublist);
			break;
		}
	}
	xmlFreeDoc(doc);
	return 0;
}
