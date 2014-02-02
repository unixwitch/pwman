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

#include	<libxml/tree.h>
#include	<libxml/parser.h>

#include	"pwman.h"
#include	"gnupg.h"
#include	"ui.h"

static int	pwlist_read(xmlNodePtr parent, pwlist_t *parent_list);
static void	pwlist_free(pwlist_t *old);
static void	pwlist_write(xmlNodePtr parent, pwlist_t *list);
static void	pwlist_read_node(xmlNodePtr parent, pwlist_t *list);
static void	pwlist_write_node(xmlNodePtr root, password_t *pw);
static int	pwlist_do_export(pwlist_t *pwlist, password_t *pw);

#if 0
static int 
pwlist_add(pwlist_t *parent, char const *name, char const *host,
	   char const *user, char const *passwd, char const *launch);

#endif

static int	pwindex = 0;

pwlist_t *
pwlist_new(char const *name)
{
pwlist_t       *ret;

	ret = xcalloc(1, sizeof(*ret));
	ret->name = xstrdup(name);
	debug("new_pwlist: %s", name);

	return ret;
}

int
pwlist_init()
{
	pwindex = 0;
	pwlist = NULL;
	current_pw_sublist = NULL;
	return 0;
}

static void
pwlist_free(pwlist_t *old)
{
password_t     *current, *next;
pwlist_t       *curlist, *nlist;

	if (!old)
		return;

	for (current = old->list; current != NULL; current = next) {
		next = current->next;
		pwlist_free_pw(current);
	}

	for (curlist = old->sublists; curlist != NULL; curlist = nlist) {
		nlist = curlist->next;
		pwlist_free(curlist);
	}

	free(old->name);
	free(old);
	old = NULL;
}

int
pwlist_free_all()
{
	pwlist_free(pwlist);
	return 0;
}

void
pwlist_free_pw(password_t *old)
{
	if (!old)
		return;

	free(old->name);
	free(old->user);
	free(old->host);
	free(old->passwd);
	free(old->launch);
	free(old);
}

int
pwlist_change_item_order(pw, parent, moveUp)
	password_t	*pw;
	pwlist_t	*parent;
{
password_t     *iter = NULL;
password_t     *pprev = NULL;
password_t     *prev = NULL;
password_t     *next = NULL;
password_t     *nnext = NULL;

	/* Find us, in our parents list of children */
	for (iter = parent->list; iter != NULL; iter = iter->next) {
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
				if (prev == parent->list) {
					parent->list = pw;
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
				if (pw == parent->list) {
					parent->list = next;
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

int
pwlist_change_list_order(pw, moveUp)
	pwlist_t	*pw;
{
	/* Grab the parent, assuming there is one */
pwlist_t       *parent = pw->parent;
pwlist_t       *iter = NULL;
pwlist_t       *pprev = NULL;
pwlist_t       *prev = NULL;
pwlist_t       *next = NULL;
pwlist_t       *nnext = NULL;

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
pwlist_rename_item(item, new_name)
	password_t	*item;
	char const	*new_name;
{
	free(item->name);
	item->name = xstrdup(new_name);
}

void
pwlist_rename_sublist(list, new_name)
	pwlist_t	*list;
	char const	*new_name;
{
	free(list->name);
	list->name = xstrdup(new_name);
}

#if 0
static int
pwlist_add(parent, name, host, user, passwd, launch)
	pwlist_t       *parent;
	char const     *name, *host, *user, *passwd, *launch;
{
password_t     *new = pwlist_new_pw();

	new->id = pwindex++;
	new->name = xstrdup(name);
	new->host = xstrdup(host);
	new->user = xstrdup(user);
	new->passwd = xstrdup(passwd);
	new->launch = xstrdup(launch);

	pwlist_add_ptr(parent, new);

	return 0;
}

#endif

int
pwlist_add_sublist(parent, new)
	pwlist_t	*parent;
	pwlist_t	*new;
{
pwlist_t       *current;

	current = parent->sublists;
	new->parent = parent;
	new->current_item = 1;

	if (current == NULL) {
		debug("add_pw_sublist: current = NULL");
		parent->sublists = new;
		new->next = NULL;
		return 0;
	}

	while (current->next != NULL)
		current = current->next;

	current->next = new;
	new->next = NULL;

	return 0;
}

int
pwlist_add_ptr(list, new)
	pwlist_t	*list;
	password_t	*new;
{
password_t     *current;

	assert(list);
	assert(new);

	if (list->list == NULL) {
		list->list = new;
		new->next = NULL;
		return 0;
	}

	debug("add_pw_ptr: add to list");

	for (current = list->list; current->next != NULL; current = current->next)
		;

	current->next = new;
	new->next = NULL;

	return 0;
}

void
pwlist_detach_pw(list, pw)
	pwlist_t	*list;
	password_t	*pw;
{
password_t     *iter, *prev;

	prev = NULL;
	for (iter = list->list; iter != NULL; iter = iter->next) {
		if (iter == pw) {
			if (prev == NULL)
				list->list = iter->next;
			else
				prev->next = iter->next;

			break;
		}
		prev = iter;
	}
}

void
pwlist_delete_pw(list, pw)
	pwlist_t	*list;
	password_t	*pw;
{
password_t     *iter, *prev;

	prev = NULL;
	for (iter = list->list; iter != NULL; iter = iter->next) {
		if (iter == pw) {
			if (prev == NULL)
				list->list = iter->next;
			else
				prev->next = iter->next;

			pwlist_free_pw(iter);
			break;
		}
		prev = iter;
	}
}

void
pwlist_detach_sublist(parent, old)
	pwlist_t	*parent, *old;
{
pwlist_t       *iter, *prev;

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
pwlist_delete_sublist(parent, old)
	pwlist_t	*parent, *old;
{
pwlist_t       *iter, *prev;

	prev = NULL;
	for (iter = parent->sublists; iter != NULL; iter = iter->next) {
		if (iter == old) {
			if (prev == NULL)
				parent->sublists = iter->next;
			else
				prev->next = iter->next;

			pwlist_free(iter);
			break;
		}
		prev = iter;
	}
}

static void
pwlist_write_node(root, pw)
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
pwlist_write(parent, list)
	xmlNodePtr	parent;
	pwlist_t	*list;
{
xmlNodePtr	node;
password_t     *iter;
pwlist_t       *pwliter;

	node = xmlNewChild(parent, NULL, (xmlChar const *)"PwList", NULL);
	xmlSetProp(node, (xmlChar const *)"name", (xmlChar *) list->name);

	for (iter = list->list; iter != NULL; iter = iter->next)
		pwlist_write_node(node, iter);

	for (pwliter = list->sublists; pwliter != NULL; pwliter = pwliter->next)
		pwlist_write(node, pwliter);
}

int
pwlist_write_file()
{
char		vers[5];
xmlDocPtr	doc;
xmlNodePtr	root;
char		tfile[PATH_MAX];

	if (options->readonly)
		return 0;

	if (!pwlist) {
		debug("write_file: bad password file");
		ui_statusline_msg("Bad password list");
		return -1;
	}

	snprintf(vers, 5, "%d", FF_VERSION);
	doc = xmlNewDoc((xmlChar const *)"1.0");

	root = xmlNewDocNode(doc, NULL, (xmlChar const *)"PWMan_PasswordList", NULL);

	xmlSetProp(root, (xmlChar const *)"version", (xmlChar *) vers);
	pwlist_write(root, pwlist);

	xmlDocSetRootElement(doc, root);

	snprintf(tfile, sizeof(tfile), "%s.tmp", options->password_file);
	if (gnupg_write(doc, options->gpg_id, tfile) == 0)
		rename(tfile, options->password_file);

	xmlFreeDoc(doc);
	return 0;
}

static void
pwlist_read_node(parent, list)
	xmlNodePtr	parent;
	pwlist_t	*list;
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

	pwlist_add_ptr(list, new);
}

static int
pwlist_read(parent, parent_list)
	xmlNodePtr	parent;
	pwlist_t	*parent_list;
{
xmlNodePtr	node;
pwlist_t       *new;
char const     *name;

	if (!parent || !parent->name) {
		ui_statusline_msg("Messed up xml node");
		return -1;
	}

	if (strcmp((char const *)parent->name, "PwList") != 0)
		return 0;

	name = (char const *)xmlGetProp(parent, (xmlChar const *)"name");
	new = pwlist_new(name);

	for (node = parent->children; node != NULL; node = node->next) {
		if (!node || !node->name) {
			debug("read_pwlist: messed up child node");
			continue;
		}

		if (strcmp((char const *)node->name, "PwList") == 0)
			pwlist_read(node, new);

		else if (strcmp((char const *)node->name, "PwItem") == 0)
			pwlist_read_node(node, new);
	}

	if (parent_list)
		pwlist_add_sublist(parent_list, new);
	else
		pwlist = current_pw_sublist = new;

	return 0;
}

int
pwlist_read_file()
{
char		fn        [STRING_LONG];
char const     *buf;
int		i = 0;
int		gnupg_worked = 0;
xmlNodePtr	node, root;
xmlDocPtr	doc;

	/* Have the defined a file yet? */
	if (!options->password_file)
		return -1;

	/* Do we need to create a new file? */
	snprintf(fn, STRING_LONG, "%s", options->password_file);
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
			pwlist_read(node, NULL);
			break;
		}
	}

	xmlFreeDoc(doc);
	return 0;
}

static int
pwlist_do_export(list, pw)
	pwlist_t	*list;
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
		pwlist_write(root, list);
	else
		pwlist_write_node(root, pw);

	xmlDocSetRootElement(doc, root);

	gnupg_write_many(doc, ids, MAX_ID_NUM, file);
	free(file);

	xmlFreeDoc(doc);

	for (i = 0; i < MAX_ID_NUM; i++)
		free(ids[i]);

	return 0;
}

int
pwlist_export_passwd(pw)
	password_t	*pw;
{
	return pwlist_do_export(NULL, pw);
}

int
pwlist_export_list(list)
	pwlist_t	*list;
{
	return pwlist_do_export(list, NULL);
}

int
pwlist_import_passwd()
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
			pwlist_read(node, current_pw_sublist);
			break;
		} else if (strcmp((char const *)node->name, "PwItem") == 0) {
			pwlist_read_node(node, current_pw_sublist);
			break;
		}
	}
	xmlFreeDoc(doc);
	return 0;
}

void
pwlist_unmark(list)
	pwlist_t	*list;
{
password_t	*pw;
pwlist_t	*pwl;

	for (pw = list->list; pw; pw = pw->next)
		pw->marked = 0;

	for (pwl = list->sublists; pwl; pwl = pwl->next)
		pwl->marked = 0;
}
