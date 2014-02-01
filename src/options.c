/*
 *  PWman - password management application
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
#include	<unistd.h>
#include	<pwd.h>

#include	<libxml/tree.h>
#include	<libxml/parser.h>

#include	"gnupg.h"
#include	"pwman.h"

static char    *options_get_file(void);
static char    *options_get_database(void);

Options *
options_new()
{
Options *ret;

	ret = xcalloc(1, sizeof(*ret));
	ret->passphrase_timeout = 180;
	ret->readonly = FALSE;

	ret->filter = filter_new();
	ret->search = search_new();

	return ret;
}

static char *
options_get_file()
{
char const     *home;
char           *ret;

	if ((home = getenv("HOME")) == NULL) {
	struct passwd  *pwd;

		if ((pwd = getpwuid(getuid())) == NULL)
			return NULL;
		home = pwd->pw_dir;
	}
	ret = xmalloc(strlen(home) + 1 + strlen(CONF_FILE) + 1);
	sprintf(ret, "%s/%s", home, CONF_FILE);
	return ret;
}

char *
options_get_database()
{
char const     *home;
char           *ret;

	if ((home = getenv("HOME")) == NULL) {
	struct passwd  *pwd;

		if ((pwd = getpwuid(getuid())) == NULL)
			return NULL;
		home = pwd->pw_dir;
	}
	ret = xmalloc(strlen(home) + 1 + strlen(DB_FILE) + 1);
	sprintf(ret, "%s/%s", home, DB_FILE);
	return ret;
}

int
options_read()
{
char           *file;
xmlDocPtr	doc;
xmlNodePtr	node, root;

	file = options_get_file();
	if (file == NULL)
		return -1;

	doc = xmlParseFile(file);
	if (!doc)
		return -1;

	root = xmlDocGetRootElement(doc);

	if (!root || !root->name || (strcmp((char *)root->name, "pwm_config") != 0)) {
		fprintf(stderr, "PWM-Warning: Badly formed .pwmanrc\n");
		return -1;
	}
	for (node = root->children; node != NULL; node = node->next) {
	char const     *text = (char const *)xmlNodeGetContent(node);

		if (!node || !node->name)
			debug("read_config: Fucked up xml node");

		else if (strcmp((char *)node->name, "gpg_id") == 0)
			options->gpg_id = xstrdup(text);

		else if (strcmp((char *)node->name, "gpg_path") == 0)
			options->gpg_path = xstrdup(text);

		else if (strcmp((char *)node->name, "copy_command") == 0)
			options->copy_command = xstrdup(text);

		else if (strcmp((char *)node->name, "password_file") == 0)
			options->password_file = xstrdup(text);

		else if (strcmp((char *)node->name, "passphrase_timeout") == 0)
			options->passphrase_timeout = atoi(text);

		else if (strcmp((char *)node->name, "filter") == 0) {
			options->filter->field = atoi((char const *)xmlGetProp(node, (xmlChar const *)"field"));
			options->filter->filter = xstrdup(text);

		} else if (strcmp((char *)node->name, "readonly") == 0)
			options->readonly = TRUE;

		else if (strcmp((char *)node->name, "text") == 0)
			/* Safe to ignore. This is whitespace etc */
			;
		else
			debug("read_config: Unrecognised xml node '%s'", (char *)node->name);
	}
	write_options = TRUE;
	xmlFreeDoc(doc);
	return 0;
}

int
options_write()
{
char           *file;
char		text[STRING_SHORT];
xmlDocPtr	doc;
xmlNodePtr	node, root;

	if (!write_options)
		return 0;

	file = options_get_file();
	if (file == NULL)
		return -1;

	if (!options)
		return -1;

	doc = xmlNewDoc((xmlChar const *) "1.0");
	root = xmlNewDocNode(doc, NULL, (xmlChar const *) "pwm_config", NULL);
	xmlNewChild(root, NULL, (xmlChar const *) "gpg_id", (xmlChar *) options->gpg_id);
	xmlNewChild(root, NULL, (xmlChar const *) "gpg_path", (xmlChar *) options->gpg_path);
	xmlNewChild(root, NULL, (xmlChar const *) "password_file", (xmlChar *) options->password_file);
	xmlNewChild(root, NULL, (xmlChar const *) "copy_command", (xmlChar *) options->copy_command);

	snprintf(text, sizeof(text), "%d", options->passphrase_timeout);
	xmlNewChild(root, NULL, (xmlChar const *) "passphrase_timeout", (xmlChar *) text);

	snprintf(text, sizeof(text), "%d", options->filter->field);
	node = xmlNewChild(root, NULL, (xmlChar const *) "filter", (xmlChar *) options->filter->filter);
	xmlSetProp(node, (xmlChar const *)"field", (xmlChar const *)text);

	/* Note - search isn't serialised, but filter is */

	xmlDocSetRootElement(doc, root);

	if (xmlSaveFormatFile(file, doc, TRUE) != -1) {
		xmlFreeDoc(doc);
		return 0;
	}

	debug("write_options: couldn't write config file");
	xmlFreeDoc(doc);
	return -1;
}

void
options_get()
{
char		*dbfile;
char		 line[1024];
char		**ids;
size_t		 nids, i;
char		*default_gpg;

	printf("~/.pwmanrc not found; starting initial configuration.\n\n");

	default_gpg = gnupg_find_program();
	if (!default_gpg) {
		fprintf(stderr, "warning: couldn't find gpg in $PATH\n");
		default_gpg = xstrdup("/usr/bin/gpg");
	}

	printf("Path to GnuPG [%s]: ", default_gpg);
	if (!fgets(line, sizeof(line), stdin))
		exit(1);
	line[strlen(line) - 1] = 0;

	options->gpg_path = *line ? xstrdup(line) : xstrdup(default_gpg);
	free(default_gpg);

	printf("\n");
	if (gnupg_list_ids(&ids, &nids)) {
		fprintf(stderr, "Couldn't invoke gpg.\n");
		exit(1);
	}

	if (nids == 0) {
		fprintf(stderr, "No keys available.\n");
		exit(1);
	}

	for (i = 0; i < nids; i++) {
		printf("%s\n", ids[i]);
		free(ids[i]);
	}
	free(ids);

	printf("\nGnuPG ID [you@yourdomain.com] or [012345AB]: ");
	if (!fgets(line, sizeof(line), stdin))
		exit(1);
	line[strlen(line) - 1] = 0;
	options->gpg_id = *line ? xstrdup(line) : xstrdup("you@yourdomain.com");

	dbfile = options_get_database();
	printf("Password database file [%s]: ", dbfile);
	if (!fgets(line, sizeof(line), stdin))
		exit(1);
	line[strlen(line) - 1] = 0;
	options->password_file = *line ? xstrdup(line) : xstrdup(dbfile);
	xfree(dbfile);

	printf("Passphrase timeout (in minutes) [180]: ");
	if (!fgets(line, sizeof(line), stdin))
		exit(1);

	if (strcmp(line, "\n") == 0)
		options->passphrase_timeout = 180;
	else
		options->passphrase_timeout = atoi(line);

	printf("Clipboard copy command [pbcopy]: ");
	if (!fgets(line, sizeof(line), stdin))
		exit(1);
	line[strlen(line) - 1] = 0;
	options->copy_command = *line ? xstrdup(line) : xstrdup("pbcopy");

	write_options = TRUE;
	options_write();
}
