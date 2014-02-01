/*
 *  Convert_PWDB - Convert old pwman files into the new format
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
#include	<stdio.h>

#include	<libxml/parser.h>

#include	"pwman.h"

#define STR_LEN 255
#define CONVERT_DB_PACKAGE "Convert_PWDB"
#define CONVERT_DB_VERSION "0.1.0"

static void		 show_version(void);
static void		 show_usage(char*);
static void		 get_options(int argc, char *argv[]);
static void		 free_pw(Pw *old);
static PWList		*parse_old_doc(xmlDocPtr doc);
static xmlDocPtr	 write_new_doc(PWList *list);
static PWList *		 new_pwlist(char const *name);
static void		 write_password_node(xmlNodePtr root, Pw *pw);
static int		 add_pw_ptr(PWList *list, Pw *new);
static xmlDocPtr	 get_data(void);
static Pw		*new_pw(void);
static Pw		*read_pw_node(xmlNodePtr parent);
static void		 write_pwlist(xmlNodePtr parent, PWList *list);
static char		*add_to_buf(char *buf, char *new);
static void		 put_data(xmlDocPtr doc);
static char		*ask(char *msg);

static char	*gpg_id;
static char	*infile;
static char	*outfile;
static int	 export;

void
debug(char const *fmt, ... )
{
#ifdef DEBUG
	va_list ap;
	int d, c;
	char *s;

	fputs("Convert_PWDB Debug% ", stderr);
	
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
#endif
}

static PWList *
new_pwlist(char const *name)
{
	PWList *new;
	new = malloc( sizeof(PWList) );
	new->name = malloc(STRING_MEDIUM);
	strncpy(new->name, name, STRING_MEDIUM);
	new->parent = NULL;
	new->list = NULL;
	new->sublists = NULL;
	debug("new_pwlist: %s", name);

	return new;
}

static int 
free_pwlist(PWList *old)
{
	Pw *current, *next;
	PWList *curlist, *nlist;

	if (!old)
		return 0;

	for (current = old->list; current != NULL; current = next) {
		next = current->next;
		free_pw(current);
	}

	for (curlist = old->sublists; curlist != NULL; curlist = nlist) {
		nlist = curlist->next;
		free_pwlist(curlist);
	}
	
	free(old->name);
	free(old);
	return 0;
}

static Pw*
new_pw()
{
	Pw *new;
	new = malloc(sizeof(Pw));
	new->id = 0;
	new->name = malloc(STRING_MEDIUM);
	new->host = malloc(STRING_MEDIUM);
	new->user = malloc(STRING_MEDIUM);
	new->passwd = malloc(STRING_SHORT);
	new->launch = malloc(STRING_LONG);

	memset(new->name, 0, STRING_MEDIUM);
	memset(new->host, 0, STRING_MEDIUM);
	memset(new->user, 0, STRING_MEDIUM);
	memset(new->passwd, 0, STRING_SHORT);
	memset(new->launch, 0, STRING_LONG);
	
	return new;
}

void
free_pw(Pw *old)
{
	free(old->name);
	free(old->user);
	free(old->host);
	free(old->passwd);
	free(old->launch);
	free(old);
}

static int
add_pw_ptr(PWList *list, Pw *new)
{
	Pw *current;
	
	if(list == NULL){
		debug("add_pw_ptr : Bad PwList");
		return -1;
	}
	if(new == NULL){
		debug("add_pw_ptr : Bad Pw");
		return -1;
	}
	if(list->list == NULL){
		list->list = new;
		new->next = NULL;
		return 0;
	}

	debug("add_pw_ptr: add to list");
	current = list->list;
	while(current->next != NULL){
		current = current->next;
	}
	current->next = new;
	new->next = NULL;

	return 0;
}

static void 
write_password_node(xmlNodePtr root, Pw *pw)
{
	xmlNodePtr node;

	node = xmlNewChild(root, NULL, (xmlChar const*)"PwItem", NULL);
	xmlNewChild(node, NULL, (xmlChar const*)"name", (xmlChar*)pw->name);
	xmlNewChild(node, NULL, (xmlChar const*)"host", (xmlChar*)pw->host);
	xmlNewChild(node, NULL, (xmlChar const*)"user", (xmlChar*)pw->user);
	xmlNewChild(node, NULL, (xmlChar const*)"passwd", (xmlChar*)pw->passwd);
	xmlNewChild(node, NULL, (xmlChar const*)"launch", (xmlChar*)pw->launch);
}

static void
write_pwlist(xmlNodePtr parent, PWList *list)
{
	xmlNodePtr node;
	Pw* iter;

	node = xmlNewChild(parent, NULL, (xmlChar const*)"PwList", NULL);
	xmlSetProp(node, (xmlChar const*)"name", (xmlChar*)list->name);

	for (iter = list->list; iter != NULL; iter = iter->next)
		write_password_node(node, iter);
}

static xmlDocPtr
write_new_doc(PWList *list)
{
char	vers[5];
	xmlDocPtr doc;
	xmlNodePtr root;

	if (list == NULL){
		puts("write_new_doc: bad password data");
		exit(-1);
	}
	snprintf(vers, 5, "%d", FF_VERSION);
	doc = xmlNewDoc((xmlChar const*)"1.0");

	if (!export) {
		root = xmlNewDocNode(doc, NULL, (xmlChar const*)"PWMan_PasswordList", NULL);
		xmlSetProp(root, (xmlChar const *)"version", (xmlChar *) vers);
		write_pwlist(root, list);
	} else {
		root = xmlNewDocNode(doc, NULL, (xmlChar const*)"PWMan_Export", NULL);
		xmlSetProp(root, (xmlChar const *) "version", (xmlChar *) vers);
		write_password_node(root, list->list);	
	}

	xmlDocSetRootElement(doc, root);

	return doc;
}

static Pw *
read_pw_node(xmlNodePtr parent)
{
	Pw *new;
	xmlNodePtr node;
	char *text;

	new = new_pw();

	for(node = parent->children; node != NULL; node = node->next){
		if(!node || !node->name){
			debug("read_pw_node: fucked node");
		} else if( strcmp((char*)node->name, "name") == 0){
			text = (char*)xmlNodeGetContent(node);
			if(text) strncpy(new->name, text, STRING_MEDIUM);
		} else if( strcmp((char*)node->name, "user") == 0){
			text = (char*)xmlNodeGetContent(node);
			if(text) strncpy(new->user, text, STRING_MEDIUM);
		} else if( strcmp((char*)node->name, "passwd") == 0){
			text = (char*)xmlNodeGetContent(node);
			if(text) strncpy(new->passwd, text, STRING_SHORT);
		} else if( strcmp((char*)node->name, "host") == 0){
			text = (char*)xmlNodeGetContent(node);
			if(text) strncpy(new->host, text, STRING_MEDIUM);
		} else if( strcmp((char*)node->name, "launch") == 0){
			text = (char*)xmlNodeGetContent(node);
			if(text) strncpy(new->launch, text, STRING_LONG);
		} else {
			debug("read_pw_node: unrecognised node \"%s\"", node->name);
		}
	}
	return new;
}

static PWList*
parse_old_doc(xmlDocPtr doc)
{
PWList		*list;
Pw		*pw;
xmlNodePtr	 root, node;

	list = new_pwlist("Main");

	if(!doc){
		debug("parse_old_doc: Bad xmlDocPtr");
		return NULL;
	}

	root = xmlDocGetRootElement(doc);
	
	if (!root || !root->name) {
		debug("parse_old_doc: Badly formed data");
		return NULL;
	}

	if (strcmp((char const *)root->name, "PWMan_Export") == 0)
		export = 1;
	else if (strcmp((char const *)root->name, "PWMan_List") == 0)
		export = 0;
	else {
		debug("parse_old_doc: Not a pwman file");
		return NULL;
	}

	for(node = root->children; node != NULL; node = node->next){
		if(!node || !node->name){
			debug("parse_old_doc: Bad xml Node");
		} else if( strcmp((char*)node->name, "PW_Item") == 0){
			pw = read_pw_node(node);
			add_pw_ptr(list, pw);
		} else {
			debug("parse_old_doc: Unrecognised xml Node - \"%s\"", node->name);
		}
	}

	if (list->list){
		return list;
	} else {
		fputs("Unrecognised file format\n", stderr);
		exit(-1);
	}
}

static char *
add_to_buf(char *buf, char *new)
{
	if (new == NULL)
		return buf;

	if (buf == NULL) {
		buf = malloc(strlen(new) + 1);
		strcpy(buf, new);
		return buf;
	}

	buf = realloc(buf, strlen(buf) + strlen(new) + 1);
	strcat(buf, new);

	return buf;
}

static xmlDocPtr
get_data()
{
	FILE *fp;
	char *cmd;
	char *data;
	char buf[STR_LEN];
	xmlDocPtr doc;

	data = NULL;
	cmd = malloc(STR_LEN);
	snprintf(cmd, STR_LEN, "gpg -d %s", infile);
	debug(cmd);
	fp = popen(cmd, "r");

	while (fgets(buf, STR_LEN, fp) != NULL)
		data = add_to_buf(data, buf);
	pclose(fp);

	if (!data){
		exit(1);
	}

	doc = xmlParseMemory(data, (int) strlen(data));

	return doc;
}

static void
put_data(xmlDocPtr doc)
{
	FILE *fp;
	char *cmd;

	cmd = malloc(STR_LEN);
	snprintf(cmd, STR_LEN, "gpg -e -r %s -o %s", gpg_id, outfile);
	debug(cmd);
	fp = popen(cmd, "w");

#if LIBXML_VERSION >= 20423
	xmlDocFormatDump(fp, doc, TRUE);
#else
	xmlDocDump(fp, doc);
#endif
	
	pclose(fp);
}

static char *
ask(char *msg)
{
	char * input;

	input = malloc(STR_LEN);

	fputs(msg, stdout);
	fputc('\t', stdout);
	fgets(input, STR_LEN, stdin);

	input[ strlen(input) - 1] = 0;

	return input;
}

static void
get_options(int argc, char *argv[])
{
	int i;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			show_usage(argv[0]);
			exit(1);
		} else if (!strcmp(argv[i], "--version") || !strcmp(argv[i], "-v")) {
			show_version();
			exit(1);
		}
	}
	
	if (argc > 1) {
		gpg_id = strdup(argv[1]);
	} else
		gpg_id = ask("ID to encrypt new file to:");

	if (argc > 2) {
		infile = strdup(argv[2]);
	} else
		infile = ask("File in old format:");

	if (argc > 3) {
		outfile = strdup(argv[3]);
	} else
		outfile = ask("File to write new format to:");
}

int
main(int argc, char *argv[])
{
xmlDocPtr	 doc;
PWList		*list;
	
	get_options(argc, argv);

	doc = get_data();
	list = parse_old_doc(doc);
	xmlFreeDoc(doc);
	
	doc = write_new_doc(list);
	put_data(doc);
	xmlFreeDoc(doc);
	free_pwlist(list);

	free(infile);
	free(outfile);
	free(gpg_id);

	return 0;
}

static void
show_version()
{
	puts(CONVERT_DB_PACKAGE " v " CONVERT_DB_VERSION);
	puts("Written by Ivan Kelly <ivan@ivankelly.net>\n");
	puts("Copyright (C) 2002 Ivan Kelly");
	puts("This program is free software; you can redistribute it and/or modify");
	puts("it under the terms of the GNU General Public License as published by");
	puts("the Free Software Foundation; either version 2 of the License, or");
	puts("(at your option) any later version.\n");

	puts("This program is distributed in the hope that it will be useful,");
	puts("but WITHOUT ANY WARRANTY; without even the implied warranty of");
	puts("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the");
	puts("GNU General Public License for more details.\n");

	puts("You should have received a copy of the GNU General Public License");
	puts("along with this program; if not, write to the Free Software");
	puts("Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.\n");
}

static void
show_usage(char *argv_0)
{
	printf("Usage: %s [<gnupg_id> [<oldfile> [<newfile>]]]\n", argv_0);
	puts("Convert Password Database from PWMan versions >= 0.2.1 to new format 0.3.0+\n");
	puts("  --help                 show usage");
	puts("  --version              display version information");
	puts("  <gnupg_id>             GnuPG ID to encrypt new password database to");
	puts("  <oldfile>              password database file in old format");
	puts("  <newfile>              password database file to write in new format\n\n");
	puts("Report bugs to <ivan@ivankelly.net>");
}
