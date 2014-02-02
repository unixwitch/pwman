/*
 *  PWDB2CSV - Convert pwman database files into Comma Separated Values
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
#include	<assert.h>

#include	<libxml/parser.h>

#include	"pwman.h"

#define STR_LEN 255
#define PWDB2CSV_PACKAGE "PWDB2CSV"
#define PWDB2CSV_VERSION "0.1.0"

static void show_version(void);
static void show_usage(char*);

static password_t*		 new_pw(void);
static folder_t		*new_folder(char *name);
static void		 free_pw(password_t *old);
static void		 free_folder(folder_t *old);

static folder_t		*parse_doc(xmlDocPtr doc);
static char		*add_to_buf(char *buf, char const *new);
static xmlDocPtr	 get_data(void);
static int		 read_folder(xmlNodePtr parent, folder_t *parent_list);
static void		 read_password_node(xmlNodePtr parent, folder_t *list);
static void		 write_password_node(FILE *fp, password_t *pw);
static int		 write_folder(FILE *fp, folder_t *folder);
static void		 add_pw_sublist(folder_t *parent, folder_t *new);
static void		 add_pw_ptr(folder_t *list, password_t *new);
static char		*escape_string(char const *str);
static void		 put_data(folder_t *list);
static char		*ask(char const *msg);
static void		 get_options(int argc, char *argv[]);

static char *infile;
static char *outfile;

void
debug(char const *fmt, ... )
{
#ifdef DEBUG
	va_list ap;
	int d, c;
	char *s;

	fputs("PWDB2CSV Debug% ", stderr);
	
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
#endif
}

static folder_t *
new_folder(char *name)
{
	folder_t *new;

	new = malloc( sizeof(folder_t) );
	new->name = malloc(STRING_MEDIUM);
	strncpy(new->name, name, STRING_MEDIUM);
	new->parent = NULL;
	PWLIST_INIT(&new->list);
	new->sublists = NULL;
	debug("new_folder: %s", name);

	return new;
}

static void
free_folder(folder_t *old)
{
password_t	*current, *next;
folder_t	*curlist, *nlist;

	debug("free_folder: free a password list");
	if (old == NULL)
		return;

	PWLIST_FOREACH_SAFE(current, &old->list, next)
		free_pw(current);

	for (curlist = old->sublists; curlist != NULL; curlist = nlist){
		nlist = curlist->next;
		free_folder(curlist);
	}
	
	free(old->name);
	free(old);
	return;
}

static password_t*
new_pw()
{
	password_t *new;
	new = malloc(sizeof(password_t));
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

static void
free_pw(password_t *old)
{
	debug("free_pw: free a password");
	if (!old)
		return;

	free(old->name);
	free(old->user);
	free(old->host);
	free(old->passwd);
	free(old->launch);
	free(old);
}

static void
add_pw_ptr(folder_t *list, password_t *new)
{
	assert(list);
	assert(new);
	
	PWLIST_INSERT_TAIL(&list->list, new);
}

static void
add_pw_sublist(folder_t *parent, folder_t *new)
{
	folder_t *current;

	current = parent->sublists;
	new->parent = parent;
	if(current == NULL){
		parent->sublists = new;
		new->next = NULL;
		return;
	} 
	while(current->next != NULL){
		current = current->next;
	}
	current->next = new;
	new->next = NULL;
}

static char *
escape_string(str)
	char const	*str;
{
char		*ret, *q;
char const	*p;

	ret = malloc(strlen(str) * 2 + 1);
	for (p = str, q = ret; *p; p++) {
		if (*p == '"')
			*q++ = '"';
		*q++ = *p;
	}

	return ret;
}

static void
write_password_node(FILE *fp, password_t *pw)
{
char	*ename, *ehost, *euser, *epasswd, *elaunch;

	ename = escape_string(pw->name);
	ehost = escape_string(pw->host);
	euser = escape_string(pw->user);
	epasswd = escape_string(pw->passwd);
	elaunch = escape_string(pw->launch);

	fprintf(fp, "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", ename, ehost, euser,
		epasswd, elaunch);

	free(ename);
	free(ehost);
	free(euser);
	free(epasswd);
	free(elaunch);
}

static int
write_folder(FILE *fp, folder_t *list)
{
password_t*	 iter;
folder_t	*pwliter;
	
	for (pwliter = list->sublists; pwliter != NULL; pwliter = pwliter->next)
		write_folder(fp, pwliter);

	PWLIST_FOREACH(iter, &list->list)
		write_password_node(fp, iter);

	return 0;
}

static void
read_password_node(xmlNodePtr parent, folder_t *list)
{
	password_t *new;
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
	add_pw_ptr(list, new);
}

static int
read_folder(xmlNodePtr parent, folder_t *parent_list)
{
xmlNodePtr	 node;
folder_t		*new;
char		 name[STRING_MEDIUM];

	if (!parent || !parent->name)
		return -1;

	debug("Parent name is %s\n", parent->name);

	if (strcmp((char const *)parent->name, "PwList") != 0)
		return 0;

	strncpy(name, (char const *) xmlGetProp(parent, (xmlChar const*)"name"), STRING_MEDIUM);
	new = new_folder(name);

	for (node = parent->children; node != NULL; node = node->next) {
		debug("Child name is %s\n", node->name);	
		if (!node)
			fprintf(stderr, "read_folder: messed up node - null\n");
		else if(strcmp((char const *)node->name, "PwList") == 0)
			read_folder(node, new);
		else if(strcmp((char const *)node->name, "PwItem") == 0)
			read_password_node(node, new);
	}

	if (parent_list)
		add_pw_sublist(parent_list, new);

	return 0;
}

static folder_t *
parse_doc(xmlDocPtr doc)
{
folder_t		*list = NULL;
xmlNodePtr	 root, node;
char		*buf;
int		 i;
	
	if(!doc)
		return NULL;

	root = xmlDocGetRootElement(doc);
	if (!root)
		return NULL;

	if (!root->name || (strcmp((char const *)root->name, "PWMan_PasswordList") != 0)) {
		xmlFreeDoc(doc);
		return NULL;
	}

	if ((buf = (char *) xmlGetProp(root, (xmlChar const *)"version")) != NULL)
		i = atoi(buf);
	else
		i = 0;

	if (i < FF_VERSION) {
		xmlFreeDoc(doc);
		return NULL;
	}

	list = new_folder("Main");
	for (node = root->children; node != NULL; node = node->next) {
		if (strcmp((char const *) node->name, "PwList") == 0) {
			read_folder(node, list);
			break;
		}
	}

	xmlFreeDoc(doc);

	return list;
}

static char *
add_to_buf(buf, new)
	char		*buf;
	char const	*new;
{
size_t	size;

	if (new == NULL)
		return buf;

	if (buf == NULL) {
		buf = malloc(strlen(new)+1);
		strcpy(buf, new);
		return buf;
	}

	size = strlen(buf) + strlen(new) + 1;
	buf = realloc(buf, size);
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

	while( fgets(buf, STR_LEN, fp) != NULL ){
		data = add_to_buf(data, buf);
	}
	pclose(fp);

	if(!data){
		exit(-1);
	}

	doc = xmlParseMemory(data, (int) strlen(data));

	return doc;
}

static void
put_data(folder_t *list)
{
FILE	*fp;

	fp = fopen(outfile, "w");

	if (!fp) {
		fprintf(stderr, "write_folder: couldn't open file \"%s\"\n", outfile);
		return;
	}

	write_folder(fp, list);

	fclose(fp);
}

static char *
ask(msg)
	char const	*msg;
{
char	*input;
	input = malloc(STR_LEN);

	fputs(msg, stdout);
	fputc('\t', stdout);
	fgets(input, STR_LEN, stdin);

	input[strlen(input) - 1] = 0;

	return input;
}

static void
get_options(int argc, char *argv[])
{
	int i;

	for(i = 0; i < argc; i++){
		if( !strcmp(argv[i], "--help") || !strcmp(argv[i], "-h") ){
			show_usage(argv[0]);
			exit(1);
		} else if( !strcmp(argv[i], "--version") || !strcmp(argv[i], "-v") ){
			show_version();
			exit(1);
		}
	}
	
	if(argc > 1){
		infile = malloc(STR_LEN);
		strncpy(infile, argv[1], STR_LEN);
	} else {
		infile = ask("Password database:");
	}
	if(argc > 2){
		outfile = malloc(STR_LEN);
		strncpy(outfile, argv[2], STR_LEN);
	} else {
		outfile = ask("CSV file:");
	}
}

int
main(int argc, char *argv[])
{
xmlDocPtr	 doc;
folder_t		*list;
	
	get_options(argc, argv);

	doc = get_data();
	list = parse_doc(doc);
	put_data(list);
	free_folder(list);

	return 0;
}

static void
show_version()
{
	puts(PWDB2CSV_PACKAGE " v " PWDB2CSV_VERSION);
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
	printf("Usage: %s [<pwdatabase> [<csvfile>]]\n", argv_0);
	puts("Convert Password Database from PWMan Encrypted Format to Comma Separated Values\n");
	puts("  --help                 show usage");
	puts("  --version              display version information");
	puts("  <pwdatabase>           password database file in encrypted");
	puts("  <csvfile>              file to write to with comma separated values\n\n");
	puts("Report bugs to <ivan@ivankelly.net>");
}
