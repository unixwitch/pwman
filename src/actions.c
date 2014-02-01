/*
 *  PWman - Password management application
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
#include	"gnupg.h"
#include	"actions.h"

static void	action_edit_pw(Pw *pw);
static void	_create_information_field(char* name, InputField* field);

static int disp_h = 15, disp_w = 60;

void
action_list_add_pw()
{
Pw	*pw;

	InputField fields[] = {
		{"Name: ",		NULL, STRING},
		{"Host: ",		NULL, STRING},
		{"User: ",		NULL, STRING},
		{"Password: ",		NULL, STRING, pwgen_ask},
		{"Launch command: ",	NULL, STRING}
	};
	int i;

	pw = pwlist_new_pw(); 
	if ((pw->name = ui_ask_str(fields[0].name, NULL)) == NULL)
		goto end;

	if ((pw->host = ui_ask_str(fields[1].name, NULL)) == NULL)
		goto end;

	if ((pw->user = ui_ask_str(fields[2].name, NULL)) == NULL)
		goto end;

	if ((pw->passwd = ui_ask_str_with_autogen(fields[3].name, NULL,
			fields[3].autogen, CNTL('G'))) == NULL)
		goto end;
	
	if ((pw->launch = ui_ask_str(fields[4].name, NULL)) == NULL)
		goto end;
	
	fields[0].value = &pw->name;
	fields[1].value = &pw->host;
	fields[2].value = &pw->user;
	fields[3].value = &pw->passwd;
	fields[4].value = &pw->launch;

	i = action_yes_no_dialog(fields, (sizeof(fields)/sizeof(InputField)), NULL, "Add this entry");

	if (i) {
		pwlist_add_ptr(current_pw_sublist, pw);
		ui_statusline_msg("New password added");
	} else {
		pwlist_free_pw(pw);
		ui_statusline_msg("New password cancelled");
	}

	uilist_refresh();
	return;

end:
	pwlist_free_pw(pw);
}

static void
action_edit_pw(Pw *pw)
{
	InputField fields[] = {
		{"Name: ",		&pw->name,	STRING},
		{"Host: ",		&pw->host,	STRING},
		{"User: ",		&pw->user,	STRING},
		{"Password: ",		&pw->passwd,	STRING, pwgen_ask},
		{"Launch command: ",	&pw->launch,	STRING}
	};

	action_input_dialog(fields, (sizeof(fields)/sizeof(InputField)), "Edit password");
}

void 
action_list_rename()
{
	Pw* curpw;
	PWList* curpwl;
	char *new_name;

	new_name = malloc(STRING_MEDIUM);

	switch(uilist_get_highlighted_type()){
		case PW_ITEM:
			curpw = uilist_get_highlighted_item();
			if (curpw) {
				new_name = ui_ask_str("New name", curpw->name);
				if (strlen(new_name) > 0)
					pwlist_rename_item(curpw, new_name);
				free(new_name);
			}
			break;

		case PW_SUBLIST:
			curpwl = uilist_get_highlighted_sublist();
			if(curpwl){
				new_name = ui_ask_str("New sublist name", curpwl->name);
				if (strlen(new_name) > 0)
					pwlist_rename_sublist(curpwl, new_name);
				free(new_name);
			}
			break;

		case PW_UPLEVEL:
		case PW_NULL:
			/* do nothing */
			break;
	}

	uilist_refresh();
}

void
action_edit_options()
{
	InputField fields[] = {
		{"GnuPG path:\t",	&options->gpg_path, STRING},
		{"GnuPG key ID:\t",	&options->gpg_id, STRING},
		{"Password file:\t",	&options->password_file, STRING},
		{"Passphrase timeout (in minutes):\t", &options->passphrase_timeout, INT}
	};

	action_input_dialog(fields, (sizeof(fields)/sizeof(InputField)), "Edit Preferences");

	write_options = TRUE;
}

void
action_input_dialog_draw_items(WINDOW* dialog_win, InputField *fields, 
		int num_fields, char *title, char *msg)
{
	int i, h = 0;

	wclear(dialog_win);
	
	box(dialog_win, 0, 0);

	if (title) {
		wattron(dialog_win, A_BOLD);
		i = strlen(title);
		h += 2;
		mvwaddstr(dialog_win, h, (disp_w - i)/2, title);
		wattroff(dialog_win, A_BOLD);
	}

	/* loop through fields */
	for(i = 0; i < num_fields; i++){
		h += 2;
		if(fields[i].type == STRING){
			mvwprintw(dialog_win, h, 3,
				"%d - %s %s", (i+1), fields[i].name, *(char**)fields[i].value);
		} else if(fields[i].type == INT){
			mvwprintw(dialog_win, h, 3,
				"%d - %s %d", (i+1), fields[i].name, *((int*)fields[i].value) );
		} else if(fields[i].type == INFORMATION){
			mvwprintw(dialog_win, h, 3,
				"%d - %s", (i+1), fields[i].name);
		}
	}

	wattron(dialog_win, A_BOLD);

	if(msg){
		i = strlen(msg);
		h += 2;
		mvwaddstr(dialog_win, h, (disp_w - i)/2, msg);
	}

	wattroff(dialog_win, A_BOLD);

	/*
	 * do final stuff the put all together
	 */
	wrefresh(dialog_win);
}

void
action_input_dialog(InputField *fields, int num_fields, char *title)
{
	int ch, i;
	WINDOW *dialog_win;
	char msg[] = "(press 'q' to return to list)";

	/*
	 * initialize the info window
	 */
	if(title)
		disp_h = ((num_fields+2) * 2) + 3;
	else
		disp_h = ((num_fields+1) * 2) + 3;
	
	dialog_win = newwin(disp_h, disp_w, (LINES - disp_h)/2, (COLS - disp_w)/2);
	keypad(dialog_win, TRUE);

	action_input_dialog_draw_items(dialog_win, fields, num_fields, title, msg);

	/*
	 * actions loop
	 */
	while ((ch = wgetch(dialog_win)) != 'q'){
		if (options->readonly) {
			statusline_readonly();
			continue;
		}

		if ((ch >= '1') && (ch <= NUM_TO_CHAR(num_fields))) {
			i = CHAR_TO_NUM(ch);
			if (fields[i].autogen != NULL) {
				*(char **)fields[i].value = ui_ask_str_with_autogen(
							fields[i].name,
							*(char **)fields[i].value,
							fields[i].autogen, CNTL('G')); 
			} else if (fields[i].type == STRING){
				*(char **)fields[i].value = ui_ask_str(fields[i].name,
							*(char **)fields[i].value);
			} else if (fields[i].type == INT) {
				*(int *)fields[i].value = ui_ask_num(fields[i].name);
			} else if(fields[i].type == INFORMATION) {
				/* Easy, do nothing! */
			}
			action_input_dialog_draw_items(dialog_win, fields, num_fields, title, msg);
		} else if(ch == 'l'){
			delwin(dialog_win);
			action_list_launch();
			break;
		}	
	}
	/*
	 * clean up
	 */
	delwin(dialog_win);
	uilist_refresh();
}

void
action_input_gpgid_dialog(InputField *fields, int num_fields, char *title)
{
	int i, valid_id;
	int ch = '1', first_time = 1;
	WINDOW *dialog_win;
	char msg[] = "(press 'q' when export recipient list is complete)";
	char msg2[80];
	/*
	 * initialize the info window
	 */
	disp_h = ((num_fields+2) * 2) + 3;
	dialog_win = newwin(disp_h, disp_w, (LINES - disp_h)/2, (COLS - disp_w)/2);
	keypad(dialog_win, TRUE);

	action_input_dialog_draw_items(dialog_win, fields, num_fields, title, msg);

	/*
	 * actions loop - ignore read only as not changing main state
	 */
	while(first_time || ((ch = wgetch(dialog_win)) != 'q')){
		/* On first loop, drop straight into recipient 1 */
		first_time = 0;

		if( (ch >= '1') && (ch <= NUM_TO_CHAR(num_fields)) ){
			i = CHAR_TO_NUM(ch);
			*(char **)fields[i].value = ui_ask_str(fields[i].name,
						*(char **)fields[i].value);
			
			/* Now verify it's a valid recipient */
			if (strlen(fields[i].value)) {
				valid_id = gnupg_check_id(fields[i].value);
				if(valid_id == 0) {
					/* Good, valid id */
				} else {
					/* Invalid id. Warn and blank */
					if(valid_id == -2)
						snprintf(msg2, sizeof(msg2), "Key expired for \"%s\"",
							 *(char**)fields[i].value);
					else
						snprintf(msg2, sizeof(msg2), "Invalid recipient \"%s\"",
							 *(char**)fields[i].value);

					ui_statusline_msg(msg2);
					*(char **) fields[i].value = NULL;
				}

				/* Redraw display */
				action_input_dialog_draw_items(dialog_win, fields, num_fields, title, msg);
			}
		}
	}

	/*
	 * clean up
	 */
	delwin(dialog_win);
	uilist_refresh();
}

int 
action_yes_no_dialog(InputField *fields, int num_fields, char *title, char *question)
{
int	 i;
WINDOW	*dialog_win;

	/*
	 * initialize the info window
	 */
	if (title)
		disp_h = ((num_fields+2) * 2) + 3;
	else
		disp_h = ((num_fields+1) * 2) + 3;
	
	dialog_win = newwin(disp_h, disp_w, (LINES - disp_h)/2, (COLS - disp_w)/2);
	keypad(dialog_win, TRUE);

	action_input_dialog_draw_items(dialog_win, fields, num_fields, title, NULL);
	
	i = ui_ask_yes_no(question, 1);

	/*
	 * clean up
	 */
	delwin(dialog_win);
	uilist_refresh();

	return i;
}

void
action_list_add_sublist()
{
char	*name;
PWList	*sublist, *iter;

	name = ui_ask_str("Sublist name:", NULL);
	for (iter = current_pw_sublist->sublists; iter != NULL; iter = iter->next) {
		if (strcmp(iter->name, name) == 0) {
			free(name);
			return;
		}
	}

	sublist = pwlist_new(name);
	free(name);

	pwlist_add_sublist(current_pw_sublist, sublist);
	uilist_refresh();
}

int
action_list_at_top_level()
{
	if(current_pw_sublist->parent){
		action_list_up_one_level();
		uilist_refresh();
		return 0;
	} else {
		return 1;
	}
}

void
action_list_select_item()
{
	Pw* curpw;
	PWList* curpwl;
	PWSearchResult* cursearch;

	/* Are they searching, or in normal mode? */
	if(search_results != NULL) {
		cursearch = uilist_get_highlighted_searchresult();
		curpwl = cursearch->sublist;
		curpw = cursearch->entry;

		if (curpw) {
			action_edit_pw(curpw);
		} else if(curpwl){
			/* Quite out of searching */
			search_remove();

			/* Now display the selected sublist */
			current_pw_sublist = curpwl;
			uilist_refresh();
		}
	} else {
		switch(uilist_get_highlighted_type()){
			case PW_ITEM:
				curpw = uilist_get_highlighted_item();
				if(curpw){
					action_edit_pw(curpw);
				}
				break;
			case PW_SUBLIST:
				curpwl = uilist_get_highlighted_sublist();
				if(curpwl){
					current_pw_sublist = curpwl;
					uilist_refresh();
				}
				break;
			case PW_UPLEVEL:
				action_list_up_one_level();
				break;
			case PW_NULL:
				/* do nothing */
				break;
		}
	}
}

void
action_list_delete_item()
{
	Pw* curpw;
	PWList* curpwl;
	PWSearchResult* cursearch;
	int i;
	char str[STRING_LONG];
	
	if (search_results) {
		cursearch = uilist_get_highlighted_searchresult();
		curpwl = cursearch->sublist;
		curpw = cursearch->entry;

		if (curpw) {
			snprintf(str, STRING_LONG, "Really delete \"%s\"", curpw->name);
			if ((i = ui_ask_yes_no(str, 0)) != 0) {
				pwlist_delete_pw(curpwl, curpw);
				ui_statusline_msg("Password deleted");
			} else {
				ui_statusline_msg("Password not deleted");
			}

			search_remove();
			return;
		}

		snprintf(str, STRING_LONG, "Really delete Sublist \"%s\"", curpwl->name);
		if ((i = ui_ask_yes_no(str, 0)) != 0) {
			pwlist_delete_sublist(curpwl->parent, curpwl);
			ui_statusline_msg("Password Sublist deleted");
		} else {
			ui_statusline_msg("Password not deleted");
		}

		search_remove();
		return;
	}

	switch(uilist_get_highlighted_type()){
		case PW_ITEM:
			curpw = uilist_get_highlighted_item();
			if(curpw){
				snprintf(str, STRING_LONG, "Really delete \"%s\"", curpw->name);
				i = ui_ask_yes_no(str, 0);
				if(i){
					pwlist_delete_pw(current_pw_sublist, curpw);
					ui_statusline_msg("Password deleted");
				} else {
					ui_statusline_msg("Password not deleted");
				}	
			}
			break;

		case PW_SUBLIST:
			curpwl = uilist_get_highlighted_sublist();
			if(curpwl){
				snprintf(str, STRING_LONG, "Really delete Sublist \"%s\"", curpwl->name);
				i = ui_ask_yes_no(str, 0);
				if(i){
					pwlist_delete_sublist(curpwl->parent, curpwl);
					ui_statusline_msg("Password Sublist deleted");
				} else {
					ui_statusline_msg("Password not deleted");
				}
			}
			break;
		case PW_UPLEVEL:
		case PW_NULL:
			/* do nothing */
			break;
	}
	uilist_refresh();
}

void
action_list_move_item()
{
Pw*	 curpw;
PWList	*curpwl, *iter;
char	 str[STRING_LONG];
char	*answer;

	switch(uilist_get_highlighted_type()){
		case PW_ITEM:
			curpw = uilist_get_highlighted_item();
			if(curpw){
				for (;;) {
					snprintf(str, sizeof(str), "Move \"%s\" to where?", curpw->name);
					answer = ui_ask_str(str, NULL);
					
					/* if user just enters nothing do nothing */
					if (answer[0] == 0) {
						free(answer);
						return;
					}
					
					for(iter = current_pw_sublist->sublists; iter != NULL; iter = iter->next){
						if (strcmp(iter->name, answer) != 0)
							continue;

						pwlist_detach_pw(current_pw_sublist, curpw);
						pwlist_add_ptr(iter, curpw);
						uilist_refresh();
						free(answer);
						return;
					}

					free(answer);
					ui_statusline_msg("Sublist does not exist, try again");
					getch();
				}
			}
			break;

		case PW_SUBLIST:
			curpwl = uilist_get_highlighted_sublist();
			if (curpwl) {
				for (;;) {
					snprintf(str, sizeof(str), "Move sublist \"%s\" to where?", curpwl->name);
					answer = ui_ask_str(str, NULL);
					
					/* if user just enters nothing, do nothing */
					if (answer[0] == 0) {
						free(answer);
						return;
					}

					if (strcmp(answer, curpwl->name) == 0) {
						free(answer);
						return;
					}

					for(iter = current_pw_sublist->sublists; iter != NULL; iter = iter->next){
						if (strcmp(iter->name, answer) != 0)
							continue;

						pwlist_detach_sublist(current_pw_sublist, curpwl);
						pwlist_add_sublist(iter, curpwl);
						uilist_refresh();
						free(answer);
						return;
					}

					ui_statusline_msg("Sublist does not exist, try again");
					getch();
				}
			}
			break;
		case PW_UPLEVEL:
		case PW_NULL:
			/* do nothing */
			break;
	}
}

void
action_list_move_item_up_level()
{
	Pw* curpw;
	PWList *curpwl;

	/* Do nothing if searching */
	if(search_results != NULL)
		return;

	/* Do the right thing based on type */
	switch (uilist_get_highlighted_type()) {
		case PW_ITEM:
			curpw = uilist_get_highlighted_item();
			if(curpw && current_pw_sublist->parent){
				pwlist_detach_pw(current_pw_sublist, curpw);
				pwlist_add_ptr(current_pw_sublist->parent, curpw);
				uilist_refresh();
			}
			break;

		case PW_SUBLIST:
			curpwl = uilist_get_highlighted_sublist();
			if(curpwl && current_pw_sublist->parent){
				pwlist_detach_sublist(current_pw_sublist, curpwl);
				pwlist_add_sublist(current_pw_sublist->parent, curpwl);
				uilist_refresh();
			}
			break;

		case PW_UPLEVEL:
		case PW_NULL:
			/* do nothing */
			break;
	}
}

void
action_list_up_one_level()
{
	/* move up one sublist */
	if(current_pw_sublist->parent){
		current_pw_sublist = current_pw_sublist->parent;
		uilist_refresh();
	}
}
	
void
action_list_export()
{
	Pw* curpw;
	PWList *curpwl;

	debug("list_export: enter switch");
	switch(uilist_get_highlighted_type()){
		case PW_ITEM:
			debug("list_export: is a pw");
			curpw = uilist_get_highlighted_item();
			if(curpw){
				pwlist_export_passwd(curpw);
			}
			break;
		case PW_SUBLIST:
			debug("list_export: is a pwlist");
			curpwl = uilist_get_highlighted_sublist();
			if(curpwl){
				pwlist_export_list(curpwl);
			}
			break;
		case PW_UPLEVEL:
		case PW_NULL:
			/* do nothing */
			break;
	}
}

static void
_create_information_field(char* name, InputField* field)
{
	field->name = name;
	field->value = NULL;
	field->type = INFORMATION;
}

void
action_list_locate()
{
	int depth = 0, count = 0;
	char* currentName = NULL;
	InputField* fields;
	Pw* curpw = NULL;
	PWList *curpwl = NULL;
	PWList *parent = NULL;
	PWSearchResult* cursearch;

	if(search_results != NULL) {
		cursearch = uilist_get_highlighted_searchresult();
		curpwl = cursearch->sublist;
		curpw = cursearch->entry;

		if(curpw) {
			parent = curpwl;
		} else {
			parent = curpwl->parent;
		}
	} else {
		parent = current_pw_sublist;
		switch(uilist_get_highlighted_type()){
			case PW_ITEM:
				curpw = uilist_get_highlighted_item();
				break;

			case PW_SUBLIST:
				curpwl = uilist_get_highlighted_sublist();
				break;

			case PW_NULL:
			case PW_UPLEVEL:
				/* do nothing */
				break;
		}
	}

	if(curpw) {
		currentName = curpw->name;
		depth = 1;
	} else if(curpwl) {
		currentName = curpwl->name;
		depth = 1;
	} else
		return;

	/* Figure out how many parents we have */
	curpwl = parent;
	while(curpwl){
		curpwl = curpwl->parent;
		depth++;
	}
	count = depth;

	/* Now grab their names */
	fields = xcalloc(depth, sizeof(InputField));
	if(currentName){
		depth--;
		_create_information_field(currentName, &fields[depth]);
	}
	curpwl = parent;
	while(curpwl){
		depth--;
		_create_information_field(curpwl->name, &fields[depth]);
		curpwl = curpwl->parent;
	}

	/* Have it rendered */
	action_input_dialog(fields, count, "Location of Item");

	/* All done, tidy up */
	free(fields);
}

void
action_list_launch()
{
	int i;
	Pw* curpw;
	char msg[STRING_LONG];

	switch (uilist_get_highlighted_type()) {
		case PW_ITEM:
			debug("list_launch: is a pw");
			curpw = uilist_get_highlighted_item();
			if (curpw) {
				i = launch(curpw);
				snprintf(msg, STRING_LONG, "Application exited with code %d", i);
				ui_statusline_msg(msg);
			}
			break;

		case PW_SUBLIST:
		case PW_UPLEVEL:
		case PW_NULL:
			/* do nothing */
			break;
	}
}

void
action_list_read_file()
{
	pwlist_free_all();
	if(pwlist_read_file() != 0){
		pwlist = pwlist_new("Main");
		current_pw_sublist = pwlist;
	}
	uilist_refresh();
}

void
action_list_move_item_up()
{
	Pw* curpw;
	PWList *curpwl;
	int worked = 0;

	/* Do nothing if searching */
	if(search_results != NULL) {
		return;
	}

	switch(uilist_get_highlighted_type()){
		case PW_ITEM:
			curpw = uilist_get_highlighted_item();
			worked = pwlist_change_item_order(curpw, current_pw_sublist, 1);
			break;
		case PW_SUBLIST:
			curpwl = uilist_get_highlighted_sublist();
			worked = pwlist_change_list_order(curpwl, 1);
			break;
		case PW_UPLEVEL:
		case PW_NULL:
			/* do nothing */
			break;
	}

	if(worked) {
		uilist_up();
	}
}

void
action_list_move_item_down()
{
	Pw* curpw;
	PWList *curpwl;
	int worked = 0;

	/* Do nothing if searching */
	if(search_results != NULL) {
		return;
	}

	switch(uilist_get_highlighted_type()){
		case PW_ITEM:
			curpw = uilist_get_highlighted_item();
			worked = pwlist_change_item_order(curpw, current_pw_sublist, 0);
			break;

		case PW_SUBLIST:
			curpwl = uilist_get_highlighted_sublist();
			worked = pwlist_change_list_order(curpwl, 0);
			break;

		case PW_UPLEVEL:
		case PW_NULL:
			/* do nothing */
			break;
	}

	if(worked) {
		uilist_down();
	}
}
