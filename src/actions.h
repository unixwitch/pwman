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

#ifndef PWMAN_ACTIONS_H
#define	PWMAN_ACTIONS_H

#include	"ui.h"

int action_yes_no_dialog(InputField *fields, int num_fields, char *title, char *question);

void action_input_dialog_draw_items(WINDOW* dialog_win, InputField *fields, int num_fields, char *title, char *msg);
void action_input_dialog(InputField *fields, int num_fields, char *title);
void action_input_gpgid_dialog(InputField *fields, int num_fields, char *title);

void action_list_launch(void);
void action_list_up_one_level(void);
void action_list_read_file(void);
void action_list_move_item_up(void);
void action_list_move_item_down(void);
void action_list_export(void);
void action_list_select_item(void);
void action_list_delete_item(void);
void action_list_move_item(void);
void action_list_rename(void);
void action_list_add_pw(void);
void action_list_add_sublist(void);
void action_list_move_item_up_level(void);
int action_list_at_top_level(void);

void action_edit_options(void);
void action_list_locate(void);

#endif	/* !PWMAN_ACTIONS_H */
