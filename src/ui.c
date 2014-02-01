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

#include	<sys/types.h>
#include	<sys/ioctl.h>

#include	<time.h>
#include	<stdlib.h>
#include	<assert.h>

#include	"pwman.h"
#include	"ui.h"
#include	"help.h"
#include	"actions.h"
#include	"gnupg.h"

static void	ui_draw_top(void);
static void	ui_draw_bottom(void);
static void	ui_init_windows(void);
static void	ui_free_windows(void);
static void	ui_display_help(void);
static void	ui_resize_windows(void);

static char	*ui_statusline_prompt(char const *, char const *, int,
		     char *(*) (void), int);

static int	should_resize = FALSE;
static int	can_resize = FALSE;

static WINDOW  *top = NULL, *bottom = NULL;

static void
ui_draw_top()
{
char	text[128];

	wbkgd(top, WA_REVERSE);
	werase(top);
	wclrtoeol(top);

	strlcpy(text, PACKAGE " " VERSION, sizeof(text));
	if (options->readonly)
		strlcat(text, " | " READONLY_MSG, sizeof(text));
	if (options->safemode)
		strlcat(text, " | " SAFE_MSG, sizeof(text));

	strlcat(text, " | " MAIN_HELPLINE, sizeof(text));
	mvwprintw(top, 0, 0, "%s", text);
	wrefresh(top);
}

static void
ui_draw_bottom()
{
	werase(bottom);
	wrefresh(bottom);
}

void
ui_refresh_windows()
{
	ui_draw_top();
	ui_draw_bottom();
	uilist_refresh();

	refresh();
}

static void
ui_resize_windows()
{

#ifdef notyet
	wresize(top, 2, COLS);
#endif
}

static void
ui_init_windows()
{
	top = newwin(1, COLS, 0, 0);
	bottom = newwin(1, COLS, LINES - 1, 0);

	uilist_init();
}

static void
ui_free_windows()
{
	uilist_free();

	erase();
	delwin(top);
	delwin(bottom);
}

static void
ui_too_small_warning()
{
	clear();
	attron(A_BOLD);
	mvprintw(((LINES - 2) / 2), 0, "Your window is too small\n\n"
		 "Minimum size is %dx%d\n\n"
		 "Please resize and press any key", MIN_LINES, MIN_COLS);
	attroff(A_BOLD);
	getch();
}

#ifdef SIGWINCH
static void
ui_resize()
{
struct winsize	winsz;

	ioctl(0, TIOCGWINSZ, &winsz);

	resizeterm(winsz.ws_row, winsz.ws_col);
	if ((winsz.ws_col < MIN_COLS) || (winsz.ws_row < MIN_LINES)) {

		/*
		 * if window is too small notify user until he changes it
		 */
		do {
			ui_too_small_warning();
			ioctl(0, TIOCGWINSZ, &winsz);
			resizeterm(winsz.ws_row, winsz.ws_col);
		} while ((winsz.ws_col < MIN_COLS) || (winsz.ws_row < MIN_LINES));

	} else {
		should_resize = FALSE;
		ui_resize_windows();
		ui_free_windows();
		ui_init_windows();
		ui_refresh_windows();
	}
}

#endif

static void
ui_win_changed(int i)
{
	if (can_resize) {
		ui_resize();
		ui_refresh_windows();	/* dunno why i need this but it wont
					 * work without it */
	} else {
		should_resize = TRUE;
	}
}

int
ui_init()
{
	initscr();
	cbreak();
	noecho();
	nonl();

	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);

	if ((LINES < MIN_LINES) || (COLS < MIN_COLS)) {
		clear();
		refresh();
		endwin();
		fprintf(stderr, "Your terminal is to small\n");
		fprintf(stderr, "Min size is %dx%d\n", MIN_COLS, MIN_LINES);

		return 1;
	}

#ifdef SIGWINCH
	signal(SIGWINCH, ui_win_changed);
#endif

	ui_init_windows();
	ui_refresh_windows();
	return 0;
}

static void
ui_display_help()
{
int		i;
WINDOW         *helpwin;

	helpwin = newwin(LINES - 5, COLS - 6, 3, 3);
	uilist_clear();

	for (i = 0; help[i] != NULL; i++) {
		waddstr(helpwin, help[i]);
		if (!((i + 1) % (LINES - 9)) || (help[i + 1] == NULL)) {
			/* refresh(); */
			wrefresh(helpwin);
			ui_statusline_msg("Press any key to continue...");
			getch();
			wclear(helpwin);
		}
	}
	uilist_refresh();
	ui_statusline_clear();
	delwin(helpwin);
}

int
ui_run()
{
int		ch;
int		load_worked = 0;

#ifdef DEBUG
int		debug_i = 0;

#endif

	time_base = time(NULL);

	while (1) {
		can_resize = TRUE;
		if (should_resize) {
			ui_resize();
		}
		ch = getch();
		ui_statusline_clear();
		can_resize = FALSE;

		if ((time_base < (time(NULL) - (options->passphrase_timeout * 60)))
		&& options->passphrase_timeout != 0 && tolower(ch) != 'q') {
			pwlist_write_file();
			pwlist_free_all();

			ui_statusline_msg("Passphrase has timed out and you must enter it again.");
			getch();

			load_worked = pwlist_read_file();
			if (load_worked != 0) {
				ui_statusline_msg("Error - unable to re-load the password file!");
				break;
			}
			if (search_results != NULL)
				search_remove();

			time_base = time(NULL);
			continue;
		}
		switch (ch) {
		case 'Q':
		case 'q':
			if (search_results != NULL)
				search_remove();
			else if (action_list_at_top_level())
				return 0;
			break;

		case '?':
			ui_display_help();
			break;

		case KEY_PPAGE:
			uilist_page_up();
			break;

		case KEY_NPAGE:
			uilist_page_down();
			break;

		case KEY_UP:
		case 'k':
			uilist_up();
			break;

		case KEY_DOWN:
		case 'j':
			uilist_down();
			break;

		case 'A':
			if (!options->readonly)
				action_list_add_sublist();
			else
				statusline_readonly();
			break;

		case 'U':
			action_list_up_one_level();
			break;

		case 'r':
			if (!options->readonly) {
				action_list_rename();
				pwlist_write_file();
			} else {
				statusline_readonly();
			}
			break;

		case 'a':
			if (!options->readonly) {
				action_list_add_pw();
				pwlist_write_file();
			} else {
				statusline_readonly();
			}
			break;

		case 'e':
		case ' ':
		case 13:	/* return/enter key */
			action_list_select_item();

			/*
			 * current_item = get_current_item();
			 * if(current_item){ edit_pw(current_item); }
			 */
			break;

		case 'd':
		case 0x14A:	/* DEL key */
			if (!options->readonly) {
				action_list_delete_item();
			} else {
				statusline_readonly();
			}
			break;

		case 'm':
			if (!options->readonly) {
				action_list_move_item();
			} else {
				statusline_readonly();
			}
			break;

		case 'M':
			if (!options->readonly) {
				action_list_move_item_up_level();
			} else {
				statusline_readonly();
			}
			break;

		case 'h':
			hide_cursor();
			break;
		case 's':
			show_cursor();
			break;

		case 'o':
			action_edit_options();
			break;

		case 0x17:	/* control-w */
			if (!options->readonly) {
				pwlist_write_file();
			} else {
				statusline_readonly();
			}
			break;

		case 0x12:	/* control-r */
			action_list_read_file();
			break;

		case 0x07:	/* control-g */
			pwgen_indep();
			break;

		case 0x06:	/* control-f */
			gnupg_forget_passphrase();
			break;

		case 0x0C:	/* control-l */
			ui_refresh_windows();
			break;

		case '/':
		case 'F':
			search_get();
			break;

		case 'f':
			filter_get();
			break;

		case 'E':
			action_list_export();
			break;

		case 'I':
			if (!options->readonly) {
				pwlist_import_passwd();
				uilist_refresh();
			} else {
				statusline_readonly();
			}
			break;

		case 'L':
			action_list_locate();
			break;

		case 'l':
			action_list_launch();
			break;

		case 0x0B:	/* control-k (up) */
		case '[':
			action_list_move_item_up();
			break;

		case 0x0A:	/* control-j (down) */
		case ']':
			action_list_move_item_down();
			break;

#ifdef DEBUG
		case '$':
			debug_i++;
			snprintf(msg, 80, "Name %d", debug_i);

			pwlist_add(current_pw_sublist, msg, "myhost", "myuser", "mypasswd", "mylaucnh");
			uilist_refresh();
			break;
#endif

		default:
			break;
		}
	}
	return 0;
}

int
ui_end()
{
	ui_free_windows();
	clear();
	refresh();
	endwin();
	echo();
	return 0;
}

int
ui_statusline_msg(char const *msg)
{
	ui_statusline_clear();
	mvwaddstr(bottom, 0, 0, msg);
	refresh();
	wrefresh(bottom);
	return 0;
}

int
ui_statusline_clear()
{
	wmove(bottom, 0, 0);
	wclrtoeol(bottom);
	wrefresh(bottom);
	refresh();
	return 0;
}

int
ui_ask_num(char const *msg)
{
char           *line;
int		ret;

	line = ui_statusline_prompt(msg, NULL, 0, NULL, 0);
	if (!line)
		return 0;

	ret = atoi(line);
	free(line);
	return ret;
}

int
ui_ask_char(char const *msg, char *valid)
{
int		x = strlen(msg) + 5;
char		c = 0;

	do {
		ui_statusline_clear();
		if (c != 0) {
			ui_statusline_msg("Bad choice, press any key to try again");
			getch();
			ui_statusline_clear();
		}
		ui_statusline_msg(msg);

		echo();
		show_cursor();

		c = mvwgetch(bottom, 0, x);

		noecho();
		hide_cursor();

	} while (!strchr(valid, c));

	ui_statusline_clear();
	return c;
}

char           *
ui_ask_str(msg, def)
	char const     *msg, *def;
{
	return ui_statusline_prompt(msg, def, 0, NULL, 0);
}

char           *
ui_ask_str_with_autogen(msg, def, autogen, ch)
	char const     *msg, *def;
	char           *(*autogen) (void);
{
char		prompt    [128];

	snprintf(prompt, sizeof(prompt), "Password (^%c for autogen): ", 0x40 + ch);
	return ui_statusline_prompt(prompt, def, 0, autogen, ch);
}

char           *
ui_ask_passwd(msg, def)
	char const     *msg, *def;
{
	return ui_statusline_prompt(msg, def, 1, NULL, 0);
}

int
ui_ask_yes_no(char const *msg, int def)
{
int		ret = -1;
size_t		len;
char           *msg2;
int		ch;

	len = strlen(msg) + 10;
	msg2 = malloc(len);

	snprintf(msg2, len, "%s%s", msg, def ? " (Y/n)?" : " (y/N)?");

	while (ret == -1) {
		ui_statusline_msg(msg2);

		ch = getch();
		switch (ch) {
		case 'n':
		case 'N':
			ret = FALSE;
			break;
		case 'y':
		case 'Y':
			ret = TRUE;
			break;
		case 13:
			ret = def;
			break;
		default:
			ui_statusline_msg("Bad option, try again.");
			getch();
			break;
		}
	}

	free(msg2);
	ui_statusline_clear();

	return ret;
}

static char    *
ui_statusline_prompt(msg, def, secret, gen, genc)
	char const     *msg, *def;
	char           *(*gen) (void);
{
WINDOW         *pwin;
char		input[256];
size_t		pos = 0;
int		old_curs;

	bzero(input, sizeof(input));
	if (def) {
		strlcpy(input, def, sizeof(input));
		pos = strlen(input);
	}
	pwin = newwin(1, COLS, LINES - 1, 0);
	keypad(pwin, TRUE);

	wattron(pwin, A_BOLD);
	wmove(pwin, 0, 0);
	waddstr(pwin, msg);
	wattroff(pwin, A_BOLD);

	old_curs = curs_set(1);

	for (;;) {
	int	c;

		wmove(pwin, 0, strlen(msg) + 1);

		if (secret) {
		size_t	i = 0,	len = strlen(input);

			for (; i < len; i++)
				waddch(pwin, '*');
		} else
			waddstr(pwin, input);

		wclrtoeol(pwin);
		wmove(pwin, 0, strlen(msg) + 1 + pos);
		wrefresh(pwin);

		if ((c = wgetch(pwin)) == ERR)
			continue;

		if (genc && (c == genc)) {
		char	*pw = gen();

			strlcpy(input, pw, sizeof(input));
			pos = strlen(input);
			free(pw);
			touchwin(pwin);
			curs_set(1);
			continue;
		}
		switch (c) {
		case '\n':
		case '\r':
			goto end;

		case KEY_BACKSPACE:
		case 0x7F:
		case 0x08:
			if (pos) {
				if (pos == strlen(input))
					input[--pos] = 0;
				else {
				int	i = strlen(input);

					pos--;
					memmove(input + pos, input + pos + 1, strlen(input) - pos);
					input[i] = 0;
				}
			}
			break;

		case KEY_DC:
			if (pos < strlen(input)) {
			int	i = strlen(input);

				memmove(input + pos, input + pos + 1, strlen(input) - pos);
				input[i] = 0;
			}
			break;

		case KEY_LEFT:
			if (pos)
				pos--;
			break;

		case KEY_RIGHT:
			if (pos < strlen(input))
				pos++;
			break;

		case KEY_HOME:
		case CNTL('A'):
			pos = 0;
			break;

		case KEY_END:
		case CNTL('E'):
			pos = strlen(input);
			break;

		case 0x1B:	/* ESC */
			curs_set(0);
			delwin(pwin);
			return NULL;

		case CNTL('U'):/* ^U */
			input[0] = 0;
			pos = 0;
			break;

#ifdef KEY_RESIZE
		case KEY_RESIZE:
			break;
#endif

		case 0:
			break;

		default:
			if (pos != strlen(input)) {
				memmove(input + pos + 1, input + pos, strlen(input) - pos);
				input[pos++] = c;
			} else {
				input[pos++] = c;
				input[pos] = 0;
			}

			break;
		}
	}
end:	;

	curs_set(old_curs);
	delwin(pwin);
	touchwin(bottom);
	ui_statusline_msg("");
	return strdup(input);
}

void
statusline_readonly()
{
	ui_statusline_msg("Password file is opened readonly");
}
