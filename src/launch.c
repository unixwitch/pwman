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

#include	<sys/types.h>
#include	<sys/wait.h>

#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<errno.h>

#include	"pwman.h"

static int	launch_execute(char const *cmd);

int
launch_execute(cmd)
	char const     *cmd;
{
int		pid, status;
char           *argv[4];

	if (cmd == NULL)
		return 1;

	pid = fork();
	if (pid == -1)
		return -1;

	if (pid == 0) {
		argv[0] = "pwman_exec";
		argv[1] = "-c";
		argv[2] = (char *)cmd;	/* deconst safe */
		argv[3] = NULL;

		execv("/bin/sh", argv);
		exit(127);
	}

	for (;;) {
		if (waitpid(pid, &status, 0) == -1) {
			if (errno != EINTR) {
				return -1;
			}
		} else {
			return status;
		}
	};
}

int
launch(password_t *pw)
{
int		i;
char           *cmd;
size_t		clen = 0;
char           *p, *q;

	if ((pw == NULL) || (pw->launch == NULL))
		return -1;

	for (p = pw->launch; *p; p++) {
		if (*p != '%') {
			clen++;
			continue;
		}

		switch (*++p) {
		case 'h':
			clen += strlen(pw->host);
			break;

		case 'u':
			clen += strlen(pw->user);
			break;

		case 'p':
			clen += strlen(pw->passwd);
			break;
		}
	}

	cmd = xmalloc(clen + 1);
	for (p = pw->launch, q = cmd; *p; p++) {
		if (*p != '%') {
			*q++ = *p;
			continue;
		}

		switch (*++p) {
		case 'h':
			bcopy(pw->host, q, strlen(pw->host));
			q += strlen(pw->host);
			break;

		case 'u':
			bcopy(pw->user, q, strlen(pw->user));
			q += strlen(pw->user);
			break;

		case 'p':
			bcopy(pw->passwd, q, strlen(pw->passwd));
			q += strlen(pw->passwd);
			break;
		}
	}
	*q = 0;

	def_prog_mode();
	ui_end();

	i = launch_execute(cmd);

	puts("Press any key to continue");
	getch();

	ui_init();
	reset_prog_mode();

	return i;
}
