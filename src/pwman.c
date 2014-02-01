/*
 *  PWMan - password management application
 *
 *  Copyright (C) 2002  Ivan Kelly <ivan@ivankelly.net>
 *  Copyright (c) 2014	Felicity Tarnell
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
#include	<sys/stat.h>

#include	<signal.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<stdarg.h>
#include	<ctype.h>
#include	<limits.h>
#include	<errno.h>

#include	"config.h"

#if	defined(HAVE_SYS_MMAN_H) && defined(HAVE_MLOCKALL)
# define USE_MLOCKALL
# include <sys/mman.h>
#endif

#include	"pwman.h"
#include	"gnupg.h"
#include	"ui.h"

static void	pwman_parse_command_line(int argc, char **argv);
static void	pwman_show_usage();
static void	pwman_show_version();
static void	pwman_quit();

Options        *options;
int		write_options;
pwlist_t       *pwlist;
pwlist_t       *current_pw_sublist;
search_result_t *search_results;
time_t		time_base;

static int
pwman_check_lock_file()
{
char		fn[PATH_MAX];

	snprintf(fn, sizeof(fn), "%s.lock", options->password_file);

	if (access(fn, F_OK) == 0)
		return 1;
	else
		return 0;
}

static void
pwman_create_lock_file()
{
char		fn[PATH_MAX];

	snprintf(fn, sizeof(fn), "%s.lock", options->password_file);
	creat(fn, S_IRWXU);
}

static void
pwman_delete_lock_file()
{
char		fn[PATH_MAX];

	snprintf(fn, sizeof(fn), "%s.lock", options->password_file);
	unlink(fn);
}

static void
pwman_init(argc, argv)
	char	**argv;
{
char		c;
int		load_worked, gpg_id_valid;

	signal(SIGKILL, pwman_quit);
	signal(SIGTERM, pwman_quit);

	umask(DEFAULT_UMASK);

	/* get options from .pwmanrc */
	options = options_new();
	if (options_read() == -1)
		options_get();

	/* parse command line options */
	pwman_parse_command_line(argc, argv);

	/* check to see if another instance of pwman is open */
	if (!options->readonly && pwman_check_lock_file()) {
		fprintf(stderr, "It seems %s is already opened by an instance of pwman\n",
			options->password_file);
		fprintf(stderr, "Two instances of pwman should not be open the same file at the same time\n");
		fprintf(stderr, "If you are sure pwman is not already open you can delete the file.\n");
		fprintf(stderr, "Alternatively, you can open the file readonly by answering 'r'\n");
		fprintf(stderr, "Delete file %s.lock? [y/n/r]\n",
			options->password_file);
		c = getchar();
		fprintf(stderr, "\n");

		switch (tolower(c)) {
		case 'y':
			pwman_delete_lock_file();
			break;

		case 'r':
			options->readonly = TRUE;
			break;

		default:
			exit(-1);
		}
	}

	/* Check that the gpg id is valid, if given */
	if (strlen(options->gpg_id)) {
		gpg_id_valid = gnupg_check_id(options->gpg_id);

		if (gpg_id_valid == -1) {
			fprintf(stderr, "Your GPG key with id of '%s' could not be found\n", options->gpg_id);
			fprintf(stderr, "You will be prompted for the correct key when saving\n");
			fprintf(stderr, "\n(press any key to continue)\n");
			c = getchar();
		}

		if (gpg_id_valid == -2) {
			fprintf(stderr, "Your GPG key with id of '%s' has expired!\n", options->gpg_id);
			fprintf(stderr, "Please change the expiry date of your key, or switch to a new one\n");
			exit(-1);
		}
	}

	/* Start up our UI */
	if (ui_init())
		exit(1);

	ui_refresh_windows();

	/* get pw database */
	pwlist_init();
	load_worked = pwlist_read_file();

	if (load_worked != 0) {
		debug("Failed to load the database, error was %d", load_worked);

		/* Did they cancel out, or is it a new file? */
		if (load_worked < 0) {
			pwlist = pwlist_new("Main");
			current_pw_sublist = pwlist;
		} else {
			/* Quit, hard! */
			ui_end();
			fprintf(stderr, "\n\nGPG read cancelled, exiting\n");
			exit(1);
		}
	}

	if (!options->readonly)
		pwman_create_lock_file();

	ui_refresh_windows();
}

static void
pwman_quit()
{
	pwlist_write_file();
	pwlist_free_all();
	pwman_delete_lock_file();

	ui_end();
	options_write();

	exit(0);
}

int
main(argc, argv)
	char	**argv;
{

#ifdef	USE_MLOCKALL
	mlockall(MCL_CURRENT | MCL_FUTURE);
#endif

	if (getuid() != geteuid()) {
		if (setuid(getuid()) == -1)
			return 1;
	}

	pwman_init(argc, argv);

	ui_run();

	pwman_quit();
	return 0;
}

static struct pw_option longopts[] = {
	{ "help",		pw_no_argument, NULL,		'h' },
	{ "version",		pw_no_argument, NULL,		'v' },
	{ "gpg-path",		pw_required_argument, NULL,	'G' },
	{ "gpg-id",		pw_required_argument, NULL,	'i' },
	{ "copy-command",	pw_required_argument, NULL,	'C' },
	{ "file",		pw_required_argument, NULL,	'f' },
	{ "passphrase-timeout",	pw_required_argument, NULL,	't' },
	{ "readonly",		pw_no_argument, NULL,		'r' },
	{ "safe",		pw_no_argument, NULL, 		's' },
	{ }
};

static void
pwman_parse_command_line(argc, argv)
	char	**argv;
{
int		i;

	while ((i = pw_getopt(argc, argv, "hvrsG:i:f:t:", longopts, NULL)) != -1) {
		switch (i) {
		case 'h':
			pwman_show_usage(argv[0]);
			exit(1);

		case 'v':
			pwman_show_version();
			exit(1);

		case 'G':
			write_options = FALSE;
			options->gpg_path = xstrdup(optarg);
			break;

		case 'i':
			write_options = FALSE;
			options->gpg_id = xstrdup(optarg);
			break;

		case 'f':
			write_options = FALSE;
			options->password_file = xstrdup(optarg);
			break;

		case 't':
			write_options = FALSE;
			options->passphrase_timeout = atoi(optarg);
			break;

		case 'r':
			write_options = FALSE;
			options->readonly = TRUE;
			break;

		case 's':
			options->safemode = TRUE;
			break;

		case 'C':
			write_options = FALSE;
			options->copy_command = xstrdup(optarg);
			break;

		default:
			exit(1);
		}
	}
}

static void
pwman_show_version()
{
	fprintf(stderr,

PACKAGE " " VERSION "\n"
"\n"
"Written by Ivan Kelly <ivan@ivankelly.net>\n"
"Copyright (C) 2002 Ivan Kelly\n"
"\n"
"Contributors to this version:\n"
"\n"
"    Nick Burch <gagravarr@users.sourceforge.net>\n"
"    Jon Stuart <lemon-732@users.sourceforge.net>\n"
"    Felicity Tarnell <felicity@loreley.flyingparchment.org.uk>\n"
"\n"
"This program is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License as published by\n"
"the Free Software Foundation; either version 2 of the License, or\n"
"(at your option) any later version.\n"
"\n"
"This program is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details.\n"
"\n"
"You should have received a copy of the GNU General Public License\n"
"along with this program; if not, write to the Free Software\n"
"Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.\n"
);
}

static void
pwman_show_usage(progname)
	char const	*progname;
{
	printf("Usage: %s [OPTIONS]...\n", progname);
	puts("Store your passwords securely using public key encryption\n");
	puts("  -h, --help a                               show usage");
	puts("  -v, --version                              display version information");
	puts("  -G <path>, --gpg-path <path>               Path to GnuPG executable");
	puts("  -i <id>, --gpg-id <id>                     GnuPG ID to use");
	puts("  -f <file>, --file <file>                   file to read passwords from");
	puts("  -t <mins>, --passphrase-timeout <mins>     time before app forgets passphrase(in minutes)");
	puts("  -r, --readonly                             open the database readonly");
	puts("  -s, --safe-mode                            disable 'l'aunch command\n\n");
	puts("Report bugs to <felicity@loreley.flyingparchment.org.uk>");
}

int
copy_string(str)
	char const	*str;
{
pid_t	pid;
int	fds[2], stat;

	if (options->safemode)
		return -1;

	pipe(fds);

	if ((pid = fork()) == -1)
		return -1;

	if (pid == 0) {
		close(fds[1]);
		dup2(fds[0], 0);

		execlp("/bin/sh", "sh", "-c", options->copy_command, (char *) 0);
		_exit(1);
	}

	close(fds[0]);
	write(fds[1], str, strlen(str));
	close(fds[1]);

	waitpid(pid, &stat, 0);
	return stat;
}
