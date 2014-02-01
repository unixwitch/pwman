/*
 *  PWMan - password manager application
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

/*
 * all code in this file is taken from pwgen
 * (c) 2001 Theodore Ts'o
 */

#include	<sys/types.h>
#include	<sys/time.h>
#include	<sys/stat.h>

#include	<unistd.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<errno.h>

#include	"pwman.h"
#include	"ui.h"

static char    *pwgen(char *buf, int size);

struct pwgen_element {
	char           *str;
	int		flags;
};

/*
 * Flags for the pw_element
 */
#define CONSONANT	0x0001
#define VOWEL		0x0002
#define DIPTHONG	0x0004
#define NOT_FIRST	0x0008


static struct pwgen_element elements[] = {
	{"a",	VOWEL},
	{"ae",	VOWEL | DIPTHONG},
	{"ah",	VOWEL | DIPTHONG},
	{"ai",	VOWEL | DIPTHONG},
	{"b",	CONSONANT},
	{"c",	CONSONANT},
	{"ch",	CONSONANT | DIPTHONG},
	{"d",	CONSONANT},
	{"e",	VOWEL},
	{"ee",	VOWEL | DIPTHONG},
	{"ei",	VOWEL | DIPTHONG},
	{"f",	CONSONANT},
	{"g",	CONSONANT},
	{"gh",	CONSONANT | DIPTHONG | NOT_FIRST},
	{"h",	CONSONANT},
	{"i",	VOWEL},
	{"ie",	VOWEL | DIPTHONG},
	{"j",	CONSONANT},
	{"k",	CONSONANT},
	{"l",	CONSONANT},
	{"m",	CONSONANT},
	{"n",	CONSONANT},
	{"ng",	CONSONANT | DIPTHONG | NOT_FIRST},
	{"o",	VOWEL},
	{"oh",	VOWEL | DIPTHONG},
	{"oo",	VOWEL | DIPTHONG},
	{"p",	CONSONANT},
	{"ph",	CONSONANT | DIPTHONG},
	{"qu",	CONSONANT | DIPTHONG},
	{"r",	CONSONANT},
	{"s",	CONSONANT},
	{"sh",	CONSONANT | DIPTHONG},
	{"t",	CONSONANT},
	{"th",	CONSONANT | DIPTHONG},
	{"u",	VOWEL},
	{"v",	CONSONANT},
	{"w",	CONSONANT},
	{"x",	CONSONANT},
	{"y",	CONSONANT},
	{"z",	CONSONANT}
};

#define NUM_ELEMENTS (sizeof(elements) / sizeof (struct pwgen_element))

static char    *
pwgen(char *buf, int size)
{
int		c, i, len, flags;
int		prev, should_be, first;
char           *str;

	if (buf == NULL)
		buf = malloc(size);

	c = 0;
	prev = 0;
	should_be = 0;
	first = 1;

	should_be = arc4random_uniform(1) ? VOWEL : CONSONANT;

	while (c < size) {
		i = arc4random_uniform(NUM_ELEMENTS);
		str = elements[i].str;
		len = strlen(str);
		flags = elements[i].flags;

		/* Filter on the basic type of the next element */
		if ((flags & should_be) == 0)
			continue;

		/* Handle the NOT_FIRST flag */
		if (first && (flags & NOT_FIRST))
			continue;

		/* Don't allow VOWEL followed a Vowel/Dipthong pair */
		if ((prev & VOWEL) && (flags & VOWEL) &&
				(flags & DIPTHONG))
			continue;

		/* Don't allow us to overflow the buffer */
		if (len > size - c)
			continue;

		/*
		 * OK, we found an element which matches our criteria, let's
		 * do it!
		 */
		strcpy(buf + c, str);

		/* Handle PW_ONE_CASE */
		if ((first || flags & CONSONANT) && (arc4random_uniform(10) < 3))
			buf[c] = toupper(buf[c]);

		c += len;

		/* Time to stop? */
		if (c >= size)
			break;

		/*
		 * Handle PW_ONE_NUMBER
		 */
		if (!first && (arc4random_uniform(10) < 3)) {
			buf[c++] = arc4random_uniform(9) + '0';
			buf[c] = 0;

			first = 1;
			prev = 0;
			should_be = arc4random_uniform(1) ? VOWEL : CONSONANT;
			continue;
		}

		/*
		 * OK, figure out what the next element should be
		 */
		if (should_be == CONSONANT) {
			should_be = VOWEL;
		} else {	/* should_be == VOWEL */
			if ((prev & VOWEL) ||
					(flags & DIPTHONG) ||
					(arc4random_uniform(10) > 3))
				should_be = CONSONANT;
			else
				should_be = VOWEL;
		}
		prev = flags;
		first = 0;
	}

	return buf;
}

char *
pwgen_ask()
{
int		i;
char           *ret;

	i = ui_ask_num("Length of password (default 16):\t");

	if (i == 0)
		i = 16;
	else if (i > STRING_SHORT)
		i = STRING_SHORT;

	ret = xcalloc(1, i + 1);
	pwgen(ret, i);

	return ret;
}

void
pwgen_indep()
{
char           *p, text[128];

	p = pwgen_ask();

	snprintf(text, sizeof(text), "Generated password: %s", p);
	free(p);

	ui_statusline_msg(text);
}
