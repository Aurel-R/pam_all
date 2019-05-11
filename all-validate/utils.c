/*
 * Copyright (C) 2015, 2019 Aurélien Rausch <aurel@aurel-r.fr>
 *  
 * This file is part of pam_all.
 * 
 * pam_all is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * pam_all is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with pam_all.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include "utils.h"

int strtosint(const char *s, int *err_or_overflow)
{
	char *end;
	long sl;	
	errno = 0;

	sl = strtol(s, &end, 10);

	if (end == s || *end != '\0' || errno == ERANGE || 
	    sl < INT_MIN || sl > INT_MAX) {
		*err_or_overflow = 1;
		return 0;
	}

	*err_or_overflow = 0;
	return sl;		
}

int strtime(time_t t, char *buff, size_t len)
{
	int ret;
	struct tm *tm = localtime(&t);
	
	if (!tm) {
		fprintf(stderr, "localtime() failed\n");
		return -1;
	}

	ret = strftime(buff, len, "%H:%M", tm);
	return ((size_t)ret != len - 1);
}

void purge_stdin(const char *s)
{
	int c;

	if (!strchr(s, '\n'))
		while ((c = getchar()) != '\n');
} 

