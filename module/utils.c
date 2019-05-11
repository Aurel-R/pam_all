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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <linux/limits.h>
#include "utils.h"

void str_replace(char *s, size_t len, const char c, const char r) 
{
	if (!s)
		return;

	for (; len--; s++) 
		if (*s == c)
			*s = r;
}

char *is_a_symlink(const char *argv, int link_level)
{
	ssize_t n;
	char link[PATH_MAX];
	char *tmp_link;

	if (link_level == MAX_SYMLINK_LEVEL)
		return NULL;

	n = readlink(argv, link, PATH_MAX);
	if (n < 0)
		return NULL;
	
	link[n] = '\0';

	tmp_link = is_a_symlink(link, link_level + 1);
	if (!tmp_link)
		return strdup(link);

	return tmp_link;
}

unsigned strtou(const char *s, int *err_or_overflow)
{
	char *end;
	long sl;	
	errno = 0;

	sl = strtol(s, &end, 10);

	if (end == s || *end != '\0' || errno == ERANGE || 
	    sl < 0 || sl > UINT_MAX) {
		*err_or_overflow = 1;
		return 0;
	}

	*err_or_overflow = 0;
	return sl;		
}

