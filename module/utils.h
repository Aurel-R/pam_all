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

#ifndef H_UTILS_H
#define H_UTILS_H

#define SET(x, FLAG)		(x |= FLAG)
#define UNSET(x, FLAG)		(x &= ~FLAG)
#define _IS_SET(x, FLAG)	(x & FLAG)

#ifndef PATH_MAX
#define PATH_MAX		4096
#endif 

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#define MAX_SYMLINK_LEVEL	20

void str_replace(char *s, size_t len, const char c, const char r);
char *is_a_symlink(const char *argv, int link_level);
unsigned strtou(const char *s, int *err_or_overflow);

#endif

