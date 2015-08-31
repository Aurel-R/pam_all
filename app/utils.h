/*
 * Copyright (C) 2015 Aurélien Rausch <aurel@aurel-r.fr>
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

#define CARAC           "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#define RANDOM_FILE	"/dev/urandom"

#define F(x) do {	\
	if (x) { free(x), x = NULL; }	\
	} while (0)


unsigned char *alea(size_t len, unsigned char *table); 
int insert(FILE *fd, const char *data, int data_len, long pos);
int passwd_callback(char *pcszBuff, int size, int rwflag, void *pPass);

#endif
