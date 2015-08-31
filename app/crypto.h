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

#ifndef H_CRYPTO_H
#define H_CRYPTO_H

#define SALT_SIZE	16
#define AES_KEY_LEN	32
#define AES_IV_LEN	16
#define MAX_BUF		1024

char *rsa_decrypt(struct pam_user *user, char *file);
char *aes_decrypt(char *file, char *key, char *iv);
int decrypt_cmd_file(struct pam_user *user, struct command_info *command);
int sign(struct pam_user *user, struct command_info *item, int pid);

#endif
