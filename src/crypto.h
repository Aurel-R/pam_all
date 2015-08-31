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

#define ENTRY           0 /* user have key */ 
#define NO_ENTRY        1 /* no key configured */ 

#define BITS            2048 /* for RSA key */ 
#define SALT_SIZE       16 /* in bytes */ 
#define AES_KEY_LEN	32 /* in Bytes (256 bits) */
#define AES_IV_LEN	16 /* in Bytes (128 bits) */
#define MAX_BUF		1024

int create_user_entry(struct pam_user *user, const char *pub_file_name, const char *priv_file_name);
int verify_user_entry(struct pam_user *user, int flag);
EVP_PKEY *get_public_key(const struct pam_user *user);
EVP_PKEY *create_rsa_key(RSA *rsa);
int sym_encrypt(unsigned char *data, int data_len, char *file, unsigned char *key, unsigned char *iv);
char *create_AES_encrypted_file(int ctrl, char *data, unsigned char *salt, char **dst_cmd);
char *create_RSA_encrypted_file(int ctrl, EVP_PKEY *public_key, char *data);
int verify(EVP_PKEY *public_key, const char *file, char *dst_cmd);

 
#endif

