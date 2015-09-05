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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <dirent.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#include "pam.h"
#include "utils.h"
#include "crypto.h"


char *rsa_decrypt(struct pam_user *user, char *file)
{
	int ret;
	FILE *fd;
	EVP_PKEY *priv_key = NULL;
	char *buffer, *decrypted_data;
	char *priv_file_name = calloc(strlen(USR_DIR) + strlen(user->name) + 1, sizeof(char));

	if (priv_file_name == NULL)
		return NULL;

	strncpy(priv_file_name, USR_DIR, strlen(USR_DIR));
	strncpy(priv_file_name+strlen(USR_DIR), user->name, strlen(user->name));

	if ((fd = fopen(priv_file_name, "r")) == NULL) {
		fprintf(stderr, "can not open '%s' file: %m\n", priv_file_name);
		F(priv_file_name);
		return NULL;
	}
	
	if (!PEM_read_PrivateKey(fd, &priv_key, passwd_callback, (void *)user->pass)) {
		fprintf(stderr, "can not read key for user '%s'\n", user->name);
		F(priv_file_name);
		return NULL;
	}	

	fclose(fd);
	
	if ((fd = fopen(file, "r")) == NULL) {
		fprintf(stderr, "can not open '%s' file: %m\n", file);
		F(priv_file_name);
		EVP_PKEY_free(priv_key);
		return NULL;
	}

	buffer = calloc(257, sizeof(char));
	
	if (buffer == NULL) {
		F(priv_file_name);	
		EVP_PKEY_free(priv_key);
		return NULL;
	}	

	ret = fread(buffer, sizeof(*buffer), 256, fd);

	fclose(fd);

	RSA *rsa = RSA_new();

	if ((rsa = EVP_PKEY_get1_RSA(priv_key)) == NULL) {
		fprintf(stderr, "can not assign RSA key\n");
		F(priv_file_name);	
		EVP_PKEY_free(priv_key);
		F(buffer);
		return NULL;
	}

	decrypted_data = calloc(257, sizeof(char));

	if (decrypted_data == NULL) {
		F(priv_file_name);	
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		F(buffer);
		return NULL;
	}

	ret = RSA_private_decrypt(256, (unsigned char *)buffer, (unsigned char *)decrypted_data, rsa, RSA_PKCS1_OAEP_PADDING);

	if (ret == -1) 
		decrypted_data = NULL;
	
	RSA_free(rsa);
	EVP_PKEY_free(priv_key);
	F(priv_file_name);
	F(buffer);
	return decrypted_data;	
}


char *aes_decrypt(char *file, char *key, char *iv)
{
	OpenSSL_add_all_algorithms();
	FILE *fd;
	EVP_CIPHER_CTX ctx;
	char buffer[MAX_BUF];
	memset(buffer, '\0', MAX_BUF);
	char *data = NULL;
	int len = 0, inlen, plain_len;

	
	if ((fd = fopen(file, "r")) == NULL) {
		fprintf(stderr, "can not open aes file '%s': %m\n", file);
		return NULL;
	}
	
	inlen = fread(buffer, sizeof(char), MAX_BUF - 1, fd);
		
	fclose(fd);

	data = calloc(inlen+1, sizeof(char));

	if (data == NULL)
		return NULL;

	
	EVP_CIPHER_CTX_init(&ctx);

	if (EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv) != 1) {
		fprintf(stderr, "impossible to initialize ctx\n"); 
		EVP_CIPHER_CTX_cleanup(&ctx);
		return NULL;
	}
	
	if (!EVP_DecryptUpdate(&ctx, (unsigned char *)data, &len, (unsigned char *)buffer, inlen)) {
		fprintf(stderr, "impossible to updata ctx\n");
		EVP_CIPHER_CTX_cleanup(&ctx);
		return NULL;
	}

	plain_len = len;
	
	if (!EVP_DecryptFinal_ex(&ctx, (unsigned char *)data + len, &len)) {
		fprintf(stderr, "impossible to decrypt aes data\n");
		EVP_CIPHER_CTX_cleanup(&ctx);
		return NULL;
	}

	plain_len += len;

	data[plain_len] = '\0';

	EVP_CIPHER_CTX_cleanup(&ctx);
	return data;	
}


int decrypt_cmd_file(struct pam_user *user, struct command_info *command)
{
	FILE *fd;
	char line[LINE_LEN];
	char *token, *rsa_file;
	char *decrypted_rsa_data = NULL;
	int len = strlen(EN_CMD_DIR) + EN_CMD_FILENAME_LEN;
	char key[AES_KEY_LEN], iv[AES_IV_LEN], aes_file[len+1];
	memset(aes_file, '\0', sizeof(aes_file));

	command->salted_cmd = NULL;
	command->cmd = NULL;
	
	if ((fd = fopen(command->cmd_file, "r")) == NULL) {
		fprintf(stderr, "can not open '%s' command file: %m\n", command->cmd_file);
		return 1;
	}

	rewind(fd);
	while (fgets(line, LINE_LEN - 1, fd) != NULL) {
		if (strncmp(line, user->name, strlen(user->name)))
			continue;

		token = strtok(line, ":");
		token = strtok(NULL, ":");
		rsa_file = token;

		decrypted_rsa_data = rsa_decrypt(user, rsa_file);	
		
		if (decrypted_rsa_data == NULL) {
			fprintf(stderr, "can not decrypt rsa data in '%s'\n", rsa_file);
			fclose(fd);
			return 1;
		}

		strncpy(aes_file, decrypted_rsa_data, len);
		strncpy(key, decrypted_rsa_data+len, AES_KEY_LEN);
		strncpy(iv, decrypted_rsa_data+len+AES_KEY_LEN, AES_IV_LEN);

		command->salted_cmd = aes_decrypt(aes_file, key, iv);

		if (command->salted_cmd != NULL) {
			command->cmd = calloc(strlen(command->salted_cmd) - SALT_SIZE - 8 + 1, sizeof(char));
			if (command->cmd == NULL)
				return 1;
			strncpy(command->cmd, command->salted_cmd + SALT_SIZE + 8, strlen(command->salted_cmd) - SALT_SIZE - 8);
		} else {
			command->cmd = NULL;	
		}
		
		break;
	}
	
	F(decrypted_rsa_data);
	fclose(fd);
	return 0;
}


int sign(struct pam_user *user, struct command_info *item, int pid)
{
	unsigned char *seed = NULL;
	char *file_name = NULL;
	FILE *fd;
	unsigned char *signed_data = NULL, hash[20];
	unsigned int signed_data_len = 0;
	EVP_PKEY *priv_key = NULL;
	char *priv_file_name = NULL; 
	char line[LINE_LEN];	
	int flag = 0;
	long pos;
	
	while (item != NULL && item->cmd_pid != pid)
		item = item->next;

	if (item == NULL) 
		return NO_CMD_MATCH;


	
	priv_file_name = calloc(strlen(USR_DIR) + strlen(user->name) + 1, sizeof(char));

	if (priv_file_name == NULL)
		return 1;

	strncpy(priv_file_name, USR_DIR, strlen(USR_DIR));
	strncpy(priv_file_name+strlen(USR_DIR), user->name, strlen(user->name));

	if ((fd = fopen(priv_file_name, "r")) == NULL) {
		fprintf(stderr, "can not open '%s' file: %m\n", priv_file_name);
		F(priv_file_name);
		return 1;
	}
	
	if (!PEM_read_PrivateKey(fd, &priv_key, passwd_callback, (void *)user->pass)) {
		fprintf(stderr, "can not read key for user '%s'\n", user->name);
		F(priv_file_name);
		return 1;
	}	

	fclose(fd);
	F(priv_file_name);

	RSA *rsa = RSA_new();

	if ((rsa = EVP_PKEY_get1_RSA(priv_key)) == NULL) {
		fprintf(stderr, "can not assign RSA key\n");
		EVP_PKEY_free(priv_key);
		return 1;
	}	

	signed_data = calloc(RSA_size(rsa), sizeof(*signed_data));

	if (signed_data == NULL) {
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		return 1;
	}

	if (!SHA1((const unsigned char *)item->salted_cmd, strlen(item->salted_cmd), hash)) {
		fprintf(stderr, "can not hash data (%s)\n", item->cmd);
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		F(signed_data);
		return 1;
	}

	if (!RSA_sign(NID_sha1, hash, sizeof(hash), signed_data, &signed_data_len, rsa)) {
		fprintf(stderr, "can not sign data (%s)\n", item->cmd);
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		F(signed_data);
		return 1;
	}

	seed = alea(EN_CMD_FILENAME_LEN, (unsigned char *)CARAC); 

	if (seed == NULL) {	
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		F(signed_data);
		return 1;
	}
	
	file_name = calloc(strlen(EN_CMD_DIR)+EN_CMD_FILENAME_LEN+1, sizeof(char));

	if (file_name == NULL) {	
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		F(signed_data);
		F(seed);
		return 1;
	}
	
	strncpy(file_name, EN_CMD_DIR, strlen(EN_CMD_DIR));
	strncpy(file_name+strlen(EN_CMD_DIR), (const char *)seed, EN_CMD_FILENAME_LEN);

	umask(0066);
	if ((fd = fopen(file_name, "wb")) == NULL) {
		fprintf(stderr, "can not open '%s' file: %m\n", file_name);
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		F(signed_data);
		F(seed);
		F(file_name);
		return 1;
	}

	fwrite(signed_data, 1, signed_data_len, fd);		
	fclose(fd);

	EVP_PKEY_free(priv_key);
	RSA_free(rsa);
	F(signed_data);
	F(seed);

	
	if ((fd = fopen(item->cmd_file, "r+")) == NULL) {
		fprintf(stderr, "can not open '%s' file: %m\n", item->cmd_file);
		F(file_name);
		return 1;
	}
	
	while(fgets(line, LINE_LEN - 1, fd) != NULL) {
		if (strncmp(user->name, line, strlen(user->name)))
			continue;
		
		pos =  ftell(fd) - 1;
		if (!insert(fd, file_name, strlen(file_name), pos)) 
			flag = 1;	
		break;		
	}
	
	fclose(fd);
	F(file_name);
	
	if (!flag) {
		fprintf(stderr, "impossible to write data in '%s'\n", item->cmd_file);
		return 1;
	}

	return 0;
}
 

