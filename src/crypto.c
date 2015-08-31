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

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <linux/limits.h>

#include "pam.h"
#include "utils.h"
#include "crypto.h"

 
EVP_PKEY *create_rsa_key(RSA *rsa) 
{ 
        EVP_PKEY *key = EVP_PKEY_new(); 
        int ret; 
 
        if (rsa && key && EVP_PKEY_assign_RSA(key, rsa)) { 
                ret = RSA_check_key(rsa); /* check key */ 
 
                if (ret == 0) { 
                        log_message(LOG_NOTICE, "(ERROR) create rsa key: no valid key"); 
                        EVP_PKEY_free(key); 
                        key = NULL; 
                } 
                 
                if (ret < 0) { 
                        log_message(LOG_NOTICE, "(ERROR) create rsa key: error check key"); 
                        EVP_PKEY_free(key); 
                        key = NULL; 
                } 
        }  
        else { 
                if (rsa)  
                        RSA_free(rsa); 
                if (key) { 
                        EVP_PKEY_free(key); 
                        key = NULL; 
                } 
        } 

        return key;      
}


 
/* 
 * create entry files for user 
 * with his public and private 
 * keys 
 */ 
int 
create_user_entry(struct pam_user *user, const char *pub_file_name, const char *priv_file_name) 
{ 
        FILE *fd; 
        RSA *rsa = RSA_new(); 
         
        log_message(LOG_INFO, "(INFO) generate RSA key... (%i bits)", BITS); 
 
        if ((rsa = RSA_generate_key(BITS, 65537, NULL, NULL)) == NULL) { 
                log_message(LOG_ERR, "(ERROR) error during  key generation"); 
                return ERR; 
        } 
 
        EVP_PKEY* priv_key = create_rsa_key(rsa); 
        EVP_PKEY* pub_key  = create_rsa_key(rsa); 
 
        if (priv_key == NULL || pub_key == NULL) { 
                log_message(LOG_ERR, "(ERROR) create key error"); 
                RSA_free(rsa); 
        } 
 
        umask(0022); /* -rw-r--r--*/     
        if ((fd = fopen(pub_file_name, "w+")) == NULL) 
                return ERR; 
 
        if (!PEM_write_PUBKEY(fd, pub_key)) { 
                log_message(LOG_ERR, "(ERROR) error when saving the public key"); 
                RSA_free(rsa); 
                fclose(fd); 
                return ERR; 
        } 
         
        fclose(fd); 
 
        umask(0066); /* -rw------- */ 
        if ((fd = fopen(priv_file_name, "w+")) == NULL) 
                return ERR; 
         
        if (!PEM_write_PrivateKey(fd, priv_key, EVP_des_ede3_cbc(), (unsigned char *)user->pass, strlen(user->pass), NULL, NULL)) {  
                log_message(LOG_ERR, "(ERROR) error when saving private key"); 
                RSA_free(rsa); 
                fclose(fd); 
                return ERR; 
        } 
 
        log_message(LOG_INFO, "(INFO) key pair created for the user %s", user->name); 
 
        RSA_free(rsa); 
        fclose(fd); 
        return SUCCESS; 
}


/* 
 * This function verify if user have an entry. 
 * If haven't, a new entry will be created. 
 * else, just test key pairs. It's possible to 
 * force a new key pairs creation with flag  
 */ 
int 
verify_user_entry(struct pam_user *user, int flag) 
{ 
        int retval; 
        FILE *fd_pub, *fd_priv; 
	
	/*
	 * free at the end of the fct
	 */
        char *pub_file_name = calloc(strlen(USR_DIR) + strlen(user->name) + 4 + 1, sizeof(char)); /* +4(.pub) +1('\0') */ 
        char *priv_file_name = calloc(strlen(USR_DIR) + strlen(user->name) + 1, sizeof(char)); 
 
        if (pub_file_name == NULL || priv_file_name == NULL) 
                return PAM_SYSTEM_ERR; 
 
        strncpy(priv_file_name, USR_DIR, strlen(USR_DIR)); 
        strncpy(priv_file_name+strlen(USR_DIR), user->name, strlen(user->name)); 
 
        strncpy(pub_file_name, USR_DIR, strlen(USR_DIR)); 
        strncpy(pub_file_name+strlen(USR_DIR), user->name, strlen(user->name)); 
        strncpy(pub_file_name+strlen(USR_DIR)+strlen(user->name), ".pub", 4);  
 
        if (flag) { 
                if ((retval = create_user_entry(user, pub_file_name, priv_file_name))) { 
                        F(pub_file_name); 
                        F(priv_file_name);    
                        return retval; 
                }        
        } 
         
        if ( ((fd_priv = fopen(priv_file_name, "r")) == NULL) || ((fd_pub = fopen(pub_file_name, "r")) == NULL) ) { 
                if ((retval = create_user_entry(user, pub_file_name, priv_file_name))) { 
                        F(pub_file_name); 
                        F(priv_file_name);    
                        return retval; 
                } 
 
                if ( ((fd_priv = fopen(priv_file_name, "r")) == NULL) || ((fd_pub = fopen(pub_file_name, "r")) == NULL) ) { 
                        F(pub_file_name); 
                        F(priv_file_name); 
                        return NO_ENTRY; 
                } 
        }        
         
        EVP_PKEY *priv_key = NULL; 
        EVP_PKEY *pub_key = NULL; 
         
        if (!PEM_read_PrivateKey(fd_priv, &priv_key, passwd_callback, (void *)user->pass) || 
            !PEM_read_PUBKEY(fd_pub, &pub_key, NULL, NULL)) { 
                log_message(LOG_ERR, "(ERROR) can not read keys"); 
                fclose(fd_pub); 
                fclose(fd_priv); 
                F(pub_file_name); 
                F(priv_file_name); 
                return ERR;              
        } 
 
        log_message(LOG_INFO, "(INFO) key pair check successfuly"); 
 
        fclose(fd_pub); 
        fclose(fd_priv); 
        F(pub_file_name); 
        F(priv_file_name); 
        EVP_PKEY_free(priv_key); 
        EVP_PKEY_free(pub_key);  
        return ENTRY; 
}


/*
 * get the public key of user
 * passed in argument
 */
EVP_PKEY 
*get_public_key(const struct pam_user *user) 
{ 
        FILE *fd; 
        EVP_PKEY *pub_key = NULL; 
        char *pub_file_name = calloc(strlen(USR_DIR) + strlen(user->name) + 4 + 1, sizeof(char));        
 
        if (pub_file_name == NULL) 
                return NULL; 
         
        strncpy(pub_file_name, USR_DIR, strlen(USR_DIR)); 
        strncpy(pub_file_name+strlen(USR_DIR), user->name, strlen(user->name)); 
        strncpy(pub_file_name+strlen(USR_DIR)+strlen(user->name), ".pub", 4);  
         
        if ((fd = fopen(pub_file_name, "r")) == NULL) { 
                log_message(LOG_ERR, "(ERROR) can not open %s : %m", pub_file_name); 
                F(pub_file_name); 
                return NULL; 
        }        
         
        if (!PEM_read_PUBKEY(fd, &pub_key, NULL, NULL)) { 
                log_message(LOG_ERR, "(ERROR) can not read public key"); 
                fclose(fd); 
                F(pub_file_name); 
                return NULL; 
        } 
 
        fclose(fd); 
        F(pub_file_name); 
        return pub_key; 
}


/*
 * encrypt data in argument using key&iv and
 * write it in file
 * return 1 if an error occured
 */
int
sym_encrypt(unsigned char *data, int data_len, char *file, unsigned char *key, unsigned char *iv)
{
	OpenSSL_add_all_algorithms();		
	int out_len, encrypted_len;
	EVP_CIPHER_CTX ctx;
	unsigned char encrypted_data[MAX_BUF];
	FILE *out;
	
	if (data_len > MAX_BUF) {
		log_message(LOG_ERR, "(ERROR) data is too large");
		return ERR;
	}
	
	EVP_CIPHER_CTX_init(&ctx);
	
	if (EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
		return ERR;

	if (!EVP_EncryptUpdate(&ctx, encrypted_data, &out_len, data, data_len))
		return ERR;

	if (!EVP_EncryptFinal_ex(&ctx, encrypted_data + out_len, &encrypted_len))
		return ERR;

	out_len += encrypted_len;
	EVP_CIPHER_CTX_cleanup(&ctx);

	umask(0066);
	if ((out = fopen(file, "wb")) == NULL)
		return ERR;

	fwrite(encrypted_data, 1, out_len, out);

	fclose(out);
	return SUCCESS; 
}


/*
 * create file with encrypted data (AES) 
 * The private key is random
 * The file name is random
 *
 * This function return the private key
 * and the file name of encrypted data (with his path)
 */
char
*create_AES_encrypted_file(int ctrl, char *data, unsigned char *salt, char **dst_cmd)
{
	char *buffer, *plain_data;
	/*unsigned char key[AES_KEY_LEN];
	unsigned char iv[AES_IV_LEN];*/
	unsigned char *key;
	unsigned char *iv;
	char *aes_file = NULL;
	unsigned char *seed;

	aes_file = calloc(strlen(EN_CMD_DIR) + EN_CMD_FILENAME_LEN + 1, sizeof(char));

	if (aes_file == NULL)
		return NULL;

	if ((seed = alea(EN_CMD_FILENAME_LEN, (unsigned char *)CARAC)) == NULL)
		return NULL;

	strncpy(aes_file, EN_CMD_DIR, strlen(EN_CMD_DIR));
	strncpy(aes_file+strlen(EN_CMD_DIR), (char *)seed, EN_CMD_FILENAME_LEN);

	if (ctrl & PAM_DEBUG_ARG)
		log_message(LOG_DEBUG, "(DEBUG) creating AES file...");	

	/* free in create_command_file() */
	buffer = calloc(strlen(aes_file)+AES_KEY_LEN+AES_IV_LEN, sizeof(char));	
	
	if (buffer == NULL)
		return NULL;

	/* generates too much zero (sometimes) on debian stable/oldstable */
	/* if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) */

	if ((key = alea(AES_KEY_LEN, (unsigned char *)CARAC)) == NULL)
		return NULL;
	if ((iv = alea(AES_IV_LEN, (unsigned char *)CARAC)) == NULL)
		return NULL;

	/*strncpy(buffer, aes_file, strlen(aes_file));
	strncpy(buffer+strlen(aes_file), (const char *)key, sizeof(key));
	strncpy(buffer+strlen(aes_file)+sizeof(key), (const char *)iv, sizeof(iv));*/

	strncpy(buffer, aes_file, strlen(aes_file));
	strncpy(buffer+strlen(aes_file), (const char *)key, AES_KEY_LEN);
	strncpy(buffer+strlen(aes_file)+AES_KEY_LEN, (const char *)iv, AES_IV_LEN);


	/*
	 * Prapare data to encrypt
	 */

	plain_data = calloc(strlen((const char *)salt)+strlen(data)+1, sizeof(char));
	
	if (plain_data == NULL)
		return NULL;

	strncpy(plain_data, (char *)salt, strlen((const char *)salt));
	strncpy(plain_data+strlen((const char *)salt), data, strlen(data));

	if (*dst_cmd == NULL) {
		/* free in wait_reply() */
		*dst_cmd = calloc(strlen(plain_data)+1, sizeof(char));

		if (*dst_cmd == NULL)
			return NULL;

		strncpy(*dst_cmd, plain_data, strlen(plain_data));
	}


	/*  encrypt data in file */
	if (sym_encrypt((unsigned char *)plain_data, strlen(plain_data), aes_file, key, iv) == ERR) {
		log_message(LOG_ERR, "(ERROR) AES encryption failed");
		return NULL;
	}

	F(key);
	F(iv);
	F(seed);
	F(plain_data);
	F(aes_file);
	return buffer;
}

/* 
 * create file containing the private AES key and 
 * the file path with encrypted(AES) data (all 
 * encrypted with RSA)
 * The file name is random
 *
 * This function return the file name (with his path) 
 */
char 
*create_RSA_encrypted_file(int ctrl, EVP_PKEY *public_key, char *data) 
{ 
        FILE *fd; 
        int retval; 
        char *encrypted_file_name = NULL; 
        char *buffer, *encrypted_data = NULL; 
        unsigned char *seed;     

	/* free in create_command_file */ 
        encrypted_file_name = calloc(strlen(EN_CMD_DIR) + EN_CMD_FILENAME_LEN + 1, sizeof(char)); 
 
        if (encrypted_file_name == NULL) 
                return NULL; 
 
	/* free at the end of the fct */
        if ((seed = alea(EN_CMD_FILENAME_LEN, (unsigned char *)CARAC)) == NULL) 
                return NULL; 
 
        strncpy(encrypted_file_name, EN_CMD_DIR, strlen(EN_CMD_DIR)); 
        strncpy(encrypted_file_name+strlen(EN_CMD_DIR), (char *)seed, EN_CMD_FILENAME_LEN); 
 	
	if (ctrl & PAM_DEBUG_ARG)
        	log_message(LOG_DEBUG, "(DEBUG) creating RSA file..."); 

	/* free at the end of the fct */
        buffer = calloc(strlen(data)+1, sizeof(char)); 
                 
        if (buffer == NULL) 
                return NULL; 
 
        strncpy(buffer, data, strlen(data)); 
        
	umask(0066); 
        if ((fd = fopen(encrypted_file_name, "w+")) == NULL) 
                return NULL; 
 
        RSA *rsa = RSA_new(); 
 
        if ((rsa = EVP_PKEY_get1_RSA(public_key)) == NULL) { 
                log_message(LOG_ERR, "(ERROR) assign RSA public key"); 
                RSA_free(rsa); 
                return NULL; 
        } 
 
	/* free at the end of the fct */
        if ((encrypted_data = malloc(RSA_size(rsa))) == NULL) 
                return NULL;     
 
        if (RSA_size(rsa) - 41 < strlen(buffer) + 1) {  
                log_message(LOG_ERR, "(ERROR) data is too large");
		return NULL; 
        } 

         
        if ((retval = RSA_public_encrypt(strlen(buffer)+1, (unsigned char *)buffer, (unsigned char *)encrypted_data, rsa, RSA_PKCS1_OAEP_PADDING)) == -1) { 
                log_message(LOG_ERR, "(ERROR) can not encrypt data"); 
                RSA_free(rsa); 
                EVP_PKEY_free(public_key); 
                return NULL; 
        } 
 
        if (encrypted_data == NULL) 
                return NULL; 
        
	fwrite(encrypted_data, sizeof(*encrypted_data),  RSA_size(rsa), fd);	

        fclose(fd); 
        F(seed); 
        F(buffer); 
        F(encrypted_data); 
        RSA_free(rsa); 
        rsa = NULL;

        return encrypted_file_name; 
}


int
verify(EVP_PKEY *public_key, const char *file, char *dst_cmd)
{
	FILE *fd;
	int len, ret;
	char *buffer;
	unsigned char hash[20];

	RSA *rsa = RSA_new();

	if ((rsa = EVP_PKEY_get1_RSA(public_key)) == NULL) { 
                log_message(LOG_ERR, "(ERROR) assign RSA public key"); 
                RSA_free(rsa); 
                return ERR; 
        }

	len = RSA_size(rsa);

	buffer = calloc(len, sizeof(char));
	
	if (buffer == NULL) {
		RSA_free(rsa);
		return ERR;
	}

	if ((fd = fopen(file, "r")) == NULL ) {
		log_message(LOG_ERR, "(ERROR) can not open signed file '%s': %m", file);
		RSA_free(rsa);
		return ERR;
	}

	ret=fread(buffer, sizeof(*buffer), len, fd); 
	fclose(fd);


	if (!SHA1((const unsigned char *)dst_cmd, strlen(dst_cmd), hash)) {
		log_message(LOG_ERR, "(ERROR) hash data for verify");
		RSA_free(rsa);
		return ERR;
	}
	

	if (!RSA_verify(NID_sha1, hash, sizeof(hash), (unsigned char *)buffer, ret, rsa)) {	
		log_message(LOG_ERR, "(ERROR) impossible to verify the singature of file '%s'", file);
		RSA_free(rsa);
		return ERR;
	}	

	return SUCCESS;
}



