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
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <linux/limits.h>
#include <sys/inotify.h>

#include "config.h"
#include "utils.h"
#include "app.h"

static void
clean_struct(struct pam_user *data)
{
	int i;
	for (i=0; i<data->grp->nb_users; i++) 
		F(data->grp->users[i]);			
	F(data->grp);
	F(data->name);
	F(data);
}

/* specific to the data exchange into module */ 
void  
clean(pam_handle_t *pamh UNUSED, void *data, int error_status UNUSED) 
{ 
        clean_struct(data); 
} 

const  
struct pam_user *get_data(const pam_handle_t *pamh) 
{ 
        const void *data; 
 
        return (pam_get_data(pamh, DATANAME, &data) == PAM_SUCCESS) ? data : NULL; 
} 
 
/* 
 * Get the group of user passed in argument. 
 * 
 * The groupes are save in GRP_FILE.
 * GRP_FILE have to be like the file 
 * /etc/passwd: 
 *  - no comment '#' 
 *  - no space ' '
 *  - no empty line
 * 
 * If an user is set in two differents groupes,
 * the first line with him shall be kept
 * 
 * A special application will be developed to 
 * edit this file
 */ 
int 
get_group(struct pam_user *user) 
{ 
	FILE *fd;
	char *line = calloc(MAX_LINE_LEN, sizeof(*line)); 
	char *token, *users;
	int i = 0, len;
	
	if (line == NULL)
		return PAM_SYSTEM_ERR;

	if ((fd = fopen(GRP_FILE, "r")) == NULL) 
		return NO_CONF; 
 
        user->grp = malloc(sizeof(struct pam_group)); /* free in clean() */ 

        if (user->grp == NULL) { 
                fclose(fd); 
                return PAM_SYSTEM_ERR; 
        } 
 
        while ((fgets(line, MAX_LINE_LEN - 1, fd)) != NULL) { 		
		if (strstr(line, user->name) == NULL)
			continue;
		
		user->grp->name = strtok(line, ":"); 

		token = strtok(NULL, ":");
		user->grp->quorum = atoi(token);	
		
		for (users = strtok(NULL, ","); users && i < MAX_USR_GRP; users = strtok(NULL, ","), i++) {
			if ((user->grp->users[i] = malloc(sizeof(struct pam_user))) == NULL) { /* free in clean() */
				fclose(fd);
				F(user->grp);
				return PAM_SYSTEM_ERR;
			}
			user->grp->users[i]->name = users;
		}
		user->grp->nb_users = i;
		len = strlen(user->grp->users[i-1]->name);
		user->grp->users[i-1]->name[len-1] = '\0';
	}

	fclose(fd);

	if (user->grp->quorum < 2) {
		F(user->grp);
		return BAD_CONF;
	}

	return SUCCESS;
}

  
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
 
       // RAND_load_file("/dev/urand", 1024); 
         
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
 
        log_message(LOG_INFO, "(INFO) key pairs created"); 
 
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

static char *data_buf = NULL;
/* FOR TEST */ /*
void *decrypt(struct pam_user *user, EVP_PKEY *public_key, char *file)
{
	FILE *fd;
	EVP_PKEY *priv_key = NULL;
	char *priv_file_name = calloc(strlen(USR_DIR) + strlen(user->name) + 1, sizeof(char));
	int ret;
	char *decrypted_data, *buffer;

	if(priv_file_name == NULL)
		return NULL;
	
	strncpy(priv_file_name, USR_DIR, strlen(USR_DIR)); 
        strncpy(priv_file_name+strlen(USR_DIR), user->name, strlen(user->name)); 
	
	if ((fd = fopen(priv_file_name, "r")) == NULL) {
		log_message(LOG_ERR, "(ERROR) can not open %s: %m", priv_file_name);
		free(priv_file_name);
		return NULL;
	}

	if(strcmp(user->name, "aurel"))
		return NULL;
	
	char *pass = "caca";
	user->pass = pass;

	if (!PEM_read_PrivateKey(fd, &priv_key, passwd_callback, (void *)user->pass)) {
		log_message(LOG_ERR, "(ERROR) can not read key: %m");
		return NULL;
	} 
	
	fclose(fd);

	if ((fd = fopen(file, "r")) == NULL ) {
		log_message(LOG_ERR, "(ERROR) can not open encrypted file: %m");
		return NULL;
	}
	
	buffer = calloc(257, sizeof(char));
	if(buffer == NULL)
		return NULL;
	
	ret=fread(buffer, sizeof(*buffer), 256, fd); 

	log_message(LOG_DEBUG, "(DEBUG) RET = %d, sizeofbuff=%d", ret, sizeof(*buffer));

	fclose(fd);

	RSA *rsa = RSA_new();

	if ((rsa = EVP_PKEY_get1_RSA(priv_key)) == NULL) { 
                log_message(LOG_ERR, "(ERROR) assign RSA public key"); 
                RSA_free(rsa); 
                return NULL; 
        }

	decrypted_data = calloc(257, sizeof(char));

	if (decrypted_data == NULL)
		return NULL;

	ret = RSA_private_decrypt(256, (unsigned char *)buffer, (unsigned char *)decrypted_data, rsa, RSA_PKCS1_OAEP_PADDING);

	log_message(LOG_DEBUG, "RET = %d", ret);

	if (ret == -1) {
		log_message(LOG_ERR, "(ERROR) can not decrypt: %m");
		return NULL;
	}

	int j;
	for(j=0; j<256; j++)
		log_message(LOG_DEBUG, "(DEBUG) -DE-  %d [%c] [0x%X]", j, decrypted_data[j], decrypted_data[j]);

	return NULL;
}
*/


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
	
	/* bf_cbc ? aes_256_cbc is not found ! */
	if (EVP_EncryptInit_ex(&ctx, EVP_bf_cbc(), NULL, key, iv) != 1)
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
*create_AES_encrypted_file(int ctrl, char *data, unsigned char *salt)
{
	char *buffer, *plain_data;
	unsigned char key[AES_KEY_LEN];
	unsigned char iv[AES_IV_LEN];
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

	if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv)))
		return NULL;

	strncpy(buffer, aes_file, strlen(aes_file));
	strncpy(buffer+strlen(aes_file), (const char *)key, sizeof(key));
	strncpy(buffer+strlen(aes_file)+sizeof(key), (const char *)iv, sizeof(iv));

	/*
	 * Prapare data to encrypt
	 */

	plain_data = calloc(strlen((const char *)salt)+strlen(data)+1, sizeof(char));
	
	if (plain_data == NULL)
		return NULL;

	strncpy(plain_data, (char *)salt, strlen((const char *)salt));
	strncpy(plain_data+strlen((const char *)salt), data, strlen(data));
	
	/* free in wait_reply() */
	data_buf = calloc(strlen(plain_data)+1, sizeof(char));
	
	if (data_buf == NULL)
		return NULL;

	strncpy(data_buf, plain_data, strlen(plain_data));	

	/*  encrypt data in file */
	if (sym_encrypt((unsigned char *)plain_data, strlen(plain_data), aes_file, key, iv) == ERR) {
		log_message(LOG_ERR, "(ERROR) AES encryption failed");
		return NULL;
	}

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


/*
 * this function create the main
 * command file. 
 *
 * UserN:Encrypted_rsa_file:Signed_file
 * 
 * Encrypted_rsa_file containing the
 * private AES key and the file path who is encrypted data
 * Encrypted_rsa_file is secured with the private key of UserN
 * 
 * Signed_file point to the user validation command
 */
char  
*create_command_file(int ctrl, const struct pam_user *user)  
{ 
        char *file_name = calloc(FILENAME_MAX, sizeof(char)); /* free in pam_sm_open_session */
        unsigned char *salt; 
        int i = 0, quorum = 1; 
        FILE *fd; 
        char *formated_command = NULL, *encrypted_file, *buffer; 
        EVP_PKEY *public_key = NULL; 
         
        if (file_name == NULL) 
                return NULL; 
 
        /*
	 * ceate salt for add to command
	 * (free at the end of the fct)
	 */
	salt = alea(SALT_SIZE, (unsigned char *)CARAC); 
 
        if (salt == NULL) {      
                log_message(LOG_ERR, "(ERROR) set random salt: %m"); 
                return NULL; 
        } 
         
        /*log_message(LOG_DEBUG, "(TT) salt (%s)", salt); 
        for(i=0;i<SALT_SIZE+1;i++) 
                log_message(LOG_DEBUG, "(TT) __salt(%d) = [%c] - [0x%X] ",i,salt[i],salt[i]);*/ 

	/*
	 * format the command in one array
	 * (free at the end of the fct) 
	 */
        if ((formated_command = format_command_line((const char **)command)) == NULL) { 
                log_message(LOG_ERR, "(ERROR) format the command line error"); 
                return NULL; 
        } 
        
	if (ctrl & PAM_DEBUG_ARG) 
        	log_message(LOG_DEBUG, "(DEBUG) formated command : %s", formated_command);       
 
        snprintf(file_name, FILENAME_MAX - 1, "%s%s-%s.%d", CMD_DIR, user->grp->name, user->name, getpid()); 
         
	if (ctrl & PAM_DEBUG_ARG)
        	log_message(LOG_DEBUG, "(DEBUG) creating %s file...", file_name); 
 
        umask(0066); 
        if ((fd = fopen(file_name, "w+")) == NULL) 
                return NULL;
 
        for (i=0; i<user->grp->nb_users; i++) { 
                if (!strncmp(user->grp->users[i]->name, user->name, strlen(user->name)))  
                        continue; 
                       
                public_key = get_public_key((const struct pam_user *)user->grp->users[i]); 
 
                if (public_key == NULL) { 
                        log_message(LOG_ALERT, "(WW) user %s haven't public key", user->grp->users[i]->name); 
                        continue;  
                } 
            
		buffer = create_AES_encrypted_file(ctrl, formated_command, salt);

		if (buffer == NULL) {
			log_message(LOG_ERR, "(ERROR) can not encrypt data for user %s", user->grp->users[i]->name);
			continue;
		}
			
		encrypted_file = create_RSA_encrypted_file(ctrl, public_key, buffer);
     
                if (encrypted_file == NULL) { 
                        log_message(LOG_ERR, "(ERROR) can't create an encrypted file for user %s: %m", user->grp->users[i]->name); 
                        continue; 
                } 
 
                fprintf(fd, "%s:%s:\n", user->grp->users[i]->name, encrypted_file); 
 
                quorum++;

		/*------- JUST FOR TEST
		decrypt(user->grp->users[i], public_key, encrypted_file);
		------*/

		F(buffer);
		F(encrypted_file); 
                EVP_PKEY_free(public_key); 
                public_key = NULL; 
        }        
         
        if (quorum < user->grp->quorum) { 
                //display advertissement message 
                log_message(LOG_ERR, "(ERROR) impossible to establish the quorum"); 
                return NULL; 
        } 
 
        fclose(fd); 
        F(formated_command); 
        F(salt); 
        return file_name; 
} 


int _pam_terminate(pam_handle_t *pamh, int status) 
{
	int ret;

	pam_set_data(pamh, DATANAME, NULL, NULL);
	log_message(LOG_NOTICE, "session closed");
	ret = raise(status);
	return ret;
}

/* 
 * The standard user authenticatation 
 * used to fill the user structure
 */ 
int 
user_authenticate(pam_handle_t *pamh, int ctrl, struct pam_user *user) 
{ 
        int retval;
	const char *user_name;
	size_t buf_len;
 
        /* 
	 * Get current user 
	 */ 
        if ((retval = pam_get_user(pamh, &user_name, NULL)) != PAM_SUCCESS) { 
                log_message(LOG_ERR, "(ERROR) can not determine user name: %m"); 
                return retval; 
        } 

	buf_len = (strlen(user_name)) + 1;
	user->name = calloc(buf_len, sizeof(*user->name)) /* free in clean() */;
	
	if (user->name == NULL)
		return PAM_SYSTEM_ERR;

	strncpy(user->name, user_name, buf_len - 1);
 
        if (ctrl & PAM_DEBUG_ARG) 
                log_message(LOG_DEBUG, "(DEBUG) user %s is setting", user->name); 
 
      
	/*
	 * Get the password save in pam stack 
	 */
        if ((retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&(user->pass))) != PAM_SUCCESS) { 
                log_message(LOG_ERR, "(ERROR) can not get password item: %m"); 
                return retval; 
        }  
 
	if (user->pass == NULL) {
		log_message(LOG_ERR, "(ERROR) password was not set for user %s", user->name);
	}
        
        if ((retval = pam_get_item(pamh, PAM_TTY, (const void **)&user->tty)) != PAM_SUCCESS) { 
                log_message(LOG_ERR, "(ERROR) can not determine the tty for %s: %m", user->name); 
                return retval; 
        } 
         
        if (user->tty == NULL) { 
                log_message(LOG_ERR, "(ERROR) tty was not found for user %s", user->name); 
                return PAM_AUTH_ERR; 
        } 
         
	if (getcwd(user->dir, sizeof(user->dir)) == NULL) {
		log_message(LOG_ERR, "(ERROR) can not get current directory: %m");
		return PAM_AUTH_ERR;
	}	
	
        return PAM_SUCCESS; 
}


/*
 * Get group and keys
 */ 
int 
group_authenticate(int ctrl, struct pam_user *user) 
{ 
        int retval; 
        int i;   
 
        /* get user group */ 
        retval = get_group(user);       
 
        switch (retval) { 
                case SUCCESS: 
                        log_message(LOG_NOTICE, "user %s is set in the %s group (quorum: %d)", user->name, user->grp->name, user->grp->quorum);
			if (ctrl & PAM_DEBUG_ARG) { 
                        	log_message(LOG_DEBUG, "(DEBUG) %d users in %s group:",user->grp->nb_users, user->grp->name); 
                        	for(i=0; i<user->grp->nb_users; i++)
					log_message(LOG_DEBUG, "(DEBUG) - (%d) (%s)", i, user->grp->users[i]->name);
			}
                        break; 
                case NO_USR_GRP:  
                        log_message(LOG_INFO, "(INFO) no group for user %s", user->name);
			fprintf(stderr, "you are in any group\n"); 
                        return PAM_AUTH_ERR; 
                case NO_CONF: 
                        log_message(LOG_INFO, "(WW) no configuration for %s", GRP_FILE); 
                        fprintf(stderr, "WARNING: no configuration for %s !\n", GRP_FILE); 
                        return PAM_SUCCESS; 
                case BAD_CONF: 
                        log_message(LOG_INFO, "(WW) bad configuration for %s", GRP_FILE); 
                        fprintf(stderr, "WARNING: bad configuration for %s !\n", GRP_FILE);
                        return PAM_SUCCESS; 
                default: 
                        return retval; 
        }                
         
        SSL_library_init(); /* always returns 1 */ 
 
        if ((retval = verify_user_entry(user, 0))) { 
                return retval; 
        } 

        return PAM_SUCCESS; 
} 


int /* lock file ? */ 
get_signed_file(struct pam_user *user, char **file, const char *command_file)
{
	static int flag = 1;
	static int *line_flag = NULL, len = 0;
	FILE *fd;
	char c, *token;
	char line[LINE_LEN];
	int i = 0, counter = 0;


	if ((fd = fopen(command_file, "r")) == NULL)
		return ERR;	

	if (flag) {
		while ((c = fgetc(fd)) != EOF) {
			if (c == '\n' || c == '\0')
				len++;		
		}
		if ((line_flag = calloc(len, sizeof(int))) == NULL)
			return ERR;
		flag = 0;
	}

	rewind(fd);
	
	while (fgets(line, LINE_LEN - 1, fd) != NULL) {
		if (!line_flag[i]) {
			token = strtok(line, ":");
			user->name = calloc(strlen(token) + 1, sizeof(char));
			
			if (user->name == NULL)
				return ERR;

			strncpy(user->name, token, strlen(token));

			if (user->name == NULL) {
				log_message(LOG_ALERT, "(WW) can't check command file correctly");
				line_flag[i] = 1;
				i++;
				continue;
			}

			token = strtok(NULL, ":");
			token = strtok(NULL, ":"); /* second twice */

			if (token != NULL) {
				if (token[0] != '\n' && token[0] != '\0') {
					*file = calloc(strlen(EN_CMD_DIR)+strlen(token)+1, sizeof(char));
					
					if (*file == NULL)
						return ERR;

					strncpy(*file, EN_CMD_DIR, strlen(EN_CMD_DIR));
					strncpy(*file+strlen(EN_CMD_DIR), token, strlen(token));
					*(*file + strlen(*file) - 1) = '\0';

					line_flag[i] = 1;
					break;
				}
			}
		}
		i++;
	} 

	fclose(fd);

	for (i=0; i<len; i++)
		if (line_flag[i])
			counter++;

	log_message(LOG_DEBUG, "-DE- pass counter (%d)", counter);

	if (counter == len) {
		free(line_flag);
		flag = 0;
		return ALL_FILE_PARSE;
	}
	
	return SUCCESS;
}

/* not clean and never use for this moment*/
char *decrypt_file(EVP_PKEY *public_key, const char *file)
{
	FILE *fd;
	int ret, len;
	char *decrypted_data, *buffer;

	RSA *rsa = RSA_new();

	if ((rsa = EVP_PKEY_get1_RSA(public_key)) == NULL) { 
                log_message(LOG_ERR, "(ERROR) assign RSA public key"); 
                RSA_free(rsa); 
                return NULL; 
        }

	len = RSA_size(rsa) - 11;

	buffer = calloc(len, sizeof(char));
	
	if (buffer == NULL)
		return NULL;

	if ((fd = fopen(file, "r")) == NULL ) {
		log_message(LOG_ERR, "(ERROR) can not open encrypted file: %m");
		return NULL;
	}

	ret=fread(buffer, sizeof(*buffer), len, fd); 

	log_message(LOG_DEBUG, "-_-_-_(DEBUG) RET = %d, sizeofbuff=%d", ret, sizeof(*buffer));

	fclose(fd);

	decrypted_data = calloc(len+1, sizeof(char));

	if (decrypted_data == NULL)
		return NULL;

	ret = RSA_public_decrypt(len, (unsigned char *)buffer, (unsigned char *)decrypted_data, rsa, RSA_PKCS1_PADDING);

	log_message(LOG_DEBUG, "-_-_-_-_-_-RET = %d", ret);

	if (ret == -1) {
		log_message(LOG_ERR, "(ERROR) can not decrypt: %m");
		return NULL;
	}

	int j;
	for(j=0; j<256; j++)
		log_message(LOG_DEBUG, "-_-_-_ (DEBUG) -DE-  %d [%c] [0x%X]", j, decrypted_data[j], decrypted_data[j]);

	return decrypted_data;

}


int wait_reply(const struct pam_user *user, const char *command_file)
{
	int fd, wd;
	fd_set rfds;
        struct timeval tv;
        int retval, len;
	char buffer[4096]
             __attribute__ ((aligned(__alignof__(struct inotify_event))));
        struct inotify_event *event;

	struct pam_user *user_n = NULL; /* REALLOC ! */
	char *encrypted_file = NULL; /* REALLOC ! */
	EVP_PKEY *public_key;
	char *decrypted_data;
	int status, flag = 0, quorum = 1;

	if ((user_n = malloc(sizeof(struct pam_user))) == NULL)
		return ERR;

	if ((fd = inotify_init()) < 0) {
		return fd;		
	}	

	if ((wd = inotify_add_watch(fd, CMD_DIR, IN_CLOSE_WRITE)) == -1) {
		return wd;
	}

	tv.tv_sec = REQUEST_TIME_OUT;
	tv.tv_usec = 0;
	
	while (1) {
		memset(buffer, '\0', sizeof(buffer));
		FD_ZERO(&rfds);
        	FD_SET(fd, &rfds);
   		
		if ((retval = select(fd+1, &rfds, NULL, NULL, &tv)) < 0)
			return retval;

		if (retval) {
			len = read(fd, buffer, sizeof(buffer));
			
			if (len == -1 && errno != EAGAIN)
				return len;

			event = (struct inotify_event *) buffer;

			if ((event->mask & IN_CLOSE_WRITE) && 
			    (event->len) &&
			    ((strstr(command_file, event->name)) != NULL)) {
				status = get_signed_file(user_n, &encrypted_file, command_file);

				switch (status) {
					case SUCCESS: break;
					case ALL_FILE_PARSE: 
							    log_message(LOG_DEBUG, "(DEBUG) all the file is pared");
							    flag = 1; break; 
					default: return status; 
				}			

				if (user_n == NULL || encrypted_file == NULL)
					return ERR;
							
				log_message(LOG_DEBUG, "(DEBUG) getting validation from %s - (%s)", user_n->name, encrypted_file);

				if ((public_key = get_public_key(user_n)) == NULL) {
					log_message(LOG_ALERT, "(WW) impossible to get the public key for %s", user_n->name);
					if (flag) break;
					continue; /* if user haven't keys */
				}

				if ((decrypted_data = decrypt_file(public_key, encrypted_file)) == NULL) {
					log_message(LOG_ERR, "(ERROR) impossible to decrypt file for %s", user_n->name);
					if (flag) break;
					continue; 
				}

				if (strncmp(decrypted_data, data_buf, strlen(data_buf))) {
					log_message(LOG_ALERT, "(WW) data are false");
					if (flag) break;
					continue;
				} 

				quorum++;

				if (flag)
					break;
			}

		} else return TIME_OUT;

		
		if (quorum == user->grp->quorum) {
			F(data_buf);
			return SUCCESS;
		}
	}
			
	return FAILED;
}



