#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <crypt.h>
#include <shadow.h>
#include <sudo_plugin.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <linux/limits.h>

#include "config.h"
#include "utils.h"
#include "app.h"

/* specific to the data exhange into module */ 
void  
clean(pam_handle_t *pamh UNUSED, void *data, int error_status UNUSED) 
{ 
        free(data); 
} 
 
const  
struct pam_user *get_data(const pam_handle_t *pamh) 
{ 
        const void *data; 
 
        return (pam_get_data(pamh, DATANAME, &data) == PAM_SUCCESS) ? data : NULL; 
} 
 
/* 
 * Get the group of user passed 
 * in argument 
 */ 
int 
get_group(struct pam_user *user) 
{ 
        FILE *fd; 
        char *line = calloc(MAX_LINE_LEN, sizeof(char)); 
        char *token; 
        int i, j; 
        struct pam_group *grp = NULL; 
 
        user->grp = NULL;        
 
        if ((fd = fopen(GRP_FILE, "r")) == NULL) 
                return NO_CONF; 
 
        grp = (struct pam_group *)malloc(sizeof(struct pam_group)); 
 
        if (grp == NULL) { 
                fclose(fd); 
                return PAM_SYSTEM_ERR; 
        } 
 
        while ((fgets(line, MAX_LINE_LEN - 1, fd)) != NULL) {  
                if (strchr(line, ':') == NULL) 
                        continue; 
 
                grp->name = strtok(line, ":"); 
 
                if (grp->name == NULL || grp->name[0] == '#') 
                        continue; 
 
                token = strtok(NULL, ":"); 
                grp->quorum = atoi(token); 
 
                if (grp->quorum < 2){ 
                        fclose(fd); 
                        free(grp); 
                        return BAD_CONF; 
                } 
                 
                i=0;     
                grp->users[i] = malloc(sizeof(struct pam_user)); 
 
                if (grp->users[i] == NULL) { 
                        fclose(fd); 
                        free(grp); 
                        return PAM_SYSTEM_ERR;   
                } 
                 
                grp->users[i]->name = strtok(NULL, ":");
		
		if (grp->users[i]->name == NULL) { 
                        fclose(fd); 
                        free(grp->users[i]); 
                        free(grp); 
                        return BAD_CONF; 
                } 
 
                grp->users[i]->name = strtok(grp->users[i]->name, ",");          
 
                if (strcmp(user->name, grp->users[i]->name) == 0) 
                        user->grp = grp; 
         
                while (grp->users[i]->name != NULL) { 
                        i++; 
                        grp->users[i] = malloc(sizeof(struct pam_user)); 
 
                        if (grp->users[i] == NULL) { 
                                fclose(fd); 
                                free(grp); 
                                return PAM_SYSTEM_ERR; 
                        } 
 
                        grp->users[i]->name = strtok(NULL, ","); 
                         
                        if (grp->users[i]->name != NULL) { 
                                if (strncmp(user->name, grp->users[i]->name, strlen(user->name)) == 0) { 
                                        user->grp = grp; 
                                } 
                        } 
                         
                        if (grp->users[i]->name == NULL) { 
                                int pos = strlen(grp->users[i-1]->name) - 1; 
                                grp->users[i-1]->name[pos] = '\0'; 
                                break; 
                        } 
                } 
 
                if (user->grp == NULL) { 
                        for (j=0; j<i; j++) 
                                free(grp->users[j]);             
                } else break;            
        } 
 
        if (grp->name == NULL) { 
                fclose(fd); 
                free(grp); 
                return NO_CONF; 
        } 
 
 
        if (user->grp == NULL) { 
                fclose(fd); 
                free(grp); 
                return NO_USR_GRP; 
        } 
        fclose(fd); 
        return SUCCESS;  
}


  
EVP_PKEY *create_rsa_key(RSA *rsa) 
{ 
        EVP_PKEY *key = EVP_PKEY_new(); 
        int ret; 
 
        if (rsa && key && EVP_PKEY_assign_RSA(key, rsa)) { 
                ret = RSA_check_key(rsa); 
 
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
         
        log_message(LOG_DEBUG, "(DEBUG) generate RSA key... (%i bits)", BITS); 
 
        RAND_load_file("/dev/urand", 1024); 
         
        if ((rsa = RSA_generate_key(BITS, 65537, NULL, NULL)) == NULL) { 
                log_message(LOG_NOTICE, "(ERROR) error during  key generation"); 
                return ERR; 
        } 
 
        EVP_PKEY* priv_key = create_rsa_key(rsa); 
        EVP_PKEY* pub_key  = create_rsa_key(rsa); 
 
        if (priv_key == NULL || pub_key == NULL) { 
                log_message(LOG_NOTICE, "(ERROR) create key error"); 
                RSA_free(rsa); 
        } 
 
        umask(0022); /* -rw-r--r--*/     
        if ((fd = fopen(pub_file_name, "w+")) == NULL) 
                return ERR; 
 
        if (!PEM_write_PUBKEY(fd, pub_key)) { 
                log_message(LOG_NOTICE, "(ERROR) error when saving the public key"); 
                RSA_free(rsa); 
                fclose(fd); 
                return ERR; 
        } 
         
        fclose(fd); 
 
        umask(0066); /* -rw------- */ 
        if ((fd = fopen(priv_file_name, "w+")) == NULL) 
                return ERR; 
         
        if (!PEM_write_PrivateKey(fd, priv_key, EVP_des_ede3_cbc(), (unsigned char *)user->pass, strlen(user->pass), NULL, NULL)) {  
                log_message(LOG_NOTICE, "(ERROR) error when saving private key"); 
                RSA_free(rsa); 
                fclose(fd); 
                return ERR; 
        } 
 
        log_message(LOG_NOTICE, "(ERROR) key pairs created"); 
 
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
                        free(pub_file_name); 
                        free(priv_file_name);    
                        return retval; 
                }        
        } 
         
        if ( ((fd_priv = fopen(priv_file_name, "r")) == NULL) || ((fd_pub = fopen(pub_file_name, "r")) == NULL) ) { 
                if ((retval = create_user_entry(user, pub_file_name, priv_file_name))) { 
                        free(pub_file_name); 
                        free(priv_file_name);    
                        return retval; 
                } 
 
                if ( ((fd_priv = fopen(priv_file_name, "r")) == NULL) || ((fd_pub = fopen(pub_file_name, "r")) == NULL) ) { 
                        free(pub_file_name); 
                        free(priv_file_name); 
                        return NO_ENTRY; 
                } 
        }        
         
        EVP_PKEY *priv_key = NULL; 
        EVP_PKEY *pub_key = NULL; 
         
        if (!PEM_read_PrivateKey(fd_priv, &priv_key, passwd_callback, (void *)user->pass) || 
            !PEM_read_PUBKEY(fd_pub, &pub_key, NULL, NULL)) { 
                log_message(LOG_NOTICE, "(ERROR) can not read keys"); 
                fclose(fd_pub); 
                fclose(fd_priv); 
                free(pub_file_name); 
                free(priv_file_name); 
                return ERR;              
        } 
 
        log_message(LOG_INFO, "(INFO) key pair check successfuly"); 
 
        fclose(fd_pub); 
        fclose(fd_priv); 
        free(pub_file_name); 
        free(priv_file_name); 
        EVP_PKEY_free(priv_key); 
        EVP_PKEY_free(pub_key);  
        return ENTRY; 
}


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
                free(pub_file_name); 
                return NULL; 
        }        
         
        if (!PEM_read_PUBKEY(fd, &pub_key, NULL, NULL)) { 
                log_message(LOG_ERR, "(ERROR) can not read public key"); 
                fclose(fd); 
                free(pub_file_name); 
                return NULL; 
        } 
 
        fclose(fd); 
        free(pub_file_name); 
        return pub_key; 
}


char  
*create_encrypted_file(EVP_PKEY *public_key, char *data, unsigned char *salt) 
{ 
        FILE *fd; 
        int retval; 
        char *encrypted_file_name = NULL; 
        char *buffer, *encrypted_data = NULL; 
        unsigned char *seed;     
 
        encrypted_file_name = calloc(strlen(EN_CMD_DIR) + EN_CMD_FILENAME_LEN + 1, sizeof(char)); 
 
        if (encrypted_file_name == NULL) 
                return NULL; 
 
        if ((seed = alea(EN_CMD_FILENAME_LEN, (unsigned char *)CARAC)) == NULL) 
                return NULL; 
 
        strncpy(encrypted_file_name, EN_CMD_DIR, strlen(EN_CMD_DIR)); 
        strncpy(encrypted_file_name+strlen(EN_CMD_DIR), (char *)seed, EN_CMD_FILENAME_LEN); 
 
        log_message(LOG_DEBUG, "(DEBUG) creating %s...", encrypted_file_name); 
 
        buffer = calloc(strlen((const char *)salt)+strlen(data)+1, sizeof(char)); 
                 
        if (buffer == NULL) 
                return NULL; 
 
        strncpy(buffer, (char *)salt, strlen((const char *)salt)); 
        strncpy(buffer+strlen((const char *)salt), data, strlen(data)); 
 
        log_message(LOG_DEBUG, "(DEBUG) buffer is %s", buffer); 
 
        umask(0066); 
        if ((fd = fopen(encrypted_file_name, "w+")) == NULL) 
                return NULL; 
 
        RSA *rsa = RSA_new(); 
 
        if ((rsa = EVP_PKEY_get1_RSA(public_key)) == NULL) { 
                log_message(LOG_ERR, "(ERROR) assign RSA public key"); 
                RSA_free(rsa); 
                return NULL; 
        } 
 
        if ((encrypted_data = calloc(RSA_size(rsa), sizeof(unsigned char))) == NULL) 
                return NULL;     
 
        if (RSA_size(rsa) - 41 < strlen(buffer)+1) { // cut + multiple encrypt. end: rewrite in 1 file 
                log_message(LOG_ERR, "(ERROR) data is too large"); 
        } 
         
        if ((retval = RSA_public_encrypt(strlen(buffer), (unsigned char *)buffer, (unsigned char *)encrypted_data, rsa, RSA_PKCS1_OAEP_PADDING)) == -1) { 
                log_message(LOG_ERR, "(ERROR) can not encrypt data"); 
                RSA_free(rsa); 
                EVP_PKEY_free(public_key); 
                return NULL; 
        } 
 
        if (encrypted_data == NULL) 
                return NULL; 
         
        fprintf(fd, "%s", encrypted_data); 
 
        fclose(fd); 
        free(seed); 
        free(buffer); 
        free(encrypted_data); 
        RSA_free(rsa); 
        rsa = NULL; 
        return encrypted_file_name; 
}

char 
*create_command_file(const struct pam_user *user)  
{ 
        char *file_name = calloc(FILENAME_MAX, sizeof(char)); 
        unsigned char *salt; 
        int i, quorum = 0; 
        FILE *fd; 
        char *formated_command = NULL, *encrypted_file; 
        EVP_PKEY *public_key = NULL; 
         
        if (file_name == NULL) 
                return NULL; 
 
        salt = alea(SALT_SIZE, (unsigned char *)CARAC); 
 
        if (salt == NULL) {      
                log_message(LOG_ERR, "(ERROR) set random salt: %m"); 
                return NULL; 
        } 
         
        /*log_message(LOG_DEBUG, "(TT) salt (%s)", salt); 
        for(i=0;i<SALT_SIZE+1;i++) 
                log_message(LOG_DEBUG, "(TT) __salt(%d) = [%c] - [0x%X] ",i,salt[i],salt[i]);*/ 
         
        if ((formated_command = format_command_line((const char **)command)) == NULL) { 
                log_message(LOG_ERR, "(ERROR) format the command line error"); 
                return NULL; 
        } 
         
        log_message(LOG_DEBUG, "(DEBUG) formated command : %s", formated_command);       
 
        snprintf(file_name, FILENAME_MAX - 1, "%s%s-%s.%d", CMD_DIR, user->grp->name, user->name, getpid()); 
         
        log_message(LOG_DEBUG, "(DEBUG) creating %s file...", file_name); 
 
        umask(0066); 
        if ((fd = fopen(file_name, "w+")) == NULL) 
                return NULL; 
 
        for (i=0; i<MAX_USR_GRP; i++) { 
                if (user->grp->users[i]->name == NULL) 
                        break; 
                if (!strcmp(user->grp->users[i]->name, user->name))  
                        continue; 
                         
                public_key = get_public_key((const struct pam_user *)user->grp->users[i]); 
 
                if (public_key == NULL) { 
                        log_message(LOG_ALERT, "(WW) user %s haven't public key", user->grp->users[i]->name); 
                        continue;  
                } 
                 
                encrypted_file = create_encrypted_file(public_key, formated_command, salt); 
 
                if (encrypted_file == NULL) { 
                        log_message(LOG_ERR, "(ERROR) can not create an encrypted file for user %s", user->grp->users[i]->name); 
                        continue; 
                } 
 
                fprintf(fd, "%s:%s:\n", user->grp->users[i]->name, encrypted_file); 
 
                quorum++;

		free(encrypted_file); 
                EVP_PKEY_free(public_key); 
                public_key = NULL; 
        }        
         
        if (quorum < user->grp->quorum) { 
                //display advertissement message 
                log_message(LOG_ERR, "(ERROR) impossible to establish the quorum"); 
                return NULL; 
        } 
 
        fclose(fd); 
        free(formated_command); 
        free(salt); 
        return file_name; 
} 



/* 
 * The standard user authenticatation 
 * used to fill the user structure 
 */ 
int 
user_authenticate(pam_handle_t *pamh, int ctrl, struct pam_user *user) 
{ 
        int retval; 
        user->pass = NULL; 
        char *crypt_password = NULL; 
        struct spwd *pwd = malloc(sizeof(struct spwd)); 
        char *usr; 
        size_t buf_len; 
 
        /* log_message(LOG_DEBUG, "__ADDR_OF_DATA  __AUTH2  user[0x%X]", user); */ 
         
        if (pwd == NULL) { 
                log_message(LOG_CRIT, "(ERROR) malloc() %m"); 
                return PAM_SYSTEM_ERR; 
        } 
 
        /* get current user */ 
        if ((retval = pam_get_user(pamh, (const char **)&usr, NULL)) != PAM_SUCCESS) { 
                log_message(LOG_ERR, "(ERROR) can not determine user name: %m"); 
                return retval; 
        } 
 
        buf_len = (strlen(usr)) + 1; 
        user->name = calloc(buf_len, sizeof(char)); /* not free in this fct */ 
 
        if(user->name == NULL) 
                return PAM_SYSTEM_ERR; 
 
        strncpy(user->name, usr, buf_len - 1); 
 
        if (ctrl & PAM_DEBUG_ARG) 
                log_message(LOG_DEBUG, "(DEBUG) user %s", user->name); 
 
        /* 
         * we have to get the password from the 
         * user directly 
         */ 
        if ((retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &user->pass, "%s", passwd_prompt)) != PAM_SUCCESS) { 
                log_message(LOG_ERR, "(ERROR) can not determine the password: %m"); 
                return retval; 
        }  
 
 
        if (user->pass == NULL) { 
                log_message(LOG_NOTICE, "(ERROR) the password is empty"); 
                return PAM_AUTH_ERR; 
        } 
 
         
        /* get user password save in /etc/shadow */ 
        if ((pwd = getspnam(user->name)) == NULL) { 
                log_message(LOG_ERR, "(ERROR) can not verify the password for user %s: %m", user->name); 
                return PAM_USER_UNKNOWN; 
        }  
 
 
        if ((crypt_password = crypt(user->pass, pwd->sp_pwdp)) == NULL) { 
                log_message(LOG_ERR, "(ERROR) can not crypt password for user %s: %m", user->name); 
                return PAM_AUTH_ERR; 
        } 
 
        /* compare passwords */ 
        if (strcmp(crypt_password, pwd->sp_pwdp)) { 
                log_message(LOG_NOTICE, "(INFO) incorrect password attempts"); 
                return PAM_AUTH_ERR; 
        }

	log_message(LOG_NOTICE, "user %s has been authenticate", user->name);    
 
        /* 
         * now we have to set the item. PAM_AUTHTOK is used for token 
         * (like password) and allows the password for other modules. 
         * 
         * So sudo can use the user password automatically 
         */ 
        if ((retval = pam_set_item(pamh, PAM_AUTHTOK, (const void *)user->pass)) != PAM_SUCCESS) { 
                log_message(LOG_ERR, "(ERROR) can not set password item: %m"); 
                return retval; 
        }  
 
 
        /* associate a tty */ 
        if ((retval = pam_get_item(pamh, PAM_TTY, (const void **)&(user->tty))) != PAM_SUCCESS) { 
                log_message(LOG_ERR, "(ERROR) can not determine the tty for %s: %m", user->name); 
                return retval; 
        } 
         
        if (user->tty == NULL) { 
                log_message(LOG_ERR, "(ERROR) tty was not found for user %s", user->name); 
                return PAM_AUTH_ERR; 
        } 
         
        if (ctrl & PAM_DEBUG_ARG) 
                log_message(LOG_DEBUG, "(DEBUG) tty %s", user->tty); 
 
        cleanup((void *)&pwd); 
        return PAM_SUCCESS; 
}



/* The Shamir authentication */ 
int 
shamir_authenticate(int ctrl, struct pam_user *user) 
{ 
        int retval; 
        int i;   
 
        /* get user group */ 
        retval = get_group(user);        
        switch (retval) { 
                case SUCCESS: 
                        log_message(LOG_NOTICE, "user %s is set in the %s group (quorum: %d)", user->name, user->grp->name, user->grp->quorum); 
                        log_message(LOG_NOTICE, "users in %s group:", user->grp->name); 
                         
                        for(i=0; i<MAX_USR_GRP; i++){ 
                                if (user->grp->users[i]->name == NULL) 
                                        break; 
                                log_message(LOG_NOTICE, "- %s", user->grp->users[i]->name);                      
                        } 
                        break; 
                case NO_USR_GRP:  
                        log_message(LOG_NOTICE, "(INFO) no group for user %s", user->name); 
                        return PAM_AUTH_ERR; 
                case NO_CONF: 
                        log_message(LOG_NOTICE, "(WW) no configuration for %s", GRP_FILE); 
                        /* display advertissement msg */ 
                        return PAM_SUCCESS; 
                case BAD_CONF: 
                        log_message(LOG_NOTICE, "(WW) bad configuration for %s", GRP_FILE); 
                        /* display advertissement msg */ 
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
 











