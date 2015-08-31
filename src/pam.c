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
#include <linux/limits.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <sys/inotify.h>

#include "pam.h"
#include "utils.h"
#include "crypto.h"

static void
clean_struct(struct pam_user *data)
{
	int i;
	if (data)
		F(data->pass);

	if (data && data->grp) {
		for (i=0; i<data->grp->nb_users; i++) 
			F(data->grp->users[i]);			
		F(data->grp);
		F(data->name);
		F(data);
	} else {
		F(data);
	}
}

/* specific to the data exchange into module */ 
void  
clean(pam_handle_t *pamh UNUSED, void *data, int error_status UNUSED) 
{ 
        clean_struct(data); 
} 

/*
 * return data save in authentication 
 * (only available for module)
 */
const  
struct pam_user *get_data(const pam_handle_t *pamh) 
{ 
        const void *data; 
 
        return (pam_get_data(pamh, DATANAME, &data) == PAM_SUCCESS) ? data : NULL; 
} 


static int 
converse(pam_handle_t *pamh, int argc, const struct pam_message *msg, struct pam_response **resp)
{
	int retval;
	struct pam_conv *conv;

	if ((retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv)) != PAM_SUCCESS)
		return retval;

	return conv->conv(argc, &msg, resp, conv->appdata_ptr); 	
}

/*
 * Use a specific conversation protocol
 */
int 
send_data(int ctrl, pam_handle_t *pamh, void *data)
{
	int retval;
	struct pam_message msg, *p_msg;
	struct pam_response *resp;	

	p_msg = &msg;
	msg.msg_style = PAM_EX_DATA;
	msg.msg = (char *)data;
	resp = NULL;

	if ((retval = converse(pamh, 1, (const struct pam_message *)p_msg, &resp)) != PAM_SUCCESS) 
		return retval;

	if (!resp || !resp->resp) {
		F(resp);
		return PAM_CONV_ERR;
	}
	
	if (strncmp(resp->resp, ACKNOWLEDGE, strlen(ACKNOWLEDGE))) {
		F(resp);
		return PAM_CONV_ERR;
	}

	
	F(resp);
	return SUCCESS;
}

void
unlink_tmp_files(struct tempory_files *tmp_files) 
{
	struct tempory_files *item;

	while ((item = tmp_files) != NULL) {
		if (item->name) {
			if(unlink(item->name) == -1)
				log_message(LOG_ERR, "(ERROR) impossible to remove '%s' file : %m", item->name);
			F(item->name);
		}
		
		tmp_files = tmp_files->next;
		F(item);
	}
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
	int i = 0, len, flag = 0;
	
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
	
		flag = 1;
	
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

	if (!flag)
		return NO_USR_GRP;

	if (user->grp->quorum < 2) {
		F(user->grp);
		return BAD_CONF;
	}

	return SUCCESS;
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
*create_command_file(int ctrl, const struct pam_user *user, char **cmd, char **dst_cmd, struct tempory_files **tmp_files)  
{ 
        char *file_name = calloc(FILENAME_MAX, sizeof(char)); /* free in pam_sm_open_session */
        unsigned char *salt; 
        int i = 0, quorum = 1, len; 
        FILE *fd; 
        char *formated_command = NULL, *encrypted_file = NULL, *buffer = NULL; 
        EVP_PKEY *public_key = NULL;
	struct tempory_files *head = NULL, *curr = NULL; 
         
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
        if ((formated_command = format_command_line((const char **)cmd)) == NULL) { 
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
            
		buffer = create_AES_encrypted_file(ctrl, formated_command, salt, dst_cmd);

		if (buffer == NULL) {
			log_message(LOG_ERR, "(ERROR) can not encrypt data for user %s", user->grp->users[i]->name);
			continue;
		}

		curr = malloc(sizeof(*curr));
		if (curr == NULL)
			goto end;
		len = strlen(EN_CMD_DIR) + EN_CMD_FILENAME_LEN;
		curr->name = calloc(len + 1, sizeof(char));
		if (curr->name == NULL)
			goto end;
		strncpy(curr->name, buffer, len);
		curr->name[len] = '\0'; 
		curr->next = head;
		head = curr; 


		encrypted_file = create_RSA_encrypted_file(ctrl, public_key, buffer);
     
                if (encrypted_file == NULL) { 
                        log_message(LOG_ERR, "(ERROR) can't create an encrypted file for user %s: %m", user->grp->users[i]->name); 
                        continue; 
                } 
 
		curr = malloc(sizeof(*curr));
		if (curr == NULL)
			goto end;
		curr->name = calloc(strlen(encrypted_file) + 1, sizeof(char));
		if (curr->name == NULL)
			goto end;
		strncpy(curr->name, encrypted_file, strlen(encrypted_file));
		curr->next = head;
		head = curr;

                fprintf(fd, "%s:%s:\n", user->grp->users[i]->name, encrypted_file); 
 
                quorum++;

		F(buffer);
		F(encrypted_file); 
                EVP_PKEY_free(public_key); 
                public_key = NULL; 
        }        
         
        if (quorum < user->grp->quorum) { 
                fprintf(stderr, "impossible to establish the quorum\r\nview the log file for more details\r\n"); 
                log_message(LOG_ERR, "(ERROR) impossible to establish the quorum");
		*tmp_files = head; 
                goto end; 
        } 
 
	*tmp_files = head;
        fclose(fd); 
        F(formated_command); 
        F(salt); 
        return file_name; 

end:
	fclose(fd);
	if(unlink(file_name) == -1)
		log_message(LOG_ERR, "(ERROR) impossible to remove '%s' : %m", file_name);
	F(file_name);
	F(formated_command);
	F(salt);
	F(buffer);
	F(encrypted_file);
	EVP_PKEY_free(public_key); 
	public_key = NULL;
	return NULL;
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
	const void *password;
	user->tty = "(tty not set)";

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
        if ((retval = pam_get_item(pamh, PAM_AUTHTOK, &password)) != PAM_SUCCESS) { 
                log_message(LOG_ERR, "(ERROR) can not get password item: %m"); 
                return retval; 
        }  
	
	if (password == NULL) {
		log_message(LOG_ERR, "(ERROR) password was not set for user %s", user->name);
		return PAM_AUTH_ERR;

	} 

	user->pass = calloc(strlen(password)+1, sizeof(char));
	if (user->pass == NULL)
		return PAM_SYSTEM_ERR;

	strncpy(user->pass, password, strlen(password));
      
        if ((retval = pam_get_item(pamh, PAM_TTY, (const void **)&user->tty)) != PAM_SUCCESS) { 
                log_message(LOG_ERR, "(ERROR) can not determine the tty for %s: %m", user->name); 
                return retval; 
        } 
         
        if (user->tty == NULL) 
                log_message(LOG_ALERT, "(WW) tty was not found for user %s", user->name); 
         
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
        int retval = PAM_SUCCESS, status; 
        int i;   
 
        /* get user group */ 
        status = get_group(user);       
 
        switch (status) { 
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
			fprintf(stderr, "you are in any group\r\n"); 
                        retval = PAM_AUTH_ERR;
			break; 
                case NO_CONF: /* return success for not blocking the system */ 
                        log_message(LOG_INFO, "(WW) no configuration for %s", GRP_FILE); 
                        fprintf(stderr, "WARNING: no configuration for %s !\r\n", GRP_FILE);
			retval = NO_CONF; 
			break; 
                case BAD_CONF: /* return success for not blocking the system */
                        log_message(LOG_INFO, "(WW) bad configuration for %s", GRP_FILE); 
                        fprintf(stderr, "WARNING: bad configuration for %s !\r\n", GRP_FILE);
			retval = BAD_CONF;
			break; 
                default: 
                        retval = status;
			break; 
        }                
         
        return retval; 
} 


static int /* lock file before ? */ 
get_signed_file(struct pam_user **user, char **file, const char *command_file)
{
	static int flag = 1;
	static int *line_flag = NULL, len = 0;
	FILE *fd;
	char c, *token;
	char line[LINE_LEN];
	int i = 0, counter = 0;
	struct pam_user *parsed_user = malloc(sizeof(struct pam_user));

	if (parsed_user == NULL)
		return ERR;

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
			parsed_user->name = calloc(strlen(token) + 1, sizeof(char)); 
			
			if (parsed_user->name == NULL)
				return ERR;

			strncpy(parsed_user->name, token, strlen(token));

			if (parsed_user->name == NULL) {
				log_message(LOG_ALERT, "(WW) can't check command file correctly");
				line_flag[i] = 1;
				i++;
				continue;
			}

			*user = parsed_user;

			token = strtok(NULL, ":");
			token = strtok(NULL, ":"); /* second twice */

			if (token != NULL) {
				if (token[0] != '\n' && token[0] != '\0') {
					*file = calloc(strlen(EN_CMD_DIR)+strlen(token)+1, sizeof(char)); 
					
					if (*file == NULL)
						return ERR;
					strncpy(*file, token, strlen(token));
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

	if (counter == len) {
		F(line_flag);
		flag = 0;
		return ALL_FILE_PARSE;
	}
	
	return SUCCESS;
}


int wait_reply(int ctrl, const struct pam_user *user, const char *command_file, char *dst_cmd)
{
	int fd, wd;
	fd_set rfds;
        struct timeval tv;
        int retval, len;
	char buffer[4096]
             __attribute__ ((aligned(__alignof__(struct inotify_event))));
        struct inotify_event *event;

	struct pam_user *user_n = NULL; 
	char *encrypted_file = NULL; 
	EVP_PKEY *public_key;
	int status, flag = 0, quorum = 1;

	
	if ((fd = inotify_init()) < 0) {
		log_message(LOG_ERR, "(ERROR) impossible to initilise inotify (%d) : %m", fd);
		return fd;		
	}	

	if ((wd = inotify_add_watch(fd, CMD_DIR, IN_CLOSE_WRITE)) == -1) {
		log_message(LOG_ERR, "(ERROR) impossible to watch '%s' (%d) : %m", CMD_DIR, wd);
		return wd;
	}

	tv.tv_sec = REQUEST_TIME_OUT;
	tv.tv_usec = 0;
	
	while (!flag) {
		memset(buffer, '\0', sizeof(buffer));
		FD_ZERO(&rfds);
        	FD_SET(fd, &rfds);
   		
		if ((retval = select(fd+1, &rfds, NULL, NULL, &tv)) < 0) {
			log_message(LOG_ERR, "(ERROR) function select() failed (%d) : %m", retval);
			return retval;
		}

		if (retval) {
			len = read(fd, buffer, sizeof(buffer));
			
			if (len == -1 && errno != EAGAIN) {
				log_message(LOG_ERR, "(ERROR) can not read inotify event (%d) : %m", len);
				return len;
			}

			event = (struct inotify_event *) buffer;

			if ((event->mask & IN_CLOSE_WRITE) && 
			    (event->len) &&
			    ((strstr(command_file, event->name)) != NULL)) {

				F(encrypted_file);
				if (user_n)				
					F(user_n->name);
				F(user_n);

				status = get_signed_file(&user_n, &encrypted_file, command_file);

				switch (status) {
					case SUCCESS: break;
					case ALL_FILE_PARSE:
							    log_message(LOG_INFO, "(INFO) all the file is parsed"); 
							    flag = 1; break; 
					default: log_message(LOG_ERR, "(ERROR) impossible to get signed file");
						 return status; 
				}			

				if (user_n == NULL || encrypted_file == NULL)
					continue; 
							
				if (ctrl & PAM_DEBUG_ARG)
					log_message(LOG_DEBUG, "(DEBUG) getting validation from %s", user_n->name);

				if ((public_key = get_public_key(user_n)) == NULL) {
					log_message(LOG_ALERT, "(WW) impossible to get the public key for %s", user_n->name);
					continue; /* if user haven't keys */
				}

				if (verify(public_key, encrypted_file, dst_cmd)) {
					log_message(LOG_ERR, "(ERROR) impossible to verify the signature for %s", user_n->name);
					continue; 
				}

				quorum++;
			
				log_message(LOG_NOTICE, "user %s validated the command", user_n->name);	
				fprintf(stdout, "user %s validated the command\r\n", user_n->name);				
			}

		} else { 
			return TIME_OUT;
		}


		if (encrypted_file) {
			if(unlink(encrypted_file) == -1)
				log_message(LOG_ERR, "(ERROR) impossible to remove '%s' : %m", encrypted_file);
			F(encrypted_file);
		}

		if (user_n)				
			F(user_n->name);
		F(user_n);

		if (quorum == user->grp->quorum) {
			F(dst_cmd);
			return SUCCESS;
		}

	} /* while */

	if (encrypted_file) {
		if(unlink(encrypted_file) == -1)
			log_message(LOG_ERR, "(ERROR) impossible to remove '%s' : %m", encrypted_file);
		F(encrypted_file);
	}

	if (user_n)				
		F(user_n->name);
	F(user_n);

	if (quorum == user->grp->quorum) {
		F(dst_cmd);
		return SUCCESS;
	}
			
	return FAILED;
}



