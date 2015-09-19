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

#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

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
#include <signal.h>
#include <sudo_plugin.h>
#include <openssl/ssl.h> 
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <linux/limits.h>

#define __dso_public __attribute__((__visibility__("default")))

#include "pam.h"
#include "utils.h"
#include "crypto.h"

static char **command; /* to get the command via sudo */
static char **command_cp; /* original command before formated */

/* local function */
static int _pam_parse(int argc, const char **argv);
static int _pam_terminate(pam_handle_t *pamh, int status);


/*
 * Parse all arguments. If debug option is found 
 * in configuration file, set the verbose mode 
 */
static int
_pam_parse(int argc, const char **argv)
{
        int i, ctrl = 0; 

	#ifdef DEBUG
		ctrl |= PAM_DEBUG_ARG;
	#else	
	
       		for (i=0; i<argc; i++) {
               		if (!strncmp(argv[i], "debug", 5))
                       		ctrl |= PAM_DEBUG_ARG;
		else {
			log_message(LOG_ERR, "(ERROR) unknow option: %s", argv[i]);
		}
       	}
	
	#endif

        return ctrl;
}



/* authentication management  */
PAM_EXTERN 
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        int retval, ctrl=0;
	struct pam_user *user;
	const void *service_name = NULL;

	if ((ctrl = _pam_parse(argc, argv)) & PAM_DEBUG_ARG) 
		log_message(LOG_DEBUG, "(DEBUG) debug mod is set for %s", __func__);


	if ((retval = pam_get_item(pamh, PAM_SERVICE, &service_name)) != PAM_SUCCESS || !service_name) {
                log_message(LOG_ERR, "(ERROR) can not determine the service");
                return PAM_AUTH_ERR;
        }    

	if (ctrl & PAM_DEBUG_ARG) 
		log_message(LOG_DEBUG, "(DEBUG) %s [auth] was called from '%s' service", NAME, service_name);
	

	user = malloc(sizeof(*user)); /* free in clean() */
	
	if (user == NULL)
		return PAM_SYSTEM_ERR;

	/* 
	 * Fill the user structure 
	 */
	retval = user_authenticate(pamh, ctrl, user);

	if (retval) {
		log_message(LOG_INFO, "(INFO) authentication failure");
		return retval;
	}

       /*
	* Set user group
	*/
	if ((retval = group_authenticate(ctrl, user)) != PAM_SUCCESS &&
	     retval != NO_CONF && retval != BAD_CONF) {
		log_message(LOG_INFO, "(INFO) can not identify the user %s", user->name);
		return retval;
	}

	if (retval == NO_CONF || retval == BAD_CONF) {
		if ((retval = pam_set_data(pamh, STATUS, "WW", NULL)) != PAM_SUCCESS) {
			log_message(LOG_ERR, "(ERROR) set status for user %s error: %m", user->name);
			return retval;
		} 
		
		return PAM_SUCCESS;
	} else {
		if ((retval = pam_set_data(pamh, STATUS, "OK", NULL)) != PAM_SUCCESS) {
			log_message(LOG_ERR, "(ERROR) set status for user %s error: %m", user->name);
			return retval;
		}	
	}

	SSL_library_init(); /* always returns 1 */

	/* 
	 * check his key pair (create if necessary) 
	 */
	if ((retval = verify_user_entry(user, 0))) {
		log_message(LOG_ERR, "(ERROR) can not check key pair for user %s", user->name);	
		return retval;
	}


       /*
	* Now we have to set current user data for the session management.
	* pam_set_data provide data for him and other modules too
	*/
	if ((retval = pam_set_data(pamh, DATANAME, user, clean)) != PAM_SUCCESS) {
		log_message(LOG_ERR, "(ERROR) set data for user %s error: %m", user->name);
		return retval;
	}

	return PAM_SUCCESS;
}



PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv){
        return PAM_IGNORE;
}

/* account management */
PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv){
	return PAM_IGNORE;
}

/* password management:
 * 
 * It call when user change his password
 * (command 'passwd')
 */
PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval;
	struct pam_user *user = malloc(sizeof(struct pam_user));
	const void *passwd; 

	if (user == NULL)
		return PAM_SYSTEM_ERR;

	if ((retval = pam_get_user(pamh, (const char **)&user->name, NULL)) != PAM_SUCCESS) {
		log_message(LOG_ERR, "(ERROR) can not determine user name: %m");
		return retval;
	}
		

	/* if user haven't group, it's not necessary to create 
	 * his keys pairs 
	 */
	if ((retval = get_group(user)) != SUCCESS) {
		F(user);
		return PAM_SUCCESS;
	}

	/* pam_get_item can get some informations like 
	 * current password (PAM_AUTHOK).
	 * Here we get the changed password and no the old because 
	 * the module was call after other module in PAM stack
	 */
	if ((retval = pam_get_item(pamh, PAM_AUTHTOK, &passwd)) != PAM_SUCCESS) {
		log_message(LOG_ERR, "(ERROR) impossible to get the password for user %s: %m", user->name);
		F(user);
		return retval;
	}	

	if (passwd != NULL) {
		log_message(LOG_INFO, "(INFO) changing key for user %s...", user->name);
		user->pass = (char *)passwd;
		SSL_library_init(); /* always returns 1 */
		if ((retval = verify_user_entry(user, 1))) {
			log_message(LOG_ERR, "(ERROR) update key pairs error");
			F(user);
			return retval;
		}
	} else {
		log_message(LOG_ERR, "(ERROR) can not determine the password for user %s", user->name);
		F(user);
		return PAM_AUTHTOK_ERR;
	}

	F(user);
	return PAM_SUCCESS;
}


/* session management */
PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int i=0, retval, ctrl=0;
	const struct pam_user *user;
	char *file_name, *ln;
	const void  *service_name = NULL;
	struct tempory_files *tmp_files = NULL;
	char *dst_command = NULL;
	const void *status;
	
	if ((ctrl = _pam_parse(argc, argv)) & PAM_DEBUG_ARG) 
		log_message(LOG_DEBUG, "(DEBUG) debug mod is set for %s", __func__);

	
	if (pam_get_data(pamh, STATUS, &status) != PAM_SUCCESS) {
		log_message(LOG_ERR, "(ERROR) impossible to recover authentification status");
		return _pam_terminate(pamh, EXIT);
	}

	if (!strncmp((const char *)status, "WW", 2))
		return PAM_SUCCESS;
	else if (!strncmp((const char *)status, "OK", 2)) {
		/* normal result */
	} 
	else return _pam_terminate(pamh, EXIT); /* normaly impossible */	


	/*
	 * getting informations save in authentication
	 */
	if ((user = get_data(pamh)) == NULL) {
		log_message(LOG_ERR, "(ERROR) impossible to recover authentification data");
		return _pam_terminate(pamh, EXIT);
	}

	if ((retval = pam_get_item(pamh, PAM_SERVICE, &service_name)) != PAM_SUCCESS || !service_name) {
                log_message(LOG_ERR, "(ERROR) can not determine the service");
                return _pam_terminate(pamh, EXIT);
        }    

	if (ctrl & PAM_DEBUG_ARG)
		log_message(LOG_DEBUG, "(DEBUG) %s [session] was called from '%s' service", NAME, service_name);

	/*
	 * getting if the service is the 'all-validate' command
	 */
        if (!strncmp(service_name, ASSOCIATED_SERVICE, strlen(ASSOCIATED_SERVICE))) {
		if (ctrl & PAM_DEBUG_ARG)
			log_message(LOG_DEBUG, "(DEBUG) sending data...");

		/* send some data to service */
		retval = send_data(ctrl, pamh, (void *)user);

		if (retval != SUCCESS) {
			log_message(LOG_ERR, "(ERROR) impossible to transmit data");
			return _pam_terminate(pamh, EXIT);
		}

		if (ctrl & PAM_DEBUG_ARG)
			log_message(LOG_DEBUG, "(DEBUG) data has been transmitted");
	
		return PAM_SUCCESS;
        }
		
	if (command == NULL || command_cp == NULL) {		
		log_message(LOG_ERR, "(ERROR) can not get the command");
		return _pam_terminate(pamh, EXIT);
	} 
	
	if (ctrl & PAM_DEBUG_ARG) {	
		do {
			log_message(LOG_DEBUG, "(DEBUG) command[%d] : %s", i, command[i]);
			i++;
		} while (command[i] != NULL);	
	}


	log_message(LOG_NOTICE, "session opened by %s in %s (member of %s)", user->name, user->tty, user->grp->name);

	/* if the command is the application for validate
	 * a command, it's not necessary to create here
	 * file too
	 */
	if (strncmp(command[0], "command=/usr/bin/all-validate", 29) == 0)
		return PAM_SUCCESS;

	log_message(LOG_NOTICE, "starting request...");
	fprintf(stdout, "strating request\r\n");
	SSL_library_init(); /* always returns 1 */
	
	
	/* create the command file for other users of 
	 * the group
	 */
	if ((file_name = create_command_file(ctrl, user, command, &dst_command, &tmp_files)) == NULL) {
		log_message(LOG_ERR, "(ERROR) can not create command file: %m");
		return _pam_terminate(pamh, EXIT);
	}


	fprintf(stdout, "waiting for authorization...\r\n");
	log_message(LOG_INFO, "(INFO) waiting for authorization...");

	/* now we wait for authorization from
	 * other users of the group (blocking 
	 * function)
	 */	
	retval = wait_reply(ctrl, user, file_name, dst_command);

	switch (retval) { 
		case SUCCESS: break; /* the command was validated */
		case TIME_OUT: 
			log_message(LOG_NOTICE, "request timeout");
			fprintf(stderr, "timeout\r\n");
			break;
		case CANCELED: break; /* impossible to do that here */
		case FAILED: 
			log_message(LOG_NOTICE, "command refused");
			fprintf(stderr, "command refused\r\n"); 
			break;
		default: 
			log_message(LOG_ERR, "(ERROR) an internal error occurred: %d", retval); 
			fprintf(stderr, "an internal error occured\r\n"); break;
	}	
	
	
	unlink_tmp_files(tmp_files);
	if (unlink(file_name) == -1)
		log_message(LOG_ERR, "(ERROR) impossible to remove '%s' file : %m", file_name); 	
	F(file_name);

	if (retval != PAM_SUCCESS) /* if the command was not validated */
		return _pam_terminate(pamh, EXIT);
	

	/* check if link was not modified during
	 * waiting validation
	 */
	i=0;
	do {
		if ((ln = is_a_symlink(command_cp[i])) != NULL) { 
			if (strncmp(ln, command[i], strlen(ln))) { 
				fprintf(stderr, "error: a link was modified\r\n%s -> %s\r\n", command_cp[i], ln);
				log_message(LOG_ERR, "(ERROR) a link was modified !");
				log_message(LOG_ERR, "%s -> %s", command_cp[i], ln);
				return _pam_terminate(pamh, EXIT);
			}
		}
		i++;
	} while (command_cp[i] != NULL);


/*	if (flag) */ /* check if edit file flag is up (if yes return error) (for V3) */	

	return PAM_SUCCESS;
}

/* calling when the session was closed.
 * We can free the user structure with a 
 * second call of pam_set_data
 */
PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{	
	int retval;

	if ((retval = pam_set_data(pamh, DATANAME, NULL, NULL)) != PAM_SUCCESS)
		return PAM_SYSTEM_ERR;

	log_message(LOG_NOTICE, "session closed");

	return PAM_SUCCESS;
}



/*
 * sudoers does not detect if session module failed.
 * (cause AUTH_FAILURE and AUTH_FATAL don't have the same value in source code)
 * I have reported the problem and a patch is apply for the
 * 1.8.15 version of sudo.
 */ 
static int 
_pam_terminate(pam_handle_t *pamh, int status) 
{
	int ret;

	pam_set_data(pamh, DATANAME, NULL, NULL);
	log_message(LOG_NOTICE, "session closed");
	F(command);
	F(command_cp);
	#ifdef SUDO_CSPAM
	return PAM_SESSION_ERR;
	#else
	ret = raise(status);
	return ret;
	#endif
}

/*
 * this function is called by sudo directly.
 * It is used to obtain the command line
 */
static int
io_open(unsigned int version, sudo_conv_t conversation,
	sudo_printf_t sudo_printf, char *const settings[],
	char *const user_info[], char *const command_info[],
	int argc, char *const argv[], char *const user_env[],
	 char *const args[])
{
	log_message(LOG_NOTICE, "io_open");
	int i;

	/* free in io_close or _pam_terminate if necessary */
	command = malloc((argc+1)*sizeof(char *));
	command_cp = malloc((argc+1)*sizeof(char *));

	if (command_cp == NULL || command == NULL) {
		log_message(LOG_ERR, "(ERROR) malloc error: %m");
		return 0;
	}

	
	for(; *command_info != NULL; *command_info++){
		if (strncmp(*command_info, "command=", 7) == 0)
			command[0] = *command_info;
	}


	for (i=1; i<argc; i++) {
		if ((command[i] = is_a_symlink(argv[i])) != NULL) {
			command_cp[i] = argv[i];
			continue;
		}		
		command[i] = argv[i];
		command_cp[i] = argv[i];		
	}

	command[argc] = NULL;
	command_cp[argc] = NULL;
	
     	return 1;
 }
 
static void
io_close(int exit_status, int error)
{
	log_message(LOG_NOTICE, "io_close");
	F(command);
	F(command_cp);
}
 

__dso_public struct io_plugin shared_io = {
	SUDO_IO_PLUGIN,
    	SUDO_API_VERSION,
    	io_open,
    	io_close,
};

