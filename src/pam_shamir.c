/* ! @Todo

V3
- conf file, edit = ok, but others admins can't check the modifcations in file after validate :
in session open, cp fic and open it
in session close,create patch and  get the validatation to others admins, and appli patch if ok

V2
-Actual group :
groupName:Quorum:user1,user2,user3,user4
new ? 
groupName:Quorum||OtherGroupName:user1,user2

V1
   - remove tmp files
   - comments 
   - rewrite cleanup
   - rewrite parse group
   - macro free : #var a,b,c, ...
   - macro display message
OK - quorum + 1
   - lock command file when read
   - debug message
   - memcheck
   - bigger encrypt size (for add directory and other) (AES + RSA)
   - Make install
   - new alea fct (more secure) with ssl
   - get ctrl+c + othersig (sigterm stps etc... for no execute the command) 
   - get OLDAUTHTOK (for compatibility)
   - static lib
   - not set fct in header if it used only in c file
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
#include <crypt.h>
#include <shadow.h>
#include <signal.h>
#include <sudo_plugin.h>
#include <openssl/ssl.h> 
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <linux/limits.h>

#define __dso_public __attribute__((__visibility__("default")))

#include "config.h"
#include "utils.h"
#include "app.h"


/* authentication management  */
PAM_EXTERN 
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        int retval, ctrl=0;
	struct pam_user *user = NULL;

	/* not free in this function */
	user = (struct pam_user *) malloc(sizeof(struct pam_user));

	if (user == NULL)
		return PAM_SYSTEM_ERR;

	/*	
	 * get if debug mod is true during compilation or 
	 * if it was indicated in config file of PAM
	 */
	#ifdef DEBUG
		ctrl |= PAM_DEBUG_ARG;
		log_message(LOG_DEBUG, "(DEBUG) the module called via %s fuction", __func__);
	#else

	if ((ctrl = _pam_parse(argc, argv)) & PAM_DEBUG_ARG) /* if is set in config file */
		log_message(LOG_DEBUG, "(DEBUG) the module called via %s function", __func__);
	
	#endif

	retval = user_authenticate(pamh, ctrl, user); /* system authentication */

	if (retval) {
		log_message(LOG_NOTICE, "(INFO) authentication failure");
		
		if (ctrl & PAM_DEBUG_ARG)
			log_message(LOG_DEBUG, "(DEBUG) end of module");

		return retval;
	}

       /*
	* Call the shamir authentication. 
	* He will get the group for user and set
	* his entry if necessary
	*/
	if ((retval = shamir_authenticate(ctrl, user)) != PAM_SUCCESS) {
		log_message(LOG_NOTICE, "(INFO) can not identify the user %s for shamir: %m", user->name);
		return retval;
	}

       /*
	* Now we have to set current user data for the session management.
	* pam_set_data provide data for him and other modules too, but never 
	* for an application
	*/
	if ((retval = pam_set_data(pamh, DATANAME, user, clean)) != PAM_SUCCESS) {
		log_message(LOG_ALERT, "(ERROR) set data for user %s error: %m", user->name);
		return retval;
	}
	
	/* log_message(LOG_DEBUG, "__ADDR_OF_DATA __AUTH user[0x%X] user->name[%s][0x%X]", user, user->name, &user->name); */

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
		free(user);
		return PAM_SUCCESS;
	}

	/* pam_get_item can get some informations like 
	 * current password (PAM_AUTHOK).
	 * Here we get the changed password and no the old because 
	 * the module was call after other module in PAM stack
	 */
	if ((retval = pam_get_item(pamh, PAM_AUTHTOK, &passwd)) != PAM_SUCCESS) {
		log_message(LOG_NOTICE, "(ERROR) can not determine the password: %m");
		return retval;
	}	

	if (passwd != NULL) {
		log_message(LOG_NOTICE, "(INFO) changing key for user %s...", user->name);
		user->pass = (char *)passwd;
		SSL_library_init(); /* always returns 1 */
		if ((retval = verify_user_entry(user, 1))) {
			log_message(LOG_CRIT, "(ERROR) update key pairs error");
			return retval;
		}
	}

	free(user);
	return PAM_SUCCESS;
}


/* session management */
PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int i=0, retval;
	const struct pam_user *user;
	char *file_name, *ln;	

	if (command == NULL || command_cp == NULL) {		
		log_message(LOG_ERR, "(ERROR), can not get the command");
		return _pam_terminate(pamh, EXIT);
	} 
	
	do {
		log_message(LOG_DEBUG, "(DEBUG) command[%d] : %s", i, command[i]);
		i++;
	} while (command[i] != NULL);	


	/* getting informations save in authentication
	 * that is the user structure
	 */
	if ((user = get_data(pamh)) == NULL) {
		log_message(LOG_CRIT, "(ERROR) impossible to recover the data");
		return _pam_terminate(pamh, EXIT);
	}

	log_message(LOG_NOTICE, "session opened by %s in %s (member of %s)", user->name, user->tty, user->grp->name);

	/* if the command is the application for validate
	 * a command, it's not necessary to create here
	 * file too
	 */
	if (strncmp(command[0], "command=/usr/bin/validate", 25) == 0)
		return PAM_SUCCESS;
	
	log_message(LOG_NOTICE, "(INFO) starting request...");
	SSL_library_init(); /* always returns 1 */
	

	/* create the command file for other users of 
	 * the group
	 */
	if ((file_name = create_command_file(user)) == NULL) {
		log_message(LOG_ERR, "(ERROR) can not create command file: %m");
		return _pam_terminate(pamh, EXIT);
	}

	log_message(LOG_NOTICE, "(INFO) waiting for authorization...");

	/* now we wait for authorization from
	 * other users of the group (blocking 
	 * function)
	 */	
	retval = wait_reply(user, file_name);

	switch (retval) { 
		case SUCCESS: break; /* the command was validated */
		case TIME_OUT: 
			log_message(LOG_NOTICE, "request timeout");
			fprintf(stderr, "timeout\n");
			break;
		case CANCELED: break; /* impossible to do that here */
		case FAILED: 
			log_message(LOG_NOTICE, "command refused");
			fprintf(stderr, "command refused\n"); 
			break;
		default: 
			log_message(LOG_ERR, "(ERROR) an internal error occurred: (%d) %m", retval); 
			fprintf(stderr, "an internal error occured"); break;
	}	
	
	
	// unlink tmp file befor !
	//unlink(file_name); 	

	if (retval != 0) /* if the command was not validated */
		return _pam_terminate(pamh, EXIT);
	

	/* check if link was not modified during
	 * waiting validation
	 */
	i=0;
	do {
		if ((ln = is_a_symlink(command_cp[i])) != NULL) { 
			if (strncmp(ln, command[i], strlen(ln))) { 
				fprintf(stderr, "error: a link was modified\n%s -> %s\n", command_cp[i], ln);
				log_message(LOG_ERR, "(ERROR) a link was modified !");
				log_message(LOG_ERR, "%s -> %s", command_cp[i], ln);
				return _pam_terminate(pamh, EXIT);
			}
		}
		i++;
	} while (command_cp[i] != NULL);


/*	if (flag) */ /* check if edit file flag is up (if yes return error) (for V3) */	

	free(file_name);
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

	log_message(LOG_INFO, "session closed");
	
	free(command);
	free(command_cp);
	return PAM_SUCCESS;
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
	log_message(LOG_DEBUG, "(DEBUG) io_open");
	int i;

	/* free in session_close */
	command = malloc((argc+1)*sizeof(char *));
	command_cp = malloc((argc+1)*sizeof(char *));

	if (command_cp == NULL || command == NULL) {
		log_message(LOG_ERR, "(ERROR) malloc error: %m");
		return 0;
	}

	
	for(i=0; *command_info != NULL; i++, *command_info++){
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


/*	for (i=1; i<argc; i++)
		command[i] = argv[i];
*/	

	command[argc] = NULL;
	command_cp[argc] = NULL;
	
     	return 1;
 }
 
static void
io_close(int exit_status, int error)
{
	log_message(LOG_DEBUG, "(DEBUG) io_close");
	free(command);
}
 

__dso_public struct io_plugin shared_io = {
	SUDO_IO_PLUGIN,
    	SUDO_API_VERSION,
    	io_open,
    	io_close,
};

