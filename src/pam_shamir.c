/* ! @Todo

- rewrite cleanup
- new clean fct (for alloc, file, etc...)
- ^ (maybe two in one ?) 
- fct for parse files (groups)
- comments 

- conf file, edit = ok, but others admins can't check the modifcations in file after validate :
in session open, cp fic and open it
in session close,create patch and  get the validatation to others admins, and appli patch if ok


-Actual group :
groupName:Quorum:user1,user2,user3,user4
new ? 
groupName:Quorum||OtherGroupName:user1,user2

Make install


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

	user = (struct pam_user *) malloc(sizeof(struct pam_user));

	if (user == NULL)
		return PAM_SYSTEM_ERR;
	
	#ifdef DEBUG
		ctrl |= PAM_DEBUG_ARG;
		log_message(LOG_DEBUG, "(DEBUG) the module called via %s fuction", __func__);
	#else

	if ((ctrl = _pam_parse(argc, argv)) & PAM_DEBUG_ARG)
		log_message(LOG_DEBUG, "(DEBUG) the module called via %s function", __func__);
	
	#endif

	retval = user_authenticate(pamh, ctrl, user);

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

/* password management */
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
		

	/* if user haven't group, it's not necessary to create his keys pairs */
	if ((retval = get_group(user)) != SUCCESS) {
		return PAM_SUCCESS;
	}

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
	return PAM_SUCCESS;
}


/* session management */
PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int i=0, retval;
	const struct pam_user *user;
	char *file_name;	
	
	do {
		log_message(LOG_DEBUG, "(DEBUG) command[%d] : %s", i, command[i]);
		i++;
	} while (command[i] != NULL);	

	if ((user = get_data(pamh)) == NULL) {
		log_message(LOG_CRIT, "(ERROR) impossible to recover the data");
		return PAM_SYSTEM_ERR;
	}

	log_message(LOG_NOTICE, "session opened by %s in %s (member of %s)", user->name, user->tty, user->grp->name);

	if (strcmp(command[0], "command=/usr/bin/validate") == 0)
		return PAM_SUCCESS;
	
	log_message(LOG_NOTICE, "(INFO) starting request...");
	SSL_library_init(); /* always returns 1 */
	
	if ((file_name = create_command_file(user)) == NULL) {
		log_message(LOG_ERR, "(ERROR) can not create command file: %m");
		return PAM_SESSION_ERR;
	}

	log_message(LOG_NOTICE, "(INFO) waiting for authorization...");
	
	retval = wait_reply(user, file_name);
	
	switch (retval) { 
		case SUCCESS: break;
		case TIME_OUT: log_message(LOG_NOTICE, "request timeout");/* display message */ break;
		case CANCELED: break;
		case FAILED: log_message(LOG_NOTICE, "command refused"); /* display message */ break;
		default: log_message(LOG_ERR, "(ERROR) unknow returned value: %d", retval); /* display message */ break;
	}	
	
	
	// unlink tmp file befor !
	//unlink(file_name); 	
	
	free(file_name);

	if (retval != 0)
		return PAM_SESSION_ERR;

	return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{	
	int retval;
	if ((retval = pam_set_data(pamh, DATANAME, NULL, NULL)) != PAM_SUCCESS)
		return PAM_SYSTEM_ERR;

	log_message(LOG_DEBUG, "(DEBUG) session closed");
	
	return PAM_SUCCESS;
}


static int
io_open(unsigned int version, sudo_conv_t conversation,
	sudo_printf_t sudo_printf, char *const settings[],
	char *const user_info[], char *const command_info[],
	int argc, char *const argv[], char *const user_env[],
	 char *const args[])
{
	log_message(LOG_DEBUG, "(DEBUG) io_open");
	int i;
		
	command = malloc((argc+1)*sizeof(char *));

	if (command == NULL) {
		log_message(LOG_ERR, "(ERROR) malloc error: %m");
		return 0;
	}
	
	for(i=0; *command_info != NULL; i++, *command_info++){
		if (strncmp(*command_info, "command=", 7) == 0)
			command[0] = *command_info;
	}

	for (i=1; i<argc; i++) {
		if ((command[i] = is_a_symlink(argv[i])) != NULL) {
			continue;
		}		
		command[i] = argv[i];		
	}

	command[argc] = NULL;
	
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

