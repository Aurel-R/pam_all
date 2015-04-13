
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
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <crypt.h>
#include <shadow.h> 

#define NAME	"pam_shamir.so"

#define PAM_DEBUG_ARG	    0x0001
#define PAM_USE_FPASS_ARG   0x0040  /* for later */

const char passwd_prompt[] = "Unix password: ";


struct pam_user {
	char *name;
	char *pass;
	char *tty;
	/* cmd */
};


/*
 * Parse all arguments. If debug option is found 
 * in configuration file, set the verbose mode 
 */

static int
_pam_parse(int argc, const char **argv)
{
	int i, ctrl = 0;

	for (i=0; i<argc; i++) {
		if (!strcmp(argv[i], "debug"))
			ctrl |= PAM_DEBUG_ARG;
	}

	return ctrl;	
}


static void 
log_message(int level, char *msg, ...)
{
	va_list args;
	
	va_start(args, msg);
	openlog(NAME, LOG_PID, LOG_AUTHPRIV);
	
	if (level)
		vsyslog(level, msg, args);
	
	closelog();
	va_end(args);
}


static int
user_authenticate(pam_handle_t *pamh, int ctrl, struct pam_user *user)
{
	int retval;
	user->pass = NULL;
	char *crypt_password = NULL;
	struct spwd *pwd = malloc(sizeof(struct spwd));
	char err_message[50];

	memset(err_message, '\0', sizeof(err_message));

	if (pwd == NULL) {
		log_message(LOG_CRIT, "malloc() %m");
		return PAM_SYSTEM_ERR;
	}

	/* get current user */

	if ((retval = pam_get_user(pamh, (const char **)&user->name, NULL)) != PAM_SUCCESS) {
		log_message(LOG_ERR, "can not determine user name: %m");
		return retval;
	}

	if (ctrl & PAM_DEBUG_ARG)
		log_message(LOG_DEBUG, "debug: user %s", user->name);

	/*
	 * we will have to get the password from the
	 * user directly
	 */

	if ((retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &user->pass, "%s", passwd_prompt)) != PAM_SUCCESS) {
		log_message(LOG_ERR, "can not determine the password: %m");
		return retval;
	} 


	if (user->pass == NULL) {
		log_message(LOG_NOTICE, "the password is empty");
		return PAM_AUTH_ERR;
	}

	
	/* get user password save in /etc/shadow */

	if ((pwd = getspnam(user->name)) == NULL) {
		log_message(LOG_ERR, "can not verify the password for user %s: %m", user->name);
		return PAM_USER_UNKNOWN;
	} 


	if ((crypt_password = crypt(user->pass, pwd->sp_pwdp)) == NULL) {
		log_message(LOG_ERR, "can not crypt password for user %s: %m", user->name);
		return PAM_AUTH_ERR;
	}

	/* compare passwords */

	if (strcmp(crypt_password, pwd->sp_pwdp)) {
		log_message(LOG_NOTICE, "incorrect password attempts");
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
		log_message(LOG_ERR, "can not set password item: %m");
		return retval;
	} 


	/* associate a tty */
	
	if ((retval = pam_get_item(pamh, PAM_TTY, (const void **)&(user->tty))) != PAM_SUCCESS) {
		log_message(LOG_ERR, "can not determine the tty for %s: %m", user->name);
		return retval;
	}
	
	if (user->tty == NULL) {
		log_message(LOG_ERR, "tty was not found for user %s", user->name);
		return PAM_AUTH_ERR;
	}
	
	if (ctrl & PAM_DEBUG_ARG)
		log_message(LOG_DEBUG, "debug: tty %s", user->tty);

	/*
	 * Do not free the struct. Maybe use a specific function like clean()... 
	 * I have to look in man 
	 */
	
/*	free(pwd); */
	return PAM_SUCCESS;
}



/* authentication management  */
PAM_EXTERN 
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        int retval, ctrl=0;
	struct pam_user user;

	memset(&user, '\0', sizeof(user));
	
	#ifdef DEBUG
		ctrl |= PAM_DEBUG_ARG;
	#else

	if ((ctrl = _pam_parse(argc, argv)) & PAM_DEBUG_ARG)
		log_message(LOG_DEBUG, "debug: the module called via %s function", __func__);
	
	#endif

	retval = user_authenticate(pamh, ctrl, &user);

	if (retval)
		log_message(LOG_NOTICE, "authentication failure");
		
	if (ctrl & PAM_DEBUG_ARG)
		log_message(LOG_DEBUG, "debug: end of module");

	return retval;
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

/* session management */
PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv){
	return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv){
        return PAM_IGNORE;
}


