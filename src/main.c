
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

const char passwd_prompt[] = "Unix password: ";

void log_message(int level, char *msg, ...)
{
	va_list args;
	
	va_start(args, msg);
	openlog(NAME, LOG_PID, LOG_AUTHPRIV);
	
	if (level)
		vsyslog(level, msg, args);
	
	closelog();
	va_end(args);
}


//int get_password(pam_handle_t *pamh, )
//int get_user(



/* authentication management  */
PAM_EXTERN 
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        int retval, i;
	int debug_mod = 0;
	char *user = NULL;
	char *p = NULL;
	char *crypt_password = NULL;
	/* struct passwd *pwd = malloc(sizeof(struct passwd)); */
	struct spwd *pwd = malloc(sizeof(struct spwd));

	if (pwd == NULL) {
		log_message(LOG_CRIT, "malloc() %m");
		return PAM_SYSTEM_ERR;
	}

	#ifdef DEBUG
		debug_mod = LOG_DEBUG;
	#endif


	/*
	 * Parse all arguments. If debug option is found 
	 * in configuration file, set the verbose mode 
	 */
	for (i=0; i<argc; i++) {
		if (strcmp(argv[i], "debug") == 0)
			debug_mod = LOG_DEBUG;
	}

	log_message(debug_mod, "debug: the module was started");	

	/* get current user */

	if ((retval = pam_get_user(pamh, (const char **)&user, NULL)) != PAM_SUCCESS) {
		log_message(LOG_ERR, "can not determine user name: %m");
		return retval;
	}

	log_message(debug_mod, "debug: user %s", user);

	/*
	 * we will have to get the password from the
	 * user directly
	 */

	if((retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &p, "%s", passwd_prompt)) != PAM_SUCCESS) {
		log_message(LOG_ERR, "can not determine the password: %m");
		return retval;
	} 


	if (p == NULL) {
		log_message(LOG_NOTICE, "the password is empty");
		return PAM_AUTH_ERR;
	}

	
	/* get user password save in /etc/shadow */

	if ((pwd = getspnam(user)) == NULL) {
		log_message(LOG_ERR, "can not verify the password for user %s: %m", user);
		return PAM_USER_UNKNOWN;
	} 


	if ((crypt_password = crypt(p, pwd->sp_pwdp)) == NULL) {
		log_message(LOG_ERR, "can not crypt password for user %s: %m", user);
		return PAM_AUTH_ERR;
	}

	/* compare passwords */

	if ((strcmp(crypt_password, pwd->sp_pwdp) != 0)) {
		log_message(LOG_NOTICE, "incorrect password attempts");
		return PAM_AUTH_ERR;
	}

	log_message(LOG_NOTICE, "user %s has been authenticate", user);	
	log_message(debug_mod, "debug: set password item");

	if ((retval = pam_set_item(pamh, PAM_AUTHTOK, (const void *)p)) != PAM_SUCCESS) {
		log_message(LOG_ERR, "can not set password item: %m");
		return retval;
	} 

	/*
	 * get user fct ; passwd fct ; and juste verify the return and print 'authentication failure' in LOG_NOTICE
	 * display message for user "sorry 
	 */
	


	log_message(debug_mod, "end of module");

	/*
	 * Do not free the struct. Maybe use a specific function like clean()... 
	 * I have to look in man 
	 */
	
/*	free(pwd); */
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

/* session management */
PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv){
	return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv){
        return PAM_IGNORE;
}


