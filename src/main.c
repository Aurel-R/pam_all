
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

#define UNUSED __attribute__((unused))

#define NAME	"pam_shamir.so"
#define PAM_DEBUG_ARG	    0x0001
#define PAM_USE_FPASS_ARG   0x0040  

#define DATANAME "current_user"

const char passwd_prompt[] = "Unix password: ";

struct pam_user {
	char *name; 
	char *pass;
	char *tty;
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


static void
cleanup(void **data)
{
	char *xx;
	
	if ((xx = (char *)data)) {
		while(*xx)	
			*xx++ = '\0';
		free(*data);
	}
}

static void 
clean(pam_handle_t *pamh UNUSED, void *data, int error_status UNUSED)
{
	free(data);
}

static const 
struct pam_user *get_data(const pam_handle_t *pamh)
{
	const void *data;

	return (pam_get_data(pamh, DATANAME, &data) == PAM_SUCCESS) ? data : NULL;
}

static int
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
		log_message(LOG_CRIT, "malloc() %m");
		return PAM_SYSTEM_ERR;
	}

	/* get current user */
	if ((retval = pam_get_user(pamh, (const char **)&usr, NULL)) != PAM_SUCCESS) {
		log_message(LOG_ERR, "can not determine user name: %m");
		return retval;
	}

	buf_len = (strlen(usr)) + 1;
	user->name = calloc(buf_len, sizeof(char)); /* not free in this fct */

	if(user->name == NULL)
		return PAM_SYSTEM_ERR;

	strncpy(user->name, usr, buf_len - 1);

	if (ctrl & PAM_DEBUG_ARG)
		log_message(LOG_DEBUG, "DEBUG: user %s", user->name);

	/*
	 * we have to get the password from the
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
		log_message(LOG_DEBUG, "DEBUG: tty %s", user->tty);

	cleanup((void *)&pwd);
	return PAM_SUCCESS;
}



/* authentication management  */
PAM_EXTERN 
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        int retval, ctrl=0;
	struct pam_user *user = NULL;

	user = (struct pam_user *) malloc(sizeof(struct pam_user));
	
	if(user == NULL)
		return PAM_SYSTEM_ERR;
	
	#ifdef DEBUG
		ctrl |= PAM_DEBUG_ARG;
		log_message(LOG_DEBUG, "DEBUG: the module called via %s fuction", __func__);
	#else

	if ((ctrl = _pam_parse(argc, argv)) & PAM_DEBUG_ARG)
		log_message(LOG_DEBUG, "DEBUG: the module called via %s function", __func__);
	
	#endif

	retval = user_authenticate(pamh, ctrl, user);

	if (retval) {
		log_message(LOG_NOTICE, "authentication failure");
		
		if (ctrl & PAM_DEBUG_ARG)
			log_message(LOG_DEBUG, "DEBUG: end of module");

		return retval;
	}

       /*
	* Now we have to set current user data for the session management.
	* pam_set_data provide data for him and other modules too, but never 
	* for an application
	*/
	if ((retval = pam_set_data(pamh, DATANAME, user, NULL)) != PAM_SUCCESS) {
		log_message(LOG_ALERT, "set data for user %s error: %m", user->name);
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

/* session management */
PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const struct pam_user *user;

	if ((user = get_data(pamh)) == NULL) {
		log_message(LOG_CRIT, "impossible to recover the data");
		return PAM_SYSTEM_ERR;
	}

	/* log_message(LOG_DEBUG, "__ADDR_OF_DATA __SESS user[0x%X] user->name[%s][0x%X]", user, user->name, &user->name); */

	log_message(LOG_NOTICE, "session opened by %s in %s", user->name, user->tty);

	return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{	
	int retval;
	if ((retval = pam_set_data(pamh, DATANAME, NULL, NULL)) != PAM_SUCCESS)
		return PAM_SYSTEM_ERR;

	log_message(LOG_DEBUG, "DEBUG: session closed");
	
	return PAM_SUCCESS;
}


