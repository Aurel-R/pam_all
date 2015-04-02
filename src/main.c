
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <syslog.h>
#include <stdarg.h>

#define NAME	"pam_shamir.so"

void log_message(int level, char *msg, ...);

/* authentication management  */
PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv){
        log_message(LOG_NOTICE, "Test message from pam_shamir");
	return PAM_IGNORE;
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



void log_message(int level, char *msg, ...){
	va_list args;
	
	va_start(args, msg);
	openlog(NAME, LOG_PID, LOG_AUTHPRIV);
	vsyslog(level, msg, args);
	closelog();
	va_end(args);
}
