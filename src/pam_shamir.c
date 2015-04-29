
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
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define UNUSED __attribute__((unused))

#define NAME	 "pam_shamir.so"

/*
 * Contains the groups of shamir.
 * Many groups as possible but one
 * user can't be in two different
 * groups.
 */
#define GRP_FILE "/etc/shared/groups"

/*
 * Contains the private and public 
 * users key. 
 */ 
#define USR_DIR  "/etc/shared/users/"

#define MAX_LINE_LEN 256 /* Maximum line lenght for groups file*/
#define MAX_USR_GRP  20  /* Maximum users per group */

#define PAM_DEBUG_ARG	    0x0001
#define PAM_USE_FPASS_ARG   0x0040  

/*
 * NO_CONF and BAD_CONF return success. 
 * it's necessary for the first configuration 
 * and for not block the system.
 */
#define SUCCESS 	0 /* user have a group */
#define NO_USR_GRP 	1 /* the user haven't group (authentication failed) */
#define NO_CONF		2 /* the group file is not configured (authentication success) */
#define BAD_CONF	3 /* bad configuration for group file (authentication success) */

#define ENTRY		0 /* user have key */
#define NO_ENTRY	1 /* no key configured */

#define ERR		1 /* error encountered */
	
/*
 * The unique name used to
 * exchange data into the module
 */
#define DATANAME "current_user"

#define BITS 		2048

/*
 * The default prompt used to get
 * password
 */
static const char passwd_prompt[] = "Unix password: ";

extern char **command; /* to get the command via sudo */

/*
 * The groups are identified
 * by their names. They point
 * to a list of users
 */
struct pam_group {
	char *name;
	int quorum;
	struct pam_user *users[MAX_USR_GRP];
};

/*
 * One user can have a single
 * group (for this moment)
 */
struct pam_user {
	char *name; 
	char *pass;
	char *tty;
	struct pam_group *grp;
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

/* specific to the passwd structure */
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

/* specific to the data exhange into module */
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

/*
 * Get the group of user passed
 * in argument
 */
static int
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

/*
 * create entry files for user
 * with his public and private
 * keys
 */
static int
create_user_entry(struct pam_user *user, const char *pub_file_name, const char *priv_file_name)
{
	FILE *fd;
	RSA *rsa = RSA_new();
	
	log_message(LOG_DEBUG, "DEBUG: generate RSA key... (%i bits)", BITS);

	RAND_load_file("/dev/urand", 128);
	
	if ((rsa = RSA_generate_key(BITS, 65537, NULL, NULL)) == NULL) {
		log_message(LOG_NOTICE, "error during  key creation");
		return ERR;
	}

	umask(0022); /* -rw-r--r--*/	
	if ((fd = fopen(pub_file_name, "w+")) == NULL)
		return ERR;

	if (!PEM_write_RSAPublicKey(fd, rsa)) {
		log_message(LOG_NOTICE, "error during save public key");
		RSA_free(rsa);
		fclose(fd);
		return ERR;
	}
	
	fclose(fd);

	umask(0066); /* -rw------- */
	if ((fd = fopen(priv_file_name, "w+")) == NULL)
		return ERR;

	if(!PEM_write_RSAPrivateKey(fd, rsa, EVP_des_ede3_cbc(), (unsigned char *)user->pass, strlen(user->pass), NULL, NULL)) {
		log_message(LOG_NOTICE, "error during save private key");
		RSA_free(rsa);
		fclose(fd);
		return ERR;
	}

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
static int
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

	// get rsa priv
	// get rsa pub
	// verify rsa key

	fclose(fd_pub);
	fclose(fd_priv);
	free(pub_file_name);
	free(priv_file_name);	
	return ENTRY;
}

/*
 * The standard user authenticatation
 * used to fill the user structure
 */
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

/* The Shamir authentication */
static int
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
			log_message(LOG_NOTICE, "no group for user %s", user->name);
			return PAM_AUTH_ERR;
		case NO_CONF:
			log_message(LOG_NOTICE, "no configuration for %s", GRP_FILE);
			/* display advertissement msg */
			return PAM_SUCCESS;
		case BAD_CONF:
			log_message(LOG_NOTICE, "bad configuration for %s", GRP_FILE);
			/* display advertissement msg */
			return PAM_SUCCESS;
		default:
			return retval;
	}		
	
	if ((retval = verify_user_entry(user, 0))) {
		return retval;
	}

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
	* Call the shamir authentication. 
	* He will get the group for user and set
	* his entry if necessary
	*/
	if ((retval = shamir_authenticate(ctrl, user)) != PAM_SUCCESS) {
		log_message(LOG_NOTICE, "can not identify the user %s for shamir: %m", user->name);
		return retval;
	}

       /*
	* Now we have to set current user data for the session management.
	* pam_set_data provide data for him and other modules too, but never 
	* for an application
	*/
	if ((retval = pam_set_data(pamh, DATANAME, user, clean)) != PAM_SUCCESS) {
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
	int i;
	const struct pam_user *user;
	
	
	for (i=0; *command != NULL; i++, *command++) {
		log_message(LOG_DEBUG, "_______cmd[%d] : %s", i, *command);
	}
	

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


