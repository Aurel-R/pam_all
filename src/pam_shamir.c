/* ! @Todo

- rewrite cleanup
- new clean fct (for alloc, file, etc...)
- ^ (maybe two in one ?) 
- fct for parse files (groups)

- many files + many fct...
	auth_standard
	auth_rsa
	sess_shamir
	passwd
	utils

- comments 
- debug message (DEBUG) (ERROR) (WW) (INFO)

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

/*
 * Contains many files with one encrypted 
 * command and his options. 
 */
#define CMD_DIR	 "/var/lib/shamir/"

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
#define SALT_SIZE	16 /* in bytes */
#define RANDOM_FILE	"/dev/urandom"
#define CARAC		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


/*
 * The default prompt used to get
 * password
 */
static const char passwd_prompt[] = "Unix password: ";

char **command; /* to get the command via sudo */

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
/* ! @Todo : rewrite */ 
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

static int
passwd_callback(char *pcszBuff, int size, int rwflag, void *pPass)
{
	size_t onPass = strlen((char*)pPass);

    	if (onPass > (size_t)size)
		onPass = (size_t)size;
    
	memcpy(pcszBuff, pPass, onPass);
    
	return (int)onPass;
}

static 
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
static int
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


static char
*format_command_line(const char **command_line)
{
	size_t length = 0, i=0;
	char *formated_command = NULL;	
		
	do {
		length += strlen(command_line[i]) + 1; /* +1 for sapce and \'0' ending */
		i++;
	} while (command_line[i] != NULL);

	formated_command = calloc(length, sizeof(char));
	if (formated_command == NULL)
		return NULL;

	length = 0;
	i = 0;

	do {
		strncpy(formated_command+length, command_line[i], strlen(command_line[i]));
		length += strlen(command_line[i]) + 1;
		formated_command[length-1] = ' ';
		i++;
	} while (command_line[i] != NULL);

	formated_command[length] = '\0';
		
	return formated_command;
}

static EVP_PKEY
*get_public_key(const struct pam_user *user)
{
	FILE *fd;
	EVP_PKEY *pub_key = NULL;
	char *pub_file_name = calloc(strlen(USR_DIR) + strlen(user->name) + 4 + 1, sizeof(char));	
	
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

static unsigned char
*alea(size_t len, unsigned char *table)
{
	FILE *fd;
	int i = 0;
	unsigned char carac, *random_buffer = NULL;	
	random_buffer = calloc(len + 1, sizeof(unsigned char));

	if (random_buffer == NULL)
		return NULL;
	
	if ((fd = fopen(RANDOM_FILE, "r")) == NULL)
		return NULL;

	if (table != NULL) {
		do  {	
			fread(&carac, sizeof(unsigned char), 1, fd);
			if ((strchr((const char *)table, carac)) != NULL) {
				if (carac == 0)
					carac = (unsigned char)48;
				random_buffer[i] = carac;
				i++;
			}
		} while (i != len);		
	} 

	else fread(random_buffer, sizeof(unsigned char), len, fd);
		
	fclose(fd);
	return random_buffer;
}



static char
*create_command_file(const struct pam_user *user) 
{
	char *file_name = calloc(FILENAME_MAX, sizeof(char));
	//unsigned char salt[SALT_SIZE+1] = {'\0'}; 
	unsigned char *salt;
	int i, retval, quorum = 0;
	FILE *fd;
	char *buffer = NULL, *formated_command = NULL;
	unsigned char *encrypted_data = NULL;
	EVP_PKEY *public_key = NULL;
	
	if (file_name == NULL)
		return NULL;

	salt = alea(SALT_SIZE, (unsigned char *)CARAC);

	if (salt == NULL) {	
		log_message(LOG_ERR, "(ERROR) set random salt: %m");
		return NULL;
	}
	
	log_message(LOG_DEBUG, "(TT) salt (%s)", salt);
	for(i=0;i<SALT_SIZE+1;i++)
		log_message(LOG_DEBUG, "(TT) __salt(%d) = [%c] - [0x%X] ",i,salt[i],salt[i]);


	
	if ((formated_command = format_command_line((const char **)command)) == NULL) {
		log_message(LOG_ERR, "(ERROR) format the command line error");
		return NULL;
	}
	
	log_message(LOG_DEBUG, "(DEBUG) formated command : %s", formated_command);	

	snprintf(file_name, FILENAME_MAX - 1, "%s%s-%s.%d", CMD_DIR, user->grp->name, user->name, getpid());
	
	log_message(LOG_DEBUG, "(DEBUG) creating %s file...", file_name);

	if ((buffer = calloc(strlen(formated_command)+SALT_SIZE+1, sizeof(unsigned char))) == NULL)
		return NULL;

	strncpy(buffer, (char *)salt, SALT_SIZE);
	strncpy(buffer+SALT_SIZE, formated_command, strlen(formated_command));		

	log_message(LOG_DEBUG, "(TT) buffer is (%s)",buffer);

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
	
	//	frpintf(fd, "%s:%s:\n", user->grp->users[i]->name, encrypted_file);
		fprintf(fd, "%s:%s:\n", user->grp->users[i]->name, encrypted_data); //user:/path/file_encrypt:/path/file_sign  random filename ?	

		quorum++;

		free(encrypted_data);
		RSA_free(rsa);
		rsa = NULL;
		EVP_PKEY_free(public_key);
		public_key = NULL;
 	} 	
	
	if (quorum < user->grp->quorum) {
		//display advertissement message
		log_message(LOG_ERR, "(ERROR) impossible to establish the quorum");
		return NULL;
	}

	free(buffer);
	fclose(fd);
	free(formated_command);
	free(salt);
	return file_name;
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
	if ((retval = (get_group(user)) != SUCCESS)) {
		return PAM_SUCCESS;
	}

	if ((retval = pam_get_item(pamh, PAM_AUTHTOK, &passwd)) != PAM_SUCCESS) {
		log_message(LOG_NOTICE, "(ERROR) can not determine the password: %m");
		return retval;
	}	

	if (passwd != NULL) {
		log_message(LOG_NOTICE, "(INFO) changing password for user %s...", user->name);
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
	int i=0;
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

	/* log_message(LOG_DEBUG, "__ADDR_OF_DATA __SESS user[0x%X] user->name[%s][0x%X]", user, user->name, &user->name); */
	log_message(LOG_NOTICE, "session opened by %s in %s (member of %s)", user->name, user->tty, user->grp->name);

	if (strcmp(command[0], "command=/bin/validate") == 0)
		return PAM_SUCCESS;
	
	log_message(LOG_NOTICE, "(INFO) starting request...");
	SSL_library_init(); /* always returns 1 */
	
	if ((file_name = create_command_file(user)) == NULL) {
		log_message(LOG_ERR, "(ERROR) can not create command file: %m");
		return PAM_SESSION_ERR;
	}

	// listen (with sig ctrl+c + timeout) : (user, file_name) return SUCCESS, TIME_OUT, CANCELED, FAILED

	//unlink(file_name); // no unlink for test		
	free(file_name);
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


static char
*is_a_symlink(char *file)
{
	char *link, *tmp_link;
	int ret;
	struct stat sb;

	if (lstat(file, &sb) == -1) 
		return NULL;
	
	link = malloc(sb.st_size + 1);
	
	if (link == NULL) { 
		log_message(LOG_ERR, "(ERROR) %m");
		fprintf(stderr, "malloc: %m");
		return NULL;	
	}

	ret = readlink(file, link, sb.st_size + 1);

        if (ret < 0) 
		return NULL;

   	if (ret > sb.st_size) {
        	fprintf(stderr, "symlink increased in size between lstat() and readlink()\n");
        	return NULL;
    	}

   	link[sb.st_size] = '\0';

   	log_message(LOG_INFO, "(TT) '%s' points to '%s'", file, link);	

	if ((tmp_link = is_a_symlink(link)) == NULL)
		return link;

	return tmp_link;
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

