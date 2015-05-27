#ifndef H_CONFIG_H
#define H_CONFIG_H

#define UNUSED __attribute__((unused))
#define NAME     "pam_shamir.so"

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
#define CMD_DIR  "/var/lib/shamir/" 
#define EN_CMD_DIR "/var/lib/shamir/tmp/" 
#define EN_CMD_FILENAME_LEN 16 /* in bytes */ 
 
#define MAX_LINE_LEN 256 /* Maximum line lenght for groups file */ 
#define MAX_USR_GRP  20  /* Maximum users per group */ 
#define LINE_LEN     512 /* Maximum line lenght for command file */

#define PAM_DEBUG_ARG       0x0001 /* debug mod  */
#define PAM_USE_FPASS_ARG   0x0040 /* used for use the first password save in PAM */
/* !! add try_first_pass too !! */   
 
/* 
 * NO_CONF and BAD_CONF return success.  
 * it's necessary for the first configuration  
 * and for not block the system. 
 */ 
#define SUCCESS         0  
#define NO_USR_GRP      1 /* the user haven't group (authentication failed) */ 
#define NO_CONF         2 /* the group file is not configured (authentication success) */ 
#define BAD_CONF        3 /* bad configuration for group file (authentication success) */ 
 
#define ENTRY           0 /* user have key */ 
#define NO_ENTRY        1 /* no key configured */ 
 
#define ERR             1 /* error encountered */ 

#define TIME_OUT	1 /* when the user is waiting validation */ 
#define CANCELED	2 /* CTRL+C */
#define FAILED		3 /* the command was refused */

#define REQUEST_TIME_OUT	120 /* 3200 */ /* in second */

#define ALL_FILE_PARSE	2 /* returned when all lines of command file was parsed */
             
/* 
 * The unique name used to 
 * exchange data into the module 
 */ 
#define DATANAME "current_user" 
 
#define BITS            2048 /* for RSA key */ 
#define SALT_SIZE       16 /* in bytes */ 
#define RANDOM_FILE     "/dev/urandom" /* file used for random data */ 
#define CARAC           "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 

#define EXIT		9	
 
/* 
 * The default prompt used to get 
 * password 
 */ 
#define passwd_prompt	 "Unix password: " 
 
char **command; /* to get the command via sudo */ 
char **command_cp; /* orginal command before formatted */

/* 
 * The groups are identified 
 * by their names. They point 
 * to a list of users 
 */ 
struct pam_group { 
        char *name; /* name of group */
        int quorum; /* his quorum */
        struct pam_user *users[MAX_USR_GRP]; /* users registred in the group */
}; 
 
/* 
 * One user can have a single 
 * group (for this moment) 
 */ 
struct pam_user { 
        char *name;  /* name of user */
        char *pass; /* his password (in clear) */
        char *tty; /* his tty */
	char dir[PATH_MAX]; /* his current worked directory */
        struct pam_group *grp; /* his group */
};


#endif

