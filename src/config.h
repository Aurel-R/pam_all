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
#define EN_CMD_FILENAME_LEN 16 /* Bytes */ 
 
#define MAX_LINE_LEN 256 /* Maximum line lenght for groups file*/ 
#define MAX_USR_GRP  20  /* Maximum users per group */ 
 
#define PAM_DEBUG_ARG       0x0001 
#define PAM_USE_FPASS_ARG   0x0040   
 
/* 
 * NO_CONF and BAD_CONF return success.  
 * it's necessary for the first configuration  
 * and for not block the system. 
 */ 
#define SUCCESS         0 /* user have a group */ 
#define NO_USR_GRP      1 /* the user haven't group (authentication failed) */ 
#define NO_CONF         2 /* the group file is not configured (authentication success) */ 
#define BAD_CONF        3 /* bad configuration for group file (authentication success) */ 
 
#define ENTRY           0 /* user have key */ 
#define NO_ENTRY        1 /* no key configured */ 
 
#define ERR             1 /* error encountered */ 

#define TIME_OUT	1 
#define CANCELED	2
#define FAILED		3

#define REQUEST_TIME_OUT	3200
             
/* 
 * The unique name used to 
 * exchange data into the module 
 */ 
#define DATANAME "current_user" 
 
#define BITS            2048 
#define SALT_SIZE       16 /* in bytes */ 
#define RANDOM_FILE     "/dev/urandom" 
#define CARAC           "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 

#define EXIT		9
 
/* 
 * The default prompt used to get 
 * password 
 */ 
#define passwd_prompt	 "Unix password: " 
 
char **command; /* to get the command via sudo */ 
char **command_cp; /* orginal command */

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
	char dir[PATH_MAX]; 
        struct pam_group *grp; 
};


#endif

