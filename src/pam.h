/*
 * Copyright (C) 2015 Aurélien Rausch <aurel@aurel-r.fr>
 * 
 * This file is part of pam_all.
 *
 * pam_all is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * pam_all is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pam_all.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef H_PAM_H
#define H_PAM_H

#define UNUSED __attribute__((unused))
#define NAME     "pam_all.so"
#define ASSOCIATED_SERVICE	"all-validate"

/*
 * Strange bug...
 */
#define PATH_MAX	4096	

/* 
 * Contains the groups of shamir. 
 * Many groups as possible but one 
 * user can't be in two different 
 * groups. 
 */ 
#define GRP_FILE "/etc/security/pam_all.d/groups" 
 
/* 
 * Contains the private and public  
 * users key.  
 */  
#define USR_DIR  "/etc/security/pam_all.d/users/" 
 
/* 
 * Contains many files with one encrypted  
 * command and his options.  
 */ 
#define CMD_DIR  "/var/lib/pam_all/" 
#define EN_CMD_DIR "/var/lib/pam_all/tmp/" 
#define EN_CMD_FILENAME_LEN 16 /* in bytes */ 
 
#define MAX_LINE_LEN 256 /* Maximum line lenght for groups file */ 
#define MAX_USR_GRP  20  /* Maximum users per group */ 
#define LINE_LEN     512 /* Maximum line lenght for command file */

#define PAM_DEBUG_ARG       		0x0001 /* debug mod  */

#define PAM_EX_DATA	5  /* specific conversation protocol */
#define ACKNOWLEDGE	"OK" /* confirm conversation */

/* 
 * NO_CONF and BAD_CONF return success.  
 * it's necessary for the first configuration  
 * and for not block the system. 
 */ 
#define SUCCESS         0  
#define NO_USR_GRP      1 /* the user haven't group (authentication failed) */ 
#define NO_CONF         2 /* the group file is not configured (authentication success) */ 
#define BAD_CONF        3 /* bad configuration for group file (authentication success) */ 
 
#define ERR             1 /* error encountered */ 

#define TIME_OUT	4 /* when the user is waiting validation */ 
#define CANCELED	2 /* CTRL+C */
#define FAILED		3 /* the command was refused */

#define REQUEST_TIME_OUT	3200 /* in second */

#define ALL_FILE_PARSE	2 /* returned when all lines of command file was parsed */
             
/* 
 * The unique name used to 
 * exchange data into the module 
 */ 
#define DATANAME "current_user" 
#define STATUS "config_status"
 
#define EXIT		9	

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

/* 
 * The groups are identified 
 * by their names. They point 
 * to a list of users 
 */ 
struct pam_group { 
        char *name; 
        int quorum;
        struct pam_user *users[MAX_USR_GRP];
	int nb_users; 
}; 

struct tempory_files {
	char *name;
	struct tempory_files *next;
};
 
 
void clean(pam_handle_t *pamh UNUSED, void *data, int error_status UNUSED);
const struct pam_user *get_data(const pam_handle_t *pamh);
int send_data(int ctrl, pam_handle_t *pamh, void *data); 
void unlink_tmp_files(struct tempory_files *tmp_files);
int get_group(struct pam_user *user);
char *create_command_file(int ctrl, const struct pam_user *user, char **cmd, char **dst_cmd, struct tempory_files **tmp_files);
int user_authenticate(pam_handle_t *pamh, int ctrl, struct pam_user *user);
int group_authenticate(int ctrl, struct pam_user *user);
int wait_reply(int ctrl, const struct pam_user *user, const char *command_file, char *dst_cmd);


#endif

