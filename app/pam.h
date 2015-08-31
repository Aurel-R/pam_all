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

#define NAME	"all-validate"

#define MAX_USR_GRP	20
#define PAM_EX_DATA	5
#define USR_DIR		"/etc/security/pam_all.d/users/"
#define CMD_DIR		"/var/lib/pam_all/"
#define EN_CMD_DIR	"/var/lib/pam_all/tmp/"
#define EN_CMD_FILENAME_LEN	16
#define LINE_LEN	512
#define SUCCESS		0
#define NO_CMD_MATCH	2


struct pam_user { 
        char *name;  
        char *pass; 
        char *tty; 
        char dir[PATH_MAX]; 
        struct pam_group *grp; 
};
 
struct pam_group { 
        char *name; 
        int quorum;
        struct pam_user *users[MAX_USR_GRP];
        int nb_users; 
}; 

struct command_info {
	int cmd_number;
	pid_t cmd_pid;
	char *cmd_file; 	/* path (and name) of the command file */
	char *user; 		/* name of the user who started the cmd */
	char *salted_cmd;	/* command line (with salt) */
	char *cmd; 		/* command line (without salt) */
	struct command_info *next; 
};

#endif
