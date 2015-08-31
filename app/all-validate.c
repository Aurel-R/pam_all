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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <dirent.h>
#include <openssl/ssl.h>

#include "pam.h"
#include "utils.h"
#include "crypto.h"

static struct pam_conv pamc;
static struct pam_user *data = NULL;


void usage(void)
{
	printf("usage: \n");
	printf("\nshow request list:\n"); 
	printf("\t$sudo %s -l\n", NAME);
	printf("\t$sudo %s --list\n", NAME);
	printf("\nvalidate a request:\n");
	printf("\t$sudo %s pid_1 [pid_2 pid_3 pid_4 ...]\n", NAME);
	printf("\ngenerate/check your key pair:\n");
	printf("\t$sudo %s --check\n\n", NAME);
}


void terminate(pam_handle_t *pamh, struct command_info *cmd, int status)
{
	int retval;
	struct command_info *item;
	
	if ((retval = pam_close_session(pamh, 0)) != PAM_SUCCESS) {
		fprintf(stderr, "closing pam session error (%d)\n", retval);
		status = retval;
	}
	
	if ((retval = pam_end(pamh,retval)) != PAM_SUCCESS) {   
     		pamh = NULL;
        	fprintf(stderr, "release pam error (%d)\n", retval);
		status = retval;
    	}

	while ((item = cmd) != NULL) {
		F(item->cmd_file);
		F(item->salted_cmd);
		F(item->cmd);
		cmd = cmd->next;
		F(item);
	}		

	exit(status);
}


int converse(int n, const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr)
{
	struct pam_response *aresp;
	char *ack = "OK";
	int i;

	if (n <= 0 || n > PAM_MAX_NUM_MSG)
		return PAM_CONV_ERR;

	/* free in module if PAM_EX_DATA */
	if ((aresp = calloc(n, sizeof *aresp)) == NULL)
		return PAM_BUF_ERR;

	for (i=0; i<n; ++i) {
		aresp[i].resp_retcode = 0;
		aresp[i].resp = NULL;

		if (msg[i]->msg_style == PAM_EX_DATA) {
			data = (struct pam_user *)msg[i]->msg;
			if (data == NULL)
				goto fail;
			aresp[i].resp = ack;
		}
	}

	if (data) {	
		*resp = aresp;
		return PAM_SUCCESS;
	}
	
	F(aresp);
	return misc_conv(n, msg, resp, appdata_ptr);
	
fail:
        for (i = 0; i < n; ++i) {
                if (aresp[i].resp != NULL) {
                        memset(aresp[i].resp, 0, strlen(aresp[i].resp));
                        F(aresp[i].resp);
                }
        }
        memset(aresp, 0, n * sizeof *aresp);
	F(aresp);
	*resp = NULL;
	return PAM_CONV_ERR;
}


struct command_info *init_list(struct pam_user *user)
{
	struct command_info *curr, *head;
	struct dirent *file;
	DIR *fd;
	char *token;
	int retval, i = 0;
	

	head = NULL;

	if ((fd = opendir(CMD_DIR)) == NULL) {
		fprintf(stderr, "can not open '%s' directory: %m\n", CMD_DIR);
		return NULL;		
	}

	while ((file = readdir(fd)) != NULL) {
		if (!strncmp(file->d_name, user->grp->name, strlen(user->grp->name)) &&
		    strstr(file->d_name, user->name) == NULL) {	
			i++;
			curr = malloc(sizeof(*curr)); 
			if (curr == NULL)
				return NULL;
			
			curr->cmd_number = i;
			curr->cmd_file = calloc(strlen(CMD_DIR) + strlen(file->d_name) + 1, sizeof(char));
			
			if (curr->cmd_file == NULL)
				return NULL;

			strncpy(curr->cmd_file, CMD_DIR, strlen(CMD_DIR));
			strncpy(curr->cmd_file+strlen(CMD_DIR), file->d_name, strlen(file->d_name));
 
			token = strtok(file->d_name, "-");
			token = strtok(NULL, "-");
			curr->user = strtok(token, ".");
			curr->cmd_pid = atoi(strtok(NULL, "."));

			retval = decrypt_cmd_file(user, curr);

			if (retval)
				fprintf(stderr, "impossible to decrypt data for file %s\n", curr->cmd_file);	

			curr->next = head;
			head = curr;				
		} 

	}
	
	if (i == 0) {
		curr = malloc(sizeof(*curr));
		if (curr == NULL)
			return NULL;
		curr->cmd_number = i;
		curr->cmd_file = NULL;
		curr->salted_cmd = NULL;
		curr->cmd = NULL;
		curr->next = head;
		head = curr;
	}
	
	closedir(fd);

	return head;
}

void show_list(struct command_info *item)
{
	while (item) {
		printf("\tPID = %d\tUSER = %s\t COMMAND = %s\n", item->cmd_pid, item->user, item->cmd);
		item = item->next;
	}
}


int main(int argc, char **argv)
{
	pam_handle_t *pamh = NULL;
	int retval, i;	
	struct pam_user *user = NULL;
	struct command_info *cmd_info;
	char *username;

	if (getuid()) {
		fprintf(stderr,"please, use 'sudo' to run this command\n");
		return 1;
	}

	/*
	 * getlogin() is an unsafe and deprecated way of determining the logged-in user
	 * More ohter, the result depend of the dist (good return on debian stable, and
	 * wroste in ubuntu)
	 * 
	 * getpwuid(getuid()) return the user you're running as (which might not be the 
	 * same as the logged-in user) 
	 *
	 * I prefer use getenv(SUDO_USER), enven if user can 'export SUDO_USER=xxx', sudo is 
	 * executed in different session and he have his SUDO_USER env. Anyway the user have 
	 * to know the password of the 'xxx' to access. So it's pretty safe
	 */	
	username = getenv("SUDO_USER");

	if (username == NULL)
		return 1;

	pamc.conv = &converse;

	if ((retval = pam_start(NAME, username, &pamc, &pamh)) != PAM_SUCCESS) {	
		fprintf(stderr, "pam start error (%d)\n", retval);
		return retval;
	}
	
	if ((retval = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
		fprintf(stderr, "authentification error (%d)\n", retval);
		return retval;
	}

	if ((retval = pam_open_session(pamh, 0)) != PAM_SUCCESS) {
		fprintf(stderr, "session error (%d)\n", retval);
		return retval;
	}	

	if (data == NULL)
		return 2;

	user = (struct pam_user *)data;

	/*----- FOR TEST ----*//*
	int i;
	printf("user name is : %s\n", user->name);
	printf("user group is : %s\n", user->grp->name);
	for (i=0; i<user->grp->nb_users; i++)
		printf("user[%d] (%s)\n", i, user->grp->users[i]->name);	
	*//*----- FOR TEST ----*/

	
	if (argc < 2 || !strncmp(argv[1], "-h", 2) || !strncmp(argv[1], "--help", 6)) {
		usage();
		terminate(pamh, NULL, 1);
	}
	
	/* nothing to do, the user start the command with sudo, his key pair is generated automaticaly.
	   else, there will be an error before coming here */
	if (!strncmp(argv[1], "--check", 7)) {
		printf("your key pair is set\n");
		terminate(pamh, NULL, 0);
	}   

	SSL_library_init();

	cmd_info = init_list(user);	
		
	if (cmd_info == NULL) {
		fprintf(stderr, "initalise list error: %m\n");
		terminate(pamh, NULL, 1);
	}

	if (cmd_info->cmd_number == 0) {
		printf("no command requires your permission\n");
		terminate(pamh, cmd_info, 0);
	}
	
	if (!strncmp(argv[1], "-l", 2) || !strncmp(argv[1], "--list", 6)) {
		show_list(cmd_info);
		terminate(pamh, cmd_info, 0);
	}

	for (i=1; i<argc; i++) {
		retval = sign(user, cmd_info, atoi(argv[i]));
		
		switch (retval) {
			case SUCCESS: printf("'%s' has been signed\n", argv[i]);
				      break;
		
			case NO_CMD_MATCH: fprintf(stderr, "no command associated to '%s'\n", argv[i]);
				      	   break; 
			
			default: fprintf(stderr, "sign() has returned an error for '%s' argument: %d\n", argv[i],  retval);
				 break; 
		}
	}	

	terminate(pamh, cmd_info, 0);

	return 0;
}
