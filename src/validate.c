#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <security/pam_appl.h>



#define MAX_USR_GRP	20
#define PAM_EX_DATA	5
#define USR_DIR	"/etc/shared/users/"
#define CMD_DIR	"/var/lib/shamir/"


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
	char *command_file; 	/* the path (and name) of the command file */
	int cmd_number; 	/* (PID of request)  */
	char *user; 		/* name of the user */
	char *command; 		/* command line */
	struct command_info *next; 
};



static struct pam_conv pamc;
static struct pam_user *data = NULL;


/*
 * 'converse' fct is under BSD(?) licence.
 * I modified 'converse' for my uses
 */
int converse(int n, const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr)
{
	struct pam_response *aresp;
	char *ack = "OK";
	char buf[PAM_MAX_RESP_SIZE];
	int i;
	
	if (n <= 0 || n > PAM_MAX_NUM_MSG)
		return PAM_CONV_ERR;

	if ((aresp = calloc(n, sizeof *aresp)) == NULL)
		return PAM_BUF_ERR;

	for (i = 0; i < n; ++i) {
		aresp[i].resp_retcode = 0;
		aresp[i].resp = NULL;

		switch(msg[i]->msg_style) {
			case PAM_PROMPT_ECHO_OFF:
				aresp[i].resp = strdup(getpass(msg[i]->msg));
				if (aresp[i].resp == NULL)
					goto fail;
				break;

			case PAM_PROMPT_ECHO_ON:
				fputs(msg[i]->msg, stderr);
				if (fgets(buf, sizeof buf, stdin) == NULL)
					goto fail;
				aresp[i].resp = strdup(buf);
				if (aresp[i].resp == NULL)
					goto fail;
				break;

			case PAM_ERROR_MSG:
				fputs(msg[i]->msg, stderr);
				if (strlen(msg[i]->msg) > 0 &&
				    msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
					fputc('\n', stderr);
				break;

			case PAM_TEXT_INFO:
				fputs(msg[i]->msg, stdout);
				if (strlen(msg[i]->msg) > 0 &&
				    msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
					fputc('\n', stdout);
				break;		

			case PAM_EX_DATA:
				printf("data received\n");
				data = (struct pam_user *)msg[i]->msg;
				if (data == NULL)
					goto fail;
				aresp[i].resp = ack;
				break;
						
			default:
				goto fail;	
		}
	}
	
	*resp = aresp;
	return PAM_SUCCESS;

fail:
        for (i = 0; i < n; ++i) {
                if (aresp[i].resp != NULL) {
                        memset(aresp[i].resp, 0, strlen(aresp[i].resp));
                        free(aresp[i].resp);
                }
        }
        memset(aresp, 0, n * sizeof *aresp);
	*resp = NULL;
	return PAM_CONV_ERR;
}



void usage(char *prog_name)
{
	printf("usage: \n");
	printf("\nshow request list:\n"); 
	printf("\t$sudo %s -l\n", prog_name);
	printf("\t$sudo %s --list\n", prog_name);
	printf("\nvalidate a request:\n");
	printf("\t$sudo %s ID_1 [ID_2 ID_3 ID_4 ...]\n\n", prog_name);
}



struct command_info *list(struct pam_user *user)
{
	struct command_info *curr, *head;

	

	return NULL;
}



int main(int argc, char **argv)
{
	pam_handle_t *pamh=NULL;
	int retval, i;	
	struct pam_user *user = NULL;
	struct command_info *cmd_info;
	char *username;

	if (getuid()) {
		fprintf(stderr,"please, use 'sudo' to run this command\n");
		return 1;
	}
	
	username = getlogin();

	if (username == NULL)
		return 1;

	pamc.conv = &converse;
	if ((retval = pam_start("validate", username, &pamc, &pamh)) != PAM_SUCCESS) {
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

	/*----- FOR TEST ----*/
	printf("user name is : %s\n", user->name);
	printf("user group is : %s\n", user->grp->name);
	for (i=0; i<user->grp->nb_users; i++)
		printf("user[%d] (%s)\n", i, user->grp->users[i]->name);	
	/*----- FOR TEST ----*/
	
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}  

	
	if (!strncmp(argv[1], "-l", 2) || !strncmp(argv[1], "--list", 6)) 
		cmd_info = list(user);	


	if ((retval = pam_close_session(pamh, 0)) != PAM_SUCCESS) {
		fprintf(stderr, "closing pam session error (%d)\n", retval);
		return 1;
	}

	if (pam_end(pamh,retval) != PAM_SUCCESS) {   
     		pamh = NULL;
        	fprintf(stderr, "release pam error\n");
        	return 1;
    	}
	
	return 0;
}
