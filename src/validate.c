/*

converse fct is under BSD(?) licence.
I modified the fct converse for my uses

*/

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


static struct pam_conv pamc;
static struct pam_user *data = NULL;

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
/* char text[] = {#include "usage.text"} */

	printf("usage: \n");
	printf("\nshow request list:\n"); 
	printf("\t$sudo %s -l\n", prog_name);
	printf("\t$sudo %s --list\n", prog_name);
	printf("\nvalidate a request:\n");
	printf("\t$sudo %s ID_1 [ID_2 ID_3 ID_4 ...]\n\n", prog_name);
}

int list(void)
{
	return 0;
}

int main(int argc, char **argv)
{
	pam_handle_t *pamh=NULL;
	int retval, i;
	const char *username="tutu";
	struct pam_user *user = NULL;

	pamc.conv = &converse;
	if ((retval = pam_start("validate", username, &pamc, &pamh)) != PAM_SUCCESS) {
		fprintf(stderr, "erreur pam_start\n");
		return 1;
	}
	
	printf("pam_start ok\n");

	if ((retval = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
		fprintf(stderr, "erreur pam_auth\n");
		return 1;
	}

	printf("pam_auth ok\n");

	if ((retval = pam_open_session(pamh, 0)) != PAM_SUCCESS) {
		fprintf(stderr, "erreur pam_sess\n");
		return 1;
	}	

	printf("pam_sess ok\n");

	if (data == NULL)
		return 2;

	user = (struct pam_user *)data;

	printf("user name is : %s\n", user->name);
	printf("user group is : %s\n", user->grp->name);
	for (i=0; i<user->grp->nb_users; i++)
		printf("user[%d] (%s)\n", i, user->grp->users[i]->name);

	
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}  

	
	if (!strncmp(argv[1], "-l", 2) || !strncmp(argv[1], "--list", 6)) 
		return list();	




	if ((retval = pam_close_session(pamh, 0)) != PAM_SUCCESS) {
		fprintf(stderr, "error: closing PAM session\n");
		return 1;
	}

	if (pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
     		pamh = NULL;
        	fprintf(stderr, "failed to release authenticator\n");
        	return 1;
    	}
	
	printf("end\n");

	return 0;
}
