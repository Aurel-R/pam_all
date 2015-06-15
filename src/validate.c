#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <security/pam_appl.h>
#include <dirent.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <openssl/sha.h>

#define NAME	"validate"

#define MAX_USR_GRP	20
#define PAM_EX_DATA	5
#define USR_DIR		"/etc/shared/users/"
#define CMD_DIR		"/var/lib/shamir/"
#define EN_CMD_DIR	"/var/lib/shamir/tmp/"
#define EN_CMD_FILENAME_LEN	16
#define LINE_LEN	512
#define SALT_SIZE	16
#define AES_KEY_LEN	32
#define AES_IV_LEN	16
#define MAX_BUF		1024
#define CARAC           "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#define RANDOM_FILE	"/dev/urandom"

#define SUCCESS		0
#define NO_CMD_MATCH	2

#define F(x) do {	\
	if (x) { free(x), x = NULL; }	\
	} while (0)


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



static struct pam_conv pamc;
static struct pam_user *data = NULL;


void usage(void)
{
	printf("usage: \n");
	printf("\nshow request list:\n"); 
	printf("\t$sudo %s -l\n", NAME);
	printf("\t$sudo %s --list\n", NAME);
	printf("\nvalidate a request:\n");
	printf("\t$sudo %s pid_1 [pid_2 pid_3 pid_4 ...]\n\n", NAME);
}

unsigned char *alea(size_t len, unsigned char *table) 
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

int insert(FILE *fd, const char *data, int data_len, long pos)
{
	long file_size, len;
	char *buffer;
	
	fseek(fd, 0, SEEK_END);
	file_size = ftell(fd);
	len = file_size - pos;

	if ((buffer = calloc(len, sizeof(char))) == NULL)
		return 1;

	fseek(fd, pos, SEEK_SET);
	fread(buffer, sizeof(char), len, fd);
	fseek(fd, pos, SEEK_SET);
	fwrite(data, sizeof(char), data_len, fd);
	fwrite(buffer, sizeof(char), len, fd);
	
	F(buffer);
		
	return 0;
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

	if (cmd == NULL)
		exit(status);

	while ((item = cmd) != NULL) {
		F(item->cmd_file);
		F(item->salted_cmd);
		F(item->cmd);
		cmd = cmd->next;
		F(item);
	}		

	exit(status);
}


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
                        F(aresp[i].resp);
                }
        }
        memset(aresp, 0, n * sizeof *aresp);
	*resp = NULL;
	return PAM_CONV_ERR;
}

int passwd_callback(char *pcszBuff, int size, int rwflag, void *pPass)
{
	size_t onPass = strlen((char *)pPass);
	
	if (onPass > (size_t)size)
		onPass = (size_t)size;

	memcpy(pcszBuff, pPass, onPass);

	return (int)onPass; 
}



char *rsa_decrypt(struct pam_user *user, char *file)
{
	int ret;
	FILE *fd;
	EVP_PKEY *priv_key = NULL;
	char *buffer, *decrypted_data;
	char *priv_file_name = calloc(strlen(USR_DIR) + strlen(user->name) + 1, sizeof(char));

	if (priv_file_name == NULL)
		return NULL;

	strncpy(priv_file_name, USR_DIR, strlen(USR_DIR));
	strncpy(priv_file_name+strlen(USR_DIR), user->name, strlen(user->name));

	if ((fd = fopen(priv_file_name, "r")) == NULL) {
		fprintf(stderr, "can not open '%s' file: %m\n", priv_file_name);
		F(priv_file_name);
		return NULL;
	}
	
	if (!PEM_read_PrivateKey(fd, &priv_key, passwd_callback, (void *)user->pass)) {
		fprintf(stderr, "can not read key for user '%s'\n", user->name);
		F(priv_file_name);
		return NULL;
	}	

	fclose(fd);
	
	if ((fd = fopen(file, "r")) == NULL) {
		fprintf(stderr, "can not open '%s' file: %m\n", file);
		F(priv_file_name);
		EVP_PKEY_free(priv_key);
		return NULL;
	}

	buffer = calloc(257, sizeof(char));
	
	if (buffer == NULL) {
		F(priv_file_name);	
		EVP_PKEY_free(priv_key);
		return NULL;
	}	

	ret = fread(buffer, sizeof(*buffer), 256, fd);

	fclose(fd);

	RSA *rsa = RSA_new();

	if ((rsa = EVP_PKEY_get1_RSA(priv_key)) == NULL) {
		fprintf(stderr, "can not assign RSA key\n");
		F(priv_file_name);	
		EVP_PKEY_free(priv_key);
		F(buffer);
		return NULL;
	}

	decrypted_data = calloc(257, sizeof(char));

	if (decrypted_data == NULL) {
		F(priv_file_name);	
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		F(buffer);
		return NULL;
	}

	ret = RSA_private_decrypt(256, (unsigned char *)buffer, (unsigned char *)decrypted_data, rsa, RSA_PKCS1_OAEP_PADDING);

	if (ret == -1) 
		decrypted_data = NULL;
	
	RSA_free(rsa);
	EVP_PKEY_free(priv_key);
	F(priv_file_name);
	F(buffer);
	return decrypted_data;	
}


char *aes_decrypt(char *file, char *key, char *iv)
{
	OpenSSL_add_all_algorithms();
	FILE *fd;
	EVP_CIPHER_CTX ctx;
	char buffer[MAX_BUF];
	memset(buffer, '\0', MAX_BUF);
	char *data = NULL;
	int len = 0, inlen, plain_len;

	
	if ((fd = fopen(file, "r")) == NULL) {
		fprintf(stderr, "can not open aes file '%s'\n", file);
		return NULL;
	}
	
	inlen = fread(buffer, sizeof(char), MAX_BUF - 1, fd);
		
	fclose(fd);

	data = calloc(inlen+1, sizeof(char));

	if (data == NULL)
		return NULL;

	
	EVP_CIPHER_CTX_init(&ctx);

	if (EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, (unsigned char *)iv) != 1) {
		fprintf(stderr, "impossible to initialize ctx\n"); 
		EVP_CIPHER_CTX_cleanup(&ctx);
		return NULL;
	}
	
	if (!EVP_DecryptUpdate(&ctx, (unsigned char *)data, &len, (unsigned char *)buffer, inlen)) {
		fprintf(stderr, "impossible to updata ctx\n");
		EVP_CIPHER_CTX_cleanup(&ctx);
		return NULL;
	}

	plain_len = len;
	
	if (!EVP_DecryptFinal_ex(&ctx, (unsigned char *)data + len, &len)) {
		fprintf(stderr, "impossible to decrypt aes data\n");
		EVP_CIPHER_CTX_cleanup(&ctx);
		return NULL;
	}

	plain_len += len;

	data[plain_len] = '\0';

	EVP_CIPHER_CTX_cleanup(&ctx);
	return data;	
}


int decrypt_cmd_file(struct pam_user *user, struct command_info *command)
{
	FILE *fd;
	char line[LINE_LEN];
	char *token, *rsa_file;
	char *decrypted_rsa_data = NULL;
	int len = strlen(EN_CMD_DIR) + EN_CMD_FILENAME_LEN;
	char key[AES_KEY_LEN], iv[AES_IV_LEN], aes_file[len+1];
	memset(aes_file, '\0', sizeof(aes_file));

	command->salted_cmd = NULL;
	command->cmd = NULL;
	
	if ((fd = fopen(command->cmd_file, "r")) == NULL) {
		fprintf(stderr, "can not open '%s' command file: %m\n", command->cmd_file);
		return 1;
	}

	rewind(fd);
	while (fgets(line, LINE_LEN - 1, fd) != NULL) {
		if (strncmp(line, user->name, strlen(user->name)))
			continue;

		token = strtok(line, ":");
		token = strtok(NULL, ":");
		rsa_file = token;

		decrypted_rsa_data = rsa_decrypt(user, rsa_file);	
		
		if (decrypted_rsa_data == NULL) {
			fprintf(stderr, "can not decrypt rsa data in '%s'\n", rsa_file);
			fclose(fd);
			return 1;
		}

		//test
		/*printf("\n\nRSA\n"); 
		int j;
		for(j=0; j<256; j++)
			printf("-DE- %d [%c] [0x%X]\n",j,decrypted_rsa_data[j], decrypted_rsa_data[j]);
		printf("\n\n\n");*/
		//test

		strncpy(aes_file, decrypted_rsa_data, len);
		strncpy(key, decrypted_rsa_data+len, AES_KEY_LEN);
		strncpy(iv, decrypted_rsa_data+len+AES_KEY_LEN, AES_IV_LEN);

		// test
		/*printf("\n\n\nAES_FILE = (%s)\n", aes_file);
		int i;
		printf("\nKEY = ");
		for (i=0; i<AES_KEY_LEN; i++)
			printf("(%d[%X]) - ", i, key[i]);
		printf("\n\nIV = ");
		for(i=0; i<AES_IV_LEN; i++)
			printf("(%d[%X]) - ", i, iv[i]);
		printf("\n\n\n");*/
		// test

		command->salted_cmd = aes_decrypt(aes_file, key, iv);

		if (command->salted_cmd != NULL) {
			command->cmd = calloc(strlen(command->salted_cmd) - SALT_SIZE - 8 + 1, sizeof(char));
			if (command->cmd == NULL)
				return 1;
			strncpy(command->cmd, command->salted_cmd + SALT_SIZE + 8, strlen(command->salted_cmd) - SALT_SIZE - 8);
		} else {
			command->cmd = NULL;	
		}
		
		break;
	}
	
	F(decrypted_rsa_data);
	fclose(fd);
	return 0;
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


int sign(struct pam_user *user, struct command_info *item, int pid)
{
	unsigned char *seed = NULL;
	char *file_name = NULL;
	FILE *fd;
	unsigned char *signed_data = NULL;
	unsigned int signed_data_len = 0;
	EVP_PKEY *priv_key = NULL;
	char *priv_file_name = NULL; 
	char line[LINE_LEN];	
	int flag = 0;
	long pos;
	
	while (item != NULL && item->cmd_pid != pid)
		item = item->next;

	if (item == NULL) 
		return NO_CMD_MATCH;


	
	priv_file_name = calloc(strlen(USR_DIR) + strlen(user->name) + 1, sizeof(char));

	if (priv_file_name == NULL)
		return 1;

	strncpy(priv_file_name, USR_DIR, strlen(USR_DIR));
	strncpy(priv_file_name+strlen(USR_DIR), user->name, strlen(user->name));

	if ((fd = fopen(priv_file_name, "r")) == NULL) {
		fprintf(stderr, "can not open '%s' file: %m\n", priv_file_name);
		F(priv_file_name);
		return 1;
	}
	
	if (!PEM_read_PrivateKey(fd, &priv_key, passwd_callback, (void *)user->pass)) {
		fprintf(stderr, "can not read key for user '%s'\n", user->name);
		F(priv_file_name);
		return 1;
	}	

	fclose(fd);
	F(priv_file_name);

	RSA *rsa = RSA_new();

	if ((rsa = EVP_PKEY_get1_RSA(priv_key)) == NULL) {
		fprintf(stderr, "can not assign RSA key\n");
		EVP_PKEY_free(priv_key);
		return 1;
	}	

	signed_data = calloc(RSA_size(rsa), sizeof(*signed_data));

	if (signed_data == NULL) {
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		return 1;
	}

	
	if (!RSA_sign(NID_sha1, (const unsigned char *)item->salted_cmd, strlen(item->salted_cmd), signed_data, &signed_data_len, rsa)) {
		fprintf(stderr, "can not sign data (%s)\n", item->cmd);
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		F(signed_data);
		return 1;
	} 

	seed = alea(EN_CMD_FILENAME_LEN, (unsigned char *)CARAC); 

	if (seed == NULL) {	
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		F(signed_data);
		return 1;
	}
	
	file_name = calloc(strlen(EN_CMD_DIR)+EN_CMD_FILENAME_LEN+1, sizeof(char));

	if (file_name == NULL) {	
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		F(signed_data);
		F(seed);
		return 1;
	}
	
	strncpy(file_name, EN_CMD_DIR, strlen(EN_CMD_DIR));
	strncpy(file_name+strlen(EN_CMD_DIR), (const char *)seed, EN_CMD_FILENAME_LEN);

	umask(0066);
	if ((fd = fopen(file_name, "wb")) == NULL) {
		fprintf(stderr, "can not open '%s' file: %m\n", file_name);
		EVP_PKEY_free(priv_key);
		RSA_free(rsa);
		F(signed_data);
		F(seed);
		F(file_name);
		return 1;
	}

	fwrite(signed_data, 1, signed_data_len, fd);		
	fclose(fd);

	EVP_PKEY_free(priv_key);
	RSA_free(rsa);
	F(signed_data);
	F(seed);

	
	if ((fd = fopen(item->cmd_file, "r+")) == NULL) {
		fprintf(stderr, "can not open '%s' file: %m\n", item->cmd_file);
		F(file_name);
		return 1;
	}
	
	while(fgets(line, LINE_LEN - 1, fd) != NULL) {
		if (strncmp(user->name, line, strlen(user->name)))
			continue;
		
		pos =  ftell(fd) - 1;
		if (!insert(fd, file_name, strlen(file_name), pos)) 
			flag = 1;	
		break;		
	}
	
	fclose(fd);
	F(file_name);
	
	if (!flag) {
		fprintf(stderr, "impossible to write data in '%s'\n", item->cmd_file);
		return 1;
	}

	return 0;
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

	SSL_library_init();

	cmd_info = init_list(user);	
		
	if (cmd_info == NULL) {
		fprintf(stderr, "initalise list error: %m\n");
		terminate(pamh, NULL, 1);
	}

	if (cmd_info->cmd_number == 0) {
		printf("no command is waitting\n");
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
		
			default: fprintf(stderr, "sign() has returned an error for '%s' argument: %d\n",argv[i],  retval);
				 break; 
		}
	}	

	terminate(pamh, cmd_info, 0);

	return 0;
}
