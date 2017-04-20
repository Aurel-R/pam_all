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


#ifndef H_PROT_H
#define H_PROT_H

#include <stdint.h>

#define PROT_ERR	-1

#define USR_NAME_LEN	64
#define REQ_BUFF	16
#define VAL_BUFF	32
#define NONCE_LEN	16

#define PROT_DATA_LEN	128
#define UNIX_PATH_MAX	108

union prot {
	uint8_t usr[USR_NAME_LEN]; 
	uint8_t req[REQ_BUFF];
	uint8_t val[VAL_BUFF];  
	uint8_t tok[NONCE_LEN];   
	uint8_t sig[SIG_LEN]; /* hash(all MINUS sig) (so buffer on PROT_DATA_LEN) */
	uint8_t buffer[PROT_DATA_LEN + SIG_LEN];
};

struct req_info {
	struct req *req_ptr;
	size_t len;
};

struct req {
	char user[USR_NAME_LEN]; 
	char saddr[UNIX_PATH_MAX]; 
	char nonce[NONCE_LEN]; 
	uint8_t sig[SIG_LEN]; 
	struct req_datas *datas;
};

struct req_datas {
	char *usr;
	pid_t pid;
	char *tty;
	char *pwd;
	char *cmd;
}; 

int start_request_srv(pam_handle_t *pamh, const char **sock_name);
struct req_info set_request(pam_handle_t *pamh, struct pam_user *usr, 
			    const char *addr, struct sudo_command cmd, 
			    const char **name);
int wait_validation(pam_handle_t *pamh, struct pam_user *usr, char *nonce, 
		    struct control ctrl, int fd);

#endif

