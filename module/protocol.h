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

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif
#define UNIX_PATH_LEN	108
#define USER_NAME_LEN	64
#define DATA_BUFF_LEN	128

enum msg_code {
	SERVER_INFO,
	CANCEL_COMMAND,
	REFUSE_COMMAND,
	VALIDATE_COMMAND
};

struct msg_packet {
	enum msg_code code;
	uint8_t data[DATA_BUFF_LEN];
};

struct request {
	pid_t pid;
	char user[USER_NAME_LEN];
	char tty[PATH_MAX];
	char pwd[PATH_MAX];
	time_t start;
	time_t end;
	char saddr[UNIX_PATH_LEN];
	char *command;
};

int start_request_srv(pam_handle_t *pamh, const char **sock_name);
int set_request(pam_handle_t *pamh, struct pam_user *usr, struct control ctrl, 
				const char *addr, struct sudo_cmd *cmd, 
				const char **name);
int wait_for_validation(pam_handle_t *pamh, struct pam_user *usr, 
						struct control ctrl, int fd);

#endif

