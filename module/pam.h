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

#include <security/pam_ext.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>

#define UNUSED	__attribute__((unused))

#define SERVICE_NAME		"sudo"
#define USER_TTY		"/dev/tty"

#define PAM_DEBUG_ARG		0x01 /* 'debug' option */
#define PAM_ECHO		0x02 /* display info to user */
#define DEFAULT_TIMEOUT		3200 /* in second */
#define MIN_MS_TIMEOUT		12000 /* in ms */
struct control {
	int opt;
	int quorum;
	const char *group;
	int timeout;
};

#define SUCCESS		PAM_SUCCESS	
#define ERR		PAM_SYSTEM_ERR

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

/* 
 * Display the standard pam error message.
 * pam handle isn't used inside the function (set to 0) 
 */
#define D_ERR(TYPE)	(pam_strerror(0,TYPE))

/*
 * Contains the private and public
 * users key
 */
#define USR_DIR	"/etc/security/pam_all.d/users/"
#define CMD_DIR "/var/lib/pam_all/"
#define SESSION_STOP	9


/* XXX: set enum with val of PAM */
/* 
 * errors begin to 32
 * (_PAM_RETURNED_VALUES in PAM-1.1.8)
 * to not interfere with the default values
 */
#define NO_USR_GRP	32 
#define GROUP_BAD_CONF	33
#define QUORUM_BAD_CONF	34
#define BAD_CONF GROUP_BAD_CONF | QUORUM_BAD_CONF /* 35 */
#define AUTH_WARN	36
#define TIMEOUT		37
#define CANCELED	38
#define ABORTED		39
#define REFUSED		40
#define CONTINUE	41
#define VALIDATE	42


/*
 * Unique name used to exchange data into 
 * the pam stack
 */
#define DATA   "current_user"
#define STATUS "config_status"

struct pam_group {
	struct group *ux_grp;
	int nb_users;
	int quorum;
};

struct pam_user {
	char *name;
	char *pass;
	char *tty;
	char cwd[PATH_MAX];
	char *sk_path; 
	char *pk_path;
	struct passwd *pwd;
	struct pam_group grp;
};


void _pam_syslog(void *pamh, int priority, const char *fmt, ...);
void _pam_info(void *pamh, int ctrl, const char *buffer);
void clean(pam_handle_t *pamh UNUSED, void *data, int err UNUSED);
int user_authenticate(pam_handle_t *pamh, struct control ctrl, struct pam_user **user);
int group_authenticate(pam_handle_t *pamh, struct control ctrl, struct pam_user **user);
int group_quorum(pam_handle_t *pamh, struct control ctrl, struct pam_user **user);
int get_auth_status(pam_handle_t *pamh);
int get_auth_data(pam_handle_t *pamh, struct pam_user **user);

#endif

