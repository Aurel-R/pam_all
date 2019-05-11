/*
 * Copyright (C) 2015, 2019 Aurélien Rausch <aurel@aurel-r.fr>
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

#define PAM_DEBUG_ARG		0x01 
#define PAM_ECHO		0x02
#define DEFAULT_TIMEOUT		3600 
struct control {
	int opt;
	unsigned quorum;
	const char *group;
	unsigned timeout;
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

#define D_ERR(TYPE)	(pam_strerror(0, TYPE))

#define in_group_nam(uname, gname) \
	(pam_modutil_user_in_group_nam_nam(pamh, uname, gname))

#define in_group_id(uid, gid) \
	(pam_modutil_user_in_group_uid_gid(_pamh, uid, gid))

#define CMDLINE		"/proc/self/cmdline"
#define USER_TTY	"/dev/tty"
#define CMD_DIR 	"/var/lib/pam_all"
#define DO_CHECK	1

/* XXX: replace by enum */
/* Errors begin at 32 (_PAM_RETURNED_VALUES in PAM-1.1.8)
 * so as not interfere with the default values */
#define USR_NOT_INGRP		32 
#define GROUP_BAD_CONF		33
#define QUORUM_BAD_CONF		34
#define BAD_CONF GROUP_BAD_CONF | QUORUM_BAD_CONF /* 35 */
#define TIMEOUT			36
#define CANCELED		37
#define ABORTED			38
#define REFUSED			39
#define CONTINUE		40
#define CONNECTION_CLOSED	41
#define VALIDATE		42

struct sudo_cmd {
	int argc;
	char **argv;
	size_t len;
	char *cmdline;
};

struct pam_group {
	struct group *ux_grp;
	size_t nb_users;
	unsigned quorum;
};

struct pam_user {
	char *name;
	char *tty;
	char cwd[PATH_MAX];
	struct passwd *pwd;
	struct ucred cred;
	struct pam_group grp;
};

void _pam_syslog(void *pamh, int priority, const char *fmt, ...);
void _pam_info(void *pamh, int ctrl, const char *fmt, ...);
void clean(pam_handle_t *pamh UNUSED, void *data, int err UNUSED);
int get_pam_user(pam_handle_t *pamh, struct control ctrl, struct pam_user **user);
int group_authenticate(pam_handle_t *pamh, struct control ctrl, struct pam_user *user);
int group_quorum(pam_handle_t *pamh, struct control ctrl, struct pam_user *user);
int check_dir_access(pam_handle_t *pamh, struct control ctrl, struct pam_user *user);
int preauth_error(int err);
struct sudo_cmd *get_command(pam_handle_t *pamh);
void clean_command(struct sudo_cmd *cmd);
int checklink(pam_handle_t *pamh, struct sudo_cmd *cmd, 
			struct sudo_cmd **cmd_copy, int do_check);

#endif

