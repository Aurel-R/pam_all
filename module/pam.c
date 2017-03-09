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

#include <security/pam_modules.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "pam.h"
#include "command_info.h"
#include "../crypto/crypto.h"
#include "../common/utils.h"
#include "prot.h"

void _pam_syslog(void *pamh, int priority, const char *fmt, ...)
{
	static pam_handle_t *ph = NULL;
	va_list args;

	if (pamh)
		ph = pamh;
	va_start(args, fmt);
	pam_vsyslog(ph, priority, fmt, args);
	va_end(args);
}

void _pam_info(void *pamh, int ctrl, const char *buffer)
{
	static pam_handle_t *ph = NULL;

	if (pamh)
		ph = pamh;
	if (_IS_SET(ctrl, PAM_ECHO))
		pam_info(ph, "\r%s\r", buffer);
}

static void clean_pam_user(struct pam_user *usr)
{
	if (usr) {
		F(usr->name);
		if (usr->pass)
			_pam_overwrite(usr->pass);
		F(usr->pass);
		F(usr->tty);
		_pam_overwrite(usr->cwd);
		F(usr->sk_path);
		F(usr->pk_path);
		usr->pwd = NULL;
		usr->grp.ux_grp = NULL;
		usr->grp.quorum = 0;
		usr->grp.nb_users = 0;	
		F(usr);
	}
}

void clean(pam_handle_t *pamh UNUSED, void *data, int err UNUSED)
{
	clean_pam_user((struct pam_user *)data);
}

static struct pam_user *init_pam_user(void)
{ 
	struct pam_user *usr;
	if ((usr = malloc(sizeof(*usr))) == NULL) {
		D(("memory allocation error: %m"));
		return NULL;
	}
	usr->name = NULL;
	usr->pass = NULL;
	usr->tty = NULL;
	memset(usr->cwd, '\0', sizeof(usr->cwd));
	usr->sk_path = NULL;
	usr->pk_path = NULL;
	usr->pwd = NULL;
	usr->grp.ux_grp = NULL;
	usr->grp.quorum = 0;
	usr->grp.nb_users = 0;
	return usr;
}

static char *get_user_item(pam_handle_t *pamh, int type, int *err)
{
	int status;
	const char *item;

	if (type == PAM_USER)
		status = pam_get_user(pamh, &item, NULL);
	else
		status = pam_get_item(pamh, type, (const void **)&item);

	*err = status;

	if (status != PAM_SUCCESS || !item) {
		D(("status: %s (%d)", D_ERR(status), status));
		return NULL;
	}	

	return strdup(item);
}

int user_authenticate(pam_handle_t *pamh, struct control ctrl, struct pam_user **user) 
{
	struct pam_user *usr;
	int err;

	if ((usr = init_pam_user()) == NULL) 
		return PAM_SYSTEM_ERR;
	
	if ((usr->name = get_user_item(pamh, PAM_USER, &err)) == NULL) {
		_pam_syslog(pamh, LOG_ERR, "can not get username");
		goto user_auth_fail;
	}
	
	if ((usr->pass = get_user_item(pamh, PAM_AUTHTOK, &err)) == NULL) {
		_pam_syslog(pamh, LOG_ERR, "impossible to define password");
		goto user_auth_fail;
	}
	
	if ((usr->tty = get_user_item(pamh, PAM_TTY, &err)) == NULL) 
		_pam_syslog(pamh, LOG_ERR, "can not get tty");
	
	if (getcwd(usr->cwd, sizeof(usr->cwd)) == NULL) {
		_pam_syslog(pamh, LOG_ERR, "can not get working directory: %m");
		goto user_auth_fail;
	}
	
	if (((usr->sk_path = locate_sk_path(usr)) == NULL) ||
	    ((usr->pk_path = locate_pk_path(usr)) == NULL)) {
		_pam_syslog(pamh, LOG_ERR, "can not get key pair location");
		goto user_auth_fail;
	}	
	
	if ((usr->pwd = pam_modutil_getpwnam(pamh, usr->name)) == NULL) {
		_pam_syslog(pamh, LOG_ERR, "can not get passwd set: %m");
		goto user_auth_fail;
	}
	
	*user = usr;
	return PAM_SUCCESS;
user_auth_fail:
	_pam_syslog(pamh, LOG_NOTICE, "user authentication failure");
	clean_pam_user(usr);
	*user = NULL;
	return (err) ? err : PAM_SYSTEM_ERR;
}

static int check_preauth_err(struct pam_user *user)
{
	if (user == NULL)
		return 1;
	return 0;
}

static int unix_group(pam_handle_t *pamh, const char *grp_name, struct pam_group *grp)
{
	int i;
	int sv_errno = errno;
	
	if (!grp_name)
	       return GROUP_BAD_CONF;

	grp->ux_grp = pam_modutil_getgrnam(pamh, grp_name);
	if (!grp->ux_grp) {
		switch(errno) {
		case 0:
		case ENOENT:
		case ESRCH:
		case EBADF:
		case EPERM:
			_pam_syslog(pamh, LOG_ERR, "group %s was not found",
				    grp_name);
			errno = sv_errno;
			return GROUP_BAD_CONF;
		default:
			_pam_syslog(pamh, LOG_ERR, "impossible to get %s group: %m",
				    grp_name);
			errno = sv_errno;
			return ERR;
		}
	}

	errno = sv_errno;
	for (i = 0; grp->ux_grp->gr_mem[i]; i++, grp->nb_users++);
	return SUCCESS;
}

int group_authenticate(pam_handle_t *pamh, struct control ctrl, struct pam_user **user)
{
	int retval;
	struct pam_user *usr = *user;
	struct pam_group grp;	

	if (check_preauth_err(usr))
		return 0;

	retval = unix_group(pamh, ctrl.group, &grp);
	switch (retval) {
	case GROUP_BAD_CONF:
		_pam_syslog(pamh, LOG_ALERT, "WARNING: bad value for group option");
		_pam_info(pamh, ctrl.opt, "WARNING: bad value for group option");
	case ERR:
		goto group_auth_fail;
	default: 
		break; /* success */
	}

	if (!in_group_nam(usr->name, grp.ux_grp->gr_name)) {
		_pam_syslog(pamh, LOG_INFO, "user %s is not in %s group", 
			    usr->name, ctrl.group);
		_pam_syslog(pamh, LOG_NOTICE, "group authentication failure");
		_pam_info(pamh, ctrl.opt, "you are not in a privileged group");
		retval = NO_USR_GRP;
		goto group_auth_fail;
	}
	
	usr->grp = grp;
	return retval;
group_auth_fail:
	clean_pam_user(usr);
	*user = NULL;
	return retval;
}

int group_quorum(pam_handle_t *pamh, struct control ctrl, struct pam_user **user)
{
	struct pam_user *usr = *user;

	if (check_preauth_err(usr))
		return 0;

	if (ctrl.quorum < 2 || ctrl.quorum > usr->grp.nb_users) {
		_pam_syslog(pamh, LOG_ALERT, "WARNING: bad value for quorum option");
		_pam_info(pamh, ctrl.opt, "WARNING: bad value for quorum option");
		clean_pam_user(usr);
		*user = NULL;
		return QUORUM_BAD_CONF;
	}

	usr->grp.quorum = ctrl.quorum;
	return SUCCESS;
}

int get_auth_status(pam_handle_t *pamh)
{
	int err;
	const void *status = NULL;

	if ((err = pam_get_data(pamh, STATUS, &status)) != PAM_SUCCESS) { 
		_pam_syslog(pamh, LOG_ERR, "get status error: %s (%d)", 
			    D_ERR(err), err);
		return err;
	}

	if (!strncmp((const char *)status, "WW", 2))
		return AUTH_WARN;
	if (!strncmp((const char *)status, "OK", 2))
		return PAM_SUCCESS;

	_pam_syslog(pamh, LOG_ERR, "impossible to recover auth status");	
	return PAM_SESSION_ERR;
}

int get_auth_data(pam_handle_t *pamh, struct pam_user **user)
{
	int err;
	const void *data = NULL;

	if ((err = pam_get_data(pamh, DATA, &data)) != PAM_SUCCESS) { 
		_pam_syslog(pamh, LOG_ERR, "get status error: %s (%d)", 
			    D_ERR(err), err);
		return err;
	}

	*user = (struct pam_user *)data;
	return PAM_SUCCESS;
}


