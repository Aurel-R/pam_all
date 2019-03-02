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
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include "pam.h"
#include "utils.h"

void _pam_syslog(void *pamh, int priority, const char *fmt, ...)
{
	va_list args;
	static pam_handle_t *ph = NULL;

	if (pamh)
		ph = pamh;
	va_start(args, fmt);
	pam_vsyslog(ph, priority, fmt, args);
	va_end(args);
}

void _pam_info(void *pamh, int ctrl, const char *fmt, ...)
{
	va_list args;
	static pam_handle_t *ph = NULL;

	if (pamh)
		ph = pamh;
	va_start(args, fmt);
	if (_IS_SET(ctrl, PAM_ECHO))
		pam_vinfo(ph, fmt, args);
	va_end(args);	
}

static void clean_pam_user(struct pam_user *usr)
{
	if (usr) {
		free(usr->name);
		free(usr->tty);
		_pam_overwrite(usr->cwd);
		usr->pwd = NULL;
		usr->grp.ux_grp = NULL;
		usr->grp.quorum = 0;
		usr->grp.nb_users = 0;	
		free(usr);
	}
}

void clean(pam_handle_t *pamh UNUSED, void *data, int err UNUSED)
{
	clean_pam_user((struct pam_user *)data);
}

static struct pam_user *init_pam_user(void)
{ 
	struct pam_user *usr;
	if (!(usr = malloc(sizeof(*usr)))) {
		D(("memory allocation error: %m"));
		return NULL;
	}
	usr->name = NULL;
	usr->tty = NULL;
	memset(usr->cwd, '\0', sizeof(usr->cwd));
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

int get_pam_user(pam_handle_t *pamh, struct control ctrl, struct pam_user **user) 
{
	int err;
	struct pam_user *usr;

	if (!(usr = init_pam_user())) {
		_pam_syslog(pamh, LOG_CRIT, "malloc() failure");
		return PAM_SYSTEM_ERR;
	}
	
	if (!(usr->name = get_user_item(pamh, PAM_USER, &err))) {
		_pam_syslog(pamh, LOG_ERR, "cannot get username");
		goto error;
	}
	
	if (!(usr->tty = get_user_item(pamh, PAM_TTY, &err))) 
		_pam_syslog(pamh, LOG_ERR, "cannot get tty");
	
	if (!getcwd(usr->cwd, sizeof(usr->cwd))) {
		_pam_syslog(pamh, LOG_ERR, "cannot get working directory: %m");
		goto error;
	}

	if (!(usr->pwd = pam_modutil_getpwnam(pamh, usr->name))) {
		_pam_syslog(pamh, LOG_ERR, "cannot get passwd set: %m");
		goto error;
	}
	
	*user = usr;
	return PAM_SUCCESS;
error:
	_pam_syslog(pamh, LOG_NOTICE, "failed to recover user information");
	clean_pam_user(usr);
	*user = NULL;
	return (err) ? err : PAM_SYSTEM_ERR;
}

static int unix_group(pam_handle_t *pamh, const char *grp_name, struct pam_group *grp)
{
	size_t i;
	int sv_errno = errno;
	
	if (!grp_name)
	       return GROUP_BAD_CONF;

	errno = 0;
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
			_pam_syslog(pamh, LOG_ERR, "failed to get %s group: %m",
				    grp_name);
			errno = sv_errno;
			return PAM_SYSTEM_ERR;
		}
	}

	errno = sv_errno;
	for (i = 0; grp->ux_grp->gr_mem[i]; i++, grp->nb_users++);
	return PAM_SUCCESS;
}

int group_authenticate(pam_handle_t *pamh, struct control ctrl, struct pam_user *user)
{
	int retval;
	struct pam_group grp = {
		.ux_grp = NULL,
		.nb_users = 0,
		.quorum = 0	
	};	

	retval = unix_group(pamh, ctrl.group, &grp);
	switch (retval) {
	case GROUP_BAD_CONF:
		_pam_syslog(pamh, LOG_ALERT, "ALERT: bad value for group option");
		_pam_info(pamh, ctrl.opt, "ALERT: bad value for group option");
		return GROUP_BAD_CONF;
	case PAM_SYSTEM_ERR:
		return PAM_SYSTEM_ERR;
	}

	if (!in_group_nam(user->name, grp.ux_grp->gr_name)) {
		_pam_syslog(pamh, LOG_INFO, "user %s is not in %s group", 
			    user->name, ctrl.group);
		_pam_syslog(pamh, LOG_NOTICE, "group authentication failure");
		_pam_info(pamh, ctrl.opt, "you are not in a privileged group");
		return USR_NOT_INGRP;
	}
	
	user->grp = grp;
	return PAM_SUCCESS;
}

int group_quorum(pam_handle_t *pamh, struct control ctrl, struct pam_user *user)
{
	if (ctrl.quorum < 2 || ctrl.quorum > user->grp.nb_users) {
		_pam_syslog(pamh, LOG_ALERT, "ALERT: bad value for quorum option");
		_pam_info(pamh, ctrl.opt, "ALERT: bad value for quorum option");
		return QUORUM_BAD_CONF;
	}

	user->grp.quorum = ctrl.quorum;
	return PAM_SUCCESS;
}

static int make_command_dir(pam_handle_t *pamh)
{
	if (mkdir(CMD_DIR, 0755)) {
		_pam_syslog(pamh, LOG_ERR, "mkdir() error: %m");
		return PAM_SYSTEM_ERR;
	}

	return PAM_SUCCESS;
}

int check_dir_access(pam_handle_t *pamh, struct control ctrl)
{
	struct stat st;

	if (lstat(CMD_DIR, &st) < 0) {
		if (errno == ENOENT || errno == ENOTDIR)
			return make_command_dir(pamh);
		_pam_syslog(pamh, LOG_ERR, "lstat() error: %m");
		return PAM_SYSTEM_ERR;
	}

	if (st.st_uid != 0 || st.st_gid != 0 || !(S_ISDIR(st.st_mode)) || 
			!((S_IRUSR & st.st_mode) &&  (S_IWUSR & st.st_mode) && 
	  		  (S_IXUSR & st.st_mode) &&  (S_IRGRP & st.st_mode) &&
			 !(S_IWGRP & st.st_mode) &&  (S_IXGRP & st.st_mode) &&
			  (S_IROTH & st.st_mode) && !(S_IWOTH & st.st_mode) &&
			  (S_IXOTH & st.st_mode))) {
		_pam_syslog(pamh, LOG_ALERT, "ALERT: bad mode for %s", CMD_DIR);
		_pam_info(pamh, ctrl.opt, "ALERT: bad mode for %s", CMD_DIR);
		return BAD_CONF;
	}

	return PAM_SUCCESS;
}

int preauth_error(int err)
{
	switch (err) {
	case GROUP_BAD_CONF:
	case QUORUM_BAD_CONF:
	case BAD_CONF:
		return PAM_IGNORE;
	case USR_NOT_INGRP:
		return PAM_AUTH_ERR;
	}
	
	return PAM_SYSTEM_ERR;
}

static int get_cmdline_argv(pam_handle_t *pamh, struct sudo_cmd *cmd)
{
	size_t i, n;
	char *command = cmd->cmdline;
	cmd->argc = 0;
	
	for (i = 0; i < cmd->len; i++)
		if (cmd->cmdline[i] == '\0')
			cmd->argc++;

	cmd->argv = malloc(cmd->argc * sizeof(*cmd->argv));
	if (!cmd->argv) {
		D(("memory allocation error: %m"));
		_pam_syslog(pamh, LOG_CRIT, "malloc() failure");
		return PAM_SYSTEM_ERR;
	} 

	for (i = 0; i < (size_t)cmd->argc; i++) {
		n = strlen(command);
		cmd->argv[i] = calloc(n + 1, sizeof(char));
		if (!cmd->argv[i]) 
			goto calloc_error;
		memmove(cmd->argv[i], command, n);
		command += n + 1;
	}

	return PAM_SUCCESS;
calloc_error:
	D(("memory allocation error: %m"));
	_pam_syslog(pamh, LOG_CRIT, "calloc() failure");
	while (i)
		free(cmd->argv[--i]);
	free(cmd->argv);
	return PAM_SYSTEM_ERR;
}

void clean_command(struct sudo_cmd *cmd)
{
	size_t i;

	if (!cmd)
		return;
	
	for (i = 0; i < (size_t)cmd->argc; i++)
		free(cmd->argv[i]);
	free(cmd->argv);
	free(cmd->cmdline);
	free(cmd);
}

struct sudo_cmd *get_command(pam_handle_t *pamh)
{
	int fd;
	ssize_t n;
	size_t arg_max = (size_t)sysconf(_SC_ARG_MAX);
	struct sudo_cmd *cmd = malloc(sizeof(*cmd));
	
	D(("ARG_MAX = %zd", arg_max));
	
	if (!cmd) {
		D(("memory allocation error: %m"));
		_pam_syslog(pamh, LOG_CRIT, "malloc() failure");
		return NULL;
	}	

	fd = open(CMDLINE, O_RDONLY);
	if (fd < 0) {
		D(("open %s error: %m", CMDLINE));
		_pam_syslog(pamh, LOG_CRIT, "open %s failure: %m", CMDLINE);
		free(cmd);
		return NULL;

	}	
	/* XXX: too much higher. Free it after read and alloc a new buffer of 
	 *	size n (return of read) */
	cmd->cmdline = calloc(arg_max, sizeof(*cmd->cmdline));
	if (!cmd->cmdline) {
		D(("memory allocation error: %m"));
		_pam_syslog(pamh, LOG_CRIT, "calloc() failure");
		free(cmd);
		close(fd);
		return NULL;
	}
	/* XXX: it is considered that the content of the file cannot exceed 
	 *	arg_max and that read() reads the entire file at once */
	n = read(fd, cmd->cmdline, arg_max);
	close(fd);
	if (n < 0) {
		D(("read() error: %m"));
		_pam_syslog(pamh, LOG_CRIT, "read() failure");
		free(cmd->cmdline);
		free(cmd);
		return NULL;
	}	

	cmd->len = (size_t)n;
	if (get_cmdline_argv(pamh, cmd) == PAM_SYSTEM_ERR) {
		free(cmd->cmdline);
		free(cmd);
		return NULL;
	}

	str_replace(cmd->cmdline, cmd->len - 1, '\0', ' ');
	return cmd;	
}

static int do_checklink(struct sudo_cmd *cmd, struct sudo_cmd *cmd_copy)
{
	size_t i;
	char *ln;

	for (i = 0; i < (size_t)cmd->argc; i++) {
		if ((ln = is_a_symlink(cmd->argv[i], 0))) {
			if (strcmp(ln, cmd_copy->argv[i])) {
				_pam_syslog(NULL, LOG_ALERT, 
					"a link has been modified (%s -> %s)",
					cmd->argv[i], ln);
				free(ln);
				return PAM_AUTH_ERR;
			}
			free(ln);
		}
	}
	
	return PAM_SUCCESS;
}

int checklink(pam_handle_t *pamh, struct sudo_cmd *cmd, struct sudo_cmd **cmd_copy)
{
	size_t i;
	struct sudo_cmd *cmdcp;
	static int do_check = 0; /* XXX: replace by arg */

	if (do_check) 
		return do_checklink(cmd, *cmd_copy);

	cmdcp = calloc(1, sizeof(*cmdcp));
	if (!cmdcp) {
		D(("memory allocation error: %m"));
		_pam_syslog(pamh, LOG_CRIT, "calloc() failure");
		*cmd_copy = NULL;
		return PAM_SYSTEM_ERR;
	}

	cmdcp->argc = cmd->argc;
	cmdcp->argv = malloc(cmd->argc * sizeof(char *));
	if (!cmdcp->argv) {
		D(("memory allocation error: %m"));
		_pam_syslog(pamh, LOG_CRIT, "malloc() failure");
		free(cmdcp);
		*cmd_copy = NULL;
		return PAM_SYSTEM_ERR;
	} 

	for (i = 0; i < (size_t)cmdcp->argc; i++) {
		if ((cmdcp->argv[i] = is_a_symlink(cmd->argv[i], 0))) {
			_pam_syslog(pamh, LOG_INFO, "'%s' point to '%s'", 
					cmd->argv[i], cmdcp->argv[i]);
			continue;
		}
		cmdcp->argv[i] = strdup(cmd->argv[i]);	
		if (!cmdcp->argv[i]) 
			goto strdup_error;
	}

	do_check = 1;
	*cmd_copy = cmdcp;
	return PAM_SUCCESS;
strdup_error:
	D(("memory allocation error: %m"));
	_pam_syslog(pamh, LOG_CRIT, "strdup() failure");
	while (i)
		free(cmdcp->argv[--i]);
	free(cmdcp->argv);
	free(cmdcp);
	*cmd_copy = NULL;
	return PAM_SYSTEM_ERR;
}

