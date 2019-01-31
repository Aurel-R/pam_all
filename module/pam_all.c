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
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/socket.h>
#include "pam.h"
#include "utils.h"
#include "protocol.h"

static struct control _pam_parse(pam_handle_t *pamh, int flags, 
						int argc, const char **argv)
{
	int ret;
	struct control ctrl = { 
		.opt = PAM_ECHO, 
		.timeout = DEFAULT_TIMEOUT, 
		.group = NULL, 
		.quorum = 0 
	};

	for (; argc--; argv++) {
		if (!strcmp(*argv, "debug")) {
			SET(ctrl.opt, PAM_DEBUG_ARG);
			D(("debug option set"));
		} else if (!strcmp(*argv, "silent")) {
			UNSET(ctrl.opt, PAM_ECHO);
			D(("silent option set"));
		} else if (!strncmp(*argv, "timeout=", 8)) { /* 0 = inf */
			ctrl.timeout = strtou(*argv + 8, &ret);
			if (ret) {
				_pam_syslog(pamh, LOG_ERR, "invalid timeout value");
				ctrl.timeout = DEFAULT_TIMEOUT;
			}
			D(("timeout value set (%d)", ctrl.timeout));
		} else if (!strncmp(*argv, "group=", 6)) {
		       ctrl.group = *argv + 6;
			D(("unix group value set (%s)", ctrl.group));
		} else if (!strncmp(*argv, "quorum=", 7)) {
			ctrl.quorum = strtou(*argv + 7, &ret);
			if (ret) 
				_pam_syslog(pamh, LOG_ERR, "invalid quorum value");
			D(("quorum value set (%d)", ctrl.quorum));		
		} else {
			_pam_syslog(pamh, LOG_ERR, "unknow option: %s", *argv);
		}
	}
/*
	if (_IS_SET(flags, PAM_SILENT)) {
		UNSET(ctrl.opt, PAM_ECHO);
		D(("silent option set"));
	}
*/
	return ctrl;
}

PAM_EXTERN 
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	int retval, srv_fd;
	struct pam_user *user;
	const char *saname, *tmpname;
	struct sudo_cmd *cmd, *cmd_copy;
        struct control ctrl = _pam_parse(pamh, flags, argc, argv);

	if ((retval = get_pam_user(pamh, ctrl, &user))      != PAM_SUCCESS ||
	    (retval = group_authenticate(pamh, ctrl, user)) != PAM_SUCCESS ||
	    (retval = group_quorum(pamh, ctrl, user))	    != PAM_SUCCESS ||
	    (retval = check_dir_access(pamh, ctrl))	    != PAM_SUCCESS)
		return preauth_error(user, retval);

	if (_IS_SET(ctrl.opt, PAM_DEBUG_ARG)) {
		_pam_syslog(pamh, LOG_INFO, "user %s is set in %s group (quorum=%u)",
			user->name, user->grp.ux_grp->gr_name, user->grp.quorum);
	}

	cmd = get_command(pamh);
	if (!cmd) {
		clean(pamh, user, PAM_SYSTEM_ERR);
		return PAM_SYSTEM_ERR;
	}

	retval = checklink(pamh, cmd, &cmd_copy);
	if (retval != PAM_SUCCESS)
		goto end;

	srv_fd = start_request_srv(pamh, &saname);
	if (srv_fd < 0 || !saname) {
		retval = PAM_SYSTEM_ERR;
		goto end; 
	}

	retval = set_request(pamh, user, ctrl, saname, cmd, &tmpname);
	if (retval != PAM_SUCCESS)
		goto end_srv;

	_pam_syslog(pamh, LOG_INFO, "starting request for user %s", user->name);
	_pam_info(pamh, ctrl.opt, "waiting for validation...");

	retval = wait_for_validation(pamh, user, ctrl, srv_fd);
	if (retval == PAM_SUCCESS)
		retval = checklink(pamh, cmd, &cmd_copy);
	
	switch (retval) {
	case PAM_SUCCESS:
		_pam_syslog(pamh, LOG_INFO, "command has been validated");
		_pam_info(pamh, ctrl.opt, "command has been validated");
		break;
	case PAM_AUTH_ERR:
		_pam_syslog(pamh, LOG_NOTICE, "authentication has failed");
		break;
	case TIMEOUT:
		_pam_syslog(pamh, LOG_INFO, "request timeout");
		_pam_info(pamh, ctrl.opt, "request timeout");
		break;
	case CANCELED:
		_pam_syslog(pamh, LOG_INFO, "command has been canceled");
		break;
	case ABORTED:
		_pam_syslog(pamh, LOG_INFO, "command has been aborted");
		break;
	case REFUSED:
		_pam_syslog(pamh, LOG_INFO, "command has been refused");
		_pam_info(pamh, ctrl.opt, "command has been refused");
		break;
	default:
		_pam_syslog(pamh, LOG_ERR, "internal error occured(%d): %m", retval);
		break;
	}
	
	unlink(tmpname); 
end_srv:
	close(srv_fd);
end:
	clean_command(cmd);
	clean_command(cmd_copy);
	clean(pamh, user, retval);
	return (retval != PAM_SUCCESS) ? PAM_AUTH_ERR : retval;
}

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

