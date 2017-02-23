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
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/limits.h>
#include <sys/mman.h>
#include <syslog.h>
#include <signal.h>
#include <sudo_plugin.h>
#include "pam.h"
#include "command_info.h"
#include "../common/utils.h"
#include "../crypto/crypto.h"
#include "prot.h"

static int io_sudo_call = 0;
static struct sudo_command command;
static struct control _pam_parse(pam_handle_t *pamh, int argc, const char **argv);
static int _pam_terminate(pam_handle_t *pamh, int status); 

#define __dso_public __attribute__((__visibility__("default")))

static struct control _pam_parse(pam_handle_t *pamh, int argc, const char **argv)
{
	struct control ctrl = { .opt = 0x00, .timeout = DEFAULT_TIMEOUT, 
				.group = NULL, .quorum = 0 };

	for (; argc--; argv++) {
		if (!strcmp(*argv, "debug")) {
			SET(ctrl.opt, PAM_DEBUG_ARG);
			D(("debug option set"));
		} else if (!strncmp(*argv, "timeout=", 8)) { 
			ctrl.timeout = atoi(*argv + 8);
			D(("timeout value set (%d)", ctrl.timeout));
		} else if (!strncmp(*argv, "group=", 6)) {
		       ctrl.group = *argv + 6;
			D(("unix group value set (%s)", ctrl.group));
		} else if (!strncmp(*argv, "quorum=", 7)) {
			ctrl.quorum = atoi(*argv + 7);
			D(("quorum value set (%d)", ctrl.quorum));		
		} else {
			_pam_syslog(pamh, LOG_ERR, "unknow option: %s", *argv);
		}
	}

	return ctrl;
}

PAM_EXTERN 
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	int err;
        struct control ctrl;
	struct pam_user *user = NULL;
	const void *service = NULL;

	ctrl = _pam_parse(pamh, argc, argv);
	ssl_init(pamh, ctrl.opt, SOFT_INIT);
	SET(ctrl.opt, PAM_ECHO);
	
	err = pam_get_item(pamh, PAM_SERVICE, &service);
	if (err != PAM_SUCCESS || !service) {
		D(("pam_get_item returned: %s (%d)", D_ERR(err), err));
		_pam_syslog(pamh, LOG_ERR, "failed to determine the service");
		return (err) ? err : PAM_SYSTEM_ERR;
	}

	if (_IS_SET(ctrl.opt, PAM_DEBUG_ARG)) {
		_pam_syslog(pamh, LOG_DEBUG, "called by %s", (char *)service);
		_pam_syslog(pamh, LOG_DEBUG, "timeout=%d group=%s quorum=%d",
			    ctrl.timeout, ctrl.group, ctrl.quorum);
	}	

	err  = user_authenticate(pamh, ctrl, &user);
	err |= group_authenticate(pamh, ctrl, &user); 
	err |= group_quorum(pamh, ctrl, &user); 
	switch (err) {	
	case GROUP_BAD_CONF:
	case QUORUM_BAD_CONF:
	case BAD_CONF:	
		if ((err = pam_set_data(pamh, STATUS, "WW", NULL)) != PAM_SUCCESS) {
			_pam_syslog(pamh, LOG_ERR, "set status error: %s (%d)",
				    D_ERR(err), err);
			return err;
		}
		return PAM_IGNORE; 
	case SUCCESS:
		if ((err = pam_set_data(pamh, STATUS, "OK", NULL)) != PAM_SUCCESS) {
			_pam_syslog(pamh, LOG_ERR, "set status error: %s (%d)",
				    D_ERR(err), err);
			return err;
		}
		break;
	case NO_USR_GRP:
		return PAM_AUTH_ERR;
	default: 
		return err;
	}	

	_pam_syslog(pamh, LOG_INFO, "user %s is set in %s group (quorum=%d)",
		    user->name, user->grp.ux_grp->gr_name, user->grp.quorum);
	ssl_init(pamh, ctrl.opt, FULL_INIT);
	if (verify_user_entry(user) == ERR && create_user_entry(user) == ERR) {
		clean(pamh, user, ERR);
		ssl_release();
		return PAM_AUTH_ERR;
	}
	ssl_release();

	if (!strncmp((const char *)service, SERVICE_NAME, strlen(SERVICE_NAME))) {
		if ((err = pam_set_data(pamh, DATA, user, clean)) != PAM_SUCCESS) {
			_pam_syslog(pamh, LOG_ERR, "set data error: %s (%d)", 
				    D_ERR(err), err);
			clean(pamh, user, ERR);
			return err;
		}
	} else { 
		clean(pamh, user, SUCCESS);
	}	
	
	return PAM_SUCCESS;
}

/* Called when the user change his password (update the key pair) */
PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int err;
        struct control ctrl;
	struct pam_user *user = NULL;
	const void *service = NULL;
	const void *old_p = NULL;
	const void *new_p = NULL;
	
	ctrl = _pam_parse(pamh, argc, argv);
	ssl_init(pamh, ctrl.opt, SOFT_INIT);
	
	err = pam_get_item(pamh, PAM_SERVICE, &service);
	if (err != PAM_SUCCESS || !service) {
		D(("pam_get_item returned: %s (%d)", D_ERR(err), err));
		_pam_syslog(pamh, LOG_ERR, "failed to determine the service");
		return (err) ? err : PAM_SYSTEM_ERR;
	}

	if (_IS_SET(ctrl.opt, PAM_DEBUG_ARG)) {
		_pam_syslog(pamh, LOG_DEBUG, "called by %s", (char *)service);
		_pam_syslog(pamh, LOG_DEBUG, "timeout=%d group=%s quorum=%d",
			    ctrl.timeout, ctrl.group, ctrl.quorum);
	}	

	if ((err = pam_get_item(pamh, PAM_AUTHTOK, &new_p)) != PAM_SUCCESS ||
	    (err = pam_get_item(pamh, PAM_OLDAUTHTOK, &old_p)) != PAM_SUCCESS) {
		D(("pam_get_item returned: %s (%d)", D_ERR(err), err));
		_pam_syslog(pamh, LOG_ERR, 
			    "authentication information can not be recovered");
		return err;
	}

	if (new_p == NULL)
	       return PAM_IGNORE;	

	err  = user_authenticate(pamh, ctrl, &user);
	err |= group_authenticate(pamh, ctrl, &user); 
	switch (err) {
	case NO_USR_GRP:
		return PAM_IGNORE;
	case SUCCESS:
		break;
	case GROUP_BAD_CONF:
	default:
		return PAM_SYSTEM_ERR;	
	}

	if (_IS_SET(ctrl.opt, PAM_DEBUG_ARG))
		_pam_syslog(pamh, LOG_DEBUG, "key pair of user %s will be updated",
			    user->name);	
	ssl_init(pamh, ctrl.opt, FULL_INIT);
	err = create_user_entry(user);
	clean(pamh, user, err);
	ssl_release();
	return (err) ? PAM_AUTHTOK_ERR : PAM_SUCCESS; 
}

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int err, srv_fd;
        struct control ctrl;
	struct pam_user *user = NULL;
	struct req_info req;
	const void *service = NULL;
	const char *saname = NULL;
	const char *tmpnam = NULL;

	ctrl = _pam_parse(pamh, argc, argv);
	ssl_init(pamh, ctrl.opt, SOFT_INIT);
	SET(ctrl.opt, PAM_ECHO);
	
	err = pam_get_item(pamh, PAM_SERVICE, &service);
	if (err != PAM_SUCCESS || !service) {
		D(("pam_get_item returned: %s (%d)", D_ERR(err), err));
		_pam_syslog(pamh, LOG_ERR, "failed to determine the service");
		return _pam_terminate(pamh, ((err) ? err : PAM_SYSTEM_ERR));
	}

	if (_IS_SET(ctrl.opt, PAM_DEBUG_ARG)) {
		_pam_syslog(pamh, LOG_DEBUG, "called by %s", (char *)service);
		_pam_syslog(pamh, LOG_DEBUG, "timeout=%d group=%s quorum=%d",
			    ctrl.timeout, ctrl.group, ctrl.quorum);
	}

	if ((err = get_auth_status(pamh)) != SUCCESS ||
	    (err = get_auth_data(pamh, &user) != SUCCESS))
		return _pam_terminate(pamh, err);	

	if (!io_sudo_call) {
		_pam_syslog(pamh, LOG_ERR, "sudo io_plugin was probably not called");
		_pam_info(pamh, ctrl.opt, "sudo io_plugin was probably not called");
		return _pam_terminate(pamh, AUTH_WARN);
	}
	
	/* TODO: add 'check_link' fct (man 2 access) */

	srv_fd = start_request_srv(pamh, &saname);
	if (srv_fd < 0 || !saname) 
		return _pam_terminate(pamh, PAM_SYSTEM_ERR);
	
	ssl_init(pamh, ctrl.opt, FULL_INIT);
	req = set_request(pamh, user, saname, command, &tmpnam);
	if (!req.req_ptr || !tmpnam) {
		err = PAM_SYSTEM_ERR;
		goto end;
	}
	
	_pam_syslog(pamh, LOG_NOTICE, "starting request for user %s", user->name);
	_pam_info(pamh, ctrl.opt, "waiting for validation...");	
	
	err = wait_validation(pamh, user, req.req_ptr->nonce, ctrl, srv_fd);
	switch(err) {
	case SUCCESS:
	case TIMEOUT:
	case CANCELED:
	case ABORTED:
		_pam_syslog(pamh, LOG_NOTICE, "command aborted");
		break;
	case REFUSED:
	default:
		_pam_syslog(pamh, LOG_ERR, "an internal error occured(%d): %m", err);
		break;
	}	

	/* TODO: (only on success) re-call 'check_link' (security symlink check) */
end:
	close(srv_fd);
	unlink(tmpnam); 
	ssl_release();
	if (req.req_ptr)
		munmap(req.req_ptr, req.len); 
	return (err) ? _pam_terminate(pamh, PAM_SYSTEM_ERR) : PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return pam_set_data(pamh, DATA, NULL, NULL);
}

/* sudoers (< 1.8.15) does not detect if the module session failed. */
static int _pam_terminate(pam_handle_t *pamh, int status) 
{
	pam_set_data(pamh, DATA, NULL, NULL);
#ifdef COMPATIBLE_SUDOERS
	return (status == AUTH_WARN) ? PAM_IGNORE : status;
#else
	return (status == AUTH_WARN) ? PAM_IGNORE : raise(SESSION_STOP);
#endif
}	

/*
 * Called by sudo directly.
 * It is used to obtain the command line.
 */
static int io_open(unsigned int version, sudo_conv_t conversation, 
		   sudo_printf_t sudo_printf, char *const settings[], 
		   char *const user_info[], char *const cmd_info[], 
		   int argc, char *const argv[], char *const user_env[], 
		   char *const args[])
{
	D(("pam_io_shared opened"));
	io_sudo_call = 1;
	command.argc = argc;
	command.argv = (char **)argv;
	for (command.path = NULL; cmd_info && *cmd_info; cmd_info++) {
		if (strncmp(*cmd_info, "command=", 8) == 0)
			command.path = *cmd_info + 8;
	}

	if (command.path && command.argv && command.argv[0])
		command.argv[0] = command.path;	

	return 1;
}

static void io_close(int exit_status, int error)
{	
	D(("pam_io_shared closed"));
}

__dso_public struct io_plugin pam_shared_io = {
	SUDO_IO_PLUGIN,
	SUDO_API_VERSION,
	io_open,
	io_close,
};	

