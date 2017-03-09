#define _GNU_SOURCE
#define __USE_GNU
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <poll.h>
#include <signal.h>
#include <pwd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <linux/limits.h>
#include <termios.h>
#include "pam.h"
#include "command_info.h"
#include "../common/cma.h"
#include "../common/utils.h"
#include "../crypto/crypto.h"
#include "prot.h"

/* TODO: add log */

int start_request_srv(pam_handle_t *pamh, const char **sock_name)
{
	int err, sock_fd;
	static struct sockaddr_un sun;
	socklen_t len = sizeof(struct sockaddr_un);

	sock_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock_fd < 0) {
		_pam_syslog(pamh, LOG_ERR, "create connection point error: %m");
		return sock_fd;
	}

	sun.sun_family = AF_UNIX;
	err = bind(sock_fd, (const struct sockaddr *)&sun, sizeof(sa_family_t));
	if (err < 0) {
		_pam_syslog(pamh, LOG_ERR, "assign sock name error: %m");
		goto sock_err;
	}

	err = listen(sock_fd, 20);
	if (err < 0) {
		_pam_syslog(pamh, LOG_ERR, "server listen error: %m");
		goto sock_err;
	}

	/* The abstract name (autobind by the kernel) is not
	 * fill in the sockaddr_un when bind() is call. It
	 * is necessary to call getsockname() to get the 
	 * abstract socketname. */
	err = getsockname(sock_fd, (struct sockaddr *)&sun, &len);
	if (err < 0) {
		_pam_syslog(pamh, LOG_ERR, "can not get the abstract name: %m");
		goto sock_err;
	}
	
	*sock_name = sun.sun_path;
	return sock_fd;
sock_err:
	close(sock_fd);
	return err;
}

/* XXX: rewrite */
static struct req *fill_request(struct pam_user *usr, const char *addr,
				struct sudo_command cmd)
{
	int i;
	struct req *r;
	size_t len, cmd_len, offset;

	if (cma(&r, sizeof(*r)))
		return NULL;

	len = strlen(usr->name) + 1;
	if (len > sizeof(r->user))
		return NULL;
	memmove(r->user, usr->name, len);
	memmove(r->saddr, addr, sizeof(r->saddr));

	if (cma(&r->datas, sizeof(*r->datas)))
		return NULL;
	
	if (ptr_to(&r->datas->usr, r->user))
		return NULL;	
	
	r->datas->pid = getpid();
	
	if (usr->tty) {
		len = strlen(usr->tty);
		if (cma(&r->datas->tty, len + 1))
			return NULL;
		memmove(r->datas->tty, usr->tty, len);
	} else {
		if (cma(&r->datas->tty, 1))
			return NULL;
	}
	
	len = strlen(usr->cwd);
	if (cma(&r->datas->pwd, len + 1))
		return NULL;
	memmove(r->datas->pwd, usr->cwd, len);

	for (i = 0, cmd_len = 0; i < cmd.argc; i++)
		cmd_len += strlen(cmd.argv[i]) + 1;
	if (cma(&r->datas->cmd, cmd_len))
		return NULL;
	for (offset = 0, i = 0; i < cmd.argc; i++) {
		len = strlen(cmd.argv[i]) + 1;
		snprintf(r->datas->cmd+offset, len + 1, "%s ", cmd.argv[i]);
		offset += len;
	}

	r->datas->cmd[cmd_len - 1] = '\0';
	return r;
}

static int sign_request(struct pam_user *usr, struct req *request)
{
	int retval = SUCCESS;
	unsigned char *md = NULL;
	size_t len = cm_get_size() - sizeof(struct req);

	if (random_bytes(request->nonce, sizeof(request->nonce)))
		return PROT_ERR;
	
	if (digest(request->user, sizeof(request->user), NULL)   ||
	    digest(request->saddr, sizeof(request->saddr), NULL) ||
	    digest(request->nonce, sizeof(request->nonce), NULL) ||
	    digest(request->datas, len, &md)			 ||
	    sign(usr, request->sig, md)) 
		retval = PROT_ERR;
	
	digest_clean(md);
	return retval;
}

struct req_info set_request(pam_handle_t *pamh, struct pam_user *usr, 
			    const char *addr, struct sudo_command cmd, 
			    const char **name)
{
	int cm_fd;
	static char path[PATH_MAX];
	struct req *request;
	struct req_info info = { .req_ptr = NULL };
	
	memset(path, '\0', sizeof(path));
	snprintf(path, sizeof(path)-1, "%sreq-XXXXXX", CMD_DIR);
	cm_fd = mkstemp(path);		
	if (cm_fd < 0) {
		_pam_syslog(pamh, LOG_ERR, "can not create tmp file: %m");
		return info;
	}
	
	if (fchown(cm_fd, -1, usr->grp.ux_grp->gr_gid) < 0 ||
	    fchmod(cm_fd, 0640) < 0) {
		_pam_syslog(pamh, LOG_ERR, "failed to set cred: %m");
		goto err;	
	}
	
	cm_set_properties(cm_fd, MAP_SHARED, 0);
	request = fill_request(usr, addr, cmd);
	if (!request || sign_request(usr, request))
		goto err;
	if ((info.req_ptr = cm_sync(MS_SYNC)) == NULL)
		goto err;

	*name = path;
	info.len = cm_free(PRESERVE_MAP);
	close(cm_fd);
	return info;
err:
	_pam_syslog(pamh, LOG_ERR, "failed to set request: %m");
	cm_free(DELETE_MAP);
	close(cm_fd);
	unlink(path);
	info.req_ptr = NULL;
	return info;
}

static pam_handle_t _pamh;
static int _ctrl;

struct poll_table {
	struct pollfd *fds;
	struct pam_user **usrs;
	size_t nmemb;
	unsigned int ncon;
};

/* Add a opened flag before read a request
 * Add a validate flag to save user choice */

static struct poll_table poll_init(int fd, size_t n)
{
	int i;
	struct poll_table pt = { .fds = NULL, .usrs = NULL, 
				 .nmemb = 0, .ncon = 0 };

	if (!(pt.fds = calloc(n, sizeof(struct pollfd))) ||
	    !(pt.usrs = calloc(n, sizeof(struct pam_user *)))) {
		F(pt.fds);
		return pt;
	}

	for (i = 0; i < n; i++)
		pt.fds[i].events = POLLIN | POLLRDHUP;

	pt.fds[0].fd = fd;
	pt.nmemb = n;
	pt.ncon = 1;
	return pt;
}

static void poll_clean(struct poll_table pt)
{
	int i;
	F(pt.fds);
	for (i = 0; i < pt.nmemb; i++)
		clean(pt.usrs[i]);
	F(pt.usrs);	
}

static int already_connected(int csock, struct ucred ccred, struct poll_table *pt)
{
	int i;
	for (i = 1; i < pt->ncon; i++) {
		if (pt->usrs[i]->pwd->pw_uid == ccred.uid) {
			close(pt->fds[i].fd);
			pt->fds[i].revents = 0;
			pt->fds[i].fd = csock;
			return 1;
		}
	}
	return 0;
}

static int new_connection(struct pam_user *usr, struct poll_table *pt)
{
	int err, csock;
	struct passwd *cpwd;
	struct ucred ccred;
	struct pam_user *cusr = NULL;
	socklen_t optlen = sizeof(struct ucred);
	
	csock = accept(fd, NULL, NULL);
	if (csock < 0)
		return PROT_ERR;
	
	err = getsockopt(csock, SOL_SOCKET, SO_PEERCRED, &ccred, &optlen); 
	if (err < 0)
		goto end;

	if (already_connected(csock, ccred, pt))
		return 0;	

	if ((cpwd = pam_modutil_getpwuid(_pamh, ccred.uid)) == NULL) {
		err = PROT_ERR;      	
		goto end;
	}

	if (!in_group_id(cpwd->pw_uid, usr->grp.ux_grp->gr_gid)) {	
		_pam_syslog(_pamh, LOG_NOTICE, "untrusted user connection (%d:%s)",
			    cpwd->pw_uid, cpwd->pw_name);
		err = CONTINUE;
		goto end;
	}

	if ((cusr = calloc(1, sizeof(struct pam_user))) == NULL) {
		err = PROT_ERR;
		goto end;
	}

	cusr->pwd = cpwd;
	cusr->name = cpwd->pw_name;
	pt->fds[pt.ncon].fd = csock;
	pt->fds[pt.ncon].events = POLLIN | POLLRHUP;
	pt->fds[pt.ncon].revents = 0;
	pt->usrs[pt.ncon] = cusr;
	pt->ncon++;
end:
	if (err) {
		close(csock);
		clean(cusr);
	}
	return (err == CONTINUE) ? 0 : err;
}

static void close_connection(struct poll_table *pt, int *pos)
{
	close(pt->fd[*pos].fd);
	clean(pt->usrs[*pos]);
	pt->fd[*pos] = pt->fd[pt->ncon - 1];
	pt->usrs[*pos] = pt->usrs[pt->ncon - 1];	
	pt->ncon--;
	*pos--;
}

static int new_request()
{
	return 0;
}

static int handle_event(struct pam_user *usr, char *nonce, struct poll_table *pt)
{
	int i;
	int err = 0;

	for (i = 0; i < pt->ncon && (!err || err == CONTINUE); i++) {
		if (!pt->fds[i].revents)
			continue;
		if (pt->fds[i].revents && !i)
			err = new_connection(usr, pt);
		else if ((pt->fds[i].revents & POLLIN) && i)
			err = new_request();
		else /* i && POLLHUP | POLLRDHUP */
			close_connection(pt, &i);
	}
	
	return (err == CONTINUE) ? 0 : err;
}

static volatile sig_atomic_t got_SIGINT = 0;
static volatile sig_atomic_t got_SIGTERM = 0;

static void signal_handler(int signo)
{
	D(("SIGINT (or) SIGTERM handled : %d", signo));
	if (signo == SIGINT)
		got_SIGINT = 1;
	if (signo == SIGTERM)
		got_SIGTERM = 1;
}

static inline int abort_waiting(void)
{
	got_SIGINT = 0;
	got_SIGTERM = 0;
	return ABORTED;
}

static int set_signal(sigset_t *omask, struct sigaction *osa, 
			struct termios *oterm, int *tty)
{
	struct termios term;
	sigset_t sigmask;
	struct sigaction sa;

	if ((*tty = open(USER_TTY, O_RDWR | O_NOCTTY, 0)) < 0)
		return PROT_ERR;
	if (tcgetattr(*tty, oterm))
		goto err;
	memmove(&term, oterm, sizeof(term));
	SET(term.c_lflag, ISIG);
	if (tcsetattr(*tty, TCSANOW, &term))
		goto err;
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = 0;
	sa.sa_handler = signal_handler;
	if (sigemptyset(&sa.sa_mask) || sigaction(SIGINT, &sa, osa) ||
	    sigemptyset(&sigmask) || sigaction(SIGTERM, &sa, NULL)  ||
	    sigaddset(&sigmask, SIGINT) || sigaddset(&sigmask, SIGTERM) ||
	    sigprocmask(SIG_UNBLOCK, &sigmask, omask))
		goto err;
	return SUCCESS;
err:
	close(*tty);
	return PROT_ERR;		
}

static int unset_signal(sigset_t mask, struct sigaction sa, 
			struct termios term, int tty)
{
	int status;
	if (sigprocmask(SIG_SETMASK, &mask, NULL) || 
	    sigaction(SIGINT, &sa, NULL) || 
	    sigaction(SIGTERM, &sa, NULL))
		return PROT_ERR;
	status = tcsetattr(tty, TCSANOW, &term);
	close(tty);
	return status;
}

static inline int set_timeout(int timeout)
{
	timeout *= 1000;
	return (timeout < MIN_MS_TIMEOUT) ? MIN_MS_TIMEOUT : timeout;	
}

/* XXX: add *usr to poll_table ? [0] */
int wait_validation(pam_handle_t *pamh, struct pam_user *usr, char *nonce, 
		    struct control ctrl, int fd)
{
	_pamh = pamh;
	_ctrl = ctrl.opt 
	sigset_t o_sigmask;
	struct sigaction o_sa;
	struct termios o_term;	
	int tty_fd, status = 0;
	int set, timeout = set_timeout(ctrl.timeout);
	struct poll_table p = poll_init(fd, usr->grp.nb_users + 2);
	
	if (!p.nmemb)
		return PROT_ERR;

	if (set_signal(&o_sigmask, &o_sa, &o_term, &tty_fd)) { 
		poll_clean(p);
		return PROT_ERR;
	}
	
	while (!status) {
		set = poll(p.fds, p.ncon, timeout);
		if (set < 0 && errno != EINTR)
			status = ERR;	
		else if ((got_SIGINT || got_SIGTERM) || 
			 (set < 0 && errno == EINTR))
			status = abort_waiting();
		else if (set)
			status = handle_event(usr, nonce, &p);
		else
			status = TIMEOUT;		
	}

	if (unset_signal(o_sigmask, o_sa, o_term, tty_fd))
		status = PROT_ERR;

	poll_clean(p);
	return (status == VALIDATE) ? SUCCESS : status;
}



