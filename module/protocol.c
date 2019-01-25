#define _GNU_SOURCE
#define __USE_GNU
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <signal.h>
#include <pwd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <linux/limits.h>
#include <termios.h>
#include <time.h>
#include "pam.h"
#include "utils.h"
#include "protocol.h"


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
		_pam_syslog(pamh, LOG_ERR, "assign socket name error: %m");
		goto sock_err;
	}

	err = listen(sock_fd, 20);
	if (err < 0) {
		_pam_syslog(pamh, LOG_ERR, "server listen error: %m");
		goto sock_err;
	}

	err = getsockname(sock_fd, (struct sockaddr *)&sun, &len);
	if (err < 0) {
		_pam_syslog(pamh, LOG_ERR, "cannot get the abstract name: %m");
		goto sock_err;
	}
	
	*sock_name = sun.sun_path;
	return sock_fd;
sock_err:
	close(sock_fd);
	return err;
}

static struct request fill_request(struct pam_user *usr, 
					unsigned timeout, const char *addr)
{
	size_t n1, n2;
	struct request req = { 0 };

	req.pid = getpid();
	n1 = sizeof(req.user) - 1;
	n2 = strlen(usr->name) + 1;
	memmove(req.user, usr->name, MIN(n1, n2));
	n1 = sizeof(req.tty) - 1;
	n2 = (usr->tty) ? strlen(usr->tty) + 1 : 0;
	memmove(req.tty, usr->tty, MIN(n1, n2));
	n1 = sizeof(req.pwd) - 1;
	n2 = strlen(usr->cwd) + 1;
	memmove(req.pwd, usr->cwd, MIN(n1, n2));
	req.start = time(NULL);
	req.end   = time(NULL) + timeout; 
	memmove(req.saddr, addr, UNIX_PATH_MAX);
	return req;
}

int set_request(pam_handle_t *pamh, struct pam_user *usr, struct control ctrl,
				const char *addr, struct sudo_cmd *cmd, 
				const char **name)
{
	int fd;
	ssize_t n;
	struct request req;
	static char path[PATH_MAX];

	memset(path, '\0', sizeof(path));
	snprintf(path, sizeof(path) - 1, "%s/req-XXXXXX", CMD_DIR);
	fd = mkstemp(path);		
	if (fd < 0) {
		_pam_syslog(pamh, LOG_ERR, "cannot create tmp file: %m");
		return PAM_SYSTEM_ERR;
	}
	
	if (fchown(fd, -1, usr->grp.ux_grp->gr_gid) < 0 ||
	    fchmod(fd, 0640) < 0) { 
		_pam_syslog(pamh, LOG_ERR, "failed to set cred: %m");
		goto err;
	}

	req = fill_request(usr, ctrl.timeout, addr);

	n = write(fd, &req, sizeof(struct request));
	if (n != sizeof(struct request)) {
		_pam_syslog(pamh, LOG_ERR, "write() error");
		goto err;	
	}
	
	n = write(fd, cmd->cmdline, cmd->len);
	if (n != (ssize_t)cmd->len) {
		_pam_syslog(pamh, LOG_ERR, "write() error");
		goto err;
	}
	
	if (fsync(fd) < 0) {
		_pam_syslog(pamh, LOG_ERR, "fsync() error: %m");
		goto err;
	}

	close(fd);
	*name = path;
	return PAM_SUCCESS;
err:
	close(fd);
	unlink(path);
	*name = NULL;
	return PAM_SYSTEM_ERR;
}

static int _opt;
static pam_handle_t *_pamh;
static volatile sig_atomic_t got_sig = 0;
static volatile sig_atomic_t got_sigalrm= 0;

struct poll_table {
	struct pollfd *fds;
	time_t *login_time;
	struct pam_user *usrs;
	struct ucred *validators;
	size_t nmemb;
	size_t ncon;
	size_t nvalidators;
};

static void signal_handler(int signo)
{
	D(("signal handled: %d", signo));
	if (signo == SIGINT || signo == SIGTERM)
		got_sig = 1;
	if (signo == SIGALRM)
		got_sigalrm = 1;
}

static int abort_waiting(void)
{
	int retval = CONTINUE;
	D(("abort_waiting() called"));

	if (got_sig)
		retval = ABORTED;
	if (got_sigalrm)
		retval = TIMEOUT;

	got_sig = 0;
	got_sigalrm = 0;
	return (retval == CONTINUE) ? 0 : retval;	
}

static int configure_signals(int timeout)
{
	int ret;
	struct termios term;
	sigset_t sigmask;
	struct sigaction sa;
	static int tty;
	static struct termios oterm;
	static sigset_t omask;
	static struct sigaction osa;
	static int unset = 0;

	if (unset) {
		if (sigprocmask(SIG_SETMASK, &omask, NULL) || 
	    	    sigaction(SIGINT, &osa, NULL) || 
	    	    sigaction(SIGTERM, &osa, NULL)) {
			_pam_syslog(_pamh, LOG_ERR, "unset signals error: %m");	
			close(tty);
			return PAM_SYSTEM_ERR;
		}
		ret = tcsetattr(tty, TCSANOW, &oterm);	
		close(tty);
		if (ret) {
			_pam_syslog(_pamh, LOG_ERR, "tcsetattr() error: %m");
			return PAM_SYSTEM_ERR;
		}
		return PAM_SUCCESS;
	}
	
	if ((tty = open(USER_TTY, O_RDWR | O_NOCTTY, 0)) < 0) {
		_pam_syslog(_pamh, LOG_ERR, "open() error: %m");
		return PAM_SYSTEM_ERR;
	}
	if (tcgetattr(tty, &oterm)) {
		_pam_syslog(_pamh, LOG_ERR, "tcgetattr() error: %m");
		goto err;
	}
	memmove(&term, &oterm, sizeof(term));
	SET(term.c_lflag, ISIG);
	if (tcsetattr(tty, TCSANOW, &term)) {
		_pam_syslog(_pamh, LOG_ERR, "tcsetattr() error: %m");
		goto err;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = 0;
	sa.sa_handler = signal_handler;
	if (sigemptyset(&sa.sa_mask) || sigaction(SIGINT, &sa, &osa) ||
	    sigemptyset(&sigmask) || sigaction(SIGTERM, &sa, NULL)   ||
	    sigaddset(&sigmask, SIGINT) || sigaddset(&sigmask, SIGTERM) ||
	    sigprocmask(SIG_UNBLOCK, &sigmask, &omask)) {
		_pam_syslog(_pamh, LOG_ERR, "set signals error: %m");
		goto err;
	}
	if (timeout > 0) {
		ret = alarm((unsigned)timeout);
		D(("sudo alarm = %u", ret)); /* I hope 0 */
		signal(SIGALRM, signal_handler);
	}
	unset = 1;
	return PAM_SUCCESS;
err:
	close(tty);
	return PAM_SYSTEM_ERR;	
	
}

static void poll_clean(struct poll_table *pt)
{
	size_t i;

	if (!pt)
		return;

	for (i = 1; i < pt->ncon; i++) 
		close(pt->fds[i].fd);
	
	free(pt->fds);
	free(pt->login_time);
	free(pt->usrs);
	free(pt->validators);
	free(pt);
}

static struct poll_table *poll_init(struct pam_user *usr, int fd)
{
	size_t i;
	size_t n = usr->grp.nb_users + 2;
	struct poll_table *pt = calloc(1, sizeof(*pt));

	if (!pt) {
		_pam_syslog(_pamh, LOG_CRIT, "calloc() failure");
		return NULL;
	}

	if (!(pt->fds = calloc(n, sizeof(struct pollfd)))    ||
	    !(pt->login_time = calloc(n, sizeof(time_t)))    ||
	    !(pt->usrs = calloc(n, sizeof(struct pam_user))) ||
	    !(pt->validators = calloc(n, sizeof(struct ucred)))) {
		_pam_syslog(_pamh, LOG_CRIT, "calloc() failure");
		poll_clean(pt);
		return NULL;
	}

	for (i = 0; i < n; i++)
		pt->fds[i].events = POLLIN | POLLRDHUP;

	pt->fds[0].fd = fd;
	pt->usrs[0] = *usr;
	pt->nmemb = n;
	pt->ncon = 1;
	pt->nvalidators = 0;
	return pt;
}

static int already_connected(int csock, struct ucred ccred, struct poll_table *pt)
{
	size_t i;
	for (i = 1; i < pt->ncon; i++) {
		if (pt->usrs[i].cred.uid == ccred.uid) {
			close(pt->fds[i].fd);
			pt->fds[i].revents = 0; 
			pt->fds[i].fd = csock;
			pt->login_time[i] = time(NULL);
			return 1;
		}
	}
	return 0;
}

static void kick_older(struct poll_table *pt)
{
	size_t i, older = 1;
	time_t current = time(NULL);
	double x, max = difftime(current, pt->login_time[older]);	

	for (i = 2; i < pt->ncon; i++) {
		x = difftime(current, pt->login_time[i]);
		if (x > max) {
			max = x;
			older = i;	
		}
	}

	close(pt->fds[older].fd);
	pt->ncon--;
	
	if (older < pt->ncon) {	
		pt->fds[older] = pt->fds[pt->ncon];
		pt->usrs[older] = pt->usrs[pt->ncon];
		pt->login_time[older] = pt->login_time[pt->ncon];
	}	
}

static int new_connection(int sfd, struct poll_table *pt)
{
	int err, csock;
	struct passwd *cpwd;
	struct ucred ccred; 
	struct pam_user cusr;
	socklen_t optlen = sizeof(struct ucred);
	gid_t gid = pt->usrs[0].grp.ux_grp->gr_gid;

	csock = accept(sfd, NULL, NULL);
	if (csock < 0) {
		_pam_syslog(_pamh, LOG_ERR, "accept() error: %m");
		return PAM_SYSTEM_ERR;
	}
	
	err = getsockopt(csock, SOL_SOCKET, SO_PEERCRED, &ccred, &optlen); 
	if (err < 0) {
		_pam_syslog(_pamh, LOG_ERR, "getsockopt() error: %m");
		err = PAM_SYSTEM_ERR;
		goto end;
	}

	if (already_connected(csock, ccred, pt))
		return 0;	

	if (!(cpwd = pam_modutil_getpwuid(_pamh, ccred.uid))) {
		_pam_syslog(_pamh, LOG_ERR, "getpwuid() error: %m");
		err = PAM_SYSTEM_ERR;      	
		goto end;
	}

	if (!in_group_id(cpwd->pw_uid, gid)) {
		_pam_syslog(_pamh, LOG_NOTICE, "untrusted user connection "\
				"(%d:%s)", cpwd->pw_uid, cpwd->pw_name);
		err = CONTINUE;
		goto end;
	}
	
	if (pt->ncon == pt->nmemb) 
		kick_older(pt);
	
	cusr.pwd = cpwd; 
	cusr.name = cpwd->pw_name; 
	cusr.cred = ccred;
	pt->fds[pt->ncon].fd = csock;
	pt->fds[pt->ncon].events = POLLIN | POLLRDHUP;
	pt->fds[pt->ncon].revents = 0;
	pt->login_time[pt->ncon] = time(NULL);
	pt->usrs[pt->ncon] = cusr;
	pt->ncon++;
end:
	if (err) close(csock);
	return (err == CONTINUE) ? 0 : err;
}

static void close_connection(struct poll_table *pt, size_t *pos)
{
	close(pt->fds[*pos].fd);
	pt->ncon--;
	
	if (*pos < pt->ncon) {
		pt->fds[*pos] = pt->fds[pt->ncon];
		pt->usrs[*pos] = pt->usrs[pt->ncon];
		pt->login_time[*pos] = pt->login_time[pt->ncon];	
		(*pos)--;
	}
}

static int recv_packet(int fd, struct msg_packet *msg)
{
	ssize_t n;
	struct msg_packet _msg;
	
	memset(&_msg, 0, sizeof(_msg));
	n = read(fd, &_msg, sizeof(_msg));
	if (n != sizeof(_msg)) {
		errno = (n < 0) ? errno : EBADMSG;
		_pam_syslog(_pamh, LOG_ERR, "recv packet error: %m");
		return PAM_SYSTEM_ERR;
	}

	*msg = _msg;
	return 0;
}

static int send_packet(int fd, struct msg_packet msg)
{
	ssize_t n = write(fd, &msg, sizeof(msg));

	if (n != sizeof(msg)) {
		_pam_syslog(_pamh, LOG_ERR, "send packet error: %m");
		return PAM_SYSTEM_ERR;
	}

	return 0;
}

static int send_info_packet(int fd, const char *info)
{
	struct msg_packet msg;
	size_t info_len = strlen(info) + 1;
	size_t len = (info_len > DATA_BUFF_LEN) ? DATA_BUFF_LEN - 1 : info_len;
	
	memset(&msg, 0, sizeof(msg));
	msg.code = SERVER_INFO;
	memmove(msg.data, info, len);
	return send_packet(fd, msg);
}

static int cancel_command(int fd, struct pam_user *usr, struct pam_user *cusr)
{
	if (usr->pwd->pw_uid == cusr->pwd->pw_uid)
		return CANCELED;

	send_info_packet(fd, "you cannot cancel this command");
	return CONTINUE;	
}

static int validate_command(int fd, struct poll_table *pt, 
				struct pam_user *cusr, unsigned *quorum)
{
	size_t i;

	if (cusr->cred.uid == pt->usrs[0].pwd->pw_uid) {
		send_info_packet(fd, "you cannot validate your own command");
		return CONTINUE;
	}

	for (i = 0; i < pt->nvalidators; i++) {
		if (cusr->cred.uid == pt->validators[i].uid) {
			send_info_packet(fd, "you have already validate "\
								"this command");
			return CONTINUE;	
		}
	}

	pt->validators[pt->nvalidators] = cusr->cred;
	pt->nvalidators++;
	(*quorum)++;
	send_info_packet(fd, "command validated");
	_pam_info(_pamh, _opt, "user %s has validated the command", cusr->name);
	return (*quorum >= pt->usrs[0].grp.quorum) ? VALIDATE : CONTINUE;
	
}

static int new_request(struct poll_table *pt, size_t pos, unsigned *quorum) 
{
	struct msg_packet msg;
	int fd = pt->fds[pos].fd;
	struct pam_user *usr = &pt->usrs[pos];
	int err = recv_packet(fd, &msg);

	if (err)
		return (errno == EBADMSG) ? CONTINUE : PAM_SYSTEM_ERR;

 	switch (msg.code) {
	case SERVER_INFO:
		return CONTINUE;
	case CANCEL_COMMAND:
		return cancel_command(fd, &pt->usrs[0], usr);
	case REFUSE_COMMAND:
		return send_info_packet(fd, "unimplemented");
	case VALIDATE_COMMAND:
		return validate_command(fd, pt, usr, quorum);	
	}

	_pam_syslog(_pamh, LOG_NOTICE, "received an invalid request code "\
			"(%d) from user %s (uid=%d)", msg.code, usr->name, 
							usr->pwd->pw_uid);
	return send_info_packet(fd,  "invalid request code");
}

static int handle_event(struct poll_table *pt, unsigned *quorum, int sfd)
{
	size_t i;
	int ret = 0;

	for (i = 0; i < pt->ncon && (!ret || ret == CONTINUE); i++) {
		if (!pt->fds[i].revents)
			continue;
		if (pt->fds[i].revents && !i)
			ret = new_connection(sfd, pt);
		else if ((pt->fds[i].revents & POLLIN) && i)
			ret = new_request(pt, i, quorum);
		else /* i && POLLHUP | POLLRDHUP */
			close_connection(pt, &i);
	}
	
	return (ret == CONTINUE) ? 0 : ret;
}

int wait_for_validation(pam_handle_t *pamh, struct pam_user *usr, 
						struct control ctrl, int fd)
{
	int set, status = 0; 
	unsigned quorum = 1;
	struct poll_table *pt = poll_init(usr, fd);
	_pamh = pamh;
	_opt = ctrl.opt;

	if (!pt) 
		return PAM_SYSTEM_ERR;

	if (configure_signals(ctrl.timeout)) {
		poll_clean(pt);
		return PAM_SYSTEM_ERR;
	}		

	while (!status) {
		set = poll(pt->fds, pt->ncon, -1);
		if (set < 0 && errno != EINTR) {
			_pam_syslog(pamh, LOG_ERR, "poll() error: %m");
			status = PAM_SYSTEM_ERR; 
		} else if ((set < 0 && errno == EINTR) || 
			   (got_sig | got_sigalrm)) {
			status = abort_waiting();
		} else {
			status = handle_event(pt, &quorum, fd);
		}
	}

	if (configure_signals(0))
		status = PAM_SYSTEM_ERR;

	poll_clean(pt);
	return (status == VALIDATE) ? PAM_SUCCESS : status;
}

