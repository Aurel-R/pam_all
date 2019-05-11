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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <pwd.h>
#include <getopt.h>
#include <dirent.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include "utils.h"

#define SERVICE_NAME	"all-validate"
#define CMD_DIR		"/var/lib/pam_all"

#define USER_NAME_LEN	64
#define UNIX_PATH_LEN	108 
#define DATA_BUFF_LEN	128
#define TIME_LEN	6

#define LONG_LIST	0x01
#define FORCE_YES	0x02
#define CANCEL_CMD	0x04

enum msg_code {
	SERVER_INFO,
	CANCEL_COMMAND,
	REFUSE_COMMAND, /* unimplemented */
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

struct request_list {
	struct iovec iov;
	struct request *req;
	struct request_list *next;
};

static void usage(const char *service_name)
{
	printf("usage:\n");
	printf("lists pending commands:\n");
	printf("\t%s [-l | --list]\n", service_name);
	printf("validate command:\n");
	printf("\t%s [-y | --yes] pid_1 [pid_2 pid_3 ...]\n", service_name);
	printf("cancel command:\n"); 
	printf("\t%s {-c | --cancel} pid_1 [pid_2 pid_3 ...]\n", service_name);
}

static int pam_auth(pam_handle_t **pamh)
{
	int err;
	pam_handle_t *_pamh = NULL;
	struct passwd *pwd = getpwuid(getuid());
	struct pam_conv pamc = { 
		misc_conv,
		NULL
	};

	if (!pwd) {
		perror("getpwuid");
		return PAM_SYSTEM_ERR;
	}
	
	err = pam_start(SERVICE_NAME, pwd->pw_name, &pamc, &_pamh);
	if (err) {
		fprintf(stderr, "pam_start error (%d): %s\n", 
					err, pam_strerror(_pamh, err));
		return err;
	}

	err = pam_authenticate(_pamh, 0);
	if (err) {
		fprintf(stderr, "authenticate error (%d): %s\n",
					err, pam_strerror(_pamh, err));
		pam_end(_pamh, err);
		return err;
	}
	
	*pamh = _pamh;
	return PAM_SUCCESS;
}

static int filter(const struct dirent *entry)
{
	return !strncmp(entry->d_name, "req-", 4);	
}

/* TODO: add + check header */
static int extract_request(struct request_list **reql, struct dirent *entry)
{
	int fd;
	struct stat st;
	char path[PATH_MAX];
	struct request_list *curr = malloc(sizeof(*curr));

	if (!curr) {
		perror("malloc");
		return -1;
	}

	memset(path, '\0', sizeof(path));
	snprintf(path, sizeof(path) - 1, "%s/%s", CMD_DIR, entry->d_name);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("open");
		free(curr);
		return -1;
	}

	if (fstat(fd, &st)) {
		perror("fstat");
		goto err;
	}

	if ((size_t)st.st_size < sizeof(struct request))
		goto wrong_file_format;

	curr->iov.iov_base = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, 
							MAP_PRIVATE, fd, 0);
	if (curr->iov.iov_base == MAP_FAILED) {
		perror("mmap");
		goto err;
	}

	curr->iov.iov_len = st.st_size;
	curr->req = curr->iov.iov_base;
	curr->req->command = curr->iov.iov_base + sizeof(struct request);
	curr->next = *reql;
	*reql = curr;
	close(fd);
	return 0;
wrong_file_format:
	fprintf(stderr, "%s: wrong file format\n", path);
err:
	close(fd);
	free(curr);
	return -1;
}

static void free_request_list(struct request_list *reql)
{
	struct request_list *tmp;
	while (reql) {
		tmp = reql->next;
		munmap(reql->iov.iov_base, reql->iov.iov_len);
		free(reql);
		reql = tmp;
	}
}

static int get_request_list(struct request_list **reql)
{
	int n, err = 0;
	struct dirent **entry;

	n = scandir(CMD_DIR, &entry, filter, alphasort);	
	if (n < 0) {
		perror("scandir");
		return -1;
	}
	
	if (!n) {
		printf("no pending requests\n");
		return 0;
	}
	
	while (n--) {
		err |= extract_request(reql, entry[n]);	
		free(entry[n]);
	}

	free(entry);
	return err;
}

static void print_request(struct request *req)
{
	char start[TIME_LEN], end[TIME_LEN];

	if (strtime(req->start, start, TIME_LEN))
		memcpy(start, "??:??", TIME_LEN);
	if (strtime(req->end, end, TIME_LEN))
		memcpy(end, "??:??", TIME_LEN);
	if (req->start == req->end)
		memcpy(end, "never", TIME_LEN);

	printf("PID=%d USER=%s TTY=%s PWD=%s START=%s END=%s COMMAND=%s\n", 
			req->pid, req->user, req->tty, req->pwd, start, 
			end, req->command);
}

static void print_request_list_long(struct request_list *reql)
{
	for (; reql; reql = reql->next) 
		print_request(reql->req);
}

static void print_request_list(struct request_list *reql, int ctrl)
{
	if (_IS_SET(ctrl, LONG_LIST))
		return print_request_list_long(reql);
	
	for (; reql; reql = reql->next) 
		printf("PID=%d USER=%s COMMAND=%s\n", reql->req->pid, 
				reql->req->user, reql->req->command);
}

static int recv_packet(int fd, struct msg_packet *msg)
{
	ssize_t n;
	struct msg_packet _msg;

	memset(&_msg, 0, sizeof(_msg));
	n = read(fd, &_msg, sizeof(_msg));
	if (n != sizeof(_msg)) {
		errno = (n < 0) ? errno : EBADMSG;
		perror("read");
		return -1;
	} 

	*msg = _msg;
	return 0;	
}

static int send_packet(int fd, struct msg_packet msg)
{
	ssize_t n = write(fd, &msg, sizeof(msg));

	if (n != sizeof(msg)) {
		fprintf(stderr, "send packet error: %m\n");
		return -1;
	}

	return 0;
}

/* XXX: add timeout on recv_packet */
static int send_msg(int fd, struct msg_packet msg)
{		
	if (send_packet(fd, msg) < 0)
		return -1;

	if (recv_packet(fd, &msg) < 0)
		return -1;

	if (msg.code == SERVER_INFO)	
		printf("%s\n", msg.data);
	
	return 0;
}

static int cancel_cmd(int fd)
{
	struct msg_packet msg = { .code = CANCEL_COMMAND };
	return send_msg(fd, msg);
}

static int validate_cmd(int fd, struct request *req, int ctrl)
{
	char yesno[3] = { 0 };
	struct msg_packet msg = { .code = VALIDATE_COMMAND };
	
	if (_IS_SET(ctrl, FORCE_YES))
		return send_msg(fd, msg);

	if (!isatty(STDIN_FILENO)) {
		fprintf(stderr, "stdin is not a tty\n");
		return -1;
	}

	printf("you are about to validate the request:\n");
	print_request(req);
retry:
	printf("validate this request? (y/n): ");
	fflush(stdout);
	if (!fgets(yesno, sizeof(yesno), stdin)) {
		fprintf(stderr, "fgets() return NULL\n");
		return -1;
	}
	purge_stdin(yesno);

	if (yesno[0] == 'y' || yesno[0] == 'Y')
		return send_msg(fd, msg);

	if (yesno[0] == 'n' || yesno[0] == 'N')
		return 0;
	
	goto retry;
}

static int connect_and_process(struct request *req, int ctrl)
{
	int err, fd;
	socklen_t len;
	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(struct sockaddr_un));

	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, req->saddr, UNIX_PATH_LEN);
	len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(sun.sun_path + 1);
	if (connect(fd, (const struct sockaddr *)&sun, len) < 0) {
		perror("connect");
		close(fd);
		return -1;
	}

	if (_IS_SET(ctrl, CANCEL_CMD))
		err = cancel_cmd(fd);
	else
		err = validate_cmd(fd, req, ctrl);
	
	close(fd);
	return err;
}

static int process_request(const char *strpid, struct request_list *reql, int ctrl)
{
	int err;
	pid_t pid = strtosint(strpid, &err);

	if (err) {
		fprintf(stderr, "error or overflow on strtol()\n");
		return -1;
	}

	for (; reql; reql = reql->next) {
		if (reql->req->pid == pid)
			return connect_and_process(reql->req, ctrl);
	}
	
	fprintf(stderr, "pid(%d) -- no such process\n", pid);
	return 0;
}

int main(int argc, char **argv)
{
	int retval, pam_err;
	pam_handle_t *pamh;
	int c, i, ctrl = 0;
	struct request_list *reql = NULL;
	struct option opt[] = {
		{"list"  , no_argument, NULL, 'l'},
		{"yes"   , no_argument, NULL, 'y'},
		{"help"  , no_argument, NULL, 'h'},
		{"cancel", no_argument, NULL, 'c'},
		{	0,	     0,    0,  0}};	

	while ((c = getopt_long(argc, argv, "hylc", opt, NULL)) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'l':
			SET(ctrl, LONG_LIST);
			break;
		case 'y':
			SET(ctrl, FORCE_YES);
			break;
		case 'c':
			SET(ctrl, CANCEL_CMD);
			break;
		default:
			fprintf(stderr, "unrecognized option -- '%c'\n", optopt);
			break;
		}
	}

	pam_err = pam_auth(&pamh);
	if (pam_err)
		return 1;

	retval = get_request_list(&reql);
	if (!reql)
		goto end;

	if (optind == argc || _IS_SET(ctrl, LONG_LIST)) {
		print_request_list(reql, ctrl);
		goto end;
	}

	for (i = optind; i < argc; i++) 
		retval |= process_request(argv[i], reql, ctrl);
end:
	free_request_list(reql);
	pam_end(pamh, pam_err);
	return (retval != 0);
}

