#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <linux/limits.h>
#include <sudo_plugin.h>

#define NAME	"shared.so"
#define FIFO_PATH	"/var/lib/shamir/"
#define __dso_public __attribute__((__visibility__("default")))

static char *
_named_fifo(pid_t process) 
{
	char *name;
	size_t n = sizeof(FIFO_PATH) + sizeof(int) + sizeof(char);
	name = calloc(n, sizeof(char));
	
	if (name == NULL)
		return NULL;

	snprintf(name, n-1, "%s%d", FIFO_PATH, process);

	return name;
}

static void
log_message(int level, const char *msg, ...)
{
	va_list args;
	
	va_start(args, msg);
	openlog(NAME, LOG_PID, LOG_AUTHPRIV);
	
	if(level)
		vsyslog(level, msg, args);
	
	closelog();
	va_end(args);
}


static int
io_open(unsigned int version, sudo_conv_t conversation,
	sudo_printf_t sudo_printf, char *const settings[],
	char *const user_info[], char *const command_info[],
	int argc, char *const argv[], char *const user_env[],
	 char *const args[])
{
	int retval, i;
	FILE *fp;
	char *fifo;
	
	log_message(LOG_INFO, "io_open");
	
	fifo = _named_fifo(getpid());
	
	
	if ((retval = mkfifo(fifo, 0600))) {
		log_message(LOG_ERR, "can not create fifo: %m");
		return false;
	}

	if ((fd = open(fifo, O_WRONLY))) {
		log_message(LOG_ERR, "can not open fifo: %m");
		unlink(fifo);
		return false;
	}

	for (i=0; i<argc; i++) {
		if ((write(fd, argv[i], strlen(argv[i]))) == -1) {
			log_message(LOG_ERR, "can not write in fifo: %m");
			break;
		}
	}	
	
	close(fd);
	unlink(fifo);
	
     	return true;
 }
 
static void
io_close(int exit_status, int error)
{
	log_message(LOG_INFO, "io_close");
	//rm fic
}
 

__dso_public struct io_plugin shared_io = {
	SUDO_IO_PLUGIN,
    	SUDO_API_VERSION,
    	io_open,
    	io_close,
};

